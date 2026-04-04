"""Central policy engine orchestrator for AEGIS."""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Dict, Optional

from .agent_monitor import AgentMonitor
from .attestation import AttestationEngine
from .containment import ContainmentEnforcer
from .constraints import ConstraintManager, ConstraintProfile
from .verifier import PolicyVerifier

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Coordinate constraint management, attestation, verification, and containment."""

    def __init__(
        self,
        attestation_interval: int = 1,
        *,
        node_id: str = "compute-node-sim",
        challenge_probability: float = 0.1,
    ):
        self.constraint_manager = ConstraintManager()
        self.attestation_engine = AttestationEngine(
            node_id=node_id,
            attestation_interval=attestation_interval,
        )
        self.verifier = PolicyVerifier(
            correlation_window_seconds=30,
            challenge_ttl_seconds=max(attestation_interval * 2, 2),
            profile_signing_key=self.constraint_manager.signing_key,
        )
        self.containment = ContainmentEnforcer()
        self.audit = self.verifier.audit

        self.monitored_agents: Dict[str, AgentMonitor] = {}
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.attestation_interval = attestation_interval
        self.challenge_probability = challenge_probability

    def register_agent(
        self,
        agent_id: str,
        user_id: str,
        project_id: str,
        constraints: ConstraintProfile,
    ) -> AgentMonitor:
        constraints.agent_id = agent_id
        constraints.user_id = user_id
        constraints.project_id = project_id
        if not constraints.session_id:
            constraints.session_id = f"session_{agent_id}_{int(time.time())}"
        if not constraints.slurm_job_id:
            constraints.slurm_job_id = f"job_{agent_id}"

        self.constraint_manager.compile_profile(constraints)
        if not constraints.signature:
            self.constraint_manager.sign_profile(constraints)

        self.verifier.register_agent(constraints)
        monitor = AgentMonitor(agent_id, constraints, self.attestation_engine)
        self.monitored_agents[agent_id] = monitor

        self.audit.append("registration", agent_id, {
            "user_id": user_id,
            "project_id": project_id,
            "session_id": constraints.session_id,
            "slurm_job_id": constraints.slurm_job_id,
            "derivation_mode": constraints.derivation_mode.value,
            "template_name": constraints.template_name,
            "profile_hash": constraints.profile_hash(),
            "profile_signature": constraints.signature,
        })
        logger.info("Registered agent %s for behavioral attestation", agent_id)
        return monitor

    def unregister_agent(self, agent_id: str) -> None:
        self.monitored_agents.pop(agent_id, None)
        self.attestation_engine.unregister_agent(agent_id)
        self.verifier.unregister_agent(agent_id)
        self.audit.append("unregistration", agent_id, {"timestamp": time.time()})
        logger.info("Unregistered agent %s", agent_id)

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._attestation_loop, daemon=True)
        self._thread.start()
        logger.info("AEGIS attestation loop started")

    def stop(self) -> None:
        self.running = False
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("AEGIS attestation loop stopped")

    def _attestation_loop(self) -> None:
        while self.running:
            time.sleep(self.attestation_interval)
            for agent_id in list(self.monitored_agents.keys()):
                try:
                    self._attest_agent(agent_id)
                except Exception as exc:
                    logger.error("Attestation error for agent %s: %s", agent_id, exc)
                    self.audit.append("error", agent_id, {"error": str(exc)})

    def _attest_agent(self, agent_id: str) -> None:
        challenge = None
        if random.random() < self.challenge_probability:
            challenge = self.verifier.issue_challenge(agent_id)
            self.audit.append("challenge", agent_id, challenge)

        evidence = self.attestation_engine.generate_evidence(agent_id, challenge=challenge)
        self.audit.append("attestation", agent_id, {
            "node_id": evidence.node_id,
            "session_id": evidence.session_id,
            "slurm_job_id": evidence.slurm_job_id,
            "transport": evidence.transport,
            "evidence_hash": evidence.compute_hash(),
            "actions_count": len(evidence.actions),
            "challenge_id": evidence.challenge_id,
            "network_egress_mb": evidence.total_network_egress_mb,
        })

        result = self.verifier.verify(evidence)
        self.audit.append("verification", agent_id, {
            "session_id": result.session_id,
            "slurm_job_id": result.slurm_job_id,
            "verdict": result.verdict.value,
            "challenge_id": result.challenge_id,
            "challenge_satisfied": result.challenge_satisfied,
            "violations": [violation.description for violation in result.violations],
            "access_graph_alerts": result.access_graph_alerts,
        })

        if result.is_violation():
            decision = self.containment.enforce(result)
            self.audit.append("containment", agent_id, {
                "slurm_job_id": decision.slurm_job_id,
                "action": decision.action.value,
                "reason": decision.reason,
                "details": decision.details,
            })

    def get_agent_status(self, agent_id: str) -> dict:
        monitor = self.monitored_agents.get(agent_id)
        profile = monitor.constraint_profile if monitor is not None else None
        last_result = next(
            (result for result in reversed(self.verifier.verification_history) if result.agent_id == agent_id),
            None,
        )
        return {
            "agent_id": agent_id,
            "state": self.containment.get_agent_state(agent_id),
            "violations": self.verifier.get_violation_count(agent_id),
            "last_verification": last_result.timestamp if last_result else None,
            "last_verdict": last_result.verdict.value if last_result else None,
            "is_monitored": agent_id in self.monitored_agents,
            "session_id": getattr(profile, "session_id", None),
            "slurm_job_id": getattr(profile, "slurm_job_id", None),
            "challenge_pending": agent_id in self.verifier.pending_challenges,
        }

    def get_system_status(self) -> dict:
        return {
            "running": self.running,
            "monitored_agents": len(self.monitored_agents),
            "total_verifications": len(self.verifier.verification_history),
            "total_containments": len(self.containment.containment_history),
            "audit_ledger": self.audit.get_summary(),
            "pending_challenges": len(self.verifier.pending_challenges),
            "tracked_paths": len(self.verifier.shared_access_graph),
            "contained_agents": {
                agent_id: state
                for agent_id, state in self.containment.agent_states.items()
                if state != "active"
            },
        }
