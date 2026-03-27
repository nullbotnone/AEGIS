"""Central policy engine orchestrator for AEGIS.

Ties together all AEGIS components into a continuous attestation loop:
AttestationEngine → PolicyVerifier → ContainmentEnforcer → AuditLedger
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Dict, Optional

from .agent_monitor import AgentMonitor
from .attestation import AttestationEngine
from .audit import AuditLedger
from .containment import ContainmentEnforcer
from .constraints import ConstraintProfile
from .verifier import PolicyVerifier

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Central orchestrator for the AEGIS framework.

    Manages the continuous attestation loop that:
    1. Generates evidence bundles for each monitored agent
    2. Verifies evidence against constraint profiles
    3. Enforces containment decisions on violations
    4. Logs everything to the tamper-evident audit ledger
    """

    def __init__(self, attestation_interval: int = 5):
        """Initialize the policy engine.

        Args:
            attestation_interval: Seconds between attestation cycles.
        """
        self.attestation_engine = AttestationEngine(
            node_id="central",
            attestation_interval=attestation_interval,
        )
        self.verifier = PolicyVerifier()
        self.containment = ContainmentEnforcer()
        self.audit = AuditLedger()

        self.monitored_agents: Dict[str, AgentMonitor] = {}
        self.running = False
        self._thread: Optional[threading.Thread] = None

        self.attestation_interval = attestation_interval

    def register_agent(
        self,
        agent_id: str,
        user_id: str,
        project_id: str,
        constraints: ConstraintProfile,
    ) -> AgentMonitor:
        """Register an agent for continuous attestation.

        Args:
            agent_id: Unique identifier for the agent.
            user_id: The user who owns this agent.
            project_id: The HPC project this agent belongs to.
            constraints: The constraint profile for this agent.

        Returns:
            The AgentMonitor for recording actions.
        """
        # Update constraint profile metadata
        constraints.agent_id = agent_id
        constraints.user_id = user_id
        constraints.project_id = project_id
        constraints.created_at = time.time()

        # Register with verifier
        self.verifier.register_agent(constraints)

        # Create monitor (which registers with attestation engine)
        monitor = AgentMonitor(agent_id, constraints, self.attestation_engine)
        self.monitored_agents[agent_id] = monitor

        # Audit the registration
        self.audit.append("registration", agent_id, {
            "user_id": user_id,
            "project_id": project_id,
            "constraints": constraints.to_dict() if hasattr(constraints, "to_dict") else str(constraints),
        })

        logger.info(f"Registered agent {agent_id} for continuous attestation")
        return monitor

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent from attestation.

        Args:
            agent_id: The agent to unregister.
        """
        self.monitored_agents.pop(agent_id, None)
        self.attestation_engine.unregister_agent(agent_id)
        self.verifier.unregister_agent(agent_id)

        self.audit.append("unregistration", agent_id, {
            "timestamp": time.time(),
        })

        logger.info(f"Unregistered agent {agent_id}")

    def start(self) -> None:
        """Start the continuous attestation loop.

        The loop runs in a background daemon thread.
        """
        if self.running:
            return

        self.running = True
        self._thread = threading.Thread(target=self._attestation_loop, daemon=True)
        self._thread.start()
        logger.info("AEGIS attestation loop started")

    def stop(self) -> None:
        """Stop the continuous attestation loop."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("AEGIS attestation loop stopped")

    def _attestation_loop(self) -> None:
        """Continuous attestation loop — runs in background thread.

        For each cycle:
        1. Generate evidence for each monitored agent
        2. Verify evidence against constraints
        3. Enforce containment on violations
        4. Log everything to audit ledger
        5. Optionally issue random challenges (10% chance)
        """
        while self.running:
            time.sleep(self.attestation_interval)

            for agent_id in list(self.monitored_agents.keys()):
                try:
                    self._attest_agent(agent_id)
                except Exception as e:
                    logger.error(f"Attestation error for agent {agent_id}: {e}")
                    self.audit.append("error", agent_id, {"error": str(e)})

    def _attest_agent(self, agent_id: str) -> None:
        """Run one attestation cycle for a single agent.

        Args:
            agent_id: The agent to attest.
        """
        # 1. Generate evidence
        evidence = self.attestation_engine.generate_evidence(agent_id)

        self.audit.append("attestation", agent_id, {
            "evidence_hash": evidence.compute_hash(),
            "actions_count": len(evidence.actions),
            "egress_mb": evidence.total_network_egress_mb,
        })

        # 2. Verify against constraints
        result = self.verifier.verify(evidence)

        self.audit.append("verification", agent_id, {
            "verdict": result.verdict.value,
            "violations": [v.description for v in result.violations],
        })

        # 3. Enforce if violation
        if result.is_violation():
            decision = self.containment.enforce(result)

            self.audit.append("containment", agent_id, {
                "action": decision.action.value,
                "reason": decision.reason,
            })

        # 4. Random challenge (10% chance)
        if random.random() < 0.1:
            challenge = self.attestation_engine.generate_challenge(agent_id)
            self.audit.append("challenge", agent_id, challenge)

    def get_agent_status(self, agent_id: str) -> dict:
        """Get the current status of an agent.

        Args:
            agent_id: The agent to query.

        Returns:
            Dictionary with agent state, violation count, and last verification.
        """
        last_verification = next(
            (
                result.timestamp
                for result in reversed(self.verifier.verification_history)
                if result.agent_id == agent_id
            ),
            None,
        )

        return {
            "agent_id": agent_id,
            "state": self.containment.get_agent_state(agent_id),
            "violations": self.verifier.get_violation_count(agent_id),
            "last_verification": last_verification,
            "is_monitored": agent_id in self.monitored_agents,
        }

    def get_system_status(self) -> dict:
        """Get overall AEGIS system status.

        Returns:
            Dictionary with system-wide metrics.
        """
        return {
            "running": self.running,
            "monitored_agents": len(self.monitored_agents),
            "total_verifications": len(self.verifier.verification_history),
            "total_containments": len(self.containment.containment_history),
            "audit_ledger": self.audit.get_summary(),
            "contained_agents": {
                aid: state
                for aid, state in self.containment.agent_states.items()
                if state != "active"
            },
        }
