"""Containment enforcer for AEGIS.

Maps verifier verdicts to Slurm-oriented containment actions such as cgroup
throttling, ACL revocation, job suspension, and termination with credential
revocation.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ContainmentAction(Enum):
    """Enforcement actions available through the containment layer."""

    NONE = "none"
    CGROUP_THROTTLE = "cgroup_throttle"
    ACL_REVOKE = "acl_revoke"
    JOB_SUSPEND = "job_suspend"
    JOB_TERMINATE = "job_terminate"

    RATE_LIMIT = "cgroup_throttle"
    ISOLATE = "acl_revoke"
    SUSPEND = "job_suspend"
    TERMINATE = "job_terminate"


@dataclass
class ContainmentDecision:
    """Containment decision derived from a verification result."""

    agent_id: str
    action: ContainmentAction
    reason: str
    timestamp: float
    details: dict
    slurm_job_id: str = ""


class ContainmentEnforcer:
    """Translate verifier verdicts into Slurm-backed containment actions."""

    def __init__(self):
        self.handlers: Dict[ContainmentAction, Callable[[ContainmentDecision], None]] = {
            ContainmentAction.CGROUP_THROTTLE: self._cgroup_throttle,
            ContainmentAction.ACL_REVOKE: self._acl_revoke,
            ContainmentAction.JOB_SUSPEND: self._job_suspend,
            ContainmentAction.JOB_TERMINATE: self._job_terminate,
        }
        self.agent_states: Dict[str, str] = {}
        self.containment_history: List[ContainmentDecision] = []
        self.slurm_operations: List[dict] = []
        self.on_containment: Optional[Callable[[ContainmentDecision], None]] = None

    def enforce(self, result: VerificationResult) -> ContainmentDecision:
        action = self._verdict_to_action(result.verdict)
        decision = ContainmentDecision(
            agent_id=result.agent_id,
            slurm_job_id=result.slurm_job_id,
            action=action,
            reason=self._format_reason(result),
            timestamp=time.time(),
            details={
                "verdict": result.verdict.value,
                "violations": [violation.description for violation in result.violations],
                "challenge_id": result.challenge_id,
                "challenge_satisfied": result.challenge_satisfied,
            },
        )

        handler = self.handlers.get(action)
        if handler is not None:
            handler(decision)

        self.containment_history.append(decision)
        if self.on_containment:
            try:
                self.on_containment(decision)
            except Exception as exc:
                logger.error("Containment callback failed: %s", exc)
        return decision

    def _verdict_to_action(self, verdict) -> ContainmentAction:
        from .verifier import Verdict

        mapping = {
            Verdict.COMPLIANT: ContainmentAction.NONE,
            Verdict.VIOLATION_MINOR: ContainmentAction.CGROUP_THROTTLE,
            Verdict.VIOLATION_MODERATE: ContainmentAction.ACL_REVOKE,
            Verdict.VIOLATION_SEVERE: ContainmentAction.JOB_SUSPEND,
            Verdict.VIOLATION_CRITICAL: ContainmentAction.JOB_TERMINATE,
        }
        return mapping.get(verdict, ContainmentAction.JOB_TERMINATE)

    def _format_reason(self, result: VerificationResult) -> str:
        if not result.violations:
            return f"Verdict: {result.verdict.value}"
        preview = "; ".join(violation.description for violation in result.violations[:3])
        if len(result.violations) > 3:
            preview += f" (+{len(result.violations) - 3} more)"
        return f"Verdict: {result.verdict.value}; {preview}"

    def _record_slurm_operation(self, decision: ContainmentDecision, operation: str, **details: object) -> None:
        payload = {
            "agent_id": decision.agent_id,
            "slurm_job_id": decision.slurm_job_id,
            "operation": operation,
            "timestamp": time.time(),
            **details,
        }
        self.slurm_operations.append(payload)
        decision.details.setdefault("slurm_operations", []).append(payload)

    def _cgroup_throttle(self, decision: ContainmentDecision) -> None:
        self.agent_states[decision.agent_id] = "throttled"
        decision.details["containment_summary"] = "Applied cgroup CPU and memory throttling"
        decision.details["credential_revoked"] = False
        self._record_slurm_operation(
            decision,
            "PATCH /slurm/v0.0.39/job/{job_id}/cgroup",
            cpu_quota="50%",
            memory_quota="50%",
        )
        logger.warning("[CONTAINMENT] Throttled agent %s: %s", decision.agent_id, decision.reason)

    def _acl_revoke(self, decision: ContainmentDecision) -> None:
        self.agent_states[decision.agent_id] = "acl_revoked"
        decision.details["containment_summary"] = "Revoked shared filesystem ACLs"
        decision.details["credential_revoked"] = False
        self._record_slurm_operation(
            decision,
            "POST /slurm/v0.0.39/job/{job_id}/acl-revoke",
            scope="shared-storage",
        )
        logger.warning("[CONTAINMENT] Revoked ACLs for agent %s: %s", decision.agent_id, decision.reason)

    def _job_suspend(self, decision: ContainmentDecision) -> None:
        self.agent_states[decision.agent_id] = "suspended"
        decision.details["containment_summary"] = "Suspended the Slurm job pending investigation"
        decision.details["credential_revoked"] = False
        self._record_slurm_operation(
            decision,
            "POST /slurm/v0.0.39/job/{job_id}/suspend",
        )
        logger.warning("[CONTAINMENT] Suspended agent %s: %s", decision.agent_id, decision.reason)

    def _job_terminate(self, decision: ContainmentDecision) -> None:
        self.agent_states[decision.agent_id] = "terminated"
        decision.details["containment_summary"] = "Terminated the Slurm job and revoked credentials"
        decision.details["credential_revoked"] = True
        self._record_slurm_operation(
            decision,
            "DELETE /slurm/v0.0.39/job/{job_id}",
            revoke_credentials=True,
        )
        logger.critical("[CONTAINMENT] Terminated agent %s: %s", decision.agent_id, decision.reason)

    def get_agent_state(self, agent_id: str) -> str:
        return self.agent_states.get(agent_id, "active")

    def is_contained(self, agent_id: str) -> bool:
        return self.get_agent_state(agent_id) != "active"

    def release(self, agent_id: str) -> None:
        old_state = self.agent_states.pop(agent_id, None)
        if old_state:
            logger.info("[CONTAINMENT] Released agent %s from %s", agent_id, old_state)


from .verifier import VerificationResult
