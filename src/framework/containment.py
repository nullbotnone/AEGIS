"""Containment enforcer for AEGIS.

Translates verification verdicts into enforcement actions ranging from
rate-limiting to full termination. In production, interfaces with Slurm REST API.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ContainmentAction(Enum):
    """Enforcement actions that can be applied to a violating agent."""
    NONE = "none"
    RATE_LIMIT = "rate_limit"
    ISOLATE = "isolate"
    SUSPEND = "suspend"
    TERMINATE = "terminate"


@dataclass
class ContainmentDecision:
    """A containment decision based on a verification result.

    Attributes:
        agent_id: The agent being contained.
        action: The containment action to apply.
        reason: Human-readable reason for the containment.
        timestamp: When the decision was made.
        details: Additional details (verdict, violation descriptions).
    """
    agent_id: str
    action: ContainmentAction
    reason: str
    timestamp: float
    details: dict


class ContainmentEnforcer:
    """Translates verification verdicts into enforcement actions.

    Maps violation severity to containment responses:
    - COMPLIANT → NONE
    - VIOLATION_MINOR → RATE_LIMIT (cgroup bandwidth throttling)
    - VIOLATION_MODERATE → ISOLATE (revoke ACLs, redirect to sandbox)
    - VIOLATION_SEVERE → Suspend (pause job, require human review)
    - VIOLATION_CRITICAL → TERMINATE (kill session, revoke creds, alert security)

    In production, enforcement actions interface with the Slurm REST API.
    This simulation applies in-process state changes and logging.
    """

    def __init__(self):
        """Initialize the containment enforcer."""
        # Enforcement handlers
        self.handlers: Dict[ContainmentAction, Callable] = {
            ContainmentAction.RATE_LIMIT: self._rate_limit,
            ContainmentAction.ISOLATE: self._isolate,
            ContainmentAction.SUSPEND: self._suspend,
            ContainmentAction.TERMINATE: self._terminate,
        }

        # Agent state tracking: agent_id -> state string
        self.agent_states: Dict[str, str] = {}
        self.containment_history: List[ContainmentDecision] = []

        # Callbacks for external systems
        self.on_containment: Optional[Callable[[ContainmentDecision], None]] = None

    def enforce(self, result: VerificationResult) -> ContainmentDecision:
        """Enforce a verification result by applying containment.

        Args:
            result: The VerificationResult from the policy verifier.

        Returns:
            The ContainmentDecision that was applied.
        """
        from .verifier import Verdict

        # Map verdict to containment action
        action = self._verdict_to_action(result.verdict)

        # Create decision
        decision = ContainmentDecision(
            agent_id=result.agent_id,
            action=action,
            reason=self._format_reason(result),
            timestamp=time.time(),
            details={
                "verdict": result.verdict.value,
                "violations": [v.description for v in result.violations],
            },
        )

        # Execute enforcement (skip if NONE)
        if action in self.handlers:
            self.handlers[action](decision)

        # Record decision
        self.containment_history.append(decision)

        # Notify external systems
        if self.on_containment:
            try:
                self.on_containment(decision)
            except Exception as e:
                logger.error(f"Containment callback failed: {e}")

        return decision

    def _verdict_to_action(self, verdict) -> ContainmentAction:
        """Map a verification verdict to a containment action.

        Args:
            verdict: The Verdict enum value.

        Returns:
            The corresponding ContainmentAction.
        """
        from .verifier import Verdict

        mapping = {
            Verdict.COMPLIANT: ContainmentAction.NONE,
            Verdict.VIOLATION_MINOR: ContainmentAction.RATE_LIMIT,
            Verdict.VIOLATION_MODERATE: ContainmentAction.ISOLATE,
            Verdict.VIOLATION_SEVERE: ContainmentAction.SUSPEND,
            Verdict.VIOLATION_CRITICAL: ContainmentAction.TERMINATE,
        }
        return mapping.get(verdict, ContainmentAction.TERMINATE)

    def _format_reason(self, result: VerificationResult) -> str:
        """Format a human-readable reason for the containment decision.

        Args:
            result: The VerificationResult.

        Returns:
            A formatted reason string.
        """
        if not result.violations:
            return f"Verdict: {result.verdict.value}"
        violation_descs = [v.description for v in result.violations[:3]]
        reason = f"Verdict: {result.verdict.value}; " + "; ".join(violation_descs)
        if len(result.violations) > 3:
            reason += f" (+{len(result.violations) - 3} more)"
        return reason

    def _rate_limit(self, decision: ContainmentDecision) -> None:
        """Rate-limit an agent's resource access (cgroup throttling).

        In production: cgroup bandwidth throttling via Slurm REST API.
        """
        self.agent_states[decision.agent_id] = "rate_limited"
        logger.warning(
            f"[CONTAINMENT] Rate-limiting agent {decision.agent_id}: {decision.reason}"
        )

    def _isolate(self, decision: ContainmentDecision) -> None:
        """Isolate an agent (revoke filesystem ACLs, redirect to sandbox).

        In production: revoke ACLs via Slurm REST API, redirect network to honeypot.
        """
        self.agent_states[decision.agent_id] = "isolated"
        logger.warning(
            f"[CONTAINMENT] Isolating agent {decision.agent_id}: {decision.reason}"
        )

    def _suspend(self, decision: ContainmentDecision) -> None:
        """Suspend an agent's execution (pause job, require human intervention).

        In production: scancel --suspend via Slurm.
        """
        self.agent_states[decision.agent_id] = "suspended"
        logger.warning(
            f"[CONTAINMENT] Suspending agent {decision.agent_id}: {decision.reason}"
        )

    def _terminate(self, decision: ContainmentDecision) -> None:
        """Terminate an agent (kill session, revoke credentials, alert security).

        In production: scancel + kdestroy + security alert to SIEM.
        """
        self.agent_states[decision.agent_id] = "terminated"
        logger.critical(
            f"[CONTAINMENT] Terminating agent {decision.agent_id}: {decision.reason}"
        )

    def get_agent_state(self, agent_id: str) -> str:
        """Get the current containment state of an agent.

        Args:
            agent_id: The agent to check.

        Returns:
            The agent's state string (or "active" if not contained).
        """
        return self.agent_states.get(agent_id, "active")

    def is_contained(self, agent_id: str) -> bool:
        """Check if an agent is currently under containment.

        Args:
            agent_id: The agent to check.

        Returns:
            True if the agent is not in "active" state.
        """
        return self.agent_states.get(agent_id, "active") != "active"

    def release(self, agent_id: str) -> None:
        """Release an agent from containment (manual override).

        Args:
            agent_id: The agent to release.
        """
        old_state = self.agent_states.pop(agent_id, None)
        if old_state:
            logger.info(
                f"[CONTAINMENT] Released agent {agent_id} from {old_state}"
            )
