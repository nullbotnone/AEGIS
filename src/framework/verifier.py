"""Policy verifier for AEGIS.

Evaluates attestation evidence against constraint profiles and produces
verification verdicts with specific violation details.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Verdict(Enum):
    """Verification verdicts indicating compliance or violation severity."""
    COMPLIANT = "compliant"
    VIOLATION_MINOR = "violation_minor"
    VIOLATION_MODERATE = "violation_moderate"
    VIOLATION_SEVERE = "violation_severe"
    VIOLATION_CRITICAL = "violation_critical"

    def __gt__(self, other: Verdict) -> bool:
        return _VERDICT_ORDER[self] > _VERDICT_ORDER[other]

    def __ge__(self, other: Verdict) -> bool:
        return _VERDICT_ORDER[self] >= _VERDICT_ORDER[other]

    def __lt__(self, other: Verdict) -> bool:
        return _VERDICT_ORDER[self] < _VERDICT_ORDER[other]

    def __le__(self, other: Verdict) -> bool:
        return _VERDICT_ORDER[self] <= _VERDICT_ORDER[other]


_VERDICT_ORDER = {
    Verdict.COMPLIANT: 0,
    Verdict.VIOLATION_MINOR: 1,
    Verdict.VIOLATION_MODERATE: 2,
    Verdict.VIOLATION_SEVERE: 3,
    Verdict.VIOLATION_CRITICAL: 4,
}


@dataclass
class ConstraintViolation:
    """A specific constraint violation detected in attestation evidence.

    Attributes:
        constraint_type: The type of constraint violated
            ("data_access", "network", "tool_invocation", "data_flow", "system").
        description: Human-readable description of the violation.
        severity: The severity level of this violation.
        evidence: The action data that triggered the violation.
        timestamp: When the violation was detected.
    """
    constraint_type: str
    description: str
    severity: Verdict
    evidence: dict
    timestamp: float


@dataclass
class VerificationResult:
    """Result of evaluating attestation evidence against constraints.

    Attributes:
        agent_id: The agent that was verified.
        session_id: The session identifier.
        timestamp: When verification occurred.
        verdict: The overall verdict (most severe violation, or COMPLIANT).
        violations: List of specific violations found.
    """
    agent_id: str
    session_id: str
    timestamp: float
    verdict: Verdict
    violations: List[ConstraintViolation] = field(default_factory=list)

    def is_violation(self) -> bool:
        """Check if this result contains any violations."""
        return self.verdict != Verdict.COMPLIANT


class PolicyVerifier:
    """Evaluates attestation evidence against constraint profiles.

    The PolicyVerifier is the core decision-making component of AEGIS.
    It checks each action in the evidence against the agent's constraint
    profile and produces a verification result with verdict and violations.
    """

    def __init__(self):
        """Initialize the policy verifier."""
        # Agent ID -> ConstraintProfile
        self.constraint_profiles: Dict[str, object] = {}

        # Verification history
        self.verification_history: List[VerificationResult] = []

        # Rate limiting state (for volume-based constraints)
        self.volume_windows: Dict[str, Dict[str, float]] = {}

    def register_agent(self, constraint_profile: object) -> None:
        """Register an agent's constraint profile.

        Args:
            constraint_profile: The ConstraintProfile for the agent.
        """
        agent_id = constraint_profile.agent_id
        self.constraint_profiles[agent_id] = constraint_profile
        self.volume_windows[agent_id] = {
            "window_start": time.time(),
            "file_read_mb": 0,
            "file_write_mb": 0,
            "network_egress_mb": 0,
        }

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent's constraint profile.

        Args:
            agent_id: The agent to unregister.
        """
        self.constraint_profiles.pop(agent_id, None)
        self.volume_windows.pop(agent_id, None)

    def verify(self, evidence: AttestationEvidence) -> VerificationResult:
        """Evaluate attestation evidence against the agent's constraint profile.

        Args:
            evidence: The attestation evidence to verify.

        Returns:
            A VerificationResult with verdict and any violations.
        """
        profile = self.constraint_profiles.get(evidence.agent_id)
        if not profile:
            return VerificationResult(
                agent_id=evidence.agent_id,
                session_id=evidence.session_id,
                timestamp=time.time(),
                verdict=Verdict.VIOLATION_SEVERE,
                violations=[ConstraintViolation(
                    constraint_type="system",
                    description=f"No constraint profile for agent {evidence.agent_id}",
                    severity=Verdict.VIOLATION_SEVERE,
                    evidence={},
                    timestamp=time.time(),
                )],
            )

        violations: List[ConstraintViolation] = []
        max_severity = Verdict.COMPLIANT

        # Check each action in the evidence
        for action in evidence.actions:
            action_violations = self._check_action(profile, action)
            violations.extend(action_violations)
            for v in action_violations:
                if v.severity > max_severity:
                    max_severity = v.severity

        # Check volume constraints
        volume_violations = self._check_volumes(profile, evidence)
        violations.extend(volume_violations)
        for v in volume_violations:
            if v.severity > max_severity:
                max_severity = v.severity

        # Update volume windows
        self._update_volume_windows(profile.agent_id, evidence)

        result = VerificationResult(
            agent_id=evidence.agent_id,
            session_id=evidence.session_id,
            timestamp=time.time(),
            verdict=max_severity,
            violations=violations,
        )

        self.verification_history.append(result)
        return result

    def _check_action(
        self, profile: object, action: AgentAction
    ) -> List[ConstraintViolation]:
        """Check a single action against constraints.

        Args:
            profile: The ConstraintProfile to check against.
            action: The AgentAction to evaluate.

        Returns:
            List of ConstraintViolation instances (empty if compliant).
        """
        # Import here to avoid circular imports at module level
        from framework.attestation import ActionType

        violations: List[ConstraintViolation] = []

        if action.action_type == ActionType.FILE_READ:
            path = action.details.get("path", "")
            allowed, reason = profile.data_access.check_access(path, "read")
            if not allowed:
                violations.append(ConstraintViolation(
                    constraint_type="data_access",
                    description=f"Unauthorized file read: {reason}",
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={"action": "file_read", "path": path},
                    timestamp=action.timestamp,
                ))

        elif action.action_type == ActionType.FILE_WRITE:
            path = action.details.get("path", "")
            allowed, reason = profile.data_access.check_access(path, "write")
            if not allowed:
                violations.append(ConstraintViolation(
                    constraint_type="data_access",
                    description=f"Unauthorized file write: {reason}",
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={"action": "file_write", "path": path},
                    timestamp=action.timestamp,
                ))

        elif action.action_type in (ActionType.NETWORK_CONNECTION, ActionType.LLM_API_CALL):
            endpoint = action.details.get("endpoint", "")
            data_size = action.details.get("data_sent_mb", 0)
            allowed, reason = profile.network.check_connection(endpoint, data_size)
            if not allowed:
                violations.append(ConstraintViolation(
                    constraint_type="network",
                    description=f"Unauthorized connection: {reason}",
                    severity=Verdict.VIOLATION_SEVERE,
                    evidence={"action": action.action_type.value, "endpoint": endpoint},
                    timestamp=action.timestamp,
                ))

        elif action.action_type == ActionType.TOOL_INVOCATION:
            tool = action.details.get("tool", "")
            allowed, reason = profile.tools.check_invocation(tool)
            if not allowed:
                violations.append(ConstraintViolation(
                    constraint_type="tool_invocation",
                    description=f"Unauthorized tool: {reason}",
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={"action": "tool_invocation", "tool": tool},
                    timestamp=action.timestamp,
                ))

        return violations

    def _check_volumes(
        self, profile: object, evidence: AttestationEvidence
    ) -> List[ConstraintViolation]:
        """Check volume-based constraints (data budgets).

        Args:
            profile: The ConstraintProfile to check against.
            evidence: The attestation evidence with volume data.

        Returns:
            List of ConstraintViolation instances.
        """
        violations: List[ConstraintViolation] = []

        # Check exfil budget (network egress rate)
        if profile.data_flow.max_exfil_budget_mb_per_hour:
            agent_id = profile.agent_id
            window = self.volume_windows.get(agent_id, {})
            window_start = window.get("window_start", time.time())
            elapsed_hours = (time.time() - window_start) / 3600

            if elapsed_hours > 0:
                current_egress = window.get("network_egress_mb", 0) + evidence.total_network_egress_mb
                rate = current_egress / elapsed_hours

                if rate > profile.data_flow.max_exfil_budget_mb_per_hour:
                    violations.append(ConstraintViolation(
                        constraint_type="data_flow",
                        description=(
                            f"Exfil budget exceeded: {rate:.2f} MB/h > "
                            f"{profile.data_flow.max_exfil_budget_mb_per_hour} MB/h"
                        ),
                        severity=Verdict.VIOLATION_SEVERE,
                        evidence={
                            "current_rate_mb_per_hour": rate,
                            "budget": profile.data_flow.max_exfil_budget_mb_per_hour,
                        },
                        timestamp=time.time(),
                    ))

        # Check read volume
        if profile.data_access.max_read_volume_mb:
            if evidence.total_file_read_mb > profile.data_access.max_read_volume_mb:
                violations.append(ConstraintViolation(
                    constraint_type="data_access",
                    description=(
                        f"Read volume exceeded: {evidence.total_file_read_mb:.1f} MB > "
                        f"{profile.data_access.max_read_volume_mb} MB"
                    ),
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={
                        "read_mb": evidence.total_file_read_mb,
                        "limit_mb": profile.data_access.max_read_volume_mb,
                    },
                    timestamp=time.time(),
                ))

        # Check write volume
        if profile.data_access.max_write_volume_mb:
            if evidence.total_file_write_mb > profile.data_access.max_write_volume_mb:
                violations.append(ConstraintViolation(
                    constraint_type="data_access",
                    description=(
                        f"Write volume exceeded: {evidence.total_file_write_mb:.1f} MB > "
                        f"{profile.data_access.max_write_volume_mb} MB"
                    ),
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={
                        "write_mb": evidence.total_file_write_mb,
                        "limit_mb": profile.data_access.max_write_volume_mb,
                    },
                    timestamp=time.time(),
                ))

        return violations

    def _update_volume_windows(
        self, agent_id: str, evidence: AttestationEvidence
    ) -> None:
        """Update running volume counters for an agent.

        Args:
            agent_id: The agent to update.
            evidence: The evidence with new volume data.
        """
        if agent_id not in self.volume_windows:
            return

        self.volume_windows[agent_id]["file_read_mb"] += evidence.total_file_read_mb
        self.volume_windows[agent_id]["file_write_mb"] += evidence.total_file_write_mb
        self.volume_windows[agent_id]["network_egress_mb"] += evidence.total_network_egress_mb

    def get_violation_count(self, agent_id: str) -> int:
        """Get the total number of violations for an agent.

        Args:
            agent_id: The agent to check.

        Returns:
            The number of verification results with violations.
        """
        return len([
            r for r in self.verification_history
            if r.agent_id == agent_id and r.is_violation()
        ])
