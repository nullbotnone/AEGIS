"""Central policy verifier for AEGIS behavioral attestation."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional

from .attestation import ActionType, AgentAction, AttestationEvidence
from .constraints import ConstraintProfile, SignatureRule


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
    """A specific constraint or signature violation."""

    constraint_type: str
    description: str
    severity: Verdict
    evidence: dict
    timestamp: float
    code: str = ""


@dataclass
class SharedAccessRecord:
    """Cluster-wide access graph record used for cross-agent correlation."""

    agent_id: str
    session_id: str
    slurm_job_id: str
    path: str
    operation: str
    timestamp: float


@dataclass
class AuditEntry:
    """A single entry in the verifier-owned tamper-evident audit ledger."""

    sequence: int
    timestamp: float
    entry_type: str
    agent_id: str
    data: Dict[str, Any]
    previous_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        content = (
            f"{self.sequence}:{self.timestamp}:{self.entry_type}:"
            f"{self.agent_id}:{json.dumps(self.data, sort_keys=True)}:"
            f"{self.previous_hash}"
        )
        return hashlib.sha256(content.encode()).hexdigest()


class AuditLedger:
    """Tamper-evident, append-only audit ledger maintained by the verifier."""

    def __init__(self):
        self.entries: List[AuditEntry] = []
        self._last_hash = "0" * 64

    def append(self, entry_type: str, agent_id: str, data: Dict[str, Any]) -> AuditEntry:
        entry = AuditEntry(
            sequence=len(self.entries),
            timestamp=time.time(),
            entry_type=entry_type,
            agent_id=agent_id,
            data=data,
            previous_hash=self._last_hash,
        )
        entry.hash = entry.compute_hash()
        self._last_hash = entry.hash
        self.entries.append(entry)
        return entry

    def verify_integrity(self) -> tuple[bool, Optional[int]]:
        expected_hash = "0" * 64
        for index, entry in enumerate(self.entries):
            if entry.previous_hash != expected_hash:
                return False, index
            if entry.hash != entry.compute_hash():
                return False, index
            expected_hash = entry.hash
        return True, None

    def get_agent_history(self, agent_id: str) -> List[AuditEntry]:
        return [entry for entry in self.entries if entry.agent_id == agent_id]

    def get_entries_by_type(self, entry_type: str) -> List[AuditEntry]:
        return [entry for entry in self.entries if entry.entry_type == entry_type]

    def replay(self, agent_id: str) -> List[Dict[str, Any]]:
        return [
            {
                "sequence": entry.sequence,
                "timestamp": entry.timestamp,
                "type": entry.entry_type,
                "data": entry.data,
            }
            for entry in self.get_agent_history(agent_id)
        ]

    def get_summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for entry in self.entries:
            counts[entry.entry_type] = counts.get(entry.entry_type, 0) + 1
        return {
            "total_entries": len(self.entries),
            "entry_counts": counts,
            "integrity_valid": self.verify_integrity()[0],
        }

    def __len__(self) -> int:
        return len(self.entries)


@dataclass
class VerificationResult:
    """Result of evaluating evidence against a compiled constraint profile."""

    agent_id: str
    session_id: str
    timestamp: float
    verdict: Verdict
    violations: List[ConstraintViolation] = field(default_factory=list)
    slurm_job_id: str = ""
    challenge_id: Optional[str] = None
    challenge_satisfied: bool = False
    access_graph_alerts: List[str] = field(default_factory=list)

    def is_violation(self) -> bool:
        return self.verdict != Verdict.COMPLIANT


class PolicyVerifier:
    """Evaluates evidence, manages challenges, and correlates cluster-wide access."""

    def __init__(
        self,
        *,
        correlation_window_seconds: int = 30,
        challenge_ttl_seconds: int = 5,
        profile_signing_key: Optional[str] = None,
        evidence_signing_key: Optional[str] = None,
    ):
        self.audit = AuditLedger()
        self.constraint_profiles: Dict[str, ConstraintProfile] = {}
        self.profile_hashes: Dict[str, str] = {}
        self.verification_history: List[VerificationResult] = []
        self.volume_windows: Dict[str, Dict[str, float]] = {}
        self.shared_access_graph: Dict[str, Deque[SharedAccessRecord]] = defaultdict(deque)
        self.pending_challenges: Dict[str, dict] = {}
        self.correlation_window_seconds = correlation_window_seconds
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.profile_signing_key = profile_signing_key
        self.evidence_signing_key = evidence_signing_key

    def record_audit(self, entry_type: str, agent_id: str, data: Dict[str, Any]) -> AuditEntry:
        return self.audit.append(entry_type, agent_id, data)

    def register_agent(self, constraint_profile: ConstraintProfile) -> None:
        agent_id = constraint_profile.agent_id
        self.constraint_profiles[agent_id] = constraint_profile
        self.profile_hashes[agent_id] = constraint_profile.profile_hash()
        self.volume_windows[agent_id] = {
            "window_start": time.time(),
            "file_read_mb": 0.0,
            "file_write_mb": 0.0,
            "network_egress_mb": 0.0,
        }

    def unregister_agent(self, agent_id: str) -> None:
        self.constraint_profiles.pop(agent_id, None)
        self.profile_hashes.pop(agent_id, None)
        self.volume_windows.pop(agent_id, None)
        self.pending_challenges.pop(agent_id, None)

    def issue_challenge(self, agent_id: str) -> dict:
        challenge = {
            "challenge_id": secrets.token_hex(16),
            "agent_id": agent_id,
            "timestamp": time.time(),
            "expires_at": time.time() + self.challenge_ttl_seconds,
            "nonce": secrets.token_hex(32),
        }
        self.pending_challenges[agent_id] = challenge
        return challenge

    def verify(self, evidence: AttestationEvidence) -> VerificationResult:
        profile = self.constraint_profiles.get(evidence.agent_id)
        if not profile:
            result = VerificationResult(
                agent_id=evidence.agent_id,
                session_id=evidence.session_id,
                slurm_job_id=evidence.slurm_job_id,
                timestamp=time.time(),
                verdict=Verdict.VIOLATION_SEVERE,
                violations=[ConstraintViolation(
                    constraint_type="system",
                    description=f"No constraint profile for agent {evidence.agent_id}",
                    severity=Verdict.VIOLATION_SEVERE,
                    evidence={},
                    timestamp=time.time(),
                    code="missing_profile",
                )],
            )
            self.verification_history.append(result)
            return result

        violations: List[ConstraintViolation] = []
        violations.extend(self._check_profile_binding(profile, evidence))
        challenge_satisfied, challenge_violations = self._check_challenge(profile, evidence)
        violations.extend(challenge_violations)
        violations.extend(self._check_execution_constraints(profile, evidence))

        for action in evidence.actions:
            violations.extend(self._check_action(profile, action))
            violations.extend(self._check_signature_rules(profile, action))

        violations.extend(self._check_volumes(profile, evidence))
        graph_violations = self._correlate_access_graph(profile, evidence)
        violations.extend(graph_violations)

        self._update_volume_windows(profile.agent_id, evidence)

        max_severity = Verdict.COMPLIANT
        for violation in violations:
            if violation.severity > max_severity:
                max_severity = violation.severity

        result = VerificationResult(
            agent_id=evidence.agent_id,
            session_id=evidence.session_id,
            slurm_job_id=evidence.slurm_job_id,
            timestamp=time.time(),
            verdict=max_severity,
            violations=violations,
            challenge_id=evidence.challenge_id,
            challenge_satisfied=challenge_satisfied,
            access_graph_alerts=[violation.description for violation in graph_violations],
        )
        self.verification_history.append(result)
        return result

    def _check_profile_binding(
        self,
        profile: ConstraintProfile,
        evidence: AttestationEvidence,
    ) -> List[ConstraintViolation]:
        violations: List[ConstraintViolation] = []
        if not profile.verify_binding(evidence.slurm_job_id):
            violations.append(ConstraintViolation(
                constraint_type="system",
                description=(
                    f"Evidence job binding mismatch: expected {profile.slurm_job_id}, "
                    f"got {evidence.slurm_job_id}"
                ),
                severity=Verdict.VIOLATION_CRITICAL,
                evidence={"expected_job": profile.slurm_job_id, "observed_job": evidence.slurm_job_id},
                timestamp=time.time(),
                code="job_binding_mismatch",
            ))
        if evidence.session_id != profile.session_id:
            violations.append(ConstraintViolation(
                constraint_type="system",
                description=(
                    f"Evidence session mismatch: expected {profile.session_id}, got {evidence.session_id}"
                ),
                severity=Verdict.VIOLATION_SEVERE,
                evidence={"expected_session": profile.session_id, "observed_session": evidence.session_id},
                timestamp=time.time(),
                code="session_mismatch",
            ))
        verification_key = self.evidence_signing_key or evidence.node_id
        if verification_key and not evidence.verify_signature(verification_key):
            violations.append(ConstraintViolation(
                constraint_type="system",
                description="Attestation evidence signature verification failed",
                severity=Verdict.VIOLATION_CRITICAL,
                evidence={"node_id": evidence.node_id},
                timestamp=time.time(),
                code="invalid_evidence_signature",
            ))
        registered_hash = self.profile_hashes.get(profile.agent_id)
        if registered_hash and registered_hash != profile.profile_hash():
            violations.append(ConstraintViolation(
                constraint_type="system",
                description="Registered constraint profile changed after enrollment",
                severity=Verdict.VIOLATION_CRITICAL,
                evidence={"agent_id": profile.agent_id},
                timestamp=time.time(),
                code="profile_tampering",
            ))
        if self.profile_signing_key and profile.signature and not profile.verify_signature(self.profile_signing_key):
            violations.append(ConstraintViolation(
                constraint_type="system",
                description="Constraint profile signature verification failed",
                severity=Verdict.VIOLATION_CRITICAL,
                evidence={"agent_id": profile.agent_id},
                timestamp=time.time(),
                code="invalid_profile_signature",
            ))
        return violations

    def _check_challenge(
        self,
        profile: ConstraintProfile,
        evidence: AttestationEvidence,
    ) -> tuple[bool, List[ConstraintViolation]]:
        violations: List[ConstraintViolation] = []
        pending = self.pending_challenges.get(profile.agent_id)
        if not pending:
            return False, violations

        if evidence.challenge_id == pending["challenge_id"] and evidence.challenge_nonce == pending["nonce"]:
            self.pending_challenges.pop(profile.agent_id, None)
            return True, violations

        severity = Verdict.VIOLATION_SEVERE if time.time() <= pending["expires_at"] else Verdict.VIOLATION_CRITICAL
        violations.append(ConstraintViolation(
            constraint_type="system",
            description="Outstanding verifier challenge was not satisfied by the evidence bundle",
            severity=severity,
            evidence={
                "expected_challenge_id": pending["challenge_id"],
                "observed_challenge_id": evidence.challenge_id,
            },
            timestamp=time.time(),
            code="challenge_unsatisfied",
        ))
        return False, violations

    def _check_execution_constraints(
        self,
        profile: ConstraintProfile,
        evidence: AttestationEvidence,
    ) -> List[ConstraintViolation]:
        violations: List[ConstraintViolation] = []
        if profile.execution.allowed_nodes and evidence.node_id not in profile.execution.allowed_nodes:
            violations.append(ConstraintViolation(
                constraint_type="execution",
                description=f"Agent observed on unauthorized node {evidence.node_id}",
                severity=Verdict.VIOLATION_SEVERE,
                evidence={"node_id": evidence.node_id},
                timestamp=time.time(),
                code="unauthorized_node",
            ))

        if profile.execution.max_runtime_seconds and profile.created_at:
            runtime_seconds = max(0.0, evidence.interval_end - profile.created_at)
            if runtime_seconds > profile.execution.max_runtime_seconds:
                violations.append(ConstraintViolation(
                    constraint_type="execution",
                    description=(
                        f"Runtime exceeded: {runtime_seconds:.1f}s > {profile.execution.max_runtime_seconds}s"
                    ),
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={
                        "runtime_seconds": runtime_seconds,
                        "limit_seconds": profile.execution.max_runtime_seconds,
                    },
                    timestamp=time.time(),
                    code="runtime_exceeded",
                ))
        return violations

    def _check_action(
        self,
        profile: ConstraintProfile,
        action: AgentAction,
    ) -> List[ConstraintViolation]:
        violations: List[ConstraintViolation] = []

        if action.action_type in {ActionType.FILE_OPEN, ActionType.FILE_READ}:
            path = action.details.get("path", "")
            allowed, reason = profile.data_access.check_access(path, "read")
            if not allowed:
                violations.append(ConstraintViolation(
                    constraint_type="data_access",
                    description=f"Unauthorized file read: {reason}",
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={"action": action.action_type.value, "path": path},
                    timestamp=action.timestamp,
                    code="unauthorized_read",
                ))

        elif action.action_type == ActionType.FILE_WRITE:
            path = action.details.get("path", "")
            allowed, reason = profile.data_access.check_access(path, "write")
            if not allowed:
                violations.append(ConstraintViolation(
                    constraint_type="data_access",
                    description=f"Unauthorized file write: {reason}",
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={"action": action.action_type.value, "path": path},
                    timestamp=action.timestamp,
                    code="unauthorized_write",
                ))

        elif action.action_type in {ActionType.NETWORK_CONNECTION, ActionType.NETWORK_SEND, ActionType.LLM_API_CALL}:
            endpoint = action.details.get("endpoint", "")
            data_size = float(action.details.get("data_sent_mb", 0))
            allowed, reason = profile.network.check_connection(endpoint, data_size)
            if not allowed:
                violations.append(ConstraintViolation(
                    constraint_type="network",
                    description=f"Unauthorized connection: {reason}",
                    severity=Verdict.VIOLATION_SEVERE,
                    evidence={"action": action.action_type.value, "endpoint": endpoint},
                    timestamp=action.timestamp,
                    code="unauthorized_network",
                ))

        elif action.action_type in {ActionType.TOOL_INVOCATION, ActionType.PROCESS_SPAWN}:
            tool = action.details.get("tool") or action.details.get("command", "")
            allowed, reason = profile.tools.check_invocation(tool)
            if not allowed:
                violations.append(ConstraintViolation(
                    constraint_type="tool_invocation",
                    description=f"Unauthorized tool: {reason}",
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={"action": action.action_type.value, "tool": tool},
                    timestamp=action.timestamp,
                    code="unauthorized_tool",
                ))

        return violations

    def _check_signature_rules(
        self,
        profile: ConstraintProfile,
        action: AgentAction,
    ) -> List[ConstraintViolation]:
        violations: List[ConstraintViolation] = []
        serialized = json.dumps(action.details, sort_keys=True)
        for rule in profile.signature_rules:
            if rule.matches(action.action_type.value, serialized):
                violations.append(ConstraintViolation(
                    constraint_type="signature",
                    description=rule.description,
                    severity=self._severity_from_name(rule.severity),
                    evidence={"rule_id": rule.rule_id, "action": action.action_type.value},
                    timestamp=action.timestamp,
                    code=f"signature:{rule.rule_id}",
                ))
        return violations

    def _check_volumes(
        self,
        profile: ConstraintProfile,
        evidence: AttestationEvidence,
    ) -> List[ConstraintViolation]:
        violations: List[ConstraintViolation] = []
        window = self.volume_windows.get(profile.agent_id, {})
        elapsed_hours = max((time.time() - window.get("window_start", time.time())) / 3600, 1e-9)
        current_egress = (
            window.get("network_egress_mb", 0)
            + self._peek_delta_total(window, "last_total_network_egress_mb", evidence.total_network_egress_mb)
        )

        if profile.network.max_egress_mb_per_hour is not None:
            egress_rate = current_egress / elapsed_hours
            if egress_rate > profile.network.max_egress_mb_per_hour:
                violations.append(ConstraintViolation(
                    constraint_type="network",
                    description=(
                        f"Network egress budget exceeded: {egress_rate:.2f} MB/h > "
                        f"{profile.network.max_egress_mb_per_hour} MB/h"
                    ),
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={"rate_mb_per_hour": egress_rate},
                    timestamp=time.time(),
                    code="network_budget_exceeded",
                ))

        if profile.data_flow.max_exfil_budget_mb_per_hour is not None:
            exfil_rate = current_egress / elapsed_hours
            if exfil_rate > profile.data_flow.max_exfil_budget_mb_per_hour:
                violations.append(ConstraintViolation(
                    constraint_type="data_flow",
                    description=(
                        f"Exfil budget exceeded: {exfil_rate:.2f} MB/h > "
                        f"{profile.data_flow.max_exfil_budget_mb_per_hour} MB/h"
                    ),
                    severity=Verdict.VIOLATION_SEVERE,
                    evidence={"rate_mb_per_hour": exfil_rate},
                    timestamp=time.time(),
                    code="exfil_budget_exceeded",
                ))

        if profile.data_access.max_read_volume_mb is not None:
            if evidence.total_file_read_mb > profile.data_access.max_read_volume_mb:
                violations.append(ConstraintViolation(
                    constraint_type="data_access",
                    description=(
                        f"Read volume exceeded: {evidence.total_file_read_mb:.1f} MB > "
                        f"{profile.data_access.max_read_volume_mb} MB"
                    ),
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={"read_mb": evidence.total_file_read_mb},
                    timestamp=time.time(),
                    code="read_budget_exceeded",
                ))

        if profile.data_access.max_write_volume_mb is not None:
            if evidence.total_file_write_mb > profile.data_access.max_write_volume_mb:
                violations.append(ConstraintViolation(
                    constraint_type="data_access",
                    description=(
                        f"Write volume exceeded: {evidence.total_file_write_mb:.1f} MB > "
                        f"{profile.data_access.max_write_volume_mb} MB"
                    ),
                    severity=Verdict.VIOLATION_MODERATE,
                    evidence={"write_mb": evidence.total_file_write_mb},
                    timestamp=time.time(),
                    code="write_budget_exceeded",
                ))
        return violations

    def _correlate_access_graph(
        self,
        profile: ConstraintProfile,
        evidence: AttestationEvidence,
    ) -> List[ConstraintViolation]:
        violations: List[ConstraintViolation] = []
        window_seconds = max(profile.data_flow.correlation_window_seconds, 1)
        threshold = max(profile.data_flow.correlation_threshold, 1)

        for action in evidence.actions:
            if action.action_type not in {ActionType.FILE_OPEN, ActionType.FILE_READ, ActionType.FILE_WRITE}:
                continue
            path = action.details.get("path")
            if not path:
                continue
            operation = "write" if action.action_type == ActionType.FILE_WRITE else "read"
            history = self.shared_access_graph[path]
            self._trim_path_history(history, action.timestamp, window_seconds)

            if operation == "read":
                matching_writes = [
                    record
                    for record in history
                    if record.operation == "write"
                    and record.agent_id != evidence.agent_id
                    and action.timestamp - record.timestamp <= window_seconds
                ]
                if (
                    len(matching_writes) >= threshold
                    and not profile.data_flow.allow_agent_data_sharing
                    and not profile.data_flow.allow_co_located_agent_reads
                ):
                    writer_ids = sorted({record.agent_id for record in matching_writes})
                    violations.append(ConstraintViolation(
                        constraint_type="data_flow",
                        description=(
                            f"Covert channel alert: agent {evidence.agent_id} read {path} after write(s) "
                            f"from {', '.join(writer_ids)} within {window_seconds}s"
                        ),
                        severity=Verdict.VIOLATION_CRITICAL,
                        evidence={"path": path, "writers": writer_ids},
                        timestamp=action.timestamp,
                        code="covert_channel_detected",
                    ))

            history.append(SharedAccessRecord(
                agent_id=evidence.agent_id,
                session_id=evidence.session_id,
                slurm_job_id=evidence.slurm_job_id,
                path=path,
                operation=operation,
                timestamp=action.timestamp,
            ))
        return violations

    def _trim_path_history(
        self,
        history: Deque[SharedAccessRecord],
        now: float,
        window_seconds: int,
    ) -> None:
        while history and now - history[0].timestamp > window_seconds:
            history.popleft()

    def _update_volume_windows(self, agent_id: str, evidence: AttestationEvidence) -> None:
        if agent_id not in self.volume_windows:
            return

        window = self.volume_windows[agent_id]
        window["file_read_mb"] += self._delta_total(window, "last_total_file_read_mb", evidence.total_file_read_mb)
        window["file_write_mb"] += self._delta_total(window, "last_total_file_write_mb", evidence.total_file_write_mb)
        window["network_egress_mb"] += self._delta_total(window, "last_total_network_egress_mb", evidence.total_network_egress_mb)

    def _peek_delta_total(self, window: Dict[str, float], total_key: str, current_total: float) -> float:
        previous_total = window.get(total_key, 0)
        return max(0.0, current_total - previous_total)

    def _delta_total(self, window: Dict[str, float], total_key: str, current_total: float) -> float:
        delta = self._peek_delta_total(window, total_key, current_total)
        window[total_key] = current_total
        return delta

    def _severity_from_name(self, severity: str) -> Verdict:
        mapping = {
            Verdict.COMPLIANT.value: Verdict.COMPLIANT,
            Verdict.VIOLATION_MINOR.value: Verdict.VIOLATION_MINOR,
            Verdict.VIOLATION_MODERATE.value: Verdict.VIOLATION_MODERATE,
            Verdict.VIOLATION_SEVERE.value: Verdict.VIOLATION_SEVERE,
            Verdict.VIOLATION_CRITICAL.value: Verdict.VIOLATION_CRITICAL,
        }
        return mapping.get(severity, Verdict.VIOLATION_CRITICAL)

    def get_violation_count(self, agent_id: str) -> int:
        return len([
            result
            for result in self.verification_history
            if result.agent_id == agent_id and result.is_violation()
        ])
