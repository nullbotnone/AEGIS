"""Attestation engine for AEGIS.

Simulates the eBPF-backed node daemon that records syscall-derived agent
activity and emits signed evidence bundles over mutually authenticated gRPC.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionType(Enum):
    """Types of monitored actions emitted by the userspace collector."""

    FILE_OPEN = "file_open"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_CONNECTION = "network_connection"
    NETWORK_SEND = "network_send"
    TOOL_INVOCATION = "tool_invocation"
    LLM_API_CALL = "llm_api_call"
    PROCESS_SPAWN = "process_spawn"


_SYSCALL_MAP = {
    ActionType.FILE_OPEN: "sys_enter_openat",
    ActionType.FILE_READ: "sys_enter_read",
    ActionType.FILE_WRITE: "sys_enter_write",
    ActionType.NETWORK_CONNECTION: "sys_enter_connect",
    ActionType.NETWORK_SEND: "sys_enter_sendto",
    ActionType.TOOL_INVOCATION: "sys_enter_execve",
    ActionType.LLM_API_CALL: "sys_enter_sendto",
    ActionType.PROCESS_SPAWN: "sys_enter_execve",
}


@dataclass
class AgentAction:
    """A single syscall-derived action recorded for an agent."""

    timestamp: float
    action_type: ActionType
    details: Dict[str, Any]
    pid: Optional[int] = None
    syscall: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "action_type": self.action_type.value,
            "details": self.details,
            "pid": self.pid,
            "syscall": self.syscall or _SYSCALL_MAP[self.action_type],
        }


@dataclass
class AttestationEvidence:
    """Signed evidence bundle emitted by the attestation engine."""

    agent_id: str
    session_id: str
    node_id: str
    slurm_job_id: str
    timestamp: float
    interval_start: float
    interval_end: float
    actions: List[AgentAction] = field(default_factory=list)
    total_file_read_mb: float = 0.0
    total_file_write_mb: float = 0.0
    total_network_egress_mb: float = 0.0
    network_connection_count: int = 0
    process_state_hash: Optional[str] = None
    monitored_syscalls: List[str] = field(
        default_factory=lambda: [
            "sys_enter_openat",
            "sys_enter_read",
            "sys_enter_write",
            "sys_enter_connect",
            "sys_enter_sendto",
            "sys_enter_execve",
        ]
    )
    transport: str = "grpc+mTLS"
    challenge_id: Optional[str] = None
    challenge_nonce: Optional[str] = None
    signature: Optional[str] = None

    @property
    def agent_process_hash(self) -> Optional[str]:
        """Backward-compatible alias for the process-state hash."""
        return self.process_state_hash

    def compute_hash(self) -> str:
        payload = json.dumps(
            {
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "node_id": self.node_id,
                "slurm_job_id": self.slurm_job_id,
                "timestamp": self.timestamp,
                "interval_start": self.interval_start,
                "interval_end": self.interval_end,
                "actions": [action.to_dict() for action in self.actions],
                "total_file_read_mb": self.total_file_read_mb,
                "total_file_write_mb": self.total_file_write_mb,
                "total_network_egress_mb": self.total_network_egress_mb,
                "network_connection_count": self.network_connection_count,
                "process_state_hash": self.process_state_hash,
                "monitored_syscalls": self.monitored_syscalls,
                "transport": self.transport,
                "challenge_id": self.challenge_id,
                "challenge_nonce": self.challenge_nonce,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def sign(self, signing_key: str) -> str:
        self.signature = hmac.new(
            signing_key.encode(),
            self.compute_hash().encode(),
            hashlib.sha256,
        ).hexdigest()
        return self.signature

    def verify_signature(self, signing_key: str) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(
            signing_key.encode(),
            self.compute_hash().encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


class AttestationEngine:
    """Node-local daemon that buffers actions and emits signed evidence bundles."""

    def __init__(self, node_id: str, attestation_interval: int = 1, transport: str = "grpc+mTLS"):
        self.node_id = node_id
        self.attestation_interval = attestation_interval
        self.transport = transport
        self.monitored_agents: Dict[str, Dict[str, Any]] = {}
        self.action_buffers: Dict[str, List[AgentAction]] = {}
        self.volume_counters: Dict[str, Dict[str, float]] = {}

    def register_agent(self, agent_id: str, constraint_profile: Any) -> None:
        session_id = getattr(constraint_profile, "session_id", None) or f"session_{agent_id}_{int(time.time())}"
        slurm_job_id = getattr(constraint_profile, "slurm_job_id", None) or f"job_{agent_id}"
        self.monitored_agents[agent_id] = {
            "session_id": session_id,
            "slurm_job_id": slurm_job_id,
        }
        self.action_buffers[agent_id] = []
        self.volume_counters[agent_id] = {
            "file_read_mb": 0.0,
            "file_write_mb": 0.0,
            "network_egress_mb": 0.0,
            "network_connection_count": 0.0,
        }

    def unregister_agent(self, agent_id: str) -> None:
        self.monitored_agents.pop(agent_id, None)
        self.action_buffers.pop(agent_id, None)
        self.volume_counters.pop(agent_id, None)

    def record_action(self, agent_id: str, action: AgentAction) -> None:
        if agent_id not in self.action_buffers:
            return

        if not action.syscall:
            action.syscall = _SYSCALL_MAP[action.action_type]
        self.action_buffers[agent_id].append(action)

        counters = self.volume_counters[agent_id]
        if action.action_type == ActionType.FILE_READ:
            counters["file_read_mb"] += float(action.details.get("size_mb", 0))
        elif action.action_type == ActionType.FILE_WRITE:
            counters["file_write_mb"] += float(action.details.get("size_mb", 0))
        elif action.action_type in {ActionType.NETWORK_SEND, ActionType.NETWORK_CONNECTION, ActionType.LLM_API_CALL}:
            counters["network_egress_mb"] += float(action.details.get("data_sent_mb", 0))

        if action.action_type in {ActionType.NETWORK_CONNECTION, ActionType.LLM_API_CALL}:
            counters["network_connection_count"] += 1

    def generate_evidence(self, agent_id: str, challenge: Optional[dict] = None) -> AttestationEvidence:
        if agent_id not in self.monitored_agents:
            raise ValueError(f"Agent {agent_id} is not registered")

        now = time.time()
        state = self.monitored_agents[agent_id]
        counters = self.volume_counters[agent_id]
        evidence = AttestationEvidence(
            agent_id=agent_id,
            session_id=state["session_id"],
            node_id=self.node_id,
            slurm_job_id=state["slurm_job_id"],
            timestamp=now,
            interval_start=now - self.attestation_interval,
            interval_end=now,
            actions=list(self.action_buffers[agent_id]),
            total_file_read_mb=counters["file_read_mb"],
            total_file_write_mb=counters["file_write_mb"],
            total_network_egress_mb=counters["network_egress_mb"],
            network_connection_count=int(counters["network_connection_count"]),
            process_state_hash=self._compute_process_hash(agent_id),
            transport=self.transport,
            challenge_id=challenge.get("challenge_id") if challenge else None,
            challenge_nonce=challenge.get("nonce") if challenge else None,
        )
        evidence.sign(self.node_id)
        self.action_buffers[agent_id] = []
        return evidence

    def generate_challenge(self, agent_id: str) -> dict:
        return {
            "challenge_id": secrets.token_hex(16),
            "agent_id": agent_id,
            "timestamp": time.time(),
            "nonce": secrets.token_hex(32),
        }

    def _compute_process_hash(self, agent_id: str) -> Optional[str]:
        if agent_id not in self.action_buffers:
            return None
        payload = json.dumps(
            {
                "actions": [action.to_dict() for action in self.action_buffers[agent_id]],
                "counters": self.volume_counters.get(agent_id, {}),
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def get_session_id(self, agent_id: str) -> str:
        state = self.monitored_agents.get(agent_id)
        if not state:
            return "unknown"
        return state["session_id"]
