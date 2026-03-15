"""Attestation engine for AEGIS.

Simulates the eBPF-based syscall interception layer that monitors agent
actions on compute nodes and produces signed evidence bundles for verification.
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
    """Types of actions that can be monitored."""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_CONNECTION = "network_connection"
    TOOL_INVOCATION = "tool_invocation"
    LLM_API_CALL = "llm_api_call"
    PROCESS_SPAWN = "process_spawn"


@dataclass
class AgentAction:
    """A single recorded action by an agent.

    Attributes:
        timestamp: Unix timestamp when the action occurred.
        action_type: The type of action.
        details: Action-specific details (path, endpoint, tool name, etc.).

    Examples:
        FILE_READ: {"path": "/projects/genomics/data.h5", "size_mb": 150}
        NETWORK_CONNECTION: {"endpoint": "api.openai.com", "data_sent_mb": 0.5}
        TOOL_INVOCATION: {"tool": "hdf5_reader", "args": ["data.h5"]}
        LLM_API_CALL: {"endpoint": "api.openai.com", "prompt_size_kb": 12}
    """
    timestamp: float
    action_type: ActionType
    details: Dict[str, Any]


@dataclass
class AttestationEvidence:
    """Signed evidence bundle from attestation engine.

    Contains all recorded actions for an agent during an attestation interval,
    along with volume counters and an integrity signature.

    Attributes:
        agent_id: The agent this evidence pertains to.
        session_id: The session identifier.
        timestamp: When this evidence bundle was generated.
        interval_start: Start of the attestation window.
        interval_end: End of the attestation window.
        actions: List of actions recorded during this interval.
        total_file_read_mb: Cumulative file read volume.
        total_file_write_mb: Cumulative file write volume.
        total_network_egress_mb: Cumulative network egress volume.
        agent_process_hash: Hash of agent process state.
        signature: HMAC signature for integrity verification.
    """
    agent_id: str
    session_id: str
    timestamp: float
    interval_start: float
    interval_end: float

    actions: List[AgentAction] = field(default_factory=list)

    # Volume counters
    total_file_read_mb: float = 0
    total_file_write_mb: float = 0
    total_network_egress_mb: float = 0

    # State
    agent_process_hash: Optional[str] = None

    # Signature
    signature: Optional[str] = None

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of evidence for integrity verification."""
        content = json.dumps({
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "actions": [
                (a.timestamp, a.action_type.value, a.details)
                for a in self.actions
            ]
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def sign(self, signing_key: str) -> str:
        """Sign the evidence bundle using HMAC-SHA256.

        In production, this would use proper asymmetric cryptography.
        For simulation, we use HMAC-based signing.

        Args:
            signing_key: The key to sign with (typically node_id or a shared secret).

        Returns:
            The hex-encoded signature.
        """
        content = self.compute_hash()
        self.signature = hmac.new(
            signing_key.encode(),
            content.encode(),
            hashlib.sha256
        ).hexdigest()
        return self.signature

    def verify_signature(self, signing_key: str) -> bool:
        """Verify the evidence signature.

        Args:
            signing_key: The key to verify against.

        Returns:
            True if signature is valid, False otherwise.
        """
        if not self.signature:
            return False
        expected = hmac.new(
            signing_key.encode(),
            self.compute_hash().encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


class AttestationEngine:
    """Simulates the eBPF-based attestation engine running on compute nodes.

    The attestation engine monitors agent actions, buffers them, and periodically
    generates signed evidence bundles for the policy verifier to evaluate.

    In production, this would be implemented as an eBPF program intercepting
    syscalls. This simulation wraps method calls instead.
    """

    def __init__(self, node_id: str, attestation_interval: int = 5):
        """Initialize the attestation engine.

        Args:
            node_id: Identifier for the compute node running this engine.
            attestation_interval: Seconds between evidence generation cycles.
        """
        self.node_id = node_id
        self.attestation_interval = attestation_interval

        # Per-agent state
        self.monitored_agents: Dict[str, Any] = {}  # agent_id -> session_id
        self.action_buffers: Dict[str, List[AgentAction]] = {}

        # Cumulative volume counters (don't reset between evidence cycles)
        self.volume_counters: Dict[str, Dict[str, float]] = {}

    def register_agent(self, agent_id: str, constraint_profile: Any) -> None:
        """Start monitoring an agent.

        Args:
            agent_id: The agent to monitor.
            constraint_profile: The agent's constraint profile.
        """
        session_id = f"session_{agent_id}_{int(time.time())}"
        self.monitored_agents[agent_id] = session_id
        self.action_buffers[agent_id] = []
        self.volume_counters[agent_id] = {
            "file_read_mb": 0,
            "file_write_mb": 0,
            "network_egress_mb": 0,
        }

    def unregister_agent(self, agent_id: str) -> None:
        """Stop monitoring an agent.

        Args:
            agent_id: The agent to stop monitoring.
        """
        self.monitored_agents.pop(agent_id, None)
        self.action_buffers.pop(agent_id, None)
        self.volume_counters.pop(agent_id, None)

    def record_action(self, agent_id: str, action: AgentAction) -> None:
        """Record an agent action (called by the monitoring layer).

        Args:
            agent_id: The agent that performed the action.
            action: The action to record.
        """
        if agent_id not in self.action_buffers:
            return  # Agent not registered

        self.action_buffers[agent_id].append(action)

        # Update volume counters
        if action.action_type == ActionType.FILE_READ:
            self.volume_counters[agent_id]["file_read_mb"] += action.details.get("size_mb", 0)
        elif action.action_type == ActionType.FILE_WRITE:
            self.volume_counters[agent_id]["file_write_mb"] += action.details.get("size_mb", 0)
        elif action.action_type in (ActionType.NETWORK_CONNECTION, ActionType.LLM_API_CALL):
            self.volume_counters[agent_id]["network_egress_mb"] += action.details.get("data_sent_mb", 0)

    def generate_evidence(self, agent_id: str) -> AttestationEvidence:
        """Generate a signed evidence bundle for an agent.

        Captures all buffered actions and resets the buffer. Volume counters
        are cumulative and not reset.

        Args:
            agent_id: The agent to generate evidence for.

        Returns:
            A signed AttestationEvidence bundle.
        """
        now = time.time()
        session_id = self.monitored_agents.get(agent_id, "unknown")
        counters = self.volume_counters.get(agent_id, {
            "file_read_mb": 0,
            "file_write_mb": 0,
            "network_egress_mb": 0,
        })

        evidence = AttestationEvidence(
            agent_id=agent_id,
            session_id=session_id,
            timestamp=now,
            interval_start=now - self.attestation_interval,
            interval_end=now,
            actions=list(self.action_buffers.get(agent_id, [])),
            total_file_read_mb=counters["file_read_mb"],
            total_file_write_mb=counters["file_write_mb"],
            total_network_egress_mb=counters["network_egress_mb"],
            agent_process_hash=self._compute_agent_hash(agent_id),
        )
        evidence.sign(self.node_id)

        # Clear action buffer after generating evidence
        self.action_buffers[agent_id] = []

        return evidence

    def generate_challenge(self, agent_id: str) -> dict:
        """Generate a random challenge requiring immediate attestation.

        Used for spot-checking agents between regular attestation cycles.

        Args:
            agent_id: The agent to challenge.

        Returns:
            A challenge dictionary with challenge_id and nonce.
        """
        return {
            "challenge_id": secrets.token_hex(16),
            "agent_id": agent_id,
            "timestamp": time.time(),
            "nonce": secrets.token_hex(32),
        }

    def _compute_agent_hash(self, agent_id: str) -> Optional[str]:
        """Compute a hash representing the agent's current state.

        In production, this would hash the agent's memory pages or code segment.
        For simulation, we hash the buffered actions.

        Args:
            agent_id: The agent to hash.

        Returns:
            Hex-encoded SHA-256 hash, or None if agent not registered.
        """
        if agent_id not in self.action_buffers:
            return None
        content = json.dumps(
            [a.details for a in self.action_buffers[agent_id]],
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def get_session_id(self, agent_id: str) -> str:
        """Get the session ID for a monitored agent.

        Args:
            agent_id: The agent to look up.

        Returns:
            The session ID, or "unknown" if not registered.
        """
        return self.monitored_agents.get(agent_id, "unknown")
