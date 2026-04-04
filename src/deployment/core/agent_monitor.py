"""Agent runtime monitoring wrapper for AEGIS.

This simulates the userspace collector that would normally receive events from
node-local eBPF probes attached to openat/read/write/connect/sendto/execve.
"""

from __future__ import annotations

import time
from typing import Any, List, Optional

from .attestation import ActionType, AgentAction, AttestationEngine


class AgentMonitor:
    """Translate agent runtime events into attestation engine actions."""

    def __init__(
        self,
        agent_id: str,
        constraint_profile: Any,
        attestation_engine: AttestationEngine,
    ):
        self.agent_id = agent_id
        self.constraint_profile = constraint_profile
        self.attestation_engine = attestation_engine
        attestation_engine.register_agent(agent_id, constraint_profile)
        self.session_id = attestation_engine.get_session_id(agent_id)

    def on_file_open(self, path: str, mode: str = "r", pid: Optional[int] = None) -> None:
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.FILE_OPEN,
            details={"path": path, "mode": mode},
            pid=pid,
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_file_read(self, path: str, size_mb: float = 0, pid: Optional[int] = None) -> None:
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.FILE_READ,
            details={"path": path, "size_mb": size_mb},
            pid=pid,
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_file_write(self, path: str, size_mb: float = 0, pid: Optional[int] = None) -> None:
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.FILE_WRITE,
            details={"path": path, "size_mb": size_mb},
            pid=pid,
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_network_connection(self, endpoint: str, data_sent_mb: float = 0, pid: Optional[int] = None) -> None:
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.NETWORK_CONNECTION,
            details={"endpoint": endpoint, "data_sent_mb": data_sent_mb},
            pid=pid,
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_network_send(self, endpoint: str, data_sent_mb: float, pid: Optional[int] = None) -> None:
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.NETWORK_SEND,
            details={"endpoint": endpoint, "data_sent_mb": data_sent_mb},
            pid=pid,
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_llm_api_call(
        self,
        endpoint: str,
        prompt_size_kb: float = 0,
        data_sent_mb: float = 0,
        pid: Optional[int] = None,
    ) -> None:
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.LLM_API_CALL,
            details={
                "endpoint": endpoint,
                "prompt_size_kb": prompt_size_kb,
                "data_sent_mb": data_sent_mb,
            },
            pid=pid,
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_tool_invocation(self, tool_name: str, args: Optional[List[str]] = None, pid: Optional[int] = None) -> None:
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.TOOL_INVOCATION,
            details={"tool": tool_name, "args": args or []},
            pid=pid,
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_process_spawn(self, command: str, args: Optional[List[str]] = None, pid: Optional[int] = None) -> None:
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.PROCESS_SPAWN,
            details={"command": command, "args": args or []},
            pid=pid,
        )
        self.attestation_engine.record_action(self.agent_id, action)
