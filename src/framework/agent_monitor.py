"""Agent runtime monitoring wrapper for AEGIS.

Wraps agent method calls to feed actions into the attestation engine.
In production, this role is filled by eBPF probes intercepting syscalls.
"""

from __future__ import annotations

import time
from typing import Any, List, Optional

from framework.attestation import AgentAction, ActionType, AttestationEngine


class AgentMonitor:
    """Monitors an agent's actions and feeds them to the attestation engine.

    In production, the monitor is implemented as eBPF probes that intercept
    syscalls (open, connect, execve, etc.) at the kernel level. This Python
    wrapper simulates that by providing explicit callback methods.

    Each callback creates an AgentAction and passes it to the attestation
    engine for buffering and evidence generation.
    """

    def __init__(
        self,
        agent_id: str,
        constraint_profile: Any,
        attestation_engine: AttestationEngine,
    ):
        """Initialize the agent monitor.

        Args:
            agent_id: The agent to monitor.
            constraint_profile: The agent's constraint profile.
            attestation_engine: The attestation engine to feed actions to.
        """
        self.agent_id = agent_id
        self.constraint_profile = constraint_profile
        self.attestation_engine = attestation_engine
        self.session_id = f"session_{agent_id}_{int(time.time())}"

        # Register with attestation engine
        attestation_engine.register_agent(agent_id, constraint_profile)

    def on_file_read(self, path: str, size_mb: float = 0) -> None:
        """Called when agent reads a file.

        In production, this maps to an eBPF probe on the open/read syscalls.

        Args:
            path: The filesystem path being read.
            size_mb: Size of data read in megabytes.
        """
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.FILE_READ,
            details={"path": path, "size_mb": size_mb},
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_file_write(self, path: str, size_mb: float = 0) -> None:
        """Called when agent writes a file.

        Args:
            path: The filesystem path being written.
            size_mb: Size of data written in megabytes.
        """
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.FILE_WRITE,
            details={"path": path, "size_mb": size_mb},
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_network_connection(self, endpoint: str, data_sent_mb: float = 0) -> None:
        """Called when agent makes a network connection.

        In production, this maps to an eBPF probe on the connect/sendto syscalls.

        Args:
            endpoint: The target endpoint (hostname or IP).
            data_sent_mb: Amount of data sent in megabytes.
        """
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.NETWORK_CONNECTION,
            details={"endpoint": endpoint, "data_sent_mb": data_sent_mb},
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_llm_api_call(
        self,
        endpoint: str,
        prompt_size_kb: float = 0,
        data_sent_mb: float = 0,
    ) -> None:
        """Called when agent makes an LLM API call.

        LLM API calls are a special case of network connections with
        additional metadata about the prompt size.

        Args:
            endpoint: The LLM API endpoint.
            prompt_size_kb: Size of the prompt in kilobytes.
            data_sent_mb: Total data sent in megabytes.
        """
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.LLM_API_CALL,
            details={
                "endpoint": endpoint,
                "prompt_size_kb": prompt_size_kb,
                "data_sent_mb": data_sent_mb,
            },
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_tool_invocation(self, tool_name: str, args: Optional[List[str]] = None) -> None:
        """Called when agent invokes a tool.

        Args:
            tool_name: The name of the tool being invoked.
            args: Arguments passed to the tool.
        """
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.TOOL_INVOCATION,
            details={"tool": tool_name, "args": args or []},
        )
        self.attestation_engine.record_action(self.agent_id, action)

    def on_process_spawn(self, command: str, args: Optional[List[str]] = None) -> None:
        """Called when agent spawns a subprocess.

        In production, this maps to an eBPF probe on the execve syscall.

        Args:
            command: The command being executed.
            args: Command arguments.
        """
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.PROCESS_SPAWN,
            details={"command": command, "args": args or []},
        )
        self.attestation_engine.record_action(self.agent_id, action)
