"""Constraint specification and management for AEGIS.

Defines constraint profiles that specify allowed behaviors for AI agents,
including data access, network, tool, execution, and data flow constraints.
"""

from __future__ import annotations

import fnmatch
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

try:
    import yaml  # type: ignore[import-not-found]
except ModuleNotFoundError:
    yaml = None


def _parse_yaml_scalar(value: str) -> Any:
    """Parse a scalar value from a simple YAML subset."""
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "none", "~"}:
        return None
    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _parse_yaml_block(lines: List[str], start: int, indent: int) -> tuple[Any, int]:
    """Parse a simple indentation-based YAML mapping or list."""
    index = start
    while index < len(lines) and not lines[index].strip():
        index += 1

    if index >= len(lines):
        return {}, index

    stripped = lines[index].lstrip()
    if stripped.startswith("- "):
        items: List[Any] = []
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                index += 1
                continue
            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent < indent:
                break
            if current_indent != indent:
                raise ValueError(f"Invalid YAML indentation at line: {line!r}")
            item_text = line.strip()[2:].strip()
            if item_text:
                items.append(_parse_yaml_scalar(item_text))
                index += 1
                continue
            item_value, index = _parse_yaml_block(lines, index + 1, indent + 2)
            items.append(item_value)
        return items, index

    mapping: Dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent < indent:
            break
        if current_indent != indent:
            raise ValueError(f"Invalid YAML indentation at line: {line!r}")
        key, separator, raw_value = line.strip().partition(":")
        if not separator:
            raise ValueError(f"Invalid YAML mapping entry: {line!r}")
        value = raw_value.strip()
        if value:
            mapping[key] = _parse_yaml_scalar(value)
            index += 1
            continue
        nested_value, index = _parse_yaml_block(lines, index + 1, indent + 2)
        mapping[key] = nested_value
    return mapping, index


def _yaml_safe_load(content: str) -> Dict[str, Any]:
    """Load YAML, falling back to a constrained built-in parser."""
    if yaml is not None:
        data = yaml.safe_load(content)
        return data or {}

    lines = [
        line.rstrip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        return {}
    data, next_index = _parse_yaml_block(lines, 0, 0)
    if next_index != len(lines):
        raise ValueError("Unexpected trailing YAML content")
    if not isinstance(data, dict):
        raise ValueError("Constraint profiles must be YAML mappings")
    return data


def _yaml_format_scalar(value: Any) -> str:
    """Format a scalar value for YAML output."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    return str(value)


def _yaml_dump_lines(value: Any, indent: int = 0) -> List[str]:
    """Serialize a simple dict/list structure to YAML lines."""
    prefix = " " * indent
    if isinstance(value, dict):
        lines: List[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(_yaml_dump_lines(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {_yaml_format_scalar(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.extend(_yaml_dump_lines(item, indent + 2))
            else:
                lines.append(f"{prefix}- {_yaml_format_scalar(item)}")
        return lines
    return [f"{prefix}{_yaml_format_scalar(value)}"]


class ConstraintType(Enum):
    """Types of constraints that can be enforced."""
    DATA_ACCESS = "data_access"
    NETWORK = "network"
    TOOL_INVOCATION = "tool_invocation"
    EXECUTION = "execution"
    DATA_FLOW = "data_flow"


@dataclass
class DataAccessConstraints:
    """Constraints on filesystem access for an agent.

    Attributes:
        allowed_paths: Glob patterns for paths the agent may access.
            If empty, all paths are allowed (unless denied).
        denied_paths: Glob patterns for paths the agent must not access.
            Takes precedence over allowed_paths.
        read_only_paths: Glob patterns for paths that are read-only.
        max_read_volume_mb: Maximum total read volume in MB (per window).
        max_write_volume_mb: Maximum total write volume in MB (per window).
    """
    allowed_paths: Set[str] = field(default_factory=set)
    denied_paths: Set[str] = field(default_factory=set)
    read_only_paths: Set[str] = field(default_factory=set)
    max_read_volume_mb: Optional[int] = None
    max_write_volume_mb: Optional[int] = None

    def check_access(self, path: str, operation: str) -> tuple[bool, str]:
        """Check if a file access is allowed.

        Args:
            path: The filesystem path being accessed.
            operation: The operation type ("read" or "write").

        Returns:
            A tuple of (allowed, reason).
        """
        # Denied paths take precedence
        for denied in self.denied_paths:
            if fnmatch.fnmatch(path, denied):
                return False, f"Path {path} matches denied pattern {denied}"

        # If allowed_paths specified, must match one
        if self.allowed_paths:
            for allowed in self.allowed_paths:
                if fnmatch.fnmatch(path, allowed):
                    # Check read-only restriction
                    if operation == "write":
                        for ro in self.read_only_paths:
                            if fnmatch.fnmatch(path, ro):
                                return False, f"Path {path} is read-only"
                    return True, "Access allowed"
            return False, f"Path {path} not in allowed paths"

        return True, "Access allowed (no path restrictions)"

    def to_dict(self) -> dict:
        return {
            "allowed_paths": sorted(self.allowed_paths),
            "denied_paths": sorted(self.denied_paths),
            "read_only_paths": sorted(self.read_only_paths),
            "max_read_volume_mb": self.max_read_volume_mb,
            "max_write_volume_mb": self.max_write_volume_mb,
        }

    @classmethod
    def from_dict(cls, data: dict) -> DataAccessConstraints:
        return cls(
            allowed_paths=set(data.get("allowed_paths", [])),
            denied_paths=set(data.get("denied_paths", [])),
            read_only_paths=set(data.get("read_only_paths", [])),
            max_read_volume_mb=data.get("max_read_volume_mb"),
            max_write_volume_mb=data.get("max_write_volume_mb"),
        )


@dataclass
class NetworkConstraints:
    """Constraints on network access for an agent.

    Attributes:
        allowed_endpoints: Glob patterns for allowed endpoints.
        denied_endpoints: Glob patterns for denied endpoints.
            Use "*" to deny all, with allowed_endpoints as exceptions.
        max_egress_mb_per_hour: Maximum egress bandwidth in MB/hour.
    """
    allowed_endpoints: Set[str] = field(default_factory=set)
    denied_endpoints: Set[str] = field(default_factory=set)
    max_egress_mb_per_hour: Optional[int] = None

    def check_connection(self, endpoint: str, data_size_mb: float = 0) -> tuple[bool, str]:
        """Check if a network connection is allowed.

        Args:
            endpoint: The target endpoint (hostname or IP).
            data_size_mb: Size of data being sent in MB.

        Returns:
            A tuple of (allowed, reason).
        """
        for denied in self.denied_endpoints:
            if denied == "*" or fnmatch.fnmatch(endpoint, denied):
                # Explicit allow overrides blanket deny
                if endpoint in self.allowed_endpoints:
                    continue
                return False, f"Endpoint {endpoint} is denied"

        if self.allowed_endpoints:
            for allowed in self.allowed_endpoints:
                if fnmatch.fnmatch(endpoint, allowed):
                    return True, "Connection allowed"
            return False, f"Endpoint {endpoint} not in allowed endpoints"

        return True, "Connection allowed (no endpoint restrictions)"

    def to_dict(self) -> dict:
        return {
            "allowed_endpoints": sorted(self.allowed_endpoints),
            "denied_endpoints": sorted(self.denied_endpoints),
            "max_egress_mb_per_hour": self.max_egress_mb_per_hour,
        }

    @classmethod
    def from_dict(cls, data: dict) -> NetworkConstraints:
        return cls(
            allowed_endpoints=set(data.get("allowed_endpoints", [])),
            denied_endpoints=set(data.get("denied_endpoints", [])),
            max_egress_mb_per_hour=data.get("max_egress_mb_per_hour"),
        )


@dataclass
class ToolConstraints:
    """Constraints on tool invocations for an agent.

    Attributes:
        allowed_tools: Set of tool names the agent may invoke.
            If empty, all tools are allowed (unless denied).
        denied_tools: Set of tool names the agent must not invoke.
    """
    allowed_tools: Set[str] = field(default_factory=set)
    denied_tools: Set[str] = field(default_factory=set)

    def check_invocation(self, tool_name: str) -> tuple[bool, str]:
        """Check if a tool invocation is allowed.

        Args:
            tool_name: The name of the tool being invoked.

        Returns:
            A tuple of (allowed, reason).
        """
        if tool_name in self.denied_tools:
            return False, f"Tool {tool_name} is denied"
        if self.allowed_tools and tool_name not in self.allowed_tools:
            return False, f"Tool {tool_name} not in allowed tools"
        return True, "Tool invocation allowed"

    def to_dict(self) -> dict:
        return {
            "allowed_tools": sorted(self.allowed_tools),
            "denied_tools": sorted(self.denied_tools),
        }

    @classmethod
    def from_dict(cls, data: dict) -> ToolConstraints:
        return cls(
            allowed_tools=set(data.get("allowed_tools", [])),
            denied_tools=set(data.get("denied_tools", [])),
        )


@dataclass
class ExecutionConstraints:
    """Constraints on agent execution.

    Attributes:
        max_runtime_seconds: Maximum allowed runtime in seconds.
        max_memory_mb: Maximum memory usage in MB.
        allowed_nodes: Set of node hostnames the agent may run on.
    """
    max_runtime_seconds: Optional[int] = None
    max_memory_mb: Optional[int] = None
    allowed_nodes: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "max_runtime_seconds": self.max_runtime_seconds,
            "max_memory_mb": self.max_memory_mb,
            "allowed_nodes": sorted(self.allowed_nodes),
        }

    @classmethod
    def from_dict(cls, data: dict) -> ExecutionConstraints:
        return cls(
            max_runtime_seconds=data.get("max_runtime_seconds"),
            max_memory_mb=data.get("max_memory_mb"),
            allowed_nodes=set(data.get("allowed_nodes", [])),
        )


@dataclass
class DataFlowConstraints:
    """Constraints on data flow and exfiltration.

    Attributes:
        project_boundary_strict: If True, no cross-project data access.
        cross_project_transfer: If True, cross-project transfers allowed.
        max_exfil_budget_mb_per_hour: Maximum data exfiltration rate in MB/hour.
    """
    project_boundary_strict: bool = False
    cross_project_transfer: bool = False
    max_exfil_budget_mb_per_hour: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "project_boundary_strict": self.project_boundary_strict,
            "cross_project_transfer": self.cross_project_transfer,
            "max_exfil_budget_mb_per_hour": self.max_exfil_budget_mb_per_hour,
        }

    @classmethod
    def from_dict(cls, data: dict) -> DataFlowConstraints:
        return cls(
            project_boundary_strict=data.get("project_boundary_strict", False),
            cross_project_transfer=data.get("cross_project_transfer", False),
            max_exfil_budget_mb_per_hour=data.get("max_exfil_budget_mb_per_hour"),
        )


@dataclass
class ConstraintProfile:
    """Complete constraint profile for an agent.

    This is the primary configuration object that defines all behavioral
    constraints for an agent. It is signed and transmitted to compute nodes.

    Attributes:
        agent_id: Unique identifier for the agent.
        user_id: The user who owns this agent.
        project_id: The HPC project this agent belongs to.
        session_id: The current session identifier.
        data_access: Filesystem access constraints.
        network: Network access constraints.
        tools: Tool invocation constraints.
        execution: Runtime execution constraints.
        data_flow: Data flow and exfiltration constraints.
        created_at: Unix timestamp when profile was created.
        expires_at: Unix timestamp when profile expires (None = no expiry).
        signature: Cryptographic signature for tamper detection.
    """
    agent_id: str
    user_id: str
    project_id: str
    session_id: str

    data_access: DataAccessConstraints = field(default_factory=DataAccessConstraints)
    network: NetworkConstraints = field(default_factory=NetworkConstraints)
    tools: ToolConstraints = field(default_factory=ToolConstraints)
    execution: ExecutionConstraints = field(default_factory=ExecutionConstraints)
    data_flow: DataFlowConstraints = field(default_factory=DataFlowConstraints)

    # Metadata
    created_at: float = 0
    expires_at: Optional[float] = None
    signature: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary for signing/transmission."""
        return {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "project_id": self.project_id,
            "session_id": self.session_id,
            "data_access": self.data_access.to_dict(),
            "network": self.network.to_dict(),
            "tools": self.tools.to_dict(),
            "execution": self.execution.to_dict(),
            "data_flow": self.data_flow.to_dict(),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ConstraintProfile:
        """Deserialize from dictionary."""
        return cls(
            agent_id=data["agent_id"],
            user_id=data["user_id"],
            project_id=data["project_id"],
            session_id=data["session_id"],
            data_access=DataAccessConstraints.from_dict(data.get("data_access", {})),
            network=NetworkConstraints.from_dict(data.get("network", {})),
            tools=ToolConstraints.from_dict(data.get("tools", {})),
            execution=ExecutionConstraints.from_dict(data.get("execution", {})),
            data_flow=DataFlowConstraints.from_dict(data.get("data_flow", {})),
            created_at=data.get("created_at", 0),
            expires_at=data.get("expires_at"),
            signature=data.get("signature"),
        )

    @classmethod
    def from_yaml(cls, yaml_content: str) -> ConstraintProfile:
        """Parse constraint profile from YAML.

        Args:
            yaml_content: YAML-formatted constraint profile string.

        Returns:
            A ConstraintProfile instance.
        """
        data = _yaml_safe_load(yaml_content)
        return cls.from_dict(data)

    def to_yaml(self) -> str:
        """Serialize to YAML string."""
        if yaml is not None:
            return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)
        return "\n".join(_yaml_dump_lines(self.to_dict())) + "\n"
