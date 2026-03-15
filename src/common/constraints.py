"""Constraint specification and evaluation for agent behavior."""
from dataclasses import dataclass, field
from typing import List, Optional, Set
from enum import Enum


class ConstraintViolation(Exception):
    """Raised when an agent action violates a constraint."""
    def __init__(self, constraint_type: str, message: str):
        self.constraint_type = constraint_type
        self.message = message
        super().__init__(f"[{constraint_type}] {message}")


@dataclass
class ConstraintProfile:
    """Defines the behavioral constraints for an agent.

    These constraints model the paper's attestation framework:
    - What data can the agent access?
    - Where can it send data?
    - What tools can it invoke?
    - How much data can it exfiltrate?
    """

    # Data access constraints
    allowed_read_paths: List[str] = field(default_factory=lambda: ["*"])
    allowed_write_paths: List[str] = field(default_factory=lambda: ["*"])
    denied_paths: List[str] = field(default_factory=list)
    read_only_paths: List[str] = field(default_factory=list)
    max_read_volume_bytes: int = 100 * 1024 * 1024  # 100 MB
    max_write_volume_bytes: int = 50 * 1024 * 1024   # 50 MB

    # Network constraints
    allowed_endpoints: List[str] = field(default_factory=lambda: ["*"])
    denied_endpoints: List[str] = field(default_factory=list)
    max_egress_bytes: int = 10 * 1024 * 1024  # 10 MB

    # Tool constraints
    allowed_tools: List[str] = field(default_factory=lambda: ["*"])
    denied_tools: List[str] = field(default_factory=list)

    # Execution constraints
    max_runtime_seconds: float = 3600.0
    max_memory_bytes: int = 4 * 1024 * 1024 * 1024  # 4 GB

    # Data flow constraints
    project_boundary: Optional[str] = None  # Restrict to this project
    exfil_budget_bytes: int = 1024 * 1024  # 1 MB exfil budget
    allow_cross_project: bool = False

    # Current usage tracking
    _read_volume: int = 0
    _write_volume: int = 0
    _egress_volume: int = 0

    def _path_matches(self, path: str, pattern: str) -> bool:
        """Check if a path matches a pattern (supports * wildcard)."""
        if pattern == "*":
            return True
        if pattern.endswith("/*"):
            return path.startswith(pattern[:-1])
        return path == pattern

    def check_read(self, path: str, size: int = 0) -> bool:
        """Check if reading from this path is allowed."""
        for denied in self.denied_paths:
            if self._path_matches(path, denied):
                return False

        if self.allowed_read_paths != ["*"]:
            allowed = any(self._path_matches(path, p) for p in self.allowed_read_paths)
            if not allowed:
                return False

        if size > 0 and self._read_volume + size > self.max_read_volume_bytes:
            return False

        self._read_volume += size
        return True

    def check_write(self, path: str, size: int = 0) -> bool:
        """Check if writing to this path is allowed."""
        for denied in self.denied_paths:
            if self._path_matches(path, denied):
                return False

        for ro in self.read_only_paths:
            if self._path_matches(path, ro):
                return False

        if self.allowed_write_paths != ["*"]:
            allowed = any(self._path_matches(path, p) for p in self.allowed_write_paths)
            if not allowed:
                return False

        if size > 0 and self._write_volume + size > self.max_write_volume_bytes:
            return False

        self._write_volume += size
        return True

    def check_egress(self, endpoint: str, size: int = 0) -> bool:
        """Check if sending data to this endpoint is allowed."""
        for denied in self.denied_endpoints:
            if self._path_matches(endpoint, denied):
                return False

        if self.allowed_endpoints != ["*"]:
            allowed = any(self._path_matches(endpoint, e) for e in self.allowed_endpoints)
            if not allowed:
                return False

        if size > 0 and self._egress_volume + size > self.max_egress_bytes:
            return False

        self._egress_volume += size
        return True

    def check_exfil_budget(self, size: int) -> bool:
        """Check if this much data can be exfiltrated."""
        return self._egress_volume + size <= self.exfil_budget_bytes

    def check_tool(self, tool_name: str) -> bool:
        """Check if invoking this tool is allowed."""
        for denied in self.denied_tools:
            if self._path_matches(tool_name, denied):
                return False

        if self.allowed_tools != ["*"]:
            return any(self._path_matches(tool_name, t) for t in self.allowed_tools)

        return True

    def check_project_boundary(self, path: str) -> bool:
        """Check if accessing this path respects project boundaries."""
        if not self.project_boundary or self.allow_cross_project:
            return True
        # Allow paths within the agent's project or user home
        return (self.project_boundary in path or
                path.startswith("/tmp") or
                path.startswith("/var/tmp"))

    def get_exfil_remaining(self) -> int:
        """Get remaining exfiltration budget in bytes."""
        return max(0, self.exfil_budget_bytes - self._egress_volume)

    def violation_summary(self) -> str:
        """Return a summary of current usage vs. limits."""
        lines = [
            "=== Constraint Usage ===",
            f"  Read volume:  {self._read_volume}/{self.max_read_volume_bytes} bytes",
            f"  Write volume: {self._write_volume}/{self.max_write_volume_bytes} bytes",
            f"  Egress:       {self._egress_volume}/{self.max_egress_bytes} bytes",
            f"  Exfil budget: {self._egress_volume}/{self.exfil_budget_bytes} bytes",
        ]
        return "\n".join(lines)


def create_strict_constraints(project_id: str, user_id: str) -> ConstraintProfile:
    """Create a strict constraint profile for a user agent."""
    return ConstraintProfile(
        allowed_read_paths=[f"/projects/{project_id}/*", f"/home/{user_id}/*", "/tmp/*"],
        allowed_write_paths=[f"/home/{user_id}/*", "/tmp/*"],
        denied_paths=["/etc/*", "/root/*", "/.cache/*"],
        read_only_paths=[f"/projects/{project_id}/*"],
        max_read_volume_bytes=50 * 1024 * 1024,
        max_write_volume_bytes=20 * 1024 * 1024,
        allowed_endpoints=["https://api.llm-provider.com/*"],
        denied_endpoints=["*"],
        max_egress_bytes=5 * 1024 * 1024,
        allowed_tools=["data_converter", "csv_reader", "hdf5_reader"],
        denied_tools=["ssh", "scp", "curl"],
        project_boundary=f"/projects/{project_id}",
        exfil_budget_bytes=512 * 1024,  # 512 KB
        allow_cross_project=False,
    )
