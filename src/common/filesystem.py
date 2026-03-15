"""Simulated shared filesystem for HPC environments.

Models a Lustre-like shared filesystem with:
- Project directories (/projects/{project_id}/)
- Shared scratch spaces (/tmp, /var/tmp)
- User home directories (/home/{user_id}/)
- File metadata support for injection payloads
"""
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, List
from .logger import ActionLogger, ActionType


@dataclass
class FileEntry:
    """Represents a file in the simulated filesystem."""
    path: str
    content: bytes
    metadata: Dict[str, str]
    owner: str
    created_at: float
    modified_at: float
    permissions: str = "rw-r--r--"

    @property
    def size(self) -> int:
        return len(self.content)


class SharedFilesystem:
    """Simulates an HPC shared filesystem (Lustre-like).

    Supports:
    - Hierarchical directory structure
    - File metadata (used for injection payloads)
    - User-based access control (simplified)
    - Action logging for attestation
    """

    def __init__(self, logger: Optional[ActionLogger] = None):
        self.files: Dict[str, FileEntry] = {}
        self.logger = logger or ActionLogger()
        self._init_directories()

    def _init_directories(self):
        """Create standard HPC directory structure."""
        # These are implicit directories; we just track them
        self._directories = {
            "/projects",
            "/home",
            "/tmp",
            "/var/tmp",
            "/.cache",
        }

    def _ensure_parent_dirs(self, path: str):
        """Ensure parent directories exist."""
        parts = path.rstrip("/").split("/")
        for i in range(2, len(parts)):
            parent = "/".join(parts[:i])
            if parent:
                self._directories.add(parent)

    def write(self, path: str, content: bytes, user: str,
              metadata: Optional[Dict[str, str]] = None) -> bool:
        """Write a file to the filesystem.

        Args:
            path: Absolute path
            content: File content as bytes
            metadata: Optional metadata dict (key for injection attacks)
            user: User performing the write
        """
        if isinstance(content, str):
            content = content.encode("utf-8")

        self._ensure_parent_dirs(path)
        now = time.time()

        if path in self.files:
            entry = self.files[path]
            entry.content = content
            entry.metadata = metadata or entry.metadata
            entry.modified_at = now
        else:
            entry = FileEntry(
                path=path,
                content=content,
                metadata=metadata or {},
                owner=user,
                created_at=now,
                modified_at=now,
            )
            self.files[path] = entry

        self.logger.log(
            ActionType.FILE_WRITE,
            agent_id=user,
            details={"path": path, "size": len(content), "has_metadata": bool(metadata)},
        )
        return True

    def read(self, path: str, user: str) -> Optional[bytes]:
        """Read a file from the filesystem.

        Returns None if file doesn't exist.
        """
        if path not in self.files:
            self.logger.log(
                ActionType.FILE_READ,
                agent_id=user,
                details={"path": path, "found": False},
            )
            return None

        entry = self.files[path]
        self.logger.log(
            ActionType.FILE_READ,
            agent_id=user,
            details={"path": path, "size": entry.size, "has_metadata": bool(entry.metadata)},
        )
        return entry.content

    def read_with_metadata(self, path: str, user: str):
        """Read a file and return content + metadata tuple."""
        if path not in self.files:
            return None, {}
        entry = self.files[path]
        self.logger.log(
            ActionType.FILE_READ,
            agent_id=user,
            details={"path": path, "size": entry.size, "has_metadata": bool(entry.metadata)},
        )
        return entry.content, entry.metadata

    def list_dir(self, path: str) -> List[str]:
        """List files in a directory."""
        prefix = path.rstrip("/") + "/"
        return [
            fpath for fpath in self.files
            if fpath.startswith(prefix) and "/" not in fpath[len(prefix):]
        ]

    def exists(self, path: str) -> bool:
        return path in self.files

    def delete(self, path: str, user: str) -> bool:
        if path in self.files:
            del self.files[path]
            self.logger.log(ActionType.FILE_WRITE, agent_id=user,
                            details={"path": path, "operation": "delete"})
            return True
        return False

    def get_file_info(self, path: str) -> Optional[FileEntry]:
        return self.files.get(path)

    def snapshot(self) -> Dict[str, FileEntry]:
        """Return a snapshot of all files (for attestation comparison)."""
        return dict(self.files)
