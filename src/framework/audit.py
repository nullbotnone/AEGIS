"""Tamper-evident audit ledger for AEGIS.

Provides append-only logging with hash-chain integrity verification.
Supports deterministic replay of agent execution history.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AuditEntry:
    """A single entry in the audit ledger.

    Attributes:
        sequence: Sequential position in the ledger (0-indexed).
        timestamp: Unix timestamp when the entry was created.
        entry_type: Type of entry ("registration", "attestation", "verification",
            "containment", "challenge", "error").
        agent_id: The agent this entry pertains to.
        data: Entry-specific data payload.
        previous_hash: SHA-256 hash of the previous entry (chain link).
        hash: SHA-256 hash of this entry.
    """
    sequence: int
    timestamp: float
    entry_type: str
    agent_id: str
    data: Dict[str, Any]
    previous_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this entry for integrity verification.

        The hash covers all fields except the hash field itself,
        creating a tamper-evident chain.
        """
        content = (
            f"{self.sequence}:{self.timestamp}:{self.entry_type}:"
            f"{self.agent_id}:{json.dumps(self.data, sort_keys=True)}:"
            f"{self.previous_hash}"
        )
        return hashlib.sha256(content.encode()).hexdigest()


class AuditLedger:
    """Tamper-evident, append-only audit ledger.

    Each entry includes a hash chain linking it to the previous entry,
    providing cryptographic integrity verification. The ledger supports
    deterministic replay of agent execution for forensic analysis.

    The hash chain works as follows:
    - Genesis entry links to "0" * 64
    - Each subsequent entry's previous_hash is the hash of the prior entry
    - Tampering with any entry breaks the chain from that point forward
    """

    def __init__(self):
        """Initialize the audit ledger with a genesis hash."""
        self.entries: List[AuditEntry] = []
        self._last_hash = "0" * 64  # Genesis hash

    def append(self, entry_type: str, agent_id: str, data: Dict[str, Any]) -> AuditEntry:
        """Append a new entry to the ledger.

        Args:
            entry_type: Type of entry (e.g., "attestation", "verification").
            agent_id: The agent this entry pertains to.
            data: Entry-specific data payload.

        Returns:
            The created AuditEntry.
        """
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
        """Verify the integrity of the entire ledger hash chain.

        Checks that:
        1. Each entry's previous_hash matches the prior entry's hash
        2. Each entry's hash is correctly computed

        Returns:
            A tuple of (is_valid, first_invalid_index).
            If valid, first_invalid_index is None.
            If invalid, first_invalid_index is the 0-based index of the
            first entry that fails verification.
        """
        expected_hash = "0" * 64  # Genesis

        for i, entry in enumerate(self.entries):
            # Check chain link
            if entry.previous_hash != expected_hash:
                return False, i

            # Check hash computation
            if entry.hash != entry.compute_hash():
                return False, i

            expected_hash = entry.hash

        return True, None

    def get_agent_history(self, agent_id: str) -> List[AuditEntry]:
        """Get all audit entries for a specific agent.

        Args:
            agent_id: The agent to retrieve history for.

        Returns:
            List of AuditEntry instances in chronological order.
        """
        return [e for e in self.entries if e.agent_id == agent_id]

    def get_entries_by_type(self, entry_type: str) -> List[AuditEntry]:
        """Get all audit entries of a specific type.

        Args:
            entry_type: The entry type to filter by.

        Returns:
            List of matching AuditEntry instances.
        """
        return [e for e in self.entries if e.entry_type == entry_type]

    def replay(self, agent_id: str) -> List[Dict[str, Any]]:
        """Replay an agent's execution from the audit log.

        Returns a chronological sequence of events for forensic analysis
        or deterministic replay.

        Args:
            agent_id: The agent to replay.

        Returns:
            List of event dictionaries in chronological order.
        """
        history = self.get_agent_history(agent_id)
        return [
            {
                "sequence": e.sequence,
                "timestamp": e.timestamp,
                "type": e.entry_type,
                "data": e.data,
            }
            for e in history
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the ledger contents.

        Returns:
            Dictionary with entry counts by type and total entries.
        """
        counts: Dict[str, int] = {}
        for entry in self.entries:
            counts[entry.entry_type] = counts.get(entry.entry_type, 0) + 1
        return {
            "total_entries": len(self.entries),
            "entry_counts": counts,
            "integrity_valid": self.verify_integrity()[0],
        }

    def __len__(self) -> int:
        """Return the number of entries in the ledger."""
        return len(self.entries)
