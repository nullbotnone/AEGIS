"""Tests for the tamper-evident audit ledger."""

import unittest

from src.framework.verifier import AuditEntry, AuditLedger


class TestAuditEntry(unittest.TestCase):
    """Test AuditEntry hash computation."""

    def test_compute_hash_deterministic(self):
        entry = AuditEntry(
            sequence=0,
            timestamp=1000.0,
            entry_type="test",
            agent_id="agent1",
            data={"key": "value"},
            previous_hash="0" * 64,
        )
        hash1 = entry.compute_hash()
        hash2 = entry.compute_hash()
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA-256 hex

    def test_different_entries_different_hash(self):
        e1 = AuditEntry(0, 1000.0, "test", "a1", {"k": "v1"}, "0" * 64)
        e2 = AuditEntry(0, 1000.0, "test", "a1", {"k": "v2"}, "0" * 64)
        self.assertNotEqual(e1.compute_hash(), e2.compute_hash())


class TestAuditLedger(unittest.TestCase):
    """Test AuditLedger behavior."""

    def setUp(self):
        self.ledger = AuditLedger()

    def test_append_entry(self):
        entry = self.ledger.append("test", "agent1", {"data": "value"})
        self.assertEqual(entry.sequence, 0)
        self.assertEqual(entry.entry_type, "test")
        self.assertEqual(entry.agent_id, "agent1")
        self.assertEqual(len(self.ledger), 1)

    def test_hash_chain(self):
        e1 = self.ledger.append("test", "agent1", {"data": "first"})
        e2 = self.ledger.append("test", "agent1", {"data": "second"})
        e3 = self.ledger.append("test", "agent1", {"data": "third"})

        # Each entry's previous_hash should be the prior entry's hash
        self.assertEqual(e1.previous_hash, "0" * 64)
        self.assertEqual(e2.previous_hash, e1.hash)
        self.assertEqual(e3.previous_hash, e2.hash)

    def test_verify_integrity_valid(self):
        self.ledger.append("test", "agent1", {"data": "a"})
        self.ledger.append("test", "agent1", {"data": "b"})
        self.ledger.append("test", "agent2", {"data": "c"})

        is_valid, invalid_idx = self.ledger.verify_integrity()
        self.assertTrue(is_valid)
        self.assertIsNone(invalid_idx)

    def test_verify_integrity_detects_tampering(self):
        self.ledger.append("test", "agent1", {"data": "a"})
        self.ledger.append("test", "agent1", {"data": "b"})

        # Tamper with the first entry's data
        self.ledger.entries[0].data = {"data": "TAMPERED"}

        is_valid, invalid_idx = self.ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertEqual(invalid_idx, 0)

    def test_verify_integrity_detects_broken_chain(self):
        self.ledger.append("test", "agent1", {"data": "a"})
        self.ledger.append("test", "agent1", {"data": "b"})

        # Break the chain by changing previous_hash
        self.ledger.entries[1].previous_hash = "F" * 64

        is_valid, invalid_idx = self.ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertEqual(invalid_idx, 1)

    def test_get_agent_history(self):
        self.ledger.append("test", "agent1", {"data": "a"})
        self.ledger.append("test", "agent2", {"data": "b"})
        self.ledger.append("test", "agent1", {"data": "c"})

        history = self.ledger.get_agent_history("agent1")
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0].data["data"], "a")
        self.assertEqual(history[1].data["data"], "c")

    def test_replay(self):
        self.ledger.append("registration", "agent1", {"user": "u1"})
        self.ledger.append("attestation", "agent1", {"actions": 5})
        self.ledger.append("verification", "agent1", {"verdict": "compliant"})

        replay = self.ledger.replay("agent1")
        self.assertEqual(len(replay), 3)
        self.assertEqual(replay[0]["type"], "registration")
        self.assertEqual(replay[1]["type"], "attestation")
        self.assertEqual(replay[2]["type"], "verification")

    def test_get_summary(self):
        self.ledger.append("attestation", "agent1", {})
        self.ledger.append("attestation", "agent2", {})
        self.ledger.append("verification", "agent1", {})

        summary = self.ledger.get_summary()
        self.assertEqual(summary["total_entries"], 3)
        self.assertEqual(summary["entry_counts"]["attestation"], 2)
        self.assertEqual(summary["entry_counts"]["verification"], 1)
        self.assertTrue(summary["integrity_valid"])

    def test_get_entries_by_type(self):
        self.ledger.append("attestation", "agent1", {})
        self.ledger.append("verification", "agent1", {})
        self.ledger.append("attestation", "agent2", {})

        attestations = self.ledger.get_entries_by_type("attestation")
        self.assertEqual(len(attestations), 2)

    def test_empty_ledger_integrity(self):
        is_valid, _ = self.ledger.verify_integrity()
        self.assertTrue(is_valid)

    def test_sequence_numbers(self):
        for i in range(5):
            entry = self.ledger.append("test", "agent1", {"i": i})
            self.assertEqual(entry.sequence, i)


if __name__ == "__main__":
    unittest.main()
