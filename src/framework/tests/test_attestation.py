"""Tests for the attestation engine."""

import time
import unittest

from src.framework.attestation import (
    ActionType,
    AgentAction,
    AttestationEngine,
    AttestationEvidence,
)
from src.framework.constraints import ConstraintProfile


class TestAgentAction(unittest.TestCase):
    """Test AgentAction data structure."""

    def test_create_action(self):
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.FILE_READ,
            details={"path": "/data/file.h5", "size_mb": 100},
        )
        self.assertEqual(action.action_type, ActionType.FILE_READ)
        self.assertEqual(action.details["path"], "/data/file.h5")
        self.assertEqual(action.to_dict()["syscall"], "sys_enter_read")


class TestAttestationEvidence(unittest.TestCase):
    """Test AttestationEvidence signing and hashing."""

    def test_compute_hash_deterministic(self):
        evidence = AttestationEvidence(
            agent_id="agent1",
            session_id="sess_001",
            node_id="node1",
            slurm_job_id="job_001",
            timestamp=1000.0,
            interval_start=995.0,
            interval_end=1000.0,
            actions=[
                AgentAction(1000.0, ActionType.FILE_READ, {"path": "/data/a", "size_mb": 10}),
            ],
        )
        hash1 = evidence.compute_hash()
        hash2 = evidence.compute_hash()
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

    def test_sign_and_verify(self):
        evidence = AttestationEvidence(
            agent_id="agent1",
            session_id="sess_001",
            node_id="node1",
            slurm_job_id="job_001",
            timestamp=1000.0,
            interval_start=995.0,
            interval_end=1000.0,
        )
        evidence.sign("node1")
        self.assertIsNotNone(evidence.signature)
        self.assertTrue(evidence.verify_signature("node1"))
        self.assertFalse(evidence.verify_signature("wrong_key"))

    def test_different_evidence_different_hash(self):
        e1 = AttestationEvidence(
            agent_id="agent1",
            session_id="sess_001",
            node_id="node1",
            slurm_job_id="job_001",
            timestamp=1000.0,
            interval_start=995.0,
            interval_end=1000.0,
        )
        e2 = AttestationEvidence(
            agent_id="agent2",
            session_id="sess_002",
            node_id="node2",
            slurm_job_id="job_002",
            timestamp=1000.0,
            interval_start=995.0,
            interval_end=1000.0,
        )
        self.assertNotEqual(e1.compute_hash(), e2.compute_hash())


class TestAttestationEngine(unittest.TestCase):
    """Test AttestationEngine behavior."""

    def setUp(self):
        self.engine = AttestationEngine(node_id="test_node", attestation_interval=1)
        self.profile = ConstraintProfile(
            agent_id="agent1",
            user_id="user1",
            project_id="proj1",
            session_id="sess_001",
            slurm_job_id="job_001",
        )

    def test_register_agent(self):
        self.engine.register_agent("agent1", self.profile)
        self.assertIn("agent1", self.engine.monitored_agents)
        self.assertEqual(self.engine.monitored_agents["agent1"]["slurm_job_id"], "job_001")
        self.assertIn("agent1", self.engine.action_buffers)
        self.assertIn("agent1", self.engine.volume_counters)

    def test_record_action(self):
        self.engine.register_agent("agent1", self.profile)
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.FILE_READ,
            details={"path": "/data/file.h5", "size_mb": 50},
        )
        self.engine.record_action("agent1", action)
        self.assertEqual(len(self.engine.action_buffers["agent1"]), 1)
        self.assertEqual(self.engine.volume_counters["agent1"]["file_read_mb"], 50)

    def test_record_unregistered_agent_ignored(self):
        action = AgentAction(
            timestamp=time.time(),
            action_type=ActionType.FILE_READ,
            details={"path": "/data/file.h5", "size_mb": 50},
        )
        self.engine.record_action("unknown_agent", action)

    def test_generate_evidence(self):
        self.engine.register_agent("agent1", self.profile)
        self.engine.record_action("agent1", AgentAction(
            time.time(), ActionType.FILE_READ, {"path": "/data/a", "size_mb": 100},
        ))
        self.engine.record_action("agent1", AgentAction(
            time.time(), ActionType.NETWORK_CONNECTION,
            {"endpoint": "api.openai.com", "data_sent_mb": 5},
        ))

        evidence = self.engine.generate_evidence("agent1")
        self.assertEqual(evidence.agent_id, "agent1")
        self.assertEqual(evidence.node_id, "test_node")
        self.assertEqual(evidence.slurm_job_id, "job_001")
        self.assertEqual(len(evidence.actions), 2)
        self.assertEqual(evidence.total_file_read_mb, 100)
        self.assertEqual(evidence.total_network_egress_mb, 5)
        self.assertEqual(evidence.network_connection_count, 1)
        self.assertEqual(evidence.transport, "grpc+mTLS")
        self.assertIsNotNone(evidence.signature)

    def test_generate_evidence_with_challenge(self):
        self.engine.register_agent("agent1", self.profile)
        challenge = self.engine.generate_challenge("agent1")
        evidence = self.engine.generate_evidence("agent1", challenge=challenge)
        self.assertEqual(evidence.challenge_id, challenge["challenge_id"])
        self.assertEqual(evidence.challenge_nonce, challenge["nonce"])

    def test_evidence_buffer_cleared(self):
        self.engine.register_agent("agent1", self.profile)
        self.engine.record_action("agent1", AgentAction(
            time.time(), ActionType.FILE_READ, {"path": "/data/a", "size_mb": 10},
        ))
        self.engine.generate_evidence("agent1")
        self.assertEqual(len(self.engine.action_buffers["agent1"]), 0)
        self.assertEqual(self.engine.volume_counters["agent1"]["file_read_mb"], 10)

    def test_generate_challenge(self):
        self.engine.register_agent("agent1", self.profile)
        challenge = self.engine.generate_challenge("agent1")
        self.assertIn("challenge_id", challenge)
        self.assertIn("nonce", challenge)
        self.assertEqual(challenge["agent_id"], "agent1")
        self.assertEqual(len(challenge["nonce"]), 64)

    def test_volume_accumulation(self):
        self.engine.register_agent("agent1", self.profile)
        self.engine.record_action("agent1", AgentAction(
            time.time(), ActionType.FILE_READ, {"path": "/a", "size_mb": 50},
        ))
        self.engine.generate_evidence("agent1")
        self.engine.record_action("agent1", AgentAction(
            time.time(), ActionType.FILE_READ, {"path": "/b", "size_mb": 30},
        ))
        evidence = self.engine.generate_evidence("agent1")
        self.assertEqual(evidence.total_file_read_mb, 80)


if __name__ == "__main__":
    unittest.main()
