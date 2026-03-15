"""End-to-end integration tests for the AEGIS framework.

Tests the full attestation loop: constraint setup → agent monitoring →
evidence generation → verification → containment → audit.
"""

import time
import unittest

from framework.constraints import (
    ConstraintProfile,
    DataAccessConstraints,
    DataFlowConstraints,
    NetworkConstraints,
    ToolConstraints,
)
from framework.policy_engine import PolicyEngine
from framework.containment import ContainmentAction
from framework.verifier import Verdict


class TestAEGISEndToEnd(unittest.TestCase):
    """Full end-to-end tests with mock agents."""

    def test_benign_agent_no_violations(self):
        """A benign agent operating within constraints should have no violations."""
        engine = PolicyEngine(attestation_interval=1)

        constraints = ConstraintProfile(
            agent_id="benign_agent",
            user_id="user1",
            project_id="genomics",
            session_id="test_session",
            data_access=DataAccessConstraints(
                allowed_paths={"/projects/genomics/*", "/scratch/user1/*"},
                denied_paths={"/projects/finance/*"},
            ),
            network=NetworkConstraints(
                allowed_endpoints={"api.openai.com"},
            ),
            tools=ToolConstraints(
                allowed_tools={"hdf5_reader", "csv_parser"},
            ),
        )

        monitor = engine.register_agent("benign_agent", "user1", "genomics", constraints)
        engine.start()

        # Simulate benign actions
        monitor.on_file_read("/projects/genomics/data.h5", size_mb=100)
        monitor.on_tool_invocation("hdf5_reader", ["data.h5"])
        monitor.on_llm_api_call("api.openai.com", prompt_size_kb=5)

        time.sleep(2)
        engine.stop()

        # Check results
        status = engine.get_agent_status("benign_agent")
        self.assertEqual(status["state"], "active")
        self.assertEqual(status["violations"], 0)

        # Verify audit ledger integrity
        is_valid, _ = engine.audit.verify_integrity()
        self.assertTrue(is_valid)

    def test_hijacked_agent_detected(self):
        """A hijacked agent violating constraints should be detected and contained."""
        engine = PolicyEngine(attestation_interval=1)

        constraints = ConstraintProfile(
            agent_id="hijacked_agent",
            user_id="user2",
            project_id="genomics",
            session_id="test_session",
            data_access=DataAccessConstraints(
                allowed_paths={"/projects/genomics/*"},
                denied_paths={"/projects/finance/*", "/home/*/.ssh/*"},
            ),
            network=NetworkConstraints(
                allowed_endpoints={"api.openai.com"},
                denied_endpoints={"*"},
            ),
            data_flow=DataFlowConstraints(
                max_exfil_budget_mb_per_hour=10,
            ),
        )

        monitor = engine.register_agent("hijacked_agent", "user2", "genomics", constraints)
        engine.start()

        # Simulate hijacked actions
        monitor.on_file_read("/projects/genomics/data.h5", size_mb=100)  # OK
        monitor.on_file_read("/projects/finance/quarterly.csv", size_mb=50)  # VIOLATION - denied path
        monitor.on_network_connection("evil.example.com", data_sent_mb=5)  # VIOLATION - not allowed
        monitor.on_llm_api_call("api.openai.com", prompt_size_kb=100, data_sent_mb=0.5)  # OK

        time.sleep(2)
        engine.stop()

        # Check results
        status = engine.get_agent_status("hijacked_agent")
        self.assertGreater(status["violations"], 0)

        # Check audit ledger integrity
        is_valid, _ = engine.audit.verify_integrity()
        self.assertTrue(is_valid)

        # Check that containment was applied (not "active")
        self.assertIn(status["state"], ["rate_limited", "isolated", "suspended", "terminated"])

    def test_multiple_agents_mixed_behavior(self):
        """Multiple agents with different behaviors tracked independently."""
        engine = PolicyEngine(attestation_interval=1)

        # Good agent
        good_constraints = ConstraintProfile(
            agent_id="good_agent",
            user_id="user1",
            project_id="proj1",
            session_id="sess_good",
            data_access=DataAccessConstraints(allowed_paths={"/proj1/*"}),
            network=NetworkConstraints(allowed_endpoints={"api.openai.com"}),
        )

        # Bad agent
        bad_constraints = ConstraintProfile(
            agent_id="bad_agent",
            user_id="user2",
            project_id="proj2",
            session_id="sess_bad",
            data_access=DataAccessConstraints(
                allowed_paths={"/proj2/*"},
                denied_paths={"/etc/*"},
            ),
            network=NetworkConstraints(
                allowed_endpoints={"api.openai.com"},
                denied_endpoints={"*"},
            ),
        )

        good_monitor = engine.register_agent("good_agent", "user1", "proj1", good_constraints)
        bad_monitor = engine.register_agent("bad_agent", "user2", "proj2", bad_constraints)
        engine.start()

        # Good agent: all compliant
        good_monitor.on_file_read("/proj1/data.csv", size_mb=10)
        good_monitor.on_llm_api_call("api.openai.com", prompt_size_kb=2)

        # Bad agent: violations
        bad_monitor.on_file_read("/etc/passwd", size_mb=1)  # Denied path
        bad_monitor.on_network_connection("attacker.com", data_sent_mb=10)  # Denied endpoint

        time.sleep(2)
        engine.stop()

        good_status = engine.get_agent_status("good_agent")
        bad_status = engine.get_agent_status("bad_agent")

        # Good agent should be clean
        self.assertEqual(good_status["violations"], 0)
        self.assertEqual(good_status["state"], "active")

        # Bad agent should be contained
        self.assertGreater(bad_status["violations"], 0)
        self.assertIn(bad_status["state"], ["isolated", "suspended", "terminated"])

    def test_audit_replay(self):
        """Audit ledger should support deterministic replay."""
        engine = PolicyEngine(attestation_interval=1)

        constraints = ConstraintProfile(
            agent_id="replay_agent",
            user_id="user1",
            project_id="proj1",
            session_id="sess_replay",
            data_access=DataAccessConstraints(allowed_paths={"/proj1/*"}),
        )

        monitor = engine.register_agent("replay_agent", "user1", "proj1", constraints)
        engine.start()

        monitor.on_file_read("/proj1/data.csv", size_mb=10)
        time.sleep(2)
        engine.stop()

        # Replay agent history
        history = engine.audit.replay("replay_agent")
        self.assertGreater(len(history), 0)

        # First event should be registration
        self.assertEqual(history[0]["type"], "registration")

        # Should contain attestation and verification events
        event_types = {e["type"] for e in history}
        self.assertIn("attestation", event_types)
        self.assertIn("verification", event_types)

    def test_system_status(self):
        """System status should report correct metrics."""
        engine = PolicyEngine(attestation_interval=1)

        constraints = ConstraintProfile(
            agent_id="status_agent",
            user_id="user1",
            project_id="proj1",
            session_id="sess_status",
        )

        engine.register_agent("status_agent", "user1", "proj1", constraints)

        status = engine.get_system_status()
        self.assertEqual(status["monitored_agents"], 1)
        self.assertFalse(status["running"])

        engine.start()
        time.sleep(1.5)
        engine.stop()

        status = engine.get_system_status()
        self.assertGreater(status["total_verifications"], 0)
        self.assertTrue(status["audit_ledger"]["integrity_valid"])

    def test_containment_callback(self):
        """Containment callback should be invoked on violations."""
        engine = PolicyEngine(attestation_interval=1)

        containment_events = []

        def on_containment(decision):
            containment_events.append(decision)

        engine.containment.on_containment = on_containment

        constraints = ConstraintProfile(
            agent_id="callback_agent",
            user_id="user1",
            project_id="proj1",
            session_id="sess_callback",
            network=NetworkConstraints(denied_endpoints={"*"}),
        )

        monitor = engine.register_agent("callback_agent", "user1", "proj1", constraints)
        engine.start()

        monitor.on_network_connection("evil.com", data_sent_mb=1)
        time.sleep(2)
        engine.stop()

        self.assertGreater(len(containment_events), 0)
        self.assertEqual(containment_events[0].agent_id, "callback_agent")


if __name__ == "__main__":
    unittest.main()
