"""Tests for the policy verifier."""

import time
import unittest

from src.framework.attestation import ActionType, AgentAction, AttestationEvidence
from src.framework.constraints import (
    ConstraintProfile,
    DataAccessConstraints,
    DataFlowConstraints,
    NetworkConstraints,
    ToolConstraints,
)
from src.framework.verifier import ConstraintViolation, PolicyVerifier, Verdict, VerificationResult


class TestVerdict(unittest.TestCase):
    """Test Verdict enum comparisons."""

    def test_severity_ordering(self):
        self.assertLess(Verdict.COMPLIANT, Verdict.VIOLATION_MINOR)
        self.assertLess(Verdict.VIOLATION_MINOR, Verdict.VIOLATION_MODERATE)
        self.assertLess(Verdict.VIOLATION_MODERATE, Verdict.VIOLATION_SEVERE)
        self.assertLess(Verdict.VIOLATION_SEVERE, Verdict.VIOLATION_CRITICAL)

    def test_equality(self):
        self.assertEqual(Verdict.COMPLIANT, Verdict.COMPLIANT)
        self.assertNotEqual(Verdict.COMPLIANT, Verdict.VIOLATION_MINOR)


class TestVerificationResult(unittest.TestCase):
    """Test VerificationResult behavior."""

    def test_is_violation(self):
        result = VerificationResult(
            agent_id="a1", session_id="s1", timestamp=time.time(),
            verdict=Verdict.COMPLIANT,
        )
        self.assertFalse(result.is_violation())

        result = VerificationResult(
            agent_id="a1", session_id="s1", timestamp=time.time(),
            verdict=Verdict.VIOLATION_MODERATE,
        )
        self.assertTrue(result.is_violation())


class TestPolicyVerifier(unittest.TestCase):
    """Test PolicyVerifier behavior."""

    def setUp(self):
        self.verifier = PolicyVerifier()
        self.profile = ConstraintProfile(
            agent_id="agent1",
            user_id="user1",
            project_id="genomics",
            session_id="sess_001",
            data_access=DataAccessConstraints(
                allowed_paths={"/projects/genomics/*"},
                denied_paths={"/projects/finance/*"},
            ),
            network=NetworkConstraints(
                allowed_endpoints={"api.openai.com"},
                denied_endpoints={"*"},
            ),
            tools=ToolConstraints(
                allowed_tools={"hdf5_reader"},
                denied_tools={"rm"},
            ),
        )
        self.verifier.register_agent(self.profile)

    def _make_evidence(self, actions):
        return AttestationEvidence(
            agent_id="agent1",
            session_id="sess_001",
            timestamp=time.time(),
            interval_start=time.time() - 5,
            interval_end=time.time(),
            actions=actions,
        )

    def test_compliant_actions(self):
        evidence = self._make_evidence([
            AgentAction(time.time(), ActionType.FILE_READ,
                        {"path": "/projects/genomics/data.h5", "size_mb": 100}),
            AgentAction(time.time(), ActionType.TOOL_INVOCATION,
                        {"tool": "hdf5_reader", "args": []}),
            AgentAction(time.time(), ActionType.LLM_API_CALL,
                        {"endpoint": "api.openai.com", "data_sent_mb": 0.1}),
        ])
        result = self.verifier.verify(evidence)
        self.assertEqual(result.verdict, Verdict.COMPLIANT)
        self.assertEqual(len(result.violations), 0)

    def test_unauthorized_file_read(self):
        evidence = self._make_evidence([
            AgentAction(time.time(), ActionType.FILE_READ,
                        {"path": "/projects/finance/salaries.csv", "size_mb": 50}),
        ])
        result = self.verifier.verify(evidence)
        self.assertTrue(result.is_violation())
        self.assertEqual(result.verdict, Verdict.VIOLATION_MODERATE)
        self.assertEqual(result.violations[0].constraint_type, "data_access")

    def test_unauthorized_network(self):
        evidence = self._make_evidence([
            AgentAction(time.time(), ActionType.NETWORK_CONNECTION,
                        {"endpoint": "evil.example.com", "data_sent_mb": 5}),
        ])
        result = self.verifier.verify(evidence)
        self.assertTrue(result.is_violation())
        self.assertEqual(result.verdict, Verdict.VIOLATION_SEVERE)
        self.assertEqual(result.violations[0].constraint_type, "network")

    def test_unauthorized_tool(self):
        evidence = self._make_evidence([
            AgentAction(time.time(), ActionType.TOOL_INVOCATION,
                        {"tool": "rm", "args": ["-rf", "/"]}),
        ])
        result = self.verifier.verify(evidence)
        self.assertTrue(result.is_violation())
        self.assertEqual(result.verdict, Verdict.VIOLATION_MODERATE)

    def test_allowed_endpoint_overrides_wildcard_deny(self):
        # api.openai.com is in allowed_endpoints, so it should pass despite "*"
        evidence = self._make_evidence([
            AgentAction(time.time(), ActionType.LLM_API_CALL,
                        {"endpoint": "api.openai.com", "data_sent_mb": 0.5}),
        ])
        result = self.verifier.verify(evidence)
        self.assertEqual(result.verdict, Verdict.COMPLIANT)

    def test_no_profile_severe_violation(self):
        """Evidence for unregistered agent should produce severe violation."""
        evidence = AttestationEvidence(
            agent_id="unknown_agent",
            session_id="unknown",
            timestamp=time.time(),
            interval_start=time.time() - 5,
            interval_end=time.time(),
            actions=[],
        )
        result = self.verifier.verify(evidence)
        self.assertEqual(result.verdict, Verdict.VIOLATION_SEVERE)
        self.assertIn("No constraint profile", result.violations[0].description)

    def test_multiple_violations_worst_severity(self):
        evidence = self._make_evidence([
            AgentAction(time.time(), ActionType.FILE_READ,
                        {"path": "/projects/finance/data.csv", "size_mb": 10}),
            AgentAction(time.time(), ActionType.NETWORK_CONNECTION,
                        {"endpoint": "evil.com", "data_sent_mb": 5}),
        ])
        result = self.verifier.verify(evidence)
        # Network violation (SEVERE) should be the verdict
        self.assertEqual(result.verdict, Verdict.VIOLATION_SEVERE)
        self.assertEqual(len(result.violations), 2)

    def test_exfil_budget_violation(self):
        profile = ConstraintProfile(
            agent_id="agent_exfil",
            user_id="user1",
            project_id="genomics",
            session_id="sess_002",
            network=NetworkConstraints(allowed_endpoints={"*"}),
            data_flow=DataFlowConstraints(max_exfil_budget_mb_per_hour=1),
        )
        self.verifier.register_agent(profile)

        # Simulate sending 100 MB — way over 1 MB/h budget
        evidence = AttestationEvidence(
            agent_id="agent_exfil",
            session_id="sess_002",
            timestamp=time.time(),
            interval_start=time.time() - 5,
            interval_end=time.time(),
            actions=[],
            total_network_egress_mb=100,
        )
        result = self.verifier.verify(evidence)
        self.assertTrue(result.is_violation())
        self.assertEqual(result.verdict, Verdict.VIOLATION_SEVERE)

    def test_verification_history(self):
        evidence = self._make_evidence([
            AgentAction(time.time(), ActionType.FILE_READ,
                        {"path": "/projects/genomics/data.h5", "size_mb": 10}),
        ])
        self.verifier.verify(evidence)
        self.assertEqual(len(self.verifier.verification_history), 1)

    def test_get_violation_count(self):
        # Compliant evidence
        self.verifier.verify(self._make_evidence([
            AgentAction(time.time(), ActionType.FILE_READ,
                        {"path": "/projects/genomics/data.h5", "size_mb": 10}),
        ]))
        # Violation evidence
        self.verifier.verify(self._make_evidence([
            AgentAction(time.time(), ActionType.FILE_READ,
                        {"path": "/projects/finance/data.csv", "size_mb": 10}),
        ]))
        self.assertEqual(self.verifier.get_violation_count("agent1"), 1)


if __name__ == "__main__":
    unittest.main()
