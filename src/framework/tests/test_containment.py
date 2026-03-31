"""Tests for the containment enforcer."""

import time
import unittest

from src.framework.containment import (
    ContainmentAction,
    ContainmentEnforcer,
)
from src.framework.verifier import ConstraintViolation, VerificationResult, Verdict


class TestContainmentEnforcer(unittest.TestCase):
    def setUp(self):
        self.enforcer = ContainmentEnforcer()

    def _make_result(self, agent_id: str, verdict: Verdict, violations=None):
        return VerificationResult(
            agent_id=agent_id,
            session_id="sess_001",
            slurm_job_id="job_001",
            timestamp=time.time(),
            verdict=verdict,
            violations=violations or [],
        )

    def test_compliant_no_action(self):
        result = self._make_result("agent1", Verdict.COMPLIANT)
        decision = self.enforcer.enforce(result)
        self.assertEqual(decision.action, ContainmentAction.NONE)
        self.assertEqual(self.enforcer.get_agent_state("agent1"), "active")

    def test_minor_violation_rate_limit(self):
        result = self._make_result("agent1", Verdict.VIOLATION_MINOR)
        decision = self.enforcer.enforce(result)
        self.assertEqual(decision.action, ContainmentAction.CGROUP_THROTTLE)
        self.assertEqual(self.enforcer.get_agent_state("agent1"), "throttled")
        self.assertIn("cgroup", decision.details["containment_summary"].lower())

    def test_moderate_violation_isolate(self):
        result = self._make_result("agent1", Verdict.VIOLATION_MODERATE)
        decision = self.enforcer.enforce(result)
        self.assertEqual(decision.action, ContainmentAction.ACL_REVOKE)
        self.assertEqual(self.enforcer.get_agent_state("agent1"), "acl_revoked")
        self.assertIn("acl", decision.details["containment_summary"].lower())

    def test_severe_violation_suspend(self):
        result = self._make_result("agent1", Verdict.VIOLATION_SEVERE)
        decision = self.enforcer.enforce(result)
        self.assertEqual(decision.action, ContainmentAction.JOB_SUSPEND)
        self.assertEqual(self.enforcer.get_agent_state("agent1"), "suspended")

    def test_critical_violation_terminate(self):
        result = self._make_result("agent1", Verdict.VIOLATION_CRITICAL)
        decision = self.enforcer.enforce(result)
        self.assertEqual(decision.action, ContainmentAction.JOB_TERMINATE)
        self.assertEqual(self.enforcer.get_agent_state("agent1"), "terminated")
        self.assertTrue(decision.details["credential_revoked"])

    def test_containment_history(self):
        for verdict in [Verdict.VIOLATION_MINOR, Verdict.VIOLATION_MODERATE]:
            result = self._make_result("agent1", verdict)
            self.enforcer.enforce(result)
        self.assertEqual(len(self.enforcer.containment_history), 2)

    def test_is_contained(self):
        result = self._make_result("agent1", Verdict.VIOLATION_SEVERE)
        self.enforcer.enforce(result)
        self.assertTrue(self.enforcer.is_contained("agent1"))

    def test_not_contained(self):
        self.assertFalse(self.enforcer.is_contained("agent1"))

    def test_release(self):
        result = self._make_result("agent1", Verdict.VIOLATION_SEVERE)
        self.enforcer.enforce(result)
        self.assertTrue(self.enforcer.is_contained("agent1"))

        self.enforcer.release("agent1")
        self.assertFalse(self.enforcer.is_contained("agent1"))
        self.assertEqual(self.enforcer.get_agent_state("agent1"), "active")

    def test_callback_invoked(self):
        callback_decisions = []

        def callback(decision):
            callback_decisions.append(decision)

        self.enforcer.on_containment = callback

        result = self._make_result("agent1", Verdict.VIOLATION_SEVERE)
        self.enforcer.enforce(result)

        self.assertEqual(len(callback_decisions), 1)
        self.assertEqual(callback_decisions[0].action, ContainmentAction.JOB_SUSPEND)

    def test_decision_details(self):
        violations = [
            ConstraintViolation(
                constraint_type="network",
                description="Unauthorized connection to evil.com",
                severity=Verdict.VIOLATION_SEVERE,
                evidence={"endpoint": "evil.com"},
                timestamp=time.time(),
            ),
        ]
        result = self._make_result("agent1", Verdict.VIOLATION_SEVERE, violations)
        decision = self.enforcer.enforce(result)

        self.assertEqual(decision.agent_id, "agent1")
        self.assertIn("evil.com", decision.reason)
        self.assertEqual(decision.details["verdict"], "violation_severe")
        self.assertEqual(len(decision.details["violations"]), 1)
        self.assertGreater(len(decision.details["slurm_operations"]), 0)

    def test_multiple_agents_independent(self):
        r1 = self._make_result("agent1", Verdict.VIOLATION_SEVERE)
        r2 = self._make_result("agent2", Verdict.COMPLIANT)

        self.enforcer.enforce(r1)
        self.enforcer.enforce(r2)

        self.assertEqual(self.enforcer.get_agent_state("agent1"), "suspended")
        self.assertEqual(self.enforcer.get_agent_state("agent2"), "active")


if __name__ == "__main__":
    unittest.main()
