"""Tests for constraint specification and management."""

import unittest

from src.framework.constraints import (
    ConstraintManager,
    ConstraintProfile,
    DataAccessConstraints,
    DataFlowConstraints,
    DerivationMode,
    ExecutionConstraints,
    NetworkConstraints,
    PolicyTemplate,
    ToolConstraints,
)


class TestDataAccessConstraints(unittest.TestCase):
    """Test DataAccessConstraints behavior."""

    def test_allowed_path(self):
        constraints = DataAccessConstraints(
            allowed_paths={"/projects/genomics/*"},
        )
        allowed, reason = constraints.check_access("/projects/genomics/data.h5", "read")
        self.assertTrue(allowed)

    def test_denied_path_overrides_allowed(self):
        constraints = DataAccessConstraints(
            allowed_paths={"/projects/*"},
            denied_paths={"/projects/finance/*"},
        )
        allowed, reason = constraints.check_access("/projects/finance/salaries.csv", "read")
        self.assertFalse(allowed)
        self.assertIn("denied", reason.lower())

    def test_path_not_in_allowed(self):
        constraints = DataAccessConstraints(
            allowed_paths={"/projects/genomics/*"},
        )
        allowed, reason = constraints.check_access("/projects/finance/data.csv", "read")
        self.assertFalse(allowed)
        self.assertIn("not in allowed", reason.lower())

    def test_read_only_enforcement(self):
        constraints = DataAccessConstraints(
            allowed_paths={"/projects/genomics/*"},
            read_only_paths={"/projects/genomics/reference/*"},
        )
        # Read is allowed
        allowed, _ = constraints.check_access("/projects/genomics/reference/genome.fa", "read")
        self.assertTrue(allowed)
        # Write is blocked
        allowed, reason = constraints.check_access("/projects/genomics/reference/genome.fa", "write")
        self.assertFalse(allowed)
        self.assertIn("read-only", reason.lower())

    def test_no_restrictions(self):
        constraints = DataAccessConstraints()
        allowed, _ = constraints.check_access("/any/path", "read")
        self.assertTrue(allowed)

    def test_glob_patterns(self):
        constraints = DataAccessConstraints(
            allowed_paths={"/scratch/user*/*.tmp"},
        )
        allowed, _ = constraints.check_access("/scratch/user1/output.tmp", "read")
        self.assertTrue(allowed)
        allowed, _ = constraints.check_access("/scratch/user2/data.tmp", "read")
        self.assertTrue(allowed)
        allowed, _ = constraints.check_access("/scratch/user1/output.csv", "read")
        self.assertFalse(allowed)

    def test_serialization_roundtrip(self):
        constraints = DataAccessConstraints(
            allowed_paths={"/projects/*"},
            denied_paths={"/projects/secret/*"},
            read_only_paths={"/projects/ref/*"},
            max_read_volume_mb=1000,
        )
        data = constraints.to_dict()
        restored = DataAccessConstraints.from_dict(data)
        self.assertEqual(constraints.allowed_paths, restored.allowed_paths)
        self.assertEqual(constraints.denied_paths, restored.denied_paths)
        self.assertEqual(constraints.read_only_paths, restored.read_only_paths)
        self.assertEqual(constraints.max_read_volume_mb, restored.max_read_volume_mb)


class TestNetworkConstraints(unittest.TestCase):
    """Test NetworkConstraints behavior."""

    def test_allowed_endpoint(self):
        constraints = NetworkConstraints(
            allowed_endpoints={"api.openai.com"},
        )
        allowed, _ = constraints.check_connection("api.openai.com")
        self.assertTrue(allowed)

    def test_denied_endpoint(self):
        constraints = NetworkConstraints(
            denied_endpoints={"evil.example.com"},
        )
        allowed, reason = constraints.check_connection("evil.example.com")
        self.assertFalse(allowed)
        self.assertIn("denied", reason.lower())

    def test_blanket_deny_with_exceptions(self):
        constraints = NetworkConstraints(
            allowed_endpoints={"api.openai.com"},
            denied_endpoints={"*"},
        )
        # Explicitly allowed endpoint passes
        allowed, _ = constraints.check_connection("api.openai.com")
        self.assertTrue(allowed)
        # Other endpoints blocked
        allowed, _ = constraints.check_connection("evil.example.com")
        self.assertFalse(allowed)

    def test_no_restrictions(self):
        constraints = NetworkConstraints()
        allowed, _ = constraints.check_connection("any.example.com")
        self.assertTrue(allowed)

    def test_endpoint_not_in_allowlist(self):
        constraints = NetworkConstraints(
            allowed_endpoints={"api.openai.com"},
        )
        allowed, reason = constraints.check_connection("other.example.com")
        self.assertFalse(allowed)
        self.assertIn("not in allowed", reason.lower())


class TestToolConstraints(unittest.TestCase):
    """Test ToolConstraints behavior."""

    def test_allowed_tool(self):
        constraints = ToolConstraints(allowed_tools={"hdf5_reader", "csv_parser"})
        allowed, _ = constraints.check_invocation("hdf5_reader")
        self.assertTrue(allowed)

    def test_denied_tool(self):
        constraints = ToolConstraints(denied_tools={"rm", "dd"})
        allowed, reason = constraints.check_invocation("rm")
        self.assertFalse(allowed)
        self.assertIn("denied", reason.lower())

    def test_tool_not_in_allowlist(self):
        constraints = ToolConstraints(allowed_tools={"hdf5_reader"})
        allowed, reason = constraints.check_invocation("unknown_tool")
        self.assertFalse(allowed)
        self.assertIn("not in allowed", reason.lower())

    def test_no_restrictions(self):
        constraints = ToolConstraints()
        allowed, _ = constraints.check_invocation("any_tool")
        self.assertTrue(allowed)


class TestConstraintProfile(unittest.TestCase):
    """Test ConstraintProfile serialization and YAML parsing."""

    def test_to_dict_roundtrip(self):
        profile = ConstraintProfile(
            agent_id="agent1",
            user_id="user1",
            project_id="genomics",
            session_id="sess_001",
            data_access=DataAccessConstraints(
                allowed_paths={"/projects/genomics/*"},
            ),
            network=NetworkConstraints(
                allowed_endpoints={"api.openai.com"},
            ),
            created_at=1700000000.0,
        )
        data = profile.to_dict()
        restored = ConstraintProfile.from_dict(data)
        self.assertEqual(profile.agent_id, restored.agent_id)
        self.assertEqual(profile.data_access.allowed_paths, restored.data_access.allowed_paths)

    def test_from_yaml(self):
        yaml_content = """
agent_id: agent1
user_id: user1
project_id: genomics
session_id: sess_001
data_access:
  allowed_paths:
    - /projects/genomics/*
  denied_paths:
    - /projects/finance/*
network:
  allowed_endpoints:
    - api.openai.com
tools:
  allowed_tools:
    - hdf5_reader
"""
        profile = ConstraintProfile.from_yaml(yaml_content)
        self.assertEqual(profile.agent_id, "agent1")
        self.assertIn("/projects/genomics/*", profile.data_access.allowed_paths)
        self.assertIn("api.openai.com", profile.network.allowed_endpoints)

    def test_to_yaml(self):
        profile = ConstraintProfile(
            agent_id="agent1",
            user_id="user1",
            project_id="genomics",
            session_id="sess_001",
        )
        yaml_str = profile.to_yaml()
        self.assertIn("agent_id: agent1", yaml_str)
        self.assertIn("project_id: genomics", yaml_str)


if __name__ == "__main__":
    unittest.main()

class TestConstraintManager(unittest.TestCase):
    """Test profile derivation, compilation, and signing."""

    def setUp(self):
        self.manager = ConstraintManager(signing_key="manager-key")

    def test_sign_profile_and_verify_binding(self):
        profile = ConstraintProfile(
            agent_id="agent1",
            user_id="user1",
            project_id="proj1",
            session_id="sess1",
            slurm_job_id="job_001",
        )
        self.manager.sign_profile(profile)
        self.assertTrue(profile.verify_signature("manager-key"))
        self.assertTrue(profile.verify_binding("job_001"))
        self.assertIn("binding", profile.compiled_policy)

    def test_from_template(self):
        profile = self.manager.from_template(
            PolicyTemplate.SIMULATION_STEERING,
            agent_id="agent1",
            user_id="user1",
            project_id="proj1",
            session_id="sess1",
            slurm_job_id="job_001",
        )
        self.assertEqual(profile.derivation_mode, DerivationMode.TEMPLATE)
        self.assertEqual(profile.template_name, PolicyTemplate.SIMULATION_STEERING.value)
        self.assertIn("sbatch", profile.tools.allowed_tools)
        self.assertTrue(profile.verify_signature("manager-key"))

    def test_infer_from_task(self):
        profile = self.manager.infer_from_task(
            agent_id="agent1",
            user_id="user1",
            project_id="proj1",
            session_id="sess1",
            slurm_job_id="job_001",
            task_description="Train a GPU model and write checkpoints",
        )
        self.assertEqual(profile.derivation_mode, DerivationMode.TASK_INFERENCE)
        self.assertEqual(profile.template_name, PolicyTemplate.ML_TRAINING.value)
        self.assertGreater(len(profile.inferred_rationale), 0)



if __name__ == "__main__":
    unittest.main()
