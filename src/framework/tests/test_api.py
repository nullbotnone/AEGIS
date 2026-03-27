"""Tests for the AEGIS framework REST API."""

from __future__ import annotations

import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from src.framework.api import create_api_server
from src.framework.constraints import ConstraintProfile
from src.framework.policy_engine import PolicyEngine


class TestAegisAPI(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine(attestation_interval=1)
        self.server = create_api_server(self.engine, host="127.0.0.1", port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_register_invalid_json_returns_400(self) -> None:
        request = Request(
            f"{self.base_url}/agents/register",
            data=b"{",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(HTTPError) as exc:
            urlopen(request)
        self.assertEqual(exc.exception.code, 400)
        payload = json.loads(exc.exception.read().decode())
        self.assertIn("Invalid JSON body", payload["error"])

    def test_delete_nested_agent_path_returns_404(self) -> None:
        constraints = ConstraintProfile(
            agent_id="agent1",
            user_id="user1",
            project_id="proj1",
            session_id="sess1",
        )
        self.engine.register_agent("agent1", "user1", "proj1", constraints)

        request = Request(f"{self.base_url}/agents/agent1/status", method="DELETE")
        with self.assertRaises(HTTPError) as exc:
            urlopen(request)
        self.assertEqual(exc.exception.code, 404)
        self.assertIn("agent1", self.engine.monitored_agents)
