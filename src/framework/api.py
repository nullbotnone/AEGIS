"""REST API for AEGIS framework integration.

Provides HTTP endpoints for managing agents, querying status,
and reviewing audit logs. Uses only Python standard library (http.server).
"""

from __future__ import annotations

import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs

from .policy_engine import PolicyEngine

logger = logging.getLogger(__name__)


class AegisAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the AEGIS REST API."""

    # Set by the server at startup
    policy_engine: PolicyEngine = None  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default request logging."""
        logger.debug(format % args)

    def _send_json(self, status: int, data: Any) -> None:
        """Send a JSON response.

        Args:
            status: HTTP status code.
            data: Data to serialize as JSON.
        """
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        """Send an error response.

        Args:
            status: HTTP status code.
            message: Error message.
        """
        self._send_json(status, {"error": message})

    def _read_body(self) -> dict:
        """Read and parse JSON request body.

        Returns:
            Parsed JSON dictionary.
        """
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length)
        return json.loads(body)

    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        if path == "/status":
            self._handle_get_status()
        elif path == "/agents":
            self._handle_list_agents()
        elif path.startswith("/agents/") and path.endswith("/status"):
            agent_id = path.split("/")[2]
            self._handle_get_agent_status(agent_id)
        elif path.startswith("/agents/") and path.endswith("/audit"):
            agent_id = path.split("/")[2]
            self._handle_get_agent_audit(agent_id)
        elif path == "/audit":
            self._handle_get_audit_summary()
        elif path == "/audit/verify":
            self._handle_verify_audit()
        else:
            self._send_error(404, f"Not found: {self.path}")

    def do_POST(self) -> None:
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/agents/register":
            self._handle_register_agent()
        elif path.startswith("/agents/") and path.endswith("/actions"):
            agent_id = path.split("/")[2]
            self._handle_record_action(agent_id)
        elif path.startswith("/agents/") and path.endswith("/release"):
            agent_id = path.split("/")[2]
            self._handle_release_agent(agent_id)
        else:
            self._send_error(404, f"Not found: {self.path}")

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/agents/"):
            agent_id = path.split("/")[2]
            self._handle_unregister_agent(agent_id)
        else:
            self._send_error(404, f"Not found: {self.path}")

    # --- Handlers ---

    def _handle_get_status(self) -> None:
        """Get overall AEGIS system status."""
        self._send_json(200, self.policy_engine.get_system_status())

    def _handle_list_agents(self) -> None:
        """List all monitored agents."""
        agents = []
        for agent_id in self.policy_engine.monitored_agents:
            agents.append(self.policy_engine.get_agent_status(agent_id))
        self._send_json(200, {"agents": agents})

    def _handle_get_agent_status(self, agent_id: str) -> None:
        """Get status of a specific agent."""
        status = self.policy_engine.get_agent_status(agent_id)
        if not status["is_monitored"]:
            self._send_error(404, f"Agent {agent_id} not found")
            return
        self._send_json(200, status)

    def _handle_get_agent_audit(self, agent_id: str) -> None:
        """Get audit history for a specific agent."""
        history = self.policy_engine.audit.replay(agent_id)
        self._send_json(200, {"agent_id": agent_id, "history": history})

    def _handle_get_audit_summary(self) -> None:
        """Get audit ledger summary."""
        self._send_json(200, self.policy_engine.audit.get_summary())

    def _handle_verify_audit(self) -> None:
        """Verify audit ledger integrity."""
        is_valid, invalid_index = self.policy_engine.audit.verify_integrity()
        self._send_json(200, {
            "valid": is_valid,
            "first_invalid_index": invalid_index,
            "total_entries": len(self.policy_engine.audit),
        })

    def _handle_register_agent(self) -> None:
        """Register a new agent for attestation."""
        from .constraints import ConstraintProfile

        body = self._read_body()
        try:
            constraints = ConstraintProfile.from_dict(body)
        except (KeyError, TypeError) as e:
            self._send_error(400, f"Invalid constraint profile: {e}")
            return

        agent_id = body.get("agent_id", constraints.agent_id)
        user_id = body.get("user_id", constraints.user_id)
        project_id = body.get("project_id", constraints.project_id)

        monitor = self.policy_engine.register_agent(
            agent_id, user_id, project_id, constraints
        )
        self._send_json(201, {
            "agent_id": agent_id,
            "session_id": monitor.session_id,
            "status": "registered",
        })

    def _handle_unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent."""
        if agent_id not in self.policy_engine.monitored_agents:
            self._send_error(404, f"Agent {agent_id} not found")
            return
        self.policy_engine.unregister_agent(agent_id)
        self._send_json(200, {"agent_id": agent_id, "status": "unregistered"})

    def _handle_record_action(self, agent_id: str) -> None:
        """Record an action for an agent."""
        from .attestation import ActionType, AgentAction

        if agent_id not in self.policy_engine.monitored_agents:
            self._send_error(404, f"Agent {agent_id} not found")
            return

        body = self._read_body()
        try:
            action_type = ActionType(body["action_type"])
        except (KeyError, ValueError) as e:
            self._send_error(400, f"Invalid action type: {e}")
            return

        import time
        action = AgentAction(
            timestamp=time.time(),
            action_type=action_type,
            details=body.get("details", {}),
        )
        self.policy_engine.attestation_engine.record_action(agent_id, action)
        self._send_json(200, {"status": "recorded"})

    def _handle_release_agent(self, agent_id: str) -> None:
        """Release an agent from containment."""
        self.policy_engine.containment.release(agent_id)
        self._send_json(200, {"agent_id": agent_id, "status": "released"})


def create_api_server(
    policy_engine: PolicyEngine,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> HTTPServer:
    """Create an HTTP server for the AEGIS REST API.

    Args:
        policy_engine: The PolicyEngine instance to serve.
        host: Bind address.
        port: Bind port.

    Returns:
        An HTTPServer instance (call .serve_forever() to start).
    """
    AegisAPIHandler.policy_engine = policy_engine
    server = HTTPServer((host, port), AegisAPIHandler)
    logger.info(f"AEGIS API server listening on {host}:{port}")
    return server
