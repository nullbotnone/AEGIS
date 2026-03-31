#!/usr/bin/env python3
"""Stateful verifier daemon for real-cluster AEGIS deployment.

This service wraps the framework policy verifier in a long-running process,
keeps profiles and audit state in memory, and exposes a small JSON-over-socket
control plane suitable for Slurm hooks and bootstrap automation.

The repository also ships ``proto/aegis.proto`` as the intended gRPC contract.
This daemon is the concrete no-extra-dependency bootstrap path.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from src.common.logger import get_logger
except ImportError:
    import logging

    def get_logger(name: str) -> logging.Logger:
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(name)

from src.defense.slurm_integration import AEGISContainmentEnforcer
from src.framework.attestation import ActionType, AgentAction, AttestationEvidence
from src.framework.constraints import ConstraintManager, ConstraintProfile
from src.framework.verifier import PolicyVerifier, VerificationResult

logger = get_logger("aegis.verifierd")
DEFAULT_SOCKET_PATH = "/run/aegis/verifier.sock"
DEFAULT_TCP_PORT = 50051


@dataclass
class VerifierServiceConfig:
    socket_path: Optional[str] = DEFAULT_SOCKET_PATH
    listen_host: Optional[str] = None
    listen_port: int = DEFAULT_TCP_PORT
    profiles_dir: str = "/var/lib/aegis/verifier/profiles"
    audit_dir: str = "/var/log/aegis/verifier"
    slurm_url: str = "http://localhost:8080"
    slurm_user: str = "root"
    correlation_window_seconds: int = 30
    challenge_ttl_seconds: int = 5
    profile_signing_key: str = "constraint-manager"
    evidence_signing_key: Optional[str] = None

    @classmethod
    def load(cls, path: Optional[str]) -> "VerifierServiceConfig":
        if not path:
            return cls()
        config_path = Path(path)
        if not config_path.exists():
            return cls()
        data = json.loads(config_path.read_text(encoding="utf-8"))
        return cls(**data)


class VerifierRuntime:
    """Stateful verifier runtime used by the daemon."""

    def __init__(self, config: VerifierServiceConfig):
        self.config = config
        self.constraint_manager = ConstraintManager(signing_key=config.profile_signing_key)
        self.verifier = PolicyVerifier(
            correlation_window_seconds=config.correlation_window_seconds,
            challenge_ttl_seconds=config.challenge_ttl_seconds,
            profile_signing_key=config.profile_signing_key,
            evidence_signing_key=config.evidence_signing_key,
        )
        self.containment = AEGISContainmentEnforcer(
            slurm_url=config.slurm_url,
            slurm_user=config.slurm_user,
        )
        self.profiles_dir = Path(config.profiles_dir)
        self.audit_dir = Path(config.audit_dir)
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log_path = self.audit_dir / "audit.jsonl"
        self.lock = threading.RLock()
        self._load_existing_profiles()

    @staticmethod
    def _safe_label(value: str) -> str:
        return value.replace("/", "_") if value else "unbound"

    def _profile_filename(self, profile: ConstraintProfile) -> Path:
        label = "__".join(
            [
                self._safe_label(profile.agent_id),
                self._safe_label(profile.session_id),
                self._safe_label(profile.slurm_job_id),
            ]
        )
        return self.profiles_dir / f"{label}.yaml"

    def _append_audit(self, entry_type: str, agent_id: str, data: Dict[str, Any]) -> None:
        entry = self.verifier.record_audit(entry_type, agent_id, data)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(entry), sort_keys=True) + "\n")

    def _load_existing_profiles(self) -> None:
        for path in sorted(self.profiles_dir.glob("*.yaml")):
            try:
                profile = ConstraintProfile.from_yaml(path.read_text(encoding="utf-8"))
                self.constraint_manager.compile_profile(profile)
                self.verifier.register_agent(profile)
            except Exception as exc:  # pragma: no cover
                logger.warning("Skipping invalid profile %s: %s", path, exc)

    def health(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "status": "ok",
                "profiles": len(self.verifier.constraint_profiles),
                "audit_entries": len(self.verifier.audit),
                "pending_challenges": len(self.verifier.pending_challenges),
                "tracked_paths": len(self.verifier.shared_access_graph),
            }

    def register_profile_from_file(self, profile_path: str) -> Dict[str, Any]:
        profile = ConstraintProfile.from_yaml(Path(profile_path).read_text(encoding="utf-8"))
        return self.register_profile(profile)

    def register_profile(self, profile: ConstraintProfile) -> Dict[str, Any]:
        with self.lock:
            self.constraint_manager.compile_profile(profile)
            if not profile.signature:
                self.constraint_manager.sign_profile(profile)
            self.verifier.register_agent(profile)
            self._profile_filename(profile).write_text(profile.to_yaml(), encoding="utf-8")
            self._append_audit(
                "registration",
                profile.agent_id,
                {
                    "session_id": profile.session_id,
                    "slurm_job_id": profile.slurm_job_id,
                    "profile_hash": profile.profile_hash(),
                },
            )
            return {
                "status": "registered",
                "agent_id": profile.agent_id,
                "session_id": profile.session_id,
                "slurm_job_id": profile.slurm_job_id,
            }

    @staticmethod
    def _action_type(raw_value: str) -> ActionType:
        aliases = {
            "FILE_OPEN": ActionType.FILE_OPEN,
            "FILE_READ": ActionType.FILE_READ,
            "FILE_WRITE": ActionType.FILE_WRITE,
            "NETWORK_CONNECTION": ActionType.NETWORK_CONNECTION,
            "NETWORK_SEND": ActionType.NETWORK_SEND,
            "TOOL_INVOCATION": ActionType.TOOL_INVOCATION,
            "LLM_API_CALL": ActionType.LLM_API_CALL,
            "PROCESS_SPAWN": ActionType.PROCESS_SPAWN,
        }
        return aliases.get(raw_value, ActionType(raw_value))

    def evidence_from_dict(self, evidence: Dict[str, Any]) -> AttestationEvidence:
        now = time.time()
        actions = [
            AgentAction(
                timestamp=float(action["timestamp"]),
                action_type=self._action_type(str(action["action_type"])),
                details=dict(action.get("details", {})),
                pid=action.get("pid"),
                syscall=action.get("syscall"),
            )
            for action in evidence.get("actions", [])
        ]
        return AttestationEvidence(
            agent_id=str(evidence["agent_id"]),
            session_id=str(evidence["session_id"]),
            node_id=str(evidence.get("node_id", "unknown-node")),
            slurm_job_id=str(evidence.get("slurm_job_id") or evidence.get("job_id") or ""),
            timestamp=float(evidence.get("timestamp", now)),
            interval_start=float(evidence.get("interval_start", now)),
            interval_end=float(evidence.get("interval_end", now)),
            actions=actions,
            total_file_read_mb=float(evidence.get("total_file_read_mb", 0.0)),
            total_file_write_mb=float(evidence.get("total_file_write_mb", 0.0)),
            total_network_egress_mb=float(evidence.get("total_network_egress_mb", 0.0)),
            network_connection_count=int(
                evidence.get("network_connection_count", evidence.get("connection_count", 0))
            ),
            process_state_hash=evidence.get("process_state_hash"),
            monitored_syscalls=list(
                evidence.get(
                    "monitored_syscalls",
                    [
                        "sys_enter_openat",
                        "sys_enter_read",
                        "sys_enter_write",
                        "sys_enter_connect",
                        "sys_enter_sendto",
                        "sys_enter_execve",
                    ],
                )
            ),
            transport=str(evidence.get("transport", "json+tcp-bootstrap")),
            challenge_id=evidence.get("challenge_id"),
            challenge_nonce=evidence.get("challenge_nonce"),
            signature=evidence.get("signature"),
        )

    @staticmethod
    def _serialize_result(result: VerificationResult) -> Dict[str, Any]:
        return {
            "agent_id": result.agent_id,
            "session_id": result.session_id,
            "slurm_job_id": result.slurm_job_id,
            "timestamp": result.timestamp,
            "verdict": result.verdict.value,
            "challenge_id": result.challenge_id,
            "challenge_satisfied": result.challenge_satisfied,
            "access_graph_alerts": list(result.access_graph_alerts),
            "violations": [
                {
                    "constraint_type": violation.constraint_type,
                    "description": violation.description,
                    "severity": violation.severity.value,
                    "evidence": violation.evidence,
                    "timestamp": violation.timestamp,
                    "code": violation.code,
                }
                for violation in result.violations
            ],
        }

    def submit_evidence_dict(self, evidence_dict: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            evidence = self.evidence_from_dict(evidence_dict)
            self._append_audit(
                "attestation",
                evidence.agent_id,
                {
                    "session_id": evidence.session_id,
                    "slurm_job_id": evidence.slurm_job_id,
                    "node_id": evidence.node_id,
                    "evidence_hash": evidence.compute_hash(),
                    "actions_count": len(evidence.actions),
                },
            )
            result = self.verifier.verify(evidence)
            serialized = self._serialize_result(result)
            self._append_audit("verification", evidence.agent_id, serialized)
            if result.is_violation() and result.slurm_job_id:
                severity = result.verdict.value.replace("violation_", "")
                reason = "; ".join(violation.description for violation in result.violations[:3])
                success = self.containment.escalate(result.slurm_job_id, severity, reason)
                self._append_audit(
                    "containment",
                    result.agent_id,
                    {
                        "slurm_job_id": result.slurm_job_id,
                        "verdict": result.verdict.value,
                        "success": success,
                        "reason": reason,
                    },
                )
            return serialized

    def close_session(
        self,
        *,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self.lock:
            removed: List[str] = []
            for candidate in list(self.verifier.constraint_profiles.values()):
                if job_id and candidate.slurm_job_id != job_id:
                    continue
                if agent_id and candidate.agent_id != agent_id:
                    continue
                if session_id and candidate.session_id != session_id:
                    continue
                self.verifier.unregister_agent(candidate.agent_id)
                profile_path = self._profile_filename(candidate)
                if profile_path.exists():
                    profile_path.unlink()
                removed.append(candidate.agent_id)
                self._append_audit(
                    "session_close",
                    candidate.agent_id,
                    {
                        "session_id": candidate.session_id,
                        "slurm_job_id": candidate.slurm_job_id,
                    },
                )
            return {"status": "closed", "agents": removed}

    def dump_audit(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        with self.lock:
            if agent_id:
                return {"entries": self.verifier.audit.replay(agent_id)}
            return {
                "summary": self.verifier.audit.get_summary(),
                "entries": [asdict(entry) for entry in self.verifier.audit.entries],
            }

    def dispatch(self, request: Dict[str, Any]) -> Dict[str, Any]:
        action = request.get("action")
        payload = dict(request.get("payload", {}))
        if action == "health":
            return {"status": "ok", "payload": self.health()}
        if action == "register_profile":
            if "profile_path" in payload:
                return {
                    "status": "ok",
                    "payload": self.register_profile_from_file(payload["profile_path"]),
                }
            if "profile" in payload:
                return {
                    "status": "ok",
                    "payload": self.register_profile(ConstraintProfile.from_dict(payload["profile"])),
                }
            raise ValueError("register_profile requires profile_path or profile")
        if action == "submit_evidence":
            if "evidence_path" in payload:
                evidence_dict = json.loads(Path(payload["evidence_path"]).read_text(encoding="utf-8"))
            elif "evidence" in payload:
                evidence_dict = dict(payload["evidence"])
            else:
                raise ValueError("submit_evidence requires evidence_path or evidence")
            return {"status": "ok", "payload": self.submit_evidence_dict(evidence_dict)}
        if action == "close_session":
            return {
                "status": "ok",
                "payload": self.close_session(
                    agent_id=payload.get("agent_id"),
                    session_id=payload.get("session_id"),
                    job_id=payload.get("job_id") or payload.get("slurm_job_id"),
                ),
            }
        if action == "dump_audit":
            return {"status": "ok", "payload": self.dump_audit(payload.get("agent_id"))}
        raise ValueError(f"unknown action: {action}")


class _JsonLineRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline().decode("utf-8")
        if not raw:
            return
        try:
            request = json.loads(raw)
            response = self.server.runtime.dispatch(request)  # type: ignore[attr-defined]
        except Exception as exc:  # pragma: no cover
            response = {"status": "error", "error": str(exc)}
        self.wfile.write((json.dumps(response, sort_keys=True) + "\n").encode("utf-8"))


class VerifierUnixServer(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True

    def __init__(self, socket_path: str, runtime: VerifierRuntime):
        self.runtime = runtime
        super().__init__(socket_path, _JsonLineRequestHandler)


class VerifierTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, host: str, port: int, runtime: VerifierRuntime):
        self.runtime = runtime
        super().__init__((host, port), _JsonLineRequestHandler)


def _read_json_response(client: socket.socket) -> Dict[str, Any]:
    chunks: List[bytes] = []
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    if not chunks:
        raise RuntimeError("empty response from verifier daemon")
    return json.loads(b"".join(chunks).decode("utf-8").strip())


def send_request(
    request: Dict[str, Any],
    *,
    socket_path: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    if host:
        with socket.create_connection((host, port or DEFAULT_TCP_PORT), timeout=timeout) as client:
            client.sendall((json.dumps(request, sort_keys=True) + "\n").encode("utf-8"))
            return _read_json_response(client)
    if not socket_path:
        raise ValueError("socket_path is required when host is not provided")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(socket_path)
        client.sendall((json.dumps(request, sort_keys=True) + "\n").encode("utf-8"))
        return _read_json_response(client)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AEGIS verifier daemon")
    parser.add_argument("--config", default=None, help="Path to verifier JSON config")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run the stateful verifier daemon")
    serve.add_argument("--socket", default=None, help="Unix socket path override")
    serve.add_argument("--host", default=None, help="Optional TCP listen host")
    serve.add_argument("--port", type=int, default=None, help="Optional TCP listen port")

    for name, help_text in [
        ("health", "Check daemon health"),
        ("register-profile", "Register a profile with the daemon"),
        ("submit-evidence", "Submit an evidence JSON document"),
        ("close-session", "Close a registered session"),
        ("dump-audit", "Dump audit state from the daemon"),
    ]:
        subparser = subparsers.add_parser(name, help=help_text)
        subparser.add_argument("--socket", default=None, help="Unix socket path override")
        subparser.add_argument("--host", default=None, help="TCP host override")
        subparser.add_argument("--port", type=int, default=None, help="TCP port override")
        if name == "register-profile":
            subparser.add_argument("--profile", required=True, help="YAML profile path")
        elif name == "submit-evidence":
            subparser.add_argument("--evidence", required=True, help="Evidence JSON path")
        elif name == "close-session":
            subparser.add_argument("--agent-id")
            subparser.add_argument("--session-id")
            subparser.add_argument("--job-id")
        elif name == "dump-audit":
            subparser.add_argument("--agent-id")
    return parser


def _resolve_unix_socket(config: VerifierServiceConfig, override: Optional[str]) -> Optional[str]:
    return config.socket_path if override is None else override


def _resolve_tcp_host(config: VerifierServiceConfig, override: Optional[str]) -> Optional[str]:
    return config.listen_host if override is None else override


def _resolve_tcp_port(config: VerifierServiceConfig, override: Optional[int]) -> int:
    return config.listen_port if override is None else override


def _serve(runtime: VerifierRuntime, config: VerifierServiceConfig, args: argparse.Namespace) -> None:
    servers: List[socketserver.BaseServer] = []
    threads: List[threading.Thread] = []
    unix_socket = _resolve_unix_socket(config, args.socket)
    tcp_host = _resolve_tcp_host(config, args.host)
    tcp_port = _resolve_tcp_port(config, args.port)

    if unix_socket:
        socket_path = Path(unix_socket)
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        if socket_path.exists():
            socket_path.unlink()
        unix_server = VerifierUnixServer(str(socket_path), runtime)
        os.chmod(socket_path, 0o660)
        servers.append(unix_server)
        threads.append(threading.Thread(target=unix_server.serve_forever, daemon=True))
        logger.info("AEGIS verifier daemon listening on unix:%s", socket_path)

    if tcp_host:
        tcp_server = VerifierTCPServer(tcp_host, tcp_port, runtime)
        servers.append(tcp_server)
        threads.append(threading.Thread(target=tcp_server.serve_forever, daemon=True))
        logger.info("AEGIS verifier daemon listening on tcp:%s:%s", tcp_host, tcp_port)

    if not servers:
        raise SystemExit("No verifier listener configured")

    for thread in threads:
        thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping verifier daemon")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        if unix_socket:
            socket_path = Path(unix_socket)
            if socket_path.exists():
                socket_path.unlink()


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    config = VerifierServiceConfig.load(args.config)

    if args.command == "serve":
        runtime = VerifierRuntime(config)
        _serve(runtime, config, args)
        return

    host = getattr(args, "host", None)
    socket_path = None if host else _resolve_unix_socket(config, getattr(args, "socket", None))
    port = _resolve_tcp_port(config, getattr(args, "port", None))

    if args.command == "health":
        request = {"action": "health", "payload": {}}
    elif args.command == "register-profile":
        request = {"action": "register_profile", "payload": {"profile_path": args.profile}}
    elif args.command == "submit-evidence":
        request = {"action": "submit_evidence", "payload": {"evidence_path": args.evidence}}
    elif args.command == "close-session":
        request = {
            "action": "close_session",
            "payload": {
                "agent_id": args.agent_id,
                "session_id": args.session_id,
                "job_id": args.job_id,
            },
        }
    else:
        request = {"action": "dump_audit", "payload": {"agent_id": args.agent_id}}

    print(
        json.dumps(
            send_request(request, socket_path=socket_path, host=host, port=port),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
