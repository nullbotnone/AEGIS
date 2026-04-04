#!/usr/bin/env python3
"""AEGIS eBPF Collector.

Reads events from the eBPF ring buffer and produces attestation evidence.
This is the userspace bridge between the kernel eBPF probe and the
AEGIS attestation framework.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import logging
import os
import socket
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def _fallback_logger(name: str) -> logging.Logger:
    logging.basicConfig(level=logging.INFO)
    return logging.getLogger(name)


from src.deployment.collector.job_registry import JobRegistration, JobRegistry
from src.deployment.core.attestation import (
    ActionType as FrameworkActionType,
    AgentAction as FrameworkAgentAction,
    AttestationEvidence as FrameworkEvidence,
)

get_logger = _fallback_logger

logger = get_logger("aegis.bpf_collector")

ACTION_FILE_READ = 1
ACTION_FILE_WRITE = 2
ACTION_NETWORK_CONN = 3
ACTION_TOOL_INVOKE = 4

ACTION_NAMES = {
    ACTION_FILE_READ: "FILE_READ",
    ACTION_FILE_WRITE: "FILE_WRITE",
    ACTION_NETWORK_CONN: "NETWORK_CONN",
    ACTION_TOOL_INVOKE: "TOOL_INVOKE",
}

_JOB_ID_PATTERNS = [
    re.compile(r"(?:^|/)job_(\d+)(?:/|$)"),
    re.compile(r"(?:^|/)job/(\d+)(?:/|$)"),
    re.compile(r"slurm(?:/|-)job(?:_|/)?(\d+)"),
]


@dataclass
class AEGISEvent:
    """Event from eBPF probe."""

    timestamp: int
    pid: int
    tid: int
    uid: int
    action_type: int
    size: int
    path: str
    endpoint: str
    endpoint_port: int


@dataclass
class AgentState:
    """Per-agent state tracked by the collector."""

    pid: int
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    job_id: Optional[str] = None
    registration_source: Optional[str] = None
    file_read_bytes: int = 0
    file_write_bytes: int = 0
    network_egress_bytes: int = 0
    connection_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    actions: List[AEGISEvent] = field(default_factory=list)


class _AegisConfig(ctypes.Structure):
    _fields_ = [
        ("sample_rate", ctypes.c_uint64),
        ("enable_network", ctypes.c_uint64),
        ("enable_file", ctypes.c_uint64),
        ("enable_exec", ctypes.c_uint64),
        ("monitor_uid", ctypes.c_uint64),
    ]


class _LibbpfBackend:
    """Minimal ctypes wrapper around system libbpf."""

    _sample_cb_type = ctypes.CFUNCTYPE(
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    )

    def __init__(self, bpf_obj_path: str):
        self.bpf_obj_path = _resolve_bpf_object_path(bpf_obj_path)
        self.lib = self._load_libbpf()
        self._configure_symbols()
        self.obj: Optional[ctypes.c_void_p] = None
        self.ring_buffer: Optional[ctypes.c_void_p] = None
        self.links: List[ctypes.c_void_p] = []
        self._sample_cb = None

    def _load_libbpf(self) -> ctypes.CDLL:
        candidates = []
        detected = ctypes.util.find_library("bpf")
        if detected:
            candidates.append(detected)
        candidates.extend([
            "/lib64/libbpf.so.1",
            "/usr/lib64/libbpf.so.1",
            "/lib/x86_64-linux-gnu/libbpf.so.1",
            "/usr/lib/x86_64-linux-gnu/libbpf.so.1",
        ])

        for candidate in candidates:
            try:
                return ctypes.CDLL(candidate, use_errno=True)
            except OSError:
                continue

        raise RuntimeError(
            "system libbpf not found; install the libbpf runtime package instead of "
            "pip-installing a Python wrapper"
        )

    def _configure_symbols(self) -> None:
        self.lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        self.lib.bpf_object__open_file.restype = ctypes.c_void_p

        self.lib.bpf_object__load.argtypes = [ctypes.c_void_p]
        self.lib.bpf_object__load.restype = ctypes.c_int

        self.lib.bpf_object__close.argtypes = [ctypes.c_void_p]
        self.lib.bpf_object__close.restype = None

        self.lib.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.bpf_object__find_map_by_name.restype = ctypes.c_void_p

        self.lib.bpf_map__fd.argtypes = [ctypes.c_void_p]
        self.lib.bpf_map__fd.restype = ctypes.c_int

        self.lib.bpf_map_update_elem.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulonglong,
        ]
        self.lib.bpf_map_update_elem.restype = ctypes.c_int

        self.lib.bpf_object__next_program.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.lib.bpf_object__next_program.restype = ctypes.c_void_p

        self.lib.bpf_program__name.argtypes = [ctypes.c_void_p]
        self.lib.bpf_program__name.restype = ctypes.c_char_p

        self.lib.bpf_program__attach.argtypes = [ctypes.c_void_p]
        self.lib.bpf_program__attach.restype = ctypes.c_void_p

        self.lib.bpf_link__destroy.argtypes = [ctypes.c_void_p]
        self.lib.bpf_link__destroy.restype = None

        self.lib.ring_buffer__new.argtypes = [
            ctypes.c_int,
            self._sample_cb_type,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.lib.ring_buffer__new.restype = ctypes.c_void_p

        self.lib.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.ring_buffer__poll.restype = ctypes.c_int

        self.lib.ring_buffer__free.argtypes = [ctypes.c_void_p]
        self.lib.ring_buffer__free.restype = None

        self.lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
        self.lib.libbpf_get_error.restype = ctypes.c_long

    def _check_ptr(self, ptr: Optional[int], action: str) -> ctypes.c_void_p:
        if not ptr:
            raise RuntimeError(f"{action} failed: null pointer")
        value = ctypes.c_void_p(ptr)
        err = int(self.lib.libbpf_get_error(value))
        if err != 0:
            detail = os.strerror(-err) if err < 0 else str(err)
            raise RuntimeError(f"{action} failed: {detail}")
        return value

    def _map_fd(self, name: str) -> int:
        if self.obj is None:
            raise RuntimeError("BPF object is not loaded")
        map_ptr = self._check_ptr(
            self.lib.bpf_object__find_map_by_name(self.obj, name.encode()),
            f"find map {name}",
        )
        fd = self.lib.bpf_map__fd(map_ptr)
        if fd < 0:
            raise RuntimeError(f"failed to get fd for map {name}: {fd}")
        return fd

    def _attach_programs(self) -> None:
        if self.obj is None:
            raise RuntimeError("BPF object is not loaded")
        prev = ctypes.c_void_p()
        while True:
            prog = self.lib.bpf_object__next_program(self.obj, prev)
            if not prog:
                break
            name = self.lib.bpf_program__name(ctypes.c_void_p(prog))
            prog_name = name.decode() if name else "<unnamed>"
            link = self._check_ptr(
                self.lib.bpf_program__attach(ctypes.c_void_p(prog)),
                f"attach program {prog_name}",
            )
            self.links.append(link)
            prev = ctypes.c_void_p(prog)

    def open(self) -> None:
        self.obj = self._check_ptr(
            self.lib.bpf_object__open_file(self.bpf_obj_path.encode(), None),
            f"open {self.bpf_obj_path}",
        )
        rc = self.lib.bpf_object__load(self.obj)
        if rc != 0:
            detail = os.strerror(-rc) if rc < 0 else str(rc)
            raise RuntimeError(f"load BPF object failed: {detail}")
        self._attach_programs()

    def set_config(
        self,
        sample_rate: int,
        enable_network: bool = True,
        enable_file: bool = True,
        enable_exec: bool = True,
        monitor_uid: int = 0,
    ) -> None:
        key = ctypes.c_uint(0)
        config = _AegisConfig(
            sample_rate,
            int(enable_network),
            int(enable_file),
            int(enable_exec),
            monitor_uid,
        )
        rc = self.lib.bpf_map_update_elem(
            self._map_fd("aegis_config"),
            ctypes.byref(key),
            ctypes.byref(config),
            0,
        )
        if rc != 0:
            err = ctypes.get_errno()
            detail = os.strerror(err) if err else str(rc)
            raise RuntimeError(f"failed to update aegis_config map: {detail}")

    def open_ring_buffer(
        self,
        map_name: str,
        callback: Callable[[int, bytes, int], None],
    ) -> None:
        map_fd = self._map_fd(map_name)

        def _dispatch(_ctx: ctypes.c_void_p, data: ctypes.c_void_p, size: int) -> int:
            payload = ctypes.string_at(data, size)
            callback(0, payload, size)
            return 0

        self._sample_cb = self._sample_cb_type(_dispatch)
        self.ring_buffer = self._check_ptr(
            self.lib.ring_buffer__new(map_fd, self._sample_cb, None, None),
            f"create ring buffer for {map_name}",
        )

    def poll_ring_buffer(self, timeout_ms: int) -> int:
        if self.ring_buffer is None:
            raise RuntimeError("ring buffer is not initialized")
        return self.lib.ring_buffer__poll(self.ring_buffer, timeout_ms)

    def close(self) -> None:
        if self.ring_buffer is not None:
            self.lib.ring_buffer__free(self.ring_buffer)
            self.ring_buffer = None
        for link in self.links:
            self.lib.bpf_link__destroy(link)
        self.links.clear()
        if self.obj is not None:
            self.lib.bpf_object__close(self.obj)
            self.obj = None


class BPFCollector:
    """Main collector class managing the eBPF probe and per-job state."""

    def __init__(
        self,
        bpf_obj_path: Optional[str] = None,
        interval: float = 1.0,
        sample_rate: int = 1,
        registry_dir: str = "/run/aegis/collector/registrations",
        node_id: Optional[str] = None,
        signing_key: Optional[str] = None,
        verifier_socket: Optional[str] = None,
        verifier_host: Optional[str] = None,
        verifier_port: int = 50051,
        emit_dir: Optional[str] = None,
        submission_timeout: float = 5.0,
    ):
        self.bpf_obj_path = bpf_obj_path
        self.interval = interval
        self.sample_rate = sample_rate
        self.node_id = node_id or os.uname().nodename
        self.signing_key = signing_key or self.node_id
        self.verifier_socket = verifier_socket
        self.verifier_host = verifier_host
        self.verifier_port = verifier_port
        self.emit_dir = Path(emit_dir) if emit_dir else None
        self.submission_timeout = submission_timeout
        self.running = False
        self.agent_states: Dict[int, AgentState] = {}
        self.event_callbacks: List[Callable[[AEGISEvent], None]] = []
        self._backend: Optional[_LibbpfBackend] = None
        self.poll_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        self.registry = JobRegistry(registry_dir) if JobRegistry is not None else None

    def load(self) -> bool:
        try:
            if os.geteuid() != 0:
                logger.error("Must run as root to load eBPF programs")
                return False
            logger.info("Loading eBPF program from %s", self.bpf_obj_path)
            backend = _LibbpfBackend(self.bpf_obj_path)
            backend.open()
            backend.set_config(self.sample_rate)
            self._backend = backend
            logger.info("eBPF program loaded successfully")
            return True
        except Exception as exc:
            logger.error("Failed to load eBPF: %s", exc)
            return False

    def register_job(
        self,
        job_id: str,
        agent_id: str,
        session_id: str,
        *,
        uid: Optional[int] = None,
        cgroup_path: Optional[str] = None,
        profile_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Path]:
        if self.registry is None:
            return None
        registration = JobRegistration(
            job_id=job_id,
            agent_id=agent_id,
            session_id=session_id,
            uid=uid,
            cgroup_path=cgroup_path,
            profile_path=profile_path,
            metadata=dict(metadata or {}),
        )
        return self.registry.register(registration)

    def unregister_job(self, job_id: str) -> bool:
        if self.registry is None:
            return False
        with self.lock:
            for pid, state in list(self.agent_states.items()):
                if state.job_id == job_id:
                    state.registration_source = None
        return self.registry.unregister(job_id)

    def register_process(
        self,
        pid: int,
        *,
        agent_id: str,
        session_id: str,
        job_id: str,
        registration_source: str = "manual",
    ) -> None:
        with self.lock:
            state = self.agent_states.setdefault(pid, AgentState(pid=pid))
            state.agent_id = agent_id
            state.session_id = session_id
            state.job_id = job_id
            state.registration_source = registration_source

    def _parse_event(self, data: bytes) -> Optional[AEGISEvent]:
        event_size = 420
        if len(data) < event_size:
            logger.warning("Truncated event: %s bytes", len(data))
            return None
        timestamp, pid, tid, uid, action_type, size = struct.unpack("<QIIIIQ", data[:32])
        endpoint_port = struct.unpack("<I", data[416:420])[0]
        path = data[32:288].rstrip(b"\0").decode("utf-8", errors="replace")
        endpoint = data[288:416].rstrip(b"\0").decode("utf-8", errors="replace")
        return AEGISEvent(
            timestamp=timestamp,
            pid=pid,
            tid=tid,
            uid=uid,
            action_type=action_type,
            size=size,
            path=path,
            endpoint=endpoint,
            endpoint_port=endpoint_port,
        )

    def _infer_job_id_for_pid(self, pid: int) -> Optional[str]:
        cgroup_path = Path(f"/proc/{pid}/cgroup")
        if not cgroup_path.exists():
            return None
        try:
            content = cgroup_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        for pattern in _JOB_ID_PATTERNS:
            match = pattern.search(content)
            if match:
                return match.group(1)
        return None

    def _lookup_registration_for_pid(self, pid: int, uid: int) -> Tuple[Optional[JobRegistration], Optional[str]]:
        if self.registry is None:
            return None, None
        job_id = self._infer_job_id_for_pid(pid)
        if job_id:
            registration = self.registry.get(job_id)
            if registration is not None:
                return registration, f"cgroup:{job_id}"
        registrations = list(self.registry.list().values())
        uid_matches = [registration for registration in registrations if registration.uid == uid]
        if len(uid_matches) == 1:
            registration = uid_matches[0]
            return registration, f"uid:{uid}"
        return None, None

    def _bind_state_from_registry(self, pid: int, state: AgentState, uid: int) -> None:
        if state.agent_id and state.session_id and state.job_id:
            return
        registration, source = self._lookup_registration_for_pid(pid, uid)
        if registration is None:
            return
        state.agent_id = registration.agent_id
        state.session_id = registration.session_id
        state.job_id = registration.job_id
        state.registration_source = source

    def _process_event(self, cpu: int, data: bytes, size: int) -> None:
        try:
            event = self._parse_event(data)
            if not event:
                return
            with self.lock:
                if event.pid not in self.agent_states:
                    self.agent_states[event.pid] = AgentState(pid=event.pid)
                state = self.agent_states[event.pid]
                self._bind_state_from_registry(event.pid, state, event.uid)
                state.last_update = time.time()
                state.actions.append(event)
                if event.action_type == ACTION_FILE_READ:
                    state.file_read_bytes += max(event.size, 4096)
                elif event.action_type == ACTION_FILE_WRITE:
                    state.file_write_bytes += max(event.size, 4096)
                elif event.action_type == ACTION_NETWORK_CONN:
                    state.connection_count += 1
                    state.network_egress_bytes += max(event.size, 0)
            for callback in self.event_callbacks:
                try:
                    callback(event)
                except Exception as exc:
                    logger.error("Callback error: %s", exc)
        except Exception as exc:
            logger.error("Error processing event: %s", exc)

    def register_callback(self, callback: Callable[[AEGISEvent], None]) -> None:
        self.event_callbacks.append(callback)

    def start(self) -> bool:
        if not self._backend:
            logger.error("BPF not loaded")
            return False
        self.running = True
        self._backend.open_ring_buffer("aegis_events", self._process_event)
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()
        logger.info("Collector started on node %s", self.node_id)
        return True

    def _poll_loop(self) -> None:
        while self.running:
            try:
                if self._backend is None:
                    return
                rc = self._backend.poll_ring_buffer(timeout_ms=100)
                if rc < 0 and self.running:
                    logger.error("Poll error: %s", rc)
                    time.sleep(0.1)
            except Exception as exc:
                if self.running:
                    logger.error("Poll error: %s", exc)
                time.sleep(0.1)

    def stop(self) -> None:
        self.running = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=1)
        if self._backend is not None:
            self._backend.close()
            self._backend = None
        logger.info("Collector stopped")

    def get_agent_state(self, pid: int) -> Optional[AgentState]:
        with self.lock:
            return self.agent_states.get(pid)

    def get_all_states(self) -> Dict[int, AgentState]:
        with self.lock:
            return dict(self.agent_states)

    def _compute_process_hash(self, state: AgentState) -> str:
        payload = json.dumps(
            {
                "pid": state.pid,
                "agent_id": state.agent_id,
                "session_id": state.session_id,
                "job_id": state.job_id,
                "actions": [
                    {
                        "timestamp": event.timestamp,
                        "action_type": event.action_type,
                        "path": event.path,
                        "endpoint": event.endpoint,
                        "port": event.endpoint_port,
                    }
                    for event in state.actions
                ],
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _framework_action(self, event: AEGISEvent):
        if FrameworkAgentAction is None or FrameworkActionType is None:
            return None
        if event.action_type == ACTION_FILE_READ:
            action_type = FrameworkActionType.FILE_READ
            details = {"path": event.path, "size_mb": max(event.size, 4096) / (1024 * 1024)}
        elif event.action_type == ACTION_FILE_WRITE:
            action_type = FrameworkActionType.FILE_WRITE
            details = {"path": event.path, "size_mb": max(event.size, 4096) / (1024 * 1024)}
        elif event.action_type == ACTION_NETWORK_CONN:
            action_type = FrameworkActionType.NETWORK_CONNECTION
            details = {"endpoint": event.endpoint, "port": event.endpoint_port, "data_sent_mb": max(event.size, 0) / (1024 * 1024)}
        elif event.action_type == ACTION_TOOL_INVOKE:
            action_type = FrameworkActionType.TOOL_INVOCATION
            details = {"tool": event.path}
        else:
            return None
        return FrameworkAgentAction(
            timestamp=event.timestamp / 1e9,
            action_type=action_type,
            details=details,
            pid=event.pid,
        )

    def _transport_label(self) -> str:
        if self.verifier_host:
            return "json+tcp-bootstrap"
        if self.verifier_socket:
            return "json+unix-bootstrap"
        if self.emit_dir:
            return "json+spool"
        return "grpc+mTLS"

    def _read_response(self, client: socket.socket) -> Dict[str, Any]:
        chunks: List[bytes] = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        if not chunks:
            raise RuntimeError("empty response from verifier")
        return json.loads(b"".join(chunks).decode("utf-8").strip())

    def _send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        payload = (json.dumps(request, sort_keys=True) + "\n").encode("utf-8")
        if self.verifier_host:
            with socket.create_connection((self.verifier_host, self.verifier_port), timeout=self.submission_timeout) as client:
                client.sendall(payload)
                return self._read_response(client)
        if self.verifier_socket:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.submission_timeout)
                client.connect(self.verifier_socket)
                client.sendall(payload)
                return self._read_response(client)
        raise RuntimeError("no verifier endpoint configured")

    def _spool_evidence(self, payload: Dict[str, Any]) -> Path:
        if self.emit_dir is None:
            raise RuntimeError("no emit_dir configured")
        self.emit_dir.mkdir(parents=True, exist_ok=True)
        job_id = payload.get("slurm_job_id") or payload.get("job_id") or "unbound"
        filename = f"{int(time.time() * 1000)}-{job_id}-{payload['pid']}.json"
        path = self.emit_dir / filename
        path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return path

    def submit_evidence(self, pid: int, clear_actions: bool = True) -> bool:
        payload = self.generate_evidence(pid, clear_actions=False)
        if not payload:
            return False
        if not payload.get("slurm_job_id") or payload["agent_id"].startswith("pid-"):
            return False
        try:
            if self.verifier_host or self.verifier_socket:
                response = self._send_request({
                    "action": "submit_evidence",
                    "payload": {"evidence": payload},
                })
                if response.get("status") != "ok":
                    logger.error("Verifier rejected evidence for pid %s: %s", pid, response)
                    return False
            elif self.emit_dir is not None:
                path = self._spool_evidence(payload)
                logger.debug("Spooled evidence for pid %s to %s", pid, path)
            else:
                return False
        except Exception as exc:
            logger.error("Failed to submit evidence for pid %s: %s", pid, exc)
            return False
        if clear_actions:
            self.clear_actions(pid)
        return True

    def flush_evidence(self) -> int:
        with self.lock:
            candidate_pids = [
                pid
                for pid, state in self.agent_states.items()
                if state.actions and state.agent_id and state.session_id and state.job_id
            ]
        submitted = 0
        for pid in candidate_pids:
            if self.submit_evidence(pid, clear_actions=True):
                submitted += 1
        return submitted

    def generate_evidence(self, pid: int, clear_actions: bool = False) -> Optional[dict]:
        with self.lock:
            state = self.agent_states.get(pid)
            if not state:
                return None
            events = list(state.actions)
        if FrameworkEvidence is not None:
            actions = [action for event in events if (action := self._framework_action(event)) is not None]
            evidence = FrameworkEvidence(
                agent_id=state.agent_id or f"pid-{pid}",
                session_id=state.session_id or f"session-{pid}",
                node_id=self.node_id,
                slurm_job_id=state.job_id or "",
                timestamp=time.time(),
                interval_start=state.first_seen,
                interval_end=time.time(),
                actions=actions,
                total_file_read_mb=state.file_read_bytes / (1024 * 1024),
                total_file_write_mb=state.file_write_bytes / (1024 * 1024),
                total_network_egress_mb=state.network_egress_bytes / (1024 * 1024),
                network_connection_count=state.connection_count,
                process_state_hash=self._compute_process_hash(state),
                transport=self._transport_label(),
            )
            evidence.sign(self.signing_key)
            payload = {
                "agent_id": evidence.agent_id,
                "session_id": evidence.session_id,
                "node_id": evidence.node_id,
                "job_id": evidence.slurm_job_id,
                "slurm_job_id": evidence.slurm_job_id,
                "pid": pid,
                "timestamp": evidence.timestamp,
                "interval_start": evidence.interval_start,
                "interval_end": evidence.interval_end,
                "actions": [action.to_dict() for action in evidence.actions],
                "total_file_read_mb": evidence.total_file_read_mb,
                "total_file_write_mb": evidence.total_file_write_mb,
                "total_network_egress_mb": evidence.total_network_egress_mb,
                "network_connection_count": evidence.network_connection_count,
                "process_state_hash": evidence.process_state_hash,
                "transport": evidence.transport,
                "signature": evidence.signature,
                "registration_source": state.registration_source,
            }
        else:
            payload = {
                "agent_id": state.agent_id or f"pid-{pid}",
                "session_id": state.session_id or f"session-{pid}",
                "node_id": self.node_id,
                "job_id": state.job_id,
                "slurm_job_id": state.job_id,
                "pid": pid,
                "timestamp": time.time(),
                "interval_start": state.first_seen,
                "interval_end": time.time(),
                "actions": [],
                "total_file_read_mb": state.file_read_bytes / (1024 * 1024),
                "total_file_write_mb": state.file_write_bytes / (1024 * 1024),
                "total_network_egress_mb": state.network_egress_bytes / (1024 * 1024),
                "network_connection_count": state.connection_count,
                "process_state_hash": self._compute_process_hash(state),
                "transport": self._transport_label(),
                "signature": None,
                "registration_source": state.registration_source,
            }
        if clear_actions:
            self.clear_actions(pid)
        return payload

    def generate_job_evidence(self, job_id: str, clear_actions: bool = False) -> List[dict]:
        with self.lock:
            pids = [pid for pid, state in self.agent_states.items() if state.job_id == job_id]
        return [evidence for pid in pids if (evidence := self.generate_evidence(pid, clear_actions=clear_actions)) is not None]

    def clear_actions(self, pid: int) -> None:
        with self.lock:
            state = self.agent_states.get(pid)
            if state is not None:
                state.actions = []

    def clear_agent(self, pid: int) -> None:
        with self.lock:
            self.agent_states.pop(pid, None)


def _resolve_bpf_object_path(requested: Optional[str] = None) -> str:
    if requested:
        candidate = Path(requested).expanduser()
        if candidate.is_file():
            return str(candidate)
        raise FileNotFoundError(f"BPF object not found: {candidate}")
    repo_root = Path(__file__).resolve().parents[3]
    env_override = os.environ.get("AEGIS_BPF_OBJ")
    candidates = [
        Path(env_override).expanduser() if env_override else None,
        repo_root / "src" / "deployment" / "bpf" / "aegis_probe.bpf.o",
        Path("/usr/share/aegis/aegis_probe.bpf.o"),
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return str(candidate)
    checked = [str(candidate) for candidate in candidates if candidate]
    raise FileNotFoundError("BPF object not found; checked: " + ", ".join(checked))


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS eBPF Collector")
    parser.add_argument("--bpf", default=None, help="Path to BPF object file")
    parser.add_argument("--interval", type=float, default=1.0, help="Attestation interval in seconds")
    parser.add_argument("--registry-dir", default="/run/aegis/collector/registrations", help="Directory containing Slurm job registrations")
    parser.add_argument("--node-id", default=None, help="Override the collector node identifier")
    parser.add_argument("--signing-key", default=os.environ.get("AEGIS_COLLECTOR_KEY"), help="Software signing key for evidence HMACs")
    parser.add_argument("--verifier-socket", default=os.environ.get("AEGIS_VERIFIER_SOCKET"), help="Unix socket path for bootstrap submission to the verifier")
    parser.add_argument("--verifier-host", default=os.environ.get("AEGIS_VERIFIER_HOST"), help="TCP host for bootstrap submission to the verifier")
    parser.add_argument("--verifier-port", type=int, default=int(os.environ.get("AEGIS_VERIFIER_PORT", "50051")), help="TCP port for bootstrap submission to the verifier")
    parser.add_argument("--emit-dir", default=os.environ.get("AEGIS_EVIDENCE_SPOOL_DIR"), help="Directory to spool evidence JSON files when no verifier endpoint is configured")
    parser.add_argument("--submission-timeout", type=float, default=float(os.environ.get("AEGIS_SUBMISSION_TIMEOUT", "5.0")), help="Timeout in seconds for verifier submission")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    collector = BPFCollector(
        bpf_obj_path=args.bpf,
        interval=args.interval,
        registry_dir=args.registry_dir,
        node_id=args.node_id,
        signing_key=args.signing_key,
        verifier_socket=args.verifier_socket,
        verifier_host=args.verifier_host,
        verifier_port=args.verifier_port,
        emit_dir=args.emit_dir,
        submission_timeout=args.submission_timeout,
    )

    def log_event(event: AEGISEvent) -> None:
        logger.debug(
            "Event: PID=%s %s path=%s",
            event.pid,
            ACTION_NAMES.get(event.action_type, "UNKNOWN"),
            event.path or event.endpoint,
        )

    collector.register_callback(log_event)
    if not collector.load():
        raise SystemExit(1)
    if not collector.start():
        raise SystemExit(1)

    logger.info("AEGIS eBPF Collector running on %s. Press Ctrl+C to stop.", collector.node_id)
    try:
        while True:
            time.sleep(args.interval)
            states = collector.get_all_states()
            if states:
                logger.info("Tracking %s processes", len(states))
                submitted = collector.flush_evidence()
                if submitted:
                    logger.info("Submitted %s evidence bundle(s)", submitted)
                for pid, state in list(states.items())[:3]:
                    logger.debug(
                        "PID %s agent=%s job=%s read=%.1fKB write=%.1fKB net=%s conns",
                        pid,
                        state.agent_id,
                        state.job_id,
                        state.file_read_bytes / 1024,
                        state.file_write_bytes / 1024,
                        state.connection_count,
                    )
    except KeyboardInterrupt:
        logger.info("Shutting down collector...")
        submitted = collector.flush_evidence()
        if submitted:
            logger.info("Submitted %s final evidence bundle(s)", submitted)
        collector.stop()


if __name__ == "__main__":
    main()
