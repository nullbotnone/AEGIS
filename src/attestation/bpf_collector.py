#!/usr/bin/env python3
"""
AEGIS eBPF Collector

Reads events from the eBPF ring buffer and produces attestation evidence.
This is the userspace bridge between the kernel eBPF probe and the
AEGIS attestation framework.

Usage:
    sudo python3 bpf_collector.py [--interval SECONDS] [--output OUTPUT]
"""

import argparse
import ctypes
import ctypes.util
import json
import logging
import os
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional


def _resolve_bpf_object_path(requested: Optional[str] = None) -> str:
    """Resolve the BPF object path for source-tree and installed layouts."""
    if requested:
        candidate = Path(requested).expanduser()
        if candidate.is_file():
            return str(candidate)
        raise FileNotFoundError(f"BPF object not found: {candidate}")

    repo_root = Path(__file__).resolve().parents[2]
    env_override = os.environ.get("AEGIS_BPF_OBJ")
    candidates = [
        Path(env_override).expanduser() if env_override else None,
        repo_root / "src" / "bpf" / "aegis_probe.bpf.o",
        Path("/usr/share/aegis/aegis_probe.bpf.o"),
    ]

    for candidate in candidates:
        if candidate and candidate.is_file():
            return str(candidate)

    checked = [str(candidate) for candidate in candidates if candidate]
    raise FileNotFoundError(
        "BPF object not found; checked: " + ", ".join(checked)
    )

# Try to import from AEGIS framework, fall back to standalone.
try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from src.common.logger import get_logger
except ImportError:
    def get_logger(name: str) -> logging.Logger:
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(name)

logger = get_logger("aegis.bpf_collector")

# Action types - must match aegis_probe.c
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
            "system libbpf not found; install the libbpf runtime package "
            "instead of pip-installing a Python wrapper"
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
    """Main collector class - manages eBPF program and event processing."""

    def __init__(
        self,
        bpf_obj_path: Optional[str] = None,
        interval: float = 1.0,
        sample_rate: int = 1,
    ):
        self.bpf_obj_path = bpf_obj_path
        self.interval = interval
        self.sample_rate = sample_rate
        self.running = False
        self.agent_states: Dict[int, AgentState] = {}
        self.event_callbacks: List[Callable[[AEGISEvent], None]] = []
        self._backend: Optional[_LibbpfBackend] = None
        self.ring_buffer = None
        self.poll_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()

    def load(self) -> bool:
        """Load the eBPF object and configure maps."""
        try:
            if os.geteuid() != 0:
                logger.error("Must run as root to load eBPF programs")
                return False

            logger.info(f"Loading eBPF program from {self.bpf_obj_path}")
            backend = _LibbpfBackend(self.bpf_obj_path)
            backend.open()
            backend.set_config(self.sample_rate)

            self._backend = backend
            logger.info("eBPF program loaded successfully")
            return True
        except Exception as exc:
            logger.error(f"Failed to load eBPF: {exc}")
            return False

    def _parse_event(self, data: bytes) -> Optional[AEGISEvent]:
        """Parse raw event data from ring buffer."""
        EVENT_SIZE = 420

        if len(data) < EVENT_SIZE:
            logger.warning(f"Truncated event: {len(data)} bytes")
            return None

        timestamp, pid, tid, uid, action_type, size = struct.unpack(
            '<QIIIIQ', data[:32]
        )
        endpoint_port = struct.unpack('<I', data[416:420])[0]

        path_bytes = data[32:288]
        path = path_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')

        endpoint_bytes = data[288:416]
        endpoint = endpoint_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')

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

    def _process_event(self, cpu: int, data: bytes, size: int) -> None:
        """Callback for ring buffer events."""
        try:
            event = self._parse_event(data)
            if not event:
                return

            with self.lock:
                if event.pid not in self.agent_states:
                    self.agent_states[event.pid] = AgentState(pid=event.pid)

                state = self.agent_states[event.pid]
                state.last_update = time.time()
                state.actions.append(event)

                if event.action_type == ACTION_FILE_READ:
                    state.file_read_bytes += max(event.size, 4096)
                elif event.action_type == ACTION_FILE_WRITE:
                    state.file_write_bytes += max(event.size, 4096)
                elif event.action_type == ACTION_NETWORK_CONN:
                    state.connection_count += 1

            for callback in self.event_callbacks:
                try:
                    callback(event)
                except Exception as exc:
                    logger.error(f"Callback error: {exc}")

        except Exception as exc:
            logger.error(f"Error processing event: {exc}")

    def register_callback(self, callback: Callable[[AEGISEvent], None]) -> None:
        """Register a callback for events."""
        self.event_callbacks.append(callback)

    def start(self) -> bool:
        """Start collecting events."""
        if not self._backend:
            logger.error("BPF not loaded")
            return False

        self.running = True
        self._backend.open_ring_buffer("aegis_events", self._process_event)
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()

        logger.info("Collector started")
        return True

    def _poll_loop(self) -> None:
        """Poll ring buffer in background."""
        while self.running:
            try:
                if self._backend is None:
                    return
                rc = self._backend.poll_ring_buffer(timeout_ms=100)
                if rc < 0 and self.running:
                    logger.error(f"Poll error: {rc}")
                    time.sleep(0.1)
            except Exception as exc:
                if self.running:
                    logger.error(f"Poll error: {exc}")
                time.sleep(0.1)

    def stop(self) -> None:
        """Stop collecting."""
        self.running = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=1)
        if self._backend is not None:
            self._backend.close()
            self._backend = None
        logger.info("Collector stopped")

    def get_agent_state(self, pid: int) -> Optional[AgentState]:
        """Get current state for an agent."""
        with self.lock:
            return self.agent_states.get(pid)

    def get_all_states(self) -> Dict[int, AgentState]:
        """Get all agent states."""
        with self.lock:
            return dict(self.agent_states)

    def generate_evidence(self, pid: int) -> Optional[dict]:
        """Generate attestation evidence for an agent."""
        with self.lock:
            state = self.agent_states.get(pid)
            if not state:
                return None

        actions = []
        for event in state.actions:
            if event.action_type == ACTION_FILE_READ:
                action_type = "FILE_READ"
                details = {"path": event.path}
            elif event.action_type == ACTION_FILE_WRITE:
                action_type = "FILE_WRITE"
                details = {"path": event.path}
            elif event.action_type == ACTION_NETWORK_CONN:
                action_type = "NETWORK_CONNECTION"
                details = {"endpoint": event.endpoint, "port": event.endpoint_port}
            elif event.action_type == ACTION_TOOL_INVOKE:
                action_type = "TOOL_INVOCATION"
                details = {"tool": event.path}
            else:
                continue

            actions.append({
                "timestamp": event.timestamp / 1e9,
                "action_type": action_type,
                "details": details,
            })

        return {
            "agent_id": state.agent_id or f"pid-{pid}",
            "session_id": state.session_id or f"session-{pid}",
            "pid": pid,
            "job_id": state.job_id,
            "timestamp": time.time(),
            "interval_start": state.first_seen,
            "interval_end": time.time(),
            "actions": actions,
            "total_file_read_mb": state.file_read_bytes / (1024 * 1024),
            "total_file_write_mb": state.file_write_bytes / (1024 * 1024),
            "total_network_egress_mb": state.network_egress_bytes / (1024 * 1024),
            "connection_count": state.connection_count,
        }

    def clear_agent(self, pid: int) -> None:
        """Clear state for an agent (e.g., when agent exits)."""
        with self.lock:
            self.agent_states.pop(pid, None)


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS eBPF Collector")
    parser.add_argument("--bpf", default=None,
                       help="Path to BPF object file (auto-detected if omitted)")
    parser.add_argument("--interval", type=float, default=1.0,
                       help="Attestation interval in seconds")
    parser.add_argument("--output", default="/var/log/aegis/events.jsonl",
                       help="Output file for events")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    collector = BPFCollector(
        bpf_obj_path=args.bpf,
        interval=args.interval,
    )

    def log_event(event: AEGISEvent) -> None:
        logger.debug(
            f"Event: PID={event.pid} "
            f"{ACTION_NAMES.get(event.action_type, 'UNKNOWN')} "
            f"path={event.path or event.endpoint}"
        )

    collector.register_callback(log_event)

    if not collector.load():
        sys.exit(1)

    if not collector.start():
        sys.exit(1)

    logger.info("AEGIS eBPF Collector running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(args.interval)
            states = collector.get_all_states()
            if states:
                logger.info(f"Tracking {len(states)} agents")
                for pid, state in list(states.items())[:3]:
                    logger.debug(
                        f"  PID {pid}: "
                        f"read={state.file_read_bytes / 1024:.1f}KB "
                        f"write={state.file_write_bytes / 1024:.1f}KB "
                        f"net={state.connection_count} conns"
                    )
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        collector.stop()


if __name__ == "__main__":
    main()
