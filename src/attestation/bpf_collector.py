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
import asyncio
import ctypes
import json
import os
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

# libbpf Python bindings
import libbpf

# Try to import from AEGIS framework, fall back to standalone
try:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from src.framework.attestation import AgentAction, ActionType
    from src.common.logger import get_logger
except ImportError:
    # Standalone mode
    from dataclasses import dataclass, field
    from enum import Enum
    from typing import Any, Dict, List
    import logging
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


class BPFCollector:
    """Main collector class - manages eBPF program and event processing."""
    
    def __init__(self, 
                 bpf_obj_path: str = "/usr/share/aegis/aegis_probe.bpf.o",
                 interval: float = 1.0,
                 sample_rate: int = 1):
        self.bpf_obj_path = bpf_obj_path
        self.interval = interval
        self.sample_rate = sample_rate
        self.running = False
        self.agent_states: Dict[int, AgentState] = {}
        self.event_callbacks: List[Callable[[AEGISEvent], None]] = []
        
        # libbpf objects
        self.bpf_obj: Optional[libbpf.BPF] = None
        self.ring_buffer = None
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
    def load(self) -> bool:
        """Load the eBPF object."""
        try:
            # Check if running as root
            if os.geteuid() != 0:
                logger.error("Must run as root to load eBPF programs")
                return False
            
            # Load BPF object
            logger.info(f"Loading eBPF program from {self.bpf_obj_path}")
            self.bpf_obj = libbpf.BPF(self.bpf_obj_path)
            
            # Get ring buffer map
            self.ring_buffer = self.bpf_obj.get_map("aegis_events")
            if not self.ring_buffer:
                logger.error("Failed to get ring buffer map")
                return False
            
            # Set configuration
            self._set_config()
            
            logger.info("eBPF program loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load eBPF: {e}")
            return False
    
    def _set_config(self):
        """Set configuration in the BPF map."""
        try:
            config_map = self.bpf_obj.get_map("aegis_config")
            if config_map:
                # Default config: enable all monitoring
                config_data = (ctypes.c_uint64 * 5)(
                    self.sample_rate,  # sample_rate
                    1,                  # enable_network
                    1,                  # enable_file
                    1,                  # enable_exec
                    0                   # monitor_uid (0 = all)
                )
                config_map[ctypes.c_int(0)] = ctypes.cast(
                    config_data, ctypes.c_void_p
                )
                logger.debug("Configuration set")
        except Exception as e:
            logger.warning(f"Could not set config: {e}")
    
    def _parse_event(self, data: bytes) -> AEGISEvent:
        """Parse raw event data from ring buffer.
        
        Must match the struct aegis_event in aegis_probe.c:
        struct aegis_event {
            __u64 timestamp;
            __u32 pid;
            __u32 tid;
            __u32 uid;
            __u32 action_type;
            __u64 size;
            char path[MAX_PATH_LEN];      // 256
            char endpoint[MAX_ENDPOINT_LEN]; // 128
            __u32 endpoint_port;
        };
        """
        # C struct layout: timestamp(8) + pid(4) + tid(4) + uid(4) + 
        #                  action_type(4) + size(8) + path(256) + 
        #                  endpoint(128) + endpoint_port(4) = 420 bytes
        EVENT_SIZE = 420
        
        if len(data) < EVENT_SIZE:
            logger.warning(f"Truncated event: {len(data)} bytes")
            return None
        
        # Unpack fixed-size fields
        (timestamp, pid, tid, uid, action_type, size, 
         endpoint_port) = struct.unpack('<QIIIII4xI', data[:32])
        
        # Extract path (offset 32, 256 bytes)
        path_bytes = data[32:288]
        path = path_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
        
        # Extract endpoint (offset 288, 128 bytes)
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
            endpoint_port=endpoint_port
        )
    
    def _process_event(self, cpu: int, data: bytes, size: int):
        """Callback for ring buffer events."""
        try:
            event = self._parse_event(data)
            if not event:
                return
            
            # Update agent state
            with self.lock:
                if event.pid not in self.agent_states:
                    self.agent_states[event.pid] = AgentState(pid=event.pid)
                
                state = self.agent_states[event.pid]
                state.last_update = time.time()
                state.actions.append(event)
                
                # Update counters
                if event.action_type == ACTION_FILE_READ:
                    state.file_read_bytes += max(event.size, 4096)
                elif event.action_type == ACTION_FILE_WRITE:
                    state.file_write_bytes += max(event.size, 4096)
                elif event.action_type == ACTION_NETWORK_CONN:
                    state.connection_count += 1
                elif event.action_type == ACTION_TOOL_INVOKE:
                    pass  # Tool invocations don't add to byte counts
            
            # Notify callbacks
            for callback in self.event_callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing event: {e}")
    
    def register_callback(self, callback: Callable[[AEGISEvent], None]):
        """Register a callback for events."""
        self.event_callbacks.append(callback)
    
    def start(self):
        """Start collecting events."""
        if not self.bpf_obj:
            logger.error("BPF not loaded")
            return False
        
        self.running = True
        
        # Open ring buffer
        self.bpf_obj.open_ring_buffer("aegis_events", self._process_event)
        
        # Start poll loop in background thread
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()
        
        logger.info("Collector started")
        return True
    
    def _poll_loop(self):
        """Poll ring buffer in background."""
        while self.running:
            try:
                self.bpf_obj.poll_ring_buffer("aegis_events", timeout_ms=100)
            except Exception as e:
                if self.running:
                    logger.error(f"Poll error: {e}")
                time.sleep(0.1)
    
    def stop(self):
        """Stop collecting."""
        self.running = False
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
        """Generate attestation evidence for an agent.
        
        This produces the evidence bundle that gets sent to the verifier.
        """
        with self.lock:
            state = self.agent_states.get(pid)
            if not state:
                return None
        
        # Convert events to framework format
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
                "timestamp": event.timestamp / 1e9,  # ns to seconds
                "action_type": action_type,
                "details": details
            })
        
        evidence = {
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
        
        return evidence
    
    def clear_agent(self, pid: int):
        """Clear state for an agent (e.g., when agent exits)."""
        with self.lock:
            if pid in self.agent_states:
                del self.agent_states[pid]


def main():
    parser = argparse.ArgumentParser(description="AEGIS eBPF Collector")
    parser.add_argument("--bpf", default="/usr/share/aegis/aegis_probe.bpf.o",
                       help="Path to BPF object file")
    parser.add_argument("--interval", type=float, default=1.0,
                       help="Attestation interval in seconds")
    parser.add_argument("--output", default="/var/log/aegis/events.jsonl",
                       help="Output file for events")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create collector
    collector = BPFCollector(
        bpf_obj_path=args.bpf,
        interval=args.interval
    )
    
    # Event callback: log events
    def log_event(event: AEGISEvent):
        logger.debug(f"Event: PID={event.pid} {ACTION_NAMES.get(event.action_type, 'UNKNOWN')} "
                    f"path={event.path or event.endpoint}")
    
    collector.register_callback(log_event)
    
    # Load and start
    if not collector.load():
        sys.exit(1)
    
    if not collector.start():
        sys.exit(1)
    
    logger.info("AEGIS eBPF Collector running. Press Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(args.interval)
            
            # Print summary periodically
            states = collector.get_all_states()
            if states:
                logger.info(f"Tracking {len(states)} agents")
                for pid, state in list(states.items())[:3]:
                    logger.debug(f"  PID {pid}: "
                               f"read={state.file_read_bytes/1024:.1f}KB "
                               f"write={state.file_write_bytes/1024:.1f}KB "
                               f"net={state.connection_count} conns")
                
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        collector.stop()


if __name__ == "__main__":
    main()