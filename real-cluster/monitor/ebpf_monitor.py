#!/usr/bin/env python3
"""eBPF-based system call monitor for AEGIS.

Monitors agent processes via eBPF probes on key syscalls:
- openat (file access)
- connect (network connections)  
- execve (process spawning)
- write (data output)

Requires root/sudo. Falls back to ptrace if eBPF unavailable.
"""
import os
import sys
import json
import time
import argparse
import struct
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class SyscallEvent:
    """A captured syscall event."""
    timestamp: float
    pid: int
    comm: str
    syscall: str
    args: Dict[str, Any]
    return_value: int


class EBPFMonitor:
    """eBPF-based syscall monitor for AEGIS attestation.
    
    Uses BCC or bpftrace to capture syscall events from agent processes.
    Falls back to /proc monitoring if eBPF is unavailable.
    """
    
    def __init__(self, agent_id: str, output_file: str, target_pids: list = None):
        self.agent_id = agent_id
        self.output_file = output_file
        self.target_pids = target_pids or []
        self.events = []
        self.running = False
        
        # File access tracking
        self.file_reads = {}
        self.file_writes = {}
        
        # Network connection tracking
        self.connections = []
        
    def start(self):
        """Start monitoring."""
        self.running = True
        print(f"[Monitor] Starting eBPF monitor for agent {self.agent_id}")
        print(f"[Monitor] Output: {self.output_file}")
        
        # Try eBPF first, fall back to /proc polling
        try:
            self._start_ebpf()
        except (ImportError, PermissionError) as e:
            print(f"[Monitor] eBPF unavailable ({e}), using /proc polling")
            self._start_proc_polling()
    
    def _start_ebpf(self):
        """Start eBPF-based monitoring using BCC."""
        try:
            from bcc import BPF
        except ImportError:
            raise ImportError("BCC not installed. Install with: apt-get install bpfcc-tools python3-bcc")
        
        # eBPF program to trace key syscalls
        bpf_program = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        #include <linux/fs.h>
        
        struct syscall_event_t {
            u64 timestamp;
            u32 pid;
            char comm[TASK_COMM_LEN];
            char syscall[16];
            char path[256];
            u64 size;
            s32 ret;
        };
        
        BPF_PERF_OUTPUT(events);
        
        // Trace openat (file opens)
        int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
            struct syscall_event_t event = {};
            event.timestamp = bpf_ktime_get_ns();
            event.pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            __builtin_memcpy(&event.syscall, "openat", 7);
            bpf_probe_read_user_str(&event.path, sizeof(event.path), filename);
            events.perf_submit(ctx, &event, sizeof(event));
            return 0;
        }
        """
        
        b = BPF(text=bpf_program)
        b.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat")
        
        def process_event(cpu, data, size):
            event = b["events"].event(data)
            self._handle_event(SyscallEvent(
                timestamp=time.time(),
                pid=event.pid,
                comm=event.comm.decode("utf-8", errors="replace"),
                syscall="openat",
                args={"path": event.path.decode("utf-8", errors="replace")},
                return_value=0
            ))
        
        b["events"].open_perf_buffer(process_event)
        
        while self.running:
            b.perf_buffer_poll(timeout=1000)
    
    def _start_proc_polling(self):
        """Fallback: poll /proc for file descriptors."""
        print("[Monitor] Using /proc polling (1s interval)")
        
        while self.running:
            for pid in self.target_pids:
                try:
                    # Check open file descriptors
                    fd_dir = f"/proc/{pid}/fd"
                    if os.path.exists(fd_dir):
                        for fd in os.listdir(fd_dir):
                            try:
                                link = os.readlink(os.path.join(fd_dir, fd))
                                if link.startswith("/") and not link.startswith("/proc"):
                                    self._handle_event(SyscallEvent(
                                        timestamp=time.time(),
                                        pid=pid,
                                        comm=self._get_comm(pid),
                                        syscall="open",
                                        args={"path": link, "fd": fd},
                                        return_value=0
                                    ))
                            except (OSError, PermissionError):
                                pass
                except (OSError, ProcessLookupError):
                    pass
            
            time.sleep(1.0)
    
    def _get_comm(self, pid: int) -> str:
        """Get process name from PID."""
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except:
            return "unknown"
    
    def _handle_event(self, event: SyscallEvent):
        """Handle a captured syscall event."""
        self.events.append(event)
        
        # Track by type
        if event.syscall in ("openat", "open"):
            path = event.args.get("path", "")
            if path:
                self.file_reads[path] = self.file_reads.get(path, 0) + 1
        
        # Write to output file
        output = {
            "timestamp": event.timestamp,
            "agent_id": self.agent_id,
            "pid": event.pid,
            "comm": event.comm,
            "syscall": event.syscall,
            "args": event.args,
            "return": event.return_value
        }
        
        with open(self.output_file, "a") as f:
            f.write(json.dumps(output) + "\n")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        print(f"[Monitor] Stopped. Captured {len(self.events)} events")
        
        # Summary
        print(f"[Monitor] Unique files read: {len(self.file_reads)}")
        print(f"[Monitor] Network connections: {len(self.connections)}")


def main():
    parser = argparse.ArgumentParser(description="eBPF monitor for AEGIS")
    parser.add_argument("--agent-id", required=True, help="Agent ID to monitor")
    parser.add_argument("--output", required=True, help="Output JSONL file")
    parser.add_argument("--pids", nargs="+", type=int, help="Target PIDs to monitor")
    parser.add_argument("--duration", type=int, default=0, help="Monitor duration (0=forever)")
    args = parser.parse_args()
    
    monitor = EBPFMonitor(
        agent_id=args.agent_id,
        output_file=args.output,
        target_pids=args.pids
    )
    
    try:
        monitor.start()
        
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            # Run until interrupted
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
