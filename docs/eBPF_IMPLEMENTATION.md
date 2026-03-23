# AEGIS eBPF Attestation Engine — Implementation Plan

## Overview

The Attestation Engine needs to intercept agent system calls in real-time on HPC compute nodes. This document scopes the eBPF implementation.

## eBPF Program Structure

### 1. Syscall Hooks Required

| Syscall | Action Type | Purpose |
|---------|-------------|---------|
| `openat`, `openat2` | `FILE_READ` | Monitor file opens for read |
| `write`, `writev` | `FILE_WRITE` | Monitor file writes |
| `connect`, `sendto` | `NETWORK_CONNECTION` | Monitor outbound connections |
| `execve` | `TOOL_INVOCATION` | Monitor process/tool spawning |

### 2. Per-Agent Tracking

- Use `bpf_map` (hash map) keyed by `task_struct` PID to track per-agent state
- Store: agent_id, session_id, cumulative bytes read/written, connection count
- Ring buffer for event delivery to userspace

### 3. Userspace Bridge (Python/BCC)

```
┌─────────────────────────────────────────────────────────────┐
│                     Compute Node                            │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  eBPF Probe  │───▶│  Ring Buffer │───▶│  Python API  │  │
│  │  (kernel)    │    │  (kernel)    │    │  (userspace) │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                                       │           │
│   sys_openat,                               Generates      │
│   sys_connect,                              Attestation     │
│   sys_execve                                Evidence        │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Files

```
src/
├── bpf/
│   ├── aegis_probe.c        # Main eBPF program (C)
│   └── aegis_probe.h        # Shared definitions
├── attestation/
│   ├── bpf_collector.py     # Reads ring buffer, produces events
│   └── evidence_generator.py # Bundles events into attestation evidence
└── framework/
    └── attestation.py       # Already exists - integrate with bpf_collector
```

## eBPF Program (aegis_probe.c) — Draft

```c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

struct agent_state {
    __u64 agent_id;
    __u64 session_id;
    __u64 file_read_bytes;
    __u64 file_write_bytes;
    __u64 network_egress_bytes;
    __u64 connection_count;
};

struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 action_type;  // 0=FILE_READ, 1=FILE_WRITE, 2=NETWORK, 3=TOOL
    __u64 size;
    char path[256];
    char endpoint[128];
};

struct bpf_map_def SEC("maps") agent_states = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct agent_state),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 128 * 1024,
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid();
    // Read path argument, emit event
    // ...
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct pt_regs *ctx) {
    // Monitor network connections
    // ...
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct pt_regs *ctx) {
    // Monitor tool/command execution
    // ...
}
```

## Implementation Phases

### Phase 1: Basic Syscall Tracing (Week 1)
- [ ] Write eBPF probe for file open/read/write
- [ ] Write eBPF probe for network connect
- [ ] Write eBPF probe for execve
- [ ] Test on single EPYC node

### Phase 2: Event Delivery (Week 1-2)
- [ ] Implement ring buffer event delivery
- [ ] Write Python collector (bpf_collector.py)
- [ ] Integrate with existing attestation.py

### Phase 3: Agent Identification (Week 2)
- [ ] Link agent processes to Slurm job IDs
- [ ] Track agent state per job
- [ ] Handle multi-process agents

### Phase 4: Performance Tuning (Week 2-3)
- [ ] Benchmark overhead (target: <5%)
- [ ] Optimize ring buffer batching
- [ ] Test at scale (100+ agents)

## Hardware Requirements

- Linux kernel 6.8+ (for latest eBPF features)
- AMD EPYC with TPM 2.0 (optional, for hardware attestation)
- Root access to load eBPF programs

## Running on EPYC

```bash
# Check kernel version
uname -r

# Check eBPF capabilities
cat /proc/sys/kernel/bpf_stats_enabled

# Load eBPF program (requires root)
sudo bpftool prog load aegis_probe.bpf /sys/fs/bpf/aegis_probe

# Start Python collector
python3 -m src.attestation.bpf_collector --interface eth0
```

## Next Steps

1. **Confirm EPYC access** — Do you have a node you can test on? What's the OS/kernel?
2. **Install BCC or libbpf** — Which eBPF framework prefer?
3. **Start Phase 1** — I'll write the initial eBPF probe code

Let me know which EPYC node you have access to and I can start drafting the actual eBPF code.