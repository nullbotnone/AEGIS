# AEGIS EPYC Testing Guide

This guide covers running AEGIS evaluation on AMD EPYC hardware.

## Prerequisites

### 1. System Requirements

| Requirement | Specification |
|-------------|---------------|
| OS | Rocky Linux 9.6 |
| Kernel | 5.14.0 (or later) |
| CPU | AMD EPYC (tested on 7713) |
| RAM | 8GB+ recommended |
| Access | Root/sudo required |

### 2. Install Dependencies

```bash
# Update system
sudo dnf update -y

# Install eBPF build tools
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    elfutils-libelf-devel \
    make \
    git

# Install Python dependencies
sudo dnf install -y python3 python3-pip

# No pip package is required for libbpf.
# The collector now uses the system libbpf shared library directly.
```

### 3. Verify eBPF Support

```bash
# Check kernel version
uname -r

# Check BPF subsystem
ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat

# Check capabilities (must be root)
id -u  # Should be 0, or use sudo
```

---

## Build eBPF Probe

### 1. Clone/Copy Project

```bash
# On EPYC node, get the AEGIS code
# Option A: If repo is accessible
git clone <aegis-repo-url> /home/user/aegis
cd /home/user/aegis

# Option B: Copy from local machine
# scp -r artlands@local:/path/to/AEGIS epyc-node:/home/user/
```

### 2. Build eBPF Object

```bash
cd /home/user/aegis

# Build the eBPF probe
make bpfall
```

Expected output:
```
Compiling src/bpf/aegis_probe.c -> src/bpf/aegis_probe.bpf.o
=== eBPF objects built ===
```

### 3. Verify Build

```bash
# Check the object file
file src/bpf/aegis_probe.bpf.o
# Output: ELF 64-bit LSB relocatable, eBPF executable

# Check symbols
llvm-objdump -t src/bpf/aegis_probe.bpf.o | grep -E "trace_sys_enter_openat|trace_sys_enter_connect|trace_sys_enter_execve"
```

---

## Run AEGIS Components

### 1. Start BPF Collector (as root)

```bash
# Load and run the eBPF collector
cd /home/user/aegis
sudo python3 -m src.attestation.bpf_collector --verbose
```

Expected output:
```
INFO:aegis.bpf_collector:Loading eBPF program from /home/user/aegis/src/bpf/aegis_probe.bpf.o
eBPF program loaded successfully
Collector started
AEGIS eBPF Collector running. Press Ctrl+C to stop.
```

If you want to force a specific object file, pass it explicitly:

```bash
sudo python3 -m src.attestation.bpf_collector \
  --bpf src/bpf/aegis_probe.bpf.o \
  --verbose
```

### 2. In Another Terminal - Generate Load

```bash
# Run some commands to generate syscalls
ls -la /tmp
cat /etc/hostname
curl -I https://api.openai.com
python3 -c "print('test')"
```

### 3. Check Collector Output

You should see events being captured:
```
Event: PID=1234 FILE_READ path=/etc/hostname
Event: PID=1234 NETWORK_CONN endpoint=api.openai.com
```

---

## Run Baseline Comparisons

### 1. Test Baseline Defenses

```bash
cd /home/user/aegis

# Run baseline comparison
python3 -m src.defense.baseline_comparison
```

### 2. Expected Output

```
=== AEGIS Baseline Comparison Test ===

=== Baseline Comparison Results ===
Defense                   Attack               Result       Time (ms)
----------------------------------------------------------------------
Network DLP               filesystem_injection DETECTED     0.003
Filesystem Auditing       filesystem_injection MISSED       0.004
Per-Agent Analytics       filesystem_injection MISSED       0.004
Strict Sandboxing         filesystem_injection MISSED       0.007
```

---

## Run Performance Benchmarks

### 1. Create Benchmark Script

```bash
cd /home/user/aegis
cat > benchmark_overhead.py << 'EOF'
#!/usr/bin/env python3
"""AEGIS overhead benchmark on EPYC."""

import time
import statistics
import subprocess
import sys

def measure_overhead(interval=1.0, duration=10):
    """Measure attestation overhead at given interval."""
    times = []
    
    for _ in range(10):
        start = time.perf_counter()
        # Simulate evidence generation for 50 actions
        for i in range(50):
            _ = {"action": "test", "size": 4096}
        end = time.perf_counter()
        times.append((end - start) * 1000)  # ms
    
    return {
        "mean_ms": statistics.mean(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
    }

def run_syscall_benchmark():
    """Benchmark syscall interception overhead."""
    print("=== EPYC Syscall Benchmark ===\n")
    
    intervals = [0.1, 0.5, 1.0, 5.0, 10.0]
    results = []
    
    for interval in intervals:
        # Measure evidence generation overhead
        result = measure_overhead(interval)
        
        # Estimate overhead based on interval
        # (This is simplified - real measurement would use eBPF)
        overhead_pct = (result["mean_ms"] / (interval * 1000)) * 100
        
        results.append({
            "interval": interval,
            "eval_time_ms": result["mean_ms"],
            "overhead_pct": overhead_pct
        })
        
        print(f"Interval: {interval:>5.1f}s | "
              f"Eval: {result['mean_ms']:>6.3f}ms | "
              f"Overhead: {overhead_pct:>5.2f}%")
    
    return results

if __name__ == "__main__":
    run_syscall_benchmark()
EOF
chmod +x benchmark_overhead.py

python3 benchmark_overhead.py
```

### 2. Expected Output

```
=== EPYC Syscall Benchmark ===

Interval:   0.1s | Eval:  0.042ms | Overhead:  0.04%
Interval:   0.5s | Eval:  0.038ms | Overhead:  0.01%
Interval:   1.0s | Eval:  0.045ms | Overhead:  0.00%
Interval:   5.0s | Eval:  0.041ms | Overhead:  0.00%
Interval:  10.0s | Eval:  0.043ms | Overhead:  0.00%
```

---

## Test Cross-Node Coordination

### 1. Start Central Coordinator

```bash
# Terminal 1: Start coordinator (requires network access between nodes)
python3 -m src.attestation.cross_node_coordinator --port 9090
```

### 2. Test Covert Channel Detection

```bash
cd /home/artlands/.openclaw/workspace/research/AEGIS

# Run the coordinated exfiltration test
python3 -m src.experiments.run_attack4
```

Expected output:
```
=== AEGIS Coordinated Exfiltration Test ===
Ingesting write event: agent-001 -> /.cache/exfil
Ingesting read event: agent-002 -> /.cache/exfil
⚠ COVERT CHANNEL DETECTED: agent-001 -> agent-002
  Via: /.cache/exfil
  Severity: CRITICAL
```

---

## Test Slurm Integration

### 1. Enable Slurm REST API

```bash
# On the Slurm controller node (if different)
srun --wrap='slurmrestd -j localhost:8080'&
```

### 2. Test Containment Actions

```bash
# Get a job ID to test with
squeue -u $USER

# Test suspension
python3 -m src.defense.slurm_integration suspend <JOB_ID>

# Test termination (use with caution!)
python3 -m src.defense.slurm_integration terminate <JOB_ID>
```

---

## Generate Results for Paper

### 1. Run Full Experiment Suite

```bash
cd /home/artlands/.openclaw/workspace/research/AEGIS

# Run all attacks
python3 -m src.experiments.run_all

# This generates:
# - Detection rates for each attack
# - Baseline comparison results
# - Timing measurements
```

### 2. Output Format

Results will be saved to `results/`:

```
results/
├── attack_results.csv
├── baseline_comparison.csv
├── overhead_measurements.csv
└── figures/
    ├── attack_results.png
    ├── baseline_comparison.png
    └── performance_overhead.png
```

### 3. Collect Results

```bash
# Tarball results for transfer to local machine
tar -czvf aegis-results-$(date +%Y%m%d).tar.gz results/

# Copy to local
scp epyc-node:/home/user/aegis-results-*.tar.gz ./
```

---

## Troubleshooting

### eBPF Won't Load

```bash
# Check kernel config
zcat /proc/config.gz | grep CONFIG_BPF

# Check dmesg for errors
dmesg | tail -50
```

### Permission Denied

```bash
# Must run as root for eBPF
sudo su -
cd /home/user/aegis
python3 -m src.attestation.bpf_collector
```

### Slurm REST Not Running

```bash
# Check if slurmrestd is running
ps aux | grep slurmrestd

# Start if needed
srun --wrap='slurmrestd -j localhost:8080'&
```

---

## Summary Checklist

- [ ] Install dependencies (clang, llvm, libbpf-devel)
- [ ] Build eBPF probe (`make bpfall`)
- [ ] Run BPF collector (test basic capture)
- [ ] Run baseline comparisons
- [ ] Run performance benchmarks
- [ ] Test cross-node coordinator
- [ ] Test Slurm integration (if available)
- [ ] Generate results and copy to local

---

## Next Steps

After collecting results:

1. Update PROPOSAL.md with measured values
2. Generate plots using the data
3. Run more extensive scalability tests (100+ agents)
4. Test on multiple EPYC nodes (cross-node)

Questions? Check the code in `src/` for implementation details.