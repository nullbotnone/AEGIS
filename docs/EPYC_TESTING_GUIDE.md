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
    git \
    perf

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
Event: PID=1234 NETWORK_CONN endpoint=ipv4
```

Note: the current probe records network family (`ipv4` / `ipv6`) and port from the
`connect` syscall tracepoint. It does not resolve hostnames such as `api.openai.com`
at capture time.

---

## Run Direct Kernel/eBPF Microbenchmark

### 1. Build the Syscall Driver

```bash
cd /home/user/aegis

# Build the kernel-side probe and the userspace syscall driver
make bpfall
make bench
```

This produces:
- `src/bpf/aegis_probe.bpf.o`
- `src/bpf/syscall_microbench`

If you install AEGIS system-wide later, `make install` now also installs the attach-only
loader and the syscall microbenchmark under the AEGIS share directory.

### 1a. Use the Automated Paired Benchmark Runner

If you want one command that runs the baseline and attached trials, saves structured
results, and prints the median overhead directly, use:

```bash
cd /home/user/aegis
sudo python3 -m src.experiments.real.run_bpf_microbenchmark \
  --mode openat \
  --iters 200000 \
  --repeats 9
```

That script:
- builds the probe and syscall driver unless `--skip-build` is set
- runs paired baseline and attached trials
- pins the workload with `taskset`
- captures `perf stat` counters plus the workload's `ops_per_sec`
- writes a JSON artifact under `results/`

Useful options:

```bash
# Network-focused measurement
sudo python3 -m src.experiments.real.run_bpf_microbenchmark \
  --mode connect \
  --iters 100000 \
  --repeats 9 \
  --probe-scope auto

# File-only probe path on a specific CPU
sudo python3 -m src.experiments.real.run_bpf_microbenchmark \
  --mode read \
  --iters 200000 \
  --size 4096 \
  --cpu 4 \
  --probe-scope file
```

### 2. Measure a Baseline Without eBPF Attached

Use `perf stat` around the C microbenchmark, not around a Python loop. Pin the
workload to one CPU to reduce scheduler noise:

```bash
cd /home/user/aegis
taskset -c 2 perf stat -r 15 \
  -e task-clock,cycles,instructions,branches,branch-misses,cache-misses,context-switches,cpu-migrations \
  ./src/bpf/syscall_microbench --mode openat --iters 200000 --path /tmp/aegis-open.dat
```

Good first targets are:
- `openat` for file-open tracepoints
- `read` or `write` for steady file I/O hooks
- `connect` for network hooks
- `execve` for process-launch hooks

### 3. Attach the Probe Without Userspace Ring-Buffer Polling

For direct kernel/eBPF overhead, keep the probe attached but do not poll events in
Python. The attach-only loader below uses the same BPF object and config map as the
collector, but it avoids userspace event-processing noise.

```bash
cd /home/user/aegis
sudo python3 -m src.attestation.bpf_attach --bpf src/bpf/aegis_probe.bpf.o
```

You can narrow the active policy paths while benchmarking:

```bash
# File-only overhead
sudo python3 -m src.attestation.bpf_attach \
  --bpf src/bpf/aegis_probe.bpf.o \
  --disable-network --disable-exec

# Network-only overhead
sudo python3 -m src.attestation.bpf_attach \
  --bpf src/bpf/aegis_probe.bpf.o \
  --disable-file --disable-exec
```

### 4. Re-run the Exact Same Workload

With the attach-only loader running in another terminal:

```bash
cd /home/user/aegis
taskset -c 2 perf stat -r 15 \
  -e task-clock,cycles,instructions,branches,branch-misses,cache-misses,context-switches,cpu-migrations \
  ./src/bpf/syscall_microbench --mode openat --iters 200000 --path /tmp/aegis-open.dat
```

Compute overhead from the median `task-clock` or from the microbenchmark's
`ops_per_sec` line:

```text
overhead % = 100 * (attached_time - baseline_time) / baseline_time
```

### 5. Example Modes

```bash
# File-open benchmark
./src/bpf/syscall_microbench --mode openat --iters 200000 --path /tmp/aegis-open.dat

# File-read benchmark
./src/bpf/syscall_microbench --mode read --iters 200000 --size 4096 --path /tmp/aegis-read.dat

# File-write benchmark
./src/bpf/syscall_microbench --mode write --iters 100000 --size 4096 --path /tmp/aegis-write.dat

# TCP connect benchmark (closed localhost port is fine; the connect syscall still executes)
./src/bpf/syscall_microbench --mode connect --iters 100000 --host 127.0.0.1 --port 9

# execve benchmark
./src/bpf/syscall_microbench --mode execve --iters 5000
```

### 6. Notes on Interpreting the Numbers

- This method measures direct kernel/eBPF hook cost much more cleanly than
  `python3 -m src.experiments.simulated.run_performance`.
- If you use `src.attestation.bpf_collector`, you will measure both kernel hook cost
  and Python ring-buffer polling/parsing overhead.
- Benchmark one syscall family at a time. Starting with the full mixed probe makes
  the deltas harder to explain.
- Report medians across repeats. Single-run `perf stat` numbers are too noisy for a
  credible claim.

## Run Baseline Comparisons

### 1. Run the Comparative Baseline Experiment

```bash
cd /home/user/aegis

# Run the simulated baseline-comparison experiment
python3 -m src.experiments.simulated.run_baseline_comparison
```

### 2. Expected Output

```
================================================================================
EXPERIMENT: BASELINE COMPARISON
================================================================================

Baseline: AEGIS
  Detection rate: ...
  Avg detection time: ... ms

Baseline: Network DLP
  Detection rate: ...
```

---

## Run Performance Benchmarks

### 1. Run Repo-Backed Performance Experiments

```bash
cd /home/user/aegis

# Overall throughput/overhead sweep
python3 -m src.experiments.simulated.run_performance

# Detection latency vs. attestation interval (measured verifier cycles)
python3 -m src.experiments.real.run_latency_sweep

# Real ablation study over measured framework controls
python3 -m src.experiments.real.run_ablation \
  --interval 1.0 \
  --repeats 3

# Single attack / interval capture with JSON output
python3 -m src.experiments.real.run_real_latency_capture \
  --attack filesystem \
  --interval 1.0 \
  --repeats 3
```

### 2. Expected Output

Both scripts print summary tables to stdout. The exact numbers will vary by node,
Python version, and background load, but you should see:

- interval sweeps across multiple attestation settings
- aggregate overhead or throughput summaries
- measured latency / exfiltration summaries from real framework attestation cycles
- measured ablation summaries showing which real controls still catch each attack
- JSON artifacts under `results/` for `run_real_latency_capture` and `run_ablation`

Note: `python3 -m src.experiments.simulated.run_performance` is still a simulation-style Python
workload benchmark. `python3 -m src.experiments.real.run_latency_sweep`,
`python3 -m src.experiments.real.run_real_latency_capture`, and
`python3 -m src.experiments.real.run_ablation` use measured framework
attestation and policy-verification cycles, but they are still not a direct substitute
for kernel-level eBPF microbenchmarking of hook overhead.

---

## Test Cross-Node Coordination

### 1. Start Central Coordinator

```bash
# Terminal 1: Start coordinator (requires network access between nodes)
python3 -m src.attestation.cross_node_coordinator --port 9090
```

### 2. Test Covert Channel Detection

```bash
cd /home/user/aegis

# Run the coordinated exfiltration test (simulation driver)
python3 -m src.experiments.simulated.run_attack4
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

### 1. Run the Main Experiment Drivers

```bash
cd /home/user/aegis
mkdir -p results

# Run all simulated attack drivers and capture the console summary
python3 -m src.experiments.simulated.run_all | tee results/run_all.txt

# Run the simulated baseline comparison and capture the console summary
python3 -m src.experiments.simulated.run_baseline_comparison | tee results/run_baseline_comparison.txt

# Optional: run the simulated ablation and false-positive studies
python3 -m src.experiments.simulated.run_ablation | tee results/run_ablation.txt
python3 -m src.experiments.simulated.run_ablation_v2 | tee results/run_ablation_v2.txt
python3 -m src.experiments.simulated.run_false_positive | tee results/run_false_positive.txt

# Run performance-related experiments
python3 -m src.experiments.simulated.run_performance | tee results/run_performance.txt
python3 -m src.experiments.real.run_latency_sweep | tee results/run_latency_sweep.txt

# Capture measured framework-path latency data as JSON
python3 -m src.experiments.real.run_real_latency_capture \
  --attack filesystem \
  --interval 1.0 \
  --repeats 3 \
  --output results/real_latency_filesystem_1s.json

# Capture measured real-ablation data as JSON
python3 -m src.experiments.real.run_ablation \
  --interval 1.0 \
  --repeats 3 \
  --output results/real_ablation_1s.json

# Capture direct kernel/eBPF microbenchmark data as JSON
sudo python3 -m src.experiments.real.run_bpf_microbenchmark \
  --mode openat \
  --iters 200000 \
  --repeats 9 \
  --output results/bpf_microbenchmark_openat.json
```

### 2. Output Format

The current repository prints summaries to stdout and, for the real-metrics paths,
also writes JSON artifacts. Documented outputs that are directly supported by the code are:

- `results/run_all.txt`
- `results/run_baseline_comparison.txt`
- `results/run_ablation.txt`
- `results/run_ablation_v2.txt`
- `results/run_false_positive.txt`
- `results/run_performance.txt`
- `results/run_latency_sweep.txt`
- `results/real_latency_*.json` from `src.experiments.real.run_real_latency_capture`
- `results/real_ablation_*.json` from `src.experiments.real.run_ablation`
- `results/bpf_microbenchmark_*.json` from `src.experiments.real.run_bpf_microbenchmark`
- `experiments/baseline_results.md` from `src.experiments.simulated.run_baseline_comparison`

For real metrics, use:
- `src.experiments.real.run_bpf_microbenchmark` for direct kernel/eBPF hook overhead
- `src.experiments.real.run_real_latency_capture` and `src.experiments.real.run_latency_sweep` for measured framework attestation / verification latency
- `src.experiments.real.run_ablation` for measured control ablations over the real framework path

`src.experiments.simulated.run_performance` remains a simulation benchmark and should not be
used as your primary source for real performance claims.

The attack, ablation, false-positive, and baseline-comparison drivers under
`src.experiments.simulated.*` are also simulation-based. Use them for comparative
evaluation, not for direct kernel/eBPF performance claims.

### 3. Collect Results

```bash
# Tarball captured results for transfer to local machine
tar -czvf aegis-results-$(date +%Y%m%d).tar.gz results/ experiments/baseline_results.md

# Copy to local
scp epyc-node:/home/user/aegis/aegis-results-*.tar.gz ./
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
- [ ] Run real framework-latency capture (`run_real_latency_capture`)
- [ ] Run direct kernel/eBPF microbenchmark (`run_bpf_microbenchmark`)
- [ ] Run simulation benchmark only if needed for comparative modeling
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