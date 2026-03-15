# Real Cluster Experiments — Design Document

## Overview

This branch contains the experiment framework for running AEGIS on an actual Slurm HPC cluster with real AI agents. These experiments replace the simulated proof-of-concept on `master` with production-quality validation.

## Hardware

| Node | Hardware | CPU / GPU | RAM | OS | Role |
|------|----------|-----------|-----|----|------|
| 4× compute | Radxa X2L | Intel N100 (4 cores, 3.4 GHz) | 8 GB DDR4 | Ubuntu 24.04 | Agent execution, eBPF monitoring |
| 1× controller | NVIDIA Jetson Orin Nano | 6-core ARM, 128-core Ampere GPU | 8 GB LPDDR5 | JetPack 6.0 | Policy verifier, coordination |

Network: TP-Link TL-SG108 switch with port mirroring (1 GbE)

## Software Prerequisites

- Ubuntu 24.04 with Linux kernel 6.8+ (eBPF support)
- Slurm 23.11+
- Shared NFS filesystem (simulates Lustre at smaller scale)
- Python 3.12+ on all nodes
- LLM API access (OpenAI, Anthropic, or local LLM)
- BCC library for eBPF monitoring
- Root/sudo on compute nodes (for eBPF)
- At least 2 user accounts (for multi-user experiments)
- Slurm-based HPC cluster (≥4 nodes, ideally 10+)
- Shared parallel filesystem (Lustre, GPFS, or BeeGFS)
- Python 3.10+ on all nodes
- LLM API access (OpenAI, Anthropic, or local LLM)
- Root/sudo access on compute nodes (for eBPF monitoring)
- At least 2 user accounts (for multi-user experiments)

## Architecture

```
real-cluster/
├── agent/                  # Real AI agent implementation
│   ├── agent.py           # Agent with actual LLM API calls
│   ├── tools.py           # Real tools (HDF5 reader, CSV parser, etc.)
│   └── task_executor.py   # Task execution with real file I/O
├── monitor/               # Real-time monitoring
│   ├── ebpf_monitor.py    # eBPF-based syscall monitoring
│   ├── fallback_monitor.py # ptrace/strace fallback (no root required)
│   └── aggregator.py      # Central evidence collector
├── attestation/           # AEGIS attestation engine
│   ├── constraints.py     # Constraint profiles
│   ├── verifier.py        # Policy verification
│   └── containment.py     # Slurm-based containment (scancel, sacctmgr)
├── attacks/               # Real attack implementations
│   ├── fs_injection.sh    # Filesystem injection (Slurm batch script)
│   ├── colocation.sh      # Co-location injection
│   ├── supply_chain.py    # Compromised tool
│   └── coordinated.sh     # Multi-node coordinated attack
├── baselines/             # Baseline defense implementations
│   ├── dlp_monitor.py     # Real network monitoring (tcpdump/tshark)
│   ├── fs_audit.py        # Real filesystem auditing (auditd/inotify)
│   ├── behavioral.py      # Behavioral analytics (statsmodels)
│   └── sandbox.sh         # Container-based sandboxing (Apptainer/Singularity)
├── experiments/           # Experiment runners
│   ├── run_attack1_real.sh
│   ├── run_attack2_real.sh
│   ├── run_attack3_real.sh
│   ├── run_attack4_real.sh
│   ├── run_baselines.sh
│   ├── run_ablation.sh
│   └── run_overhead.sh
├── data/                  # Real scientific datasets (or generators)
└── scripts/               # Cluster setup and utility scripts
```

## Key Differences from Simulation

| Aspect | Simulation (master) | Real Cluster (this branch) |
|--------|--------------------|-----------------------------|
| Agent execution | Scripted actions | Real LLM API calls, real file I/O |
| Monitoring | Action log inspection | eBPF syscall tracing |
| Filesystem | In-memory SharedFilesystem | Real Lustre/GPFS |
| Network | Simulated endpoints | Real HTTPS connections |
| Scheduler | None | Real Slurm job submission |
| Containment | In-process flags | scancel, sacctmgr, cgroups |
| Timing | time.perf_counter() | Actual end-to-end latency |
| Scale | 4 agents | 10-100+ agents |
| Data | Synthetic (<1MB) | Real scientific datasets (GB) |

## Experiment Plan

### Experiment 1: Filesystem-Mediated Injection (Real)

**Setup:**
1. Create shared project directory on Lustre: `/projects/shared/aegis-exp1/`
2. Place real HDF5 dataset with embedded injection payload in metadata
3. Place real credentials file (synthetic but realistic)
4. Submit Slurm job running victim agent

**Victim agent task:**
```python
# Real agent reads real data and makes real LLM call
import h5py
data = h5py.File('/projects/shared/aegis-exp1/dataset.h5', 'r')
metadata = dict(data.attrs)  # Injection payload in metadata
response = llm.analyze(metadata)  # Real API call
```

**Measure:**
- eBPF monitor captures all syscalls
- AEGIS attestation evaluates against constraints
- Time from injection to detection
- Data exfiltrated (intercept API call payload)

### Experiment 2: Co-Location Injection (Real)

**Setup:**
1. Submit two Slurm jobs that land on same node (use `--nodelist` or `--constraint`)
2. Both have access to shared `/tmp`
3. Attacker job writes to `/tmp/aegis-exp2-shared.log`
4. Victim job reads it

**Key challenge:** Ensuring co-location. Solutions:
- Use `--nodelist=<specific-node>` for both jobs
- Or use Slurm's `--pack-group` feature
- Or measure co-location probability over many submissions

### Experiment 3: Supply Chain Injection (Real)

**Setup:**
1. Create a real Python package/tool that victim agent uses
2. Tool performs real data conversion
3. Tool output contains injection payload in metadata

### Experiment 4: Coordinated Multi-Agent Exfiltration (Real)

**Setup:**
1. Submit 4 Slurm jobs on 4 different nodes
2. Jobs 1 and 3 run hijacked agents
3. Real covert channel via shared filesystem
4. Measure cross-agent detection

### Experiment 5: Performance Overhead (Real)

**Setup:**
1. Run representative HPC workloads with/without AEGIS
2. Measure actual overhead

**Workloads:**
- HPCG (standard HPC benchmark)
- LAMMPS (molecular dynamics)
- TensorFlow/PyTorch training
- IOR (filesystem benchmark)

**Measurements:**
- Application throughput (jobs/hour)
- CPU overhead (% of core for monitoring)
- Memory overhead (RSS of monitor)
- Network overhead (bytes for attestation traffic)
- Filesystem overhead (extra I/O for audit logging)

## Implementation Status

- [ ] Real agent with LLM API integration
- [ ] eBPF monitor (requires root)
- [ ] Fallback monitor (ptrace/strace, no root)
- [ ] Slurm job scripts for each attack
- [ ] Baseline implementations (DLP, FS audit, etc.)
- [ ] Overhead measurement framework
- [ ] Result collection and analysis scripts

## Running on a Cluster

### Quick Start

```bash
# 1. Clone and setup
git clone <repo>
cd AEGIS
git checkout real-cluster-experiments
cd real-cluster

# 2. Install dependencies
pip install -r requirements.txt

# 3. Setup cluster environment
./scripts/setup_cluster.sh

# 4. Run all experiments
./experiments/run_all_real.sh

# 5. Collect results
./scripts/collect_results.sh
```

### Configuration

Create `config.yaml`:
```yaml
cluster:
  scheduler: slurm
  partition: gpu  # or compute
  account: aegis-research
  nodes: 4

agent:
  llm_provider: openai  # or anthropic, local
  llm_model: gpt-4o
  api_key_env: OPENAI_API_KEY

monitor:
  method: ebpf  # or ptrace, strace
  interval_ms: 1000

attestation:
  interval_seconds: 1
  verifier_host: login-node
  verifier_port: 8443
```
