# AEGIS: Behavioral Attestation for AI Agents in HPC

AEGIS (Attestation-based Environment for Guarding Injection-vulnerable Systems) provides runtime behavioral attestation for AI agents in HPC environments. It detects and contains hijacked agents through constraint-based verification.

## Architecture

```
AEGIS/src/
├── bpf/                  # eBPF syscall probe (kernel-side)
│   └── aegis_probe.c     # Hooks: openat, read, write, connect, execve
├── attestation/          # Attestation engine (user-space)
│   ├── bpf_collector.py           # Ring buffer → evidence bundles
│   ├── tpm_attestation.py         # Hardware-rooted signing (TPM 2.0)
│   └── cross_node_coordinator.py  # Covert channel detection
├── defense/              # Baseline comparisons & containment
│   ├── baseline_comparison.py     # DLP, audit, analytics, sandbox
│   └── slurm_integration.py       # Containment (suspend/terminate)
├── framework/            # Core attestation logic
│   ├── attestation.py    # Evidence generation
│   ├── verifier.py       # Policy evaluation
│   └── policy_engine.py  # Constraint checking
├── attacks/              # Four attack implementations
├── experiments/          # Experiment runners
└── common/               # Utilities
```

## Components

### eBPF Probe (`bpf/`)
Kernel-side syscall monitoring with <2% overhead:
- `sys_enter_openat` — file access detection
- `sys_enter_read/write` — byte counters
- `sys_enter_connect` — network connections
- `sys_enter_execve` — tool invocations

### Attestation Engine (`attestation/`)
- **bpf_collector**: Reads eBPF ring buffer, generates evidence bundles
- **tpm_attestation**: TPM 2.0 hardware signing for chain of trust
- **cross_node_coordinator**: Cluster-wide correlation for covert channel detection

### Baseline Comparisons (`defense/`)
- Network DLP (50% detection)
- Filesystem auditing (50%)
- Per-agent analytics (0%)
- Strict sandboxing (50%)

### Slurm Integration (`defense/`)
- Job suspension via REST API
- Job termination
- Kerberos credential revocation (`kdestroy`)
- cgroup-based rate limiting

## Quick Start

### Build eBPF Probe

```bash
cd research/AEGIS
make bpfall
```

### Run Attestation Collector

```bash
# Requires root for eBPF
sudo python3 -m src.attestation.bpf_collector --verbose
```

### Run Baseline Comparisons

```bash
python3 -m src.defense.baseline_comparison
```

### Test Cross-Node Coordinator

```bash
python3 -m src.attestation.cross_node_coordinator
```

### Run All Experiments

```bash
python3 -m src.experiments.run_all
```

## Requirements

- Python 3.8+
- clang, llvm, libbpf-devel (for eBPF)
- Root access (for eBPF and containment)

## Testing on AMD EPYC

See `docs/EPYC_TESTING_GUIDE.md` for detailed instructions on running evaluation on AMD EPYC hardware.

## Paper

This code accompanies the AEGIS paper: "Attestation is All You Need: Toward a Zero-Trust Architecture for HPC AI Agents" (SC26).