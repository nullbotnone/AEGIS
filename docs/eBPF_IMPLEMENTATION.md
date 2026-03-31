# AEGIS eBPF Implementation Notes

This document summarizes the current node-side implementation.

## Components

- `src/bpf/aegis_probe.c`: eBPF syscall probe source
- `src/attestation/bpf_collector.py`: userspace collector that attaches the probe, polls events, signs evidence, and submits or spools bundles
- `src/attestation/job_registry.py`: Slurm job registration and PID-to-job binding

## Covered Syscall Families

The current probe covers the syscall families used by the design:
- file access via `openat`
- byte-volume tracking via `read` and `write`
- network connection and send tracking
- tool execution via `execve`

## Build And Entry Points

Build the probe and paired benchmark:

```bash
make bpfall
make bench
```

Collector CLI:

```bash
python3 -m src.attestation.bpf_collector --help
```

Attach-only helper for measurement support:

```bash
sudo python3 -m src.attestation.bpf_attach --bpf src/bpf/aegis_probe.bpf.o
```

Direct microbenchmark example:

```bash
sudo python3 -m src.experiments.real.run_bpf_microbenchmark --mode openat --iters 200000 --repeats 9
```

## Relationship To Deployment

The probe and collector are the node-local half of AEGIS. Full deployment also requires:
- `src/services/verifierd.py`
- `src/framework/verifier.py`
- `src/defense/slurm_integration.py`
- the Slurm hook files under `deploy/slurm/`

Use [REAL_CLUSTER_DEPLOYMENT.md](REAL_CLUSTER_DEPLOYMENT.md) for the full deployment path.
