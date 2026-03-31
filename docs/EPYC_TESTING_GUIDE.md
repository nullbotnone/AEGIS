# AEGIS EPYC Testing Guide

This guide is for preparing and validating a single AMD EPYC measurement host.

Use [SC26_EVALUATION.md](SC26_EVALUATION.md) for the full paper run order and exact experiment commands.

## Purpose

Use this guide to:
- install the packages needed for the real measurement path
- build the eBPF probe and paired microbenchmark
- confirm that probe attach works on the target host
- run one or two smoke measurements before a larger campaign

## Baseline Environment

Recommended baseline:
- Rocky Linux 9.x or equivalent
- Linux kernel 5.14 or later
- AMD EPYC node with root access
- `clang`, `llvm`, `libbpf-devel`, `kernel-devel`, `elfutils-libelf-devel`, `make`, `perf`, `python3`

Install on Rocky Linux:

```bash
sudo dnf install -y clang llvm libbpf-devel kernel-devel elfutils-libelf-devel make perf python3
```

## Build

From the repository root:

```bash
make bpfall
make bench
```

Expected build outputs:
- `src/bpf/aegis_probe.bpf.o`
- `src/bpf/syscall_microbench`

## Smoke Validation

Check that the collector CLI is available:

```bash
python3 -m src.attestation.bpf_collector --help
```

Run one direct microbenchmark:

```bash
sudo python3 -m src.experiments.real.run_bpf_microbenchmark \
  --mode openat \
  --iters 200000 \
  --repeats 9
```

Run one verifier-path latency measurement:

```bash
python3 -m src.experiments.real.run_real_latency_capture \
  --attack filesystem \
  --interval 1.0 \
  --repeats 3
```

If these succeed, the node is ready for the full SC26 workflow.

## Output Handling

By default, experiment scripts write artifacts under `results/`.

For paper campaigns, archive:
- generated JSON and markdown artifacts
- the current git commit hash
- deployed verifier and collector configs if services were involved
- `journalctl` logs for `aegis-verifier.service` and `aegis-collector.service` when applicable

Use [SC26_EVALUATION.md](SC26_EVALUATION.md) for the full artifact checklist.
