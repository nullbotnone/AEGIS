# AEGIS

AEGIS is a behavioral-attestation prototype for HPC AI agents. This repository is organized for two concrete goals:
- deploy AEGIS on a real Slurm cluster
- reproduce the SC26 evaluation with structured artifacts under `results/`

## Start Here

If you are operating a cluster:
- read [deploy/README.md](deploy/README.md)
- then follow [docs/REAL_CLUSTER_DEPLOYMENT.md](docs/REAL_CLUSTER_DEPLOYMENT.md)

If you are running the evaluation:
- read [src/paper/experiments/README.md](src/paper/experiments/README.md)
- store artifacts under `results/` as described in [docs/SC26_EVALUATION.md](docs/SC26_EVALUATION.md)
- use [docs/SC26_EVALUATION.md](docs/SC26_EVALUATION.md) for the concrete evaluation matrix and reproduction runbook

## Active Architecture

The current deployable path is:
- [bpf_collector.py](src/deployment/collector/bpf_collector.py) on each compute node
- [verifierd.py](src/deployment/control_plane/verifierd.py) on the verifier host
- [slurm_integration.py](src/deployment/enforcement/slurm_integration.py) for enforcement
- [verifier.py](src/deployment/core/verifier.py) as the policy core, including the audit ledger and cross-agent correlation

The simulation and experiment layers are still kept for reproducibility, but they are not required to deploy AEGIS on a cluster.

## Repository Map

- [src/README.md](src/README.md): source tree map
- [deploy/README.md](deploy/README.md): install the verifier, collector, and Slurm hooks
- [src/paper/experiments/README.md](src/paper/experiments/README.md): run the paper experiments
- [docs/README.md](docs/README.md): engineering guides and measurement notes
- [docs/SC26_EVALUATION.md](docs/SC26_EVALUATION.md): SC26 evaluation matrix and reproduction guide
- [figures/README.md](figures/README.md): paper figures and plot regeneration

## Quick Commands

Build the probe and microbenchmark:

```bash
make bpfall
make bench
```

Run the verifier daemon:

```bash
python3 -m src.deployment.control_plane.verifierd --config /etc/aegis/verifier.json serve
```

Run the node collector:

```bash
sudo python3 -m src.deployment.collector.bpf_collector --bpf /usr/share/aegis/aegis_probe.bpf.o --interval 1.0
```

Collect measured latency for one attack:

```bash
python3 -m src.paper.experiments.real.run_real_latency_capture --attack filesystem --interval 1.0 --repeats 3
```

Run the documented SC26 wrapper:

```bash
bash scripts/run_sc26_eval.sh
```

## Scope Note

`src/deployment/core/` models the behavioral-attestation semantics and is heavily unit tested. Real deployment uses that core through the service and collector wrappers rather than by importing the framework alone.
