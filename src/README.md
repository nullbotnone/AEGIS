# AEGIS Source Tree

`src/` is organized around two concrete code paths:
- `deployment/`: code used to run AEGIS on real HPC clusters
- `paper/`: code used to reproduce the research-paper experiments

## Deployment Path

Start at [deployment/README.md](deployment/README.md).

Key packages:
- `deployment/core/`: verifier, constraints, attestation model, containment, tests
- `deployment/control_plane/`: long-running verifier daemon
- `deployment/collector/`: node-side collector, job registry, attach helper
- `deployment/enforcement/`: Slurm containment implementation
- `deployment/bpf/`: eBPF probe source and syscall microbenchmark

Primary commands:
- `python3 -m src.deployment.control_plane.verifierd`
- `python3 -m src.deployment.collector.bpf_collector`
- `make bpfall`
- `python3 -m unittest discover -s src/deployment/core/tests -v`

## Paper Evaluation Path

Start at [paper/README.md](paper/README.md).

Key packages:
- `paper/experiments/real/`: measured experiments on real hardware
- `paper/experiments/simulated/`: simulation-based experiments
- `paper/attacks/`: attack workloads used by the paper
- `paper/support/`: simulation support layer and experiment-only attestation logic
- `paper/data/`: synthetic datasets and dataset-generation helpers
