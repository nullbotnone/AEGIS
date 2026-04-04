# Experiment Entry Points

`src/paper/experiments/` contains the runnable evaluation scripts used for the paper.

## Subdirectories

- `real/`: measured framework-path and kernel/eBPF experiments
- `simulated/`: synthetic attack, ablation, false-positive, and performance studies

## Result Policy

Use the runners in this directory to generate fresh artifacts under `results/`. Do not treat older checked-in markdown summaries or ad hoc local outputs as authoritative rerun outputs.

## Deployment Boundary

These scripts are for evaluation. To operate AEGIS on a cluster, use:
- `src/deployment/control_plane/verifierd.py`
- `src/deployment/collector/bpf_collector.py`
- `deploy/systemd/`
- `deploy/slurm/`
