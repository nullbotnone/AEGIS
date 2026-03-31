# Experiment Entry Points

`src/experiments/` contains the runnable evaluation scripts used for the paper.

## Subdirectories

- `real/`: measured framework-path and kernel/eBPF experiments
- `simulated/`: synthetic attack, ablation, false-positive, and performance studies

## Result Policy

Use the runners in this directory to generate fresh artifacts under `results/`. Do not treat older markdown summaries in the top-level `experiments/` directory as authoritative rerun outputs.

## Deployment Boundary

These scripts are for evaluation. To operate AEGIS on a cluster, use:
- `src/services/verifierd.py`
- `src/attestation/bpf_collector.py`
- `deploy/systemd/`
- `deploy/slurm/`
