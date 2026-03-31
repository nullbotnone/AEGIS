# Simulated Experiment Runners

`src/experiments/simulated/` contains the synthetic evaluation suite used to exercise attacks, ablations, false-positive behavior, and throughput overhead.

## Main Entry Points

- `run_all.py`: full synthetic attack suite, writes JSON under `results/`
- `run_ablation.py`: synthetic ablation study, writes JSON under `results/`
- `run_false_positive.py`: benign-workflow false-positive study, writes JSON under `results/`
- `run_performance.py`: synthetic overhead study, writes JSON under `results/`
- `run_baseline_comparison.py`: comparative baseline study, writes markdown under `results/`

## Scope

These runners still depend on the legacy simulation layer in `src/common/`, `src/attacks/`, and `src/defense/attestation.py`. That code remains because it is part of the reproducible paper evaluation, not because it is part of the real-cluster deployment path.
