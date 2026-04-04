# Paper Experiment Source

`src/paper/` contains the source code used to reproduce the research-paper evaluation.

## Packages

- `experiments/real/`: experiments run on real hardware
- `experiments/simulated/`: simulation-based experiments
- `attacks/`: attack workloads exercised by the paper
- `support/`: simulation primitives, experiment-only attestation logic, and baseline implementations
- `data/`: synthetic inputs and dataset-generation helpers

## Primary Entry Points

- `python3 -m src.paper.experiments.real.run_bpf_microbenchmark`
- `python3 -m src.paper.experiments.real.run_real_latency_capture`
- `python3 -m src.paper.experiments.simulated.run_all`
- `python3 -m src.paper.experiments.simulated.run_ablation`

Use `results/` for generated artifacts and `docs/SC26_EVALUATION.md` for the reproduction matrix.
