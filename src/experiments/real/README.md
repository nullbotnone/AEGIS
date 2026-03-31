# Real Experiment Runners

`src/experiments/real/` contains measured experiments.

## What These Scripts Measure

These runners measure either:
- direct kernel/eBPF overhead using the real probe and syscall microbenchmark
- measured framework-path attestation and verifier cycles using instrumented attack scenarios

They are closer to deployment than the synthetic runners, but they are still evaluation code, not the production daemon path.

## Main Entry Points

- `run_bpf_microbenchmark.py`: paired baseline vs attached probe measurements, writes JSON under `results/`
- `run_real_latency_capture.py`: one attack/interval measured latency capture, writes JSON under `results/`
- `run_latency_sweep.py`: interval sweep for measured detection latency, writes JSON under `results/`
- `run_ablation.py`: measured ablation study, writes JSON under `results/`
- `real_latency.py`: shared measurement helpers for the framework-path experiments
