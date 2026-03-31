# AEGIS Figures

`figures/` contains paper figures and the notebook used to regenerate them from SC26 evaluation artifacts.

## Inputs

Run one evaluation campaign first and place its artifacts under `results/sc26_run_*`.

The notebook reads:
- `baseline_comparison.md`
- `bpf_microbenchmark_*.json`
- `real_latency_*.json`
- `real_latency_sweep.json`
- `real_ablation.json`
- `simulated_all_attacks.json`
- `simulated_ablation.json`
- `simulated_false_positive.json`
- `simulated_performance.json`

The false-positive artifact reflects the expanded benign suite used for the paper: standard single-agent workflows, authorized multi-agent collaboration, budget-edge LLM reporting, and tool-heavy benign postprocessing.

By default, [paper_figures.ipynb](paper_figures.ipynb) auto-selects the newest `results/sc26_run_*` directory. To target a specific campaign, set `AEGIS_RESULTS_DIR` before executing it.

## Outputs

The notebook regenerates the SC26 paper figure set:
- `baseline_comparison.png`
- `attack_results.png`
- `ablation_heatmap.png`
- `latency_tradeoff.png`
- `microbenchmark_breakdown.png`
- `simulated_ablation_breakdown.png`
- `scaling_sweep.png`
- `false_positive_summary.png`: benign-suite coverage with explicit no-false-positive outcome
- `performance_overhead.png`

## Regeneration

From `figures/`:

```bash
jupyter nbconvert --to notebook --execute paper_figures.ipynb --output paper_figures.ipynb
```

For a specific campaign:

```bash
AEGIS_RESULTS_DIR=../results/sc26_run_20260331T165053Z \
  jupyter nbconvert --to notebook --execute paper_figures.ipynb --output paper_figures.ipynb
```
