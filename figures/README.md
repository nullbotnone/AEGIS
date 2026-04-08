# AEGIS Figures

`figures/` contains paper figures, a script-backed generator, and a notebook wrapper used to regenerate them from SC26 evaluation artifacts.

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
- `simulated_performance.json` when present in the same result bundle

If `simulated_performance.json` is stored separately, set `AEGIS_PERF_ARTIFACT` to its path before executing the notebook.

The false-positive artifact reflects the expanded benign suite used for the paper: standard single-agent workflows, authorized multi-agent collaboration, budget-edge LLM reporting, and tool-heavy benign postprocessing.

By default, [paper_figures.ipynb](paper_figures.ipynb) auto-selects the newest `results/sc26_run_*` directory. To target a specific campaign, set `AEGIS_RESULTS_DIR` before executing it.

## Outputs

`generate_paper_figures.py` regenerates the SC26 paper figure set and emits both PNG and PDF outputs for the plots. The notebook is a thin wrapper around that script.
- `baseline_comparison.png`
- `attack_results.png`
- `ablation_heatmap.png`
- `simulated_ablation_breakdown.png`
- `scaling_sweep.png`
- `performance_overhead.png`
- `performance_summary.png`

## Regeneration

From `figures/`:

```bash
python3 generate_paper_figures.py
```

Notebook wrapper:

```bash
jupyter nbconvert --to notebook --execute paper_figures.ipynb --output paper_figures.ipynb
```

For a specific campaign:

```bash
AEGIS_RESULTS_DIR=../results/sc26_run_20260331T165053Z \
  jupyter nbconvert --to notebook --execute paper_figures.ipynb --output paper_figures.ipynb
```

When the scaling appendix artifact is stored elsewhere:

```bash
AEGIS_RESULTS_DIR=../results/sc26_run_20260331T165053Z \
AEGIS_PERF_ARTIFACT=/path/to/simulated_performance.json \
  jupyter nbconvert --to notebook --execute paper_figures.ipynb --output paper_figures.ipynb
```
