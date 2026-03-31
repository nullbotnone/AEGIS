# Experiment Directory

The top-level `experiments/` directory is intentionally minimal.

## Purpose

- keep this README as the pointer to the evaluation workflow
- avoid mixing fresh results with stale checked-in markdown or JSON snapshots

## Use Instead

Run experiments from `src/experiments/` and write outputs into `results/`.

Start here:
- [src/experiments/README.md](../src/experiments/README.md)
- [docs/EPYC_TESTING_GUIDE.md](../docs/EPYC_TESTING_GUIDE.md)
- [results/README.md](../results/README.md)
- [docs/SC26_EVALUATION.md](../docs/SC26_EVALUATION.md)
- `bash scripts/run_sc26_eval.sh` for the wrapper around that workflow
