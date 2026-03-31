# Results Directory

`results/` is the canonical destination for fresh evaluation artifacts.

## Artifact Policy

Write new measurement outputs here rather than into checked-in markdown notes elsewhere in the repo.

Expected artifact families include:
- `bpf_microbenchmark_*.json`
- `real_latency_*.json`
- `real_latency_sweep_*.json`
- `real_ablation_*.json`
- `simulated_all_attacks_*.json`
- `simulated_ablation_*.json`
- `simulated_false_positive_*.json`
- `simulated_performance_*.json`
- `baseline_comparison_*.md`

Generated result artifacts do not need to be committed. Treat this directory as the working output location for each evaluation campaign.

## Collection For SC26

For each campaign, preserve:
- all generated JSON and markdown artifacts
- the commit hash
- verifier and collector configs used for the run
- service logs when the deployment path is involved

A minimal archive recipe is:

```bash
mkdir -p results/sc26_bundle
cp results/*.json results/*.md results/sc26_bundle/ 2>/dev/null || true
git rev-parse HEAD > results/sc26_bundle/commit.txt
```

If you ran deployed services, also archive:

```bash
journalctl -u aegis-verifier.service > results/sc26_bundle/verifier.log
journalctl -u aegis-collector.service > results/sc26_bundle/collector.log
```
