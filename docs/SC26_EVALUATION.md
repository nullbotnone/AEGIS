# SC26 Evaluation Matrix And Reproduction Guide

This is the canonical runbook for reproducing the AEGIS evaluation for an SC26 paper submission.

AEGIS uses two experiment families:
- `real`: measured results from the implemented eBPF and verifier path
- `simulated`: controlled studies for broader attack coverage, ablation, and baseline comparison

Use both, but keep their claims separate.

## Claim Boundaries

Use `real` experiments for claims about:
- implementation completeness
- deployment viability
- syscall and probe overhead
- attestation and verification latency
- measured behavior on EPYC hardware or the real cluster path

Use `simulated` experiments for claims about:
- broader attack-space coverage
- component-necessity ablation
- false-positive behavior on benign workflows
- comparison against baseline defenses

Do not present simulated overhead or latency as measured deployment data.

## Evaluation Matrix

| Paper Question | Source | Script | Output Artifact | Paper Placement |
|---|---|---|---|---|
| Direct eBPF probe overhead | Real | `python3 -m src.experiments.real.run_bpf_microbenchmark` | `results/bpf_microbenchmark_*.json` | Main paper |
| Latency vs attestation interval | Real | `python3 -m src.experiments.real.run_latency_sweep` | `results/real_latency_sweep_*.json` | Main paper |
| Measured latency and exfiltration per attack | Real | `python3 -m src.experiments.real.run_real_latency_capture` | `results/real_latency_*.json` | Main paper |
| Measured policy-dimension ablation | Real | `python3 -m src.experiments.real.run_ablation` | `results/real_ablation_*.json` | Main paper |
| Controlled full-attack detection coverage | Simulated | `python3 -m src.experiments.simulated.run_all` | `results/simulated_all_attacks_*.json` | Main paper if labeled simulation |
| Detection component ablation | Simulated | `python3 -m src.experiments.simulated.run_ablation` | `results/simulated_ablation_*.json` | Main paper if labeled simulation |
| False-positive behavior on benign workflows | Simulated | `python3 -m src.experiments.simulated.run_false_positive` | `results/simulated_false_positive_*.json` | Main paper if labeled simulation |
| Baseline comparison | Simulated | `python3 -m src.experiments.simulated.run_baseline_comparison` | `results/baseline_comparison_*.md` | Main paper if labeled simulation |
| Synthetic scaling trends | Simulated | `python3 -m src.experiments.simulated.run_performance` | `results/simulated_performance_*.json` | Appendix or secondary table |

## Prerequisites

Install the measurement dependencies:

```bash
sudo dnf install -y clang llvm libbpf-devel kernel-devel elfutils-libelf-devel make perf python3
```

Build the probe and benchmark harness:

```bash
make bpfall
make bench
```

## Recommended Run Order

1. Run the real microbenchmarks.
2. Run the real verifier-path latency studies.
3. Run the simulated coverage, ablation, false-positive, and baseline studies.
4. Archive all artifacts under `results/sc26_bundle/` or a campaign-specific directory.

## Wrapper Script

For one-command execution of the documented workflow:

```bash
bash scripts/run_sc26_eval.sh
```

Useful variants:

```bash
bash scripts/run_sc26_eval.sh --mode real
bash scripts/run_sc26_eval.sh --mode simulated
bash scripts/run_sc26_eval.sh --output-dir results/sc26_camera_ready --collect-configs --collect-logs
```

## Manual Reproduction Commands

### Real measurements

Direct probe overhead:

```bash
sudo python3 -m src.experiments.real.run_bpf_microbenchmark \
  --mode openat \
  --iters 200000 \
  --repeats 9

sudo python3 -m src.experiments.real.run_bpf_microbenchmark \
  --mode read \
  --iters 200000 \
  --size 4096 \
  --probe-scope file

sudo python3 -m src.experiments.real.run_bpf_microbenchmark \
  --mode connect \
  --iters 100000 \
  --probe-scope network
```

Optional exec-path microbenchmark:

```bash
sudo python3 -m src.experiments.real.run_bpf_microbenchmark \
  --mode execve \
  --iters 100000 \
  --probe-scope exec
```

Verifier-path latency sweep:

```bash
python3 -m src.experiments.real.run_latency_sweep \
  --repeats 3 \
  --max-interval 10.0
```

Per-attack latency capture:

```bash
python3 -m src.experiments.real.run_real_latency_capture \
  --attack filesystem \
  --interval 1.0 \
  --repeats 3

python3 -m src.experiments.real.run_real_latency_capture \
  --attack colocation \
  --interval 1.0 \
  --repeats 3

python3 -m src.experiments.real.run_real_latency_capture \
  --attack supply_chain \
  --interval 1.0 \
  --repeats 3

python3 -m src.experiments.real.run_real_latency_capture \
  --attack coordinated \
  --interval 1.0 \
  --repeats 3
```

Measured policy ablation:

```bash
python3 -m src.experiments.real.run_ablation \
  --interval 1.0 \
  --repeats 3
```

### Simulated measurements

```bash
python3 -m src.experiments.simulated.run_all
python3 -m src.experiments.simulated.run_ablation
python3 -m src.experiments.simulated.run_false_positive
python3 -m src.experiments.simulated.run_baseline_comparison
python3 -m src.experiments.simulated.run_performance
```

## Expected Artifacts

A complete campaign should produce:
- `bpf_microbenchmark_*.json`
- `real_latency_*.json`
- `real_latency_sweep_*.json`
- `real_ablation_*.json`
- `simulated_all_attacks_*.json`
- `simulated_ablation_*.json`
- `simulated_false_positive_*.json`
- `simulated_performance_*.json`
- `baseline_comparison_*.md`

## Artifact Bundle

After a campaign, archive the results:

```bash
mkdir -p results/sc26_bundle
cp results/*.json results/*.md results/sc26_bundle/ 2>/dev/null || true
git rev-parse HEAD > results/sc26_bundle/commit.txt
```

If deployed services were involved, also archive:

```bash
journalctl -u aegis-verifier.service > results/sc26_bundle/verifier.log
journalctl -u aegis-collector.service > results/sc26_bundle/collector.log
cp /etc/aegis/verifier.json results/sc26_bundle/ 2>/dev/null || true
cp /etc/aegis/collector.env results/sc26_bundle/ 2>/dev/null || true
```

## Figure And Table Mapping

| Figure/Table | Source | Artifact |
|---|---|---|
| Probe overhead figure | `run_bpf_microbenchmark` | `bpf_microbenchmark_*.json` |
| Latency vs interval | `run_latency_sweep` | `real_latency_sweep_*.json` |
| Per-attack latency/exfiltration table | `run_real_latency_capture` | `real_latency_*.json` |
| Real-policy ablation table | `src.experiments.real.run_ablation` | `real_ablation_*.json` |
| Full attack detection figure | `run_all` | `simulated_all_attacks_*.json` |
| Component ablation heatmap | `src.experiments.simulated.run_ablation` | `simulated_ablation_*.json` |
| False-positive table | `run_false_positive` | `simulated_false_positive_*.json` |
| Baseline comparison table | `run_baseline_comparison` | `baseline_comparison_*.md` |
| Secondary scaling appendix figure | `run_performance` | `simulated_performance_*.json` |

## Safe Paper Wording

Use:
- `measured on AMD EPYC hardware` for real experiments
- `simulation-based controlled study` for simulated experiments

Do not describe simulated overhead or latency as deployment measurements.
