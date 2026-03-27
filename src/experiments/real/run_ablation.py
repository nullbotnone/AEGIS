#!/usr/bin/env python3
"""Measured experiment: ablation study over real framework constraints."""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .real_latency import (
    ATTACK_LABELS,
    ATTACK_ORDER,
    REAL_ABLATIONS,
    REAL_ABLATION_ORDER,
    measure_attack_latency,
)


def median(values: List[float]) -> float:
    return statistics.median(values) if values else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run measured real ablation experiments")
    parser.add_argument("--interval", type=float, default=1.0, help="Attestation interval in seconds")
    parser.add_argument("--repeats", type=int, default=1, help="Trials per ablation/attack cell")
    parser.add_argument("--attack", action="append", choices=ATTACK_ORDER, help="Attack(s) to include; repeat for multiple")
    parser.add_argument("--config", action="append", choices=REAL_ABLATION_ORDER, help="Ablation config(s) to include; repeat for multiple")
    parser.add_argument("--attack-offset", type=float, default=None, help="Seconds from cycle start to launch the attack (default: interval/2)")
    parser.add_argument("--max-wait", type=float, default=None, help="Maximum wait time per trial in seconds")
    parser.add_argument("--output", default=None, help="Optional JSON output path")
    args = parser.parse_args()

    attacks = args.attack or ATTACK_ORDER
    configs = args.config or REAL_ABLATION_ORDER

    print("=" * 80)
    print("EXPERIMENT: REAL ABLATION STUDY")
    print("=" * 80)
    print()
    print("Measured mode: framework attestation + policy verification")
    print(f"Interval: {args.interval:.1f}s")
    print(f"Repeats per cell: {max(1, args.repeats)}")
    print(f"Attacks: {', '.join(ATTACK_LABELS[key] for key in attacks)}")
    print(f"Configs: {', '.join(REAL_ABLATIONS[key].name for key in configs)}")
    print()

    all_trials: List[Dict[str, object]] = []
    summary_rows: List[Dict[str, object]] = []

    for index, config_key in enumerate(configs, start=1):
        config = REAL_ABLATIONS[config_key]
        print(f"[{index}] {config.name}")
        print(f"    {config.description}")

        config_detected = 0
        for attack_key in attacks:
            trials = [
                measure_attack_latency(
                    attack_key,
                    args.interval,
                    args.attack_offset,
                    args.max_wait,
                    ablation_key=config_key,
                )
                for _ in range(max(1, args.repeats))
            ]
            detected_trials = [trial for trial in trials if trial.detected]
            median_latency = median([trial.detection_latency_ms for trial in detected_trials])
            median_exfil = int(median([float(trial.data_exfiltrated_bytes) for trial in detected_trials])) if detected_trials else -1
            median_cpu = median([trial.cpu_overhead_percent for trial in trials])
            median_cycles = median([float(trial.attestation_cycles) for trial in trials])
            all_detected = len(detected_trials) == len(trials)
            if all_detected:
                config_detected += 1

            violation_samples: List[str] = []
            for trial in detected_trials:
                for violation in trial.verification_violations:
                    if violation not in violation_samples:
                        violation_samples.append(violation)
                    if len(violation_samples) == 2:
                        break
                if len(violation_samples) == 2:
                    break
            violation_summary = "; ".join(violation_samples) if violation_samples else "none"

            print(
                f"    {ATTACK_LABELS[attack_key]:<30} "
                f"detected={len(detected_trials)}/{len(trials)}, "
                f"latency={'n/a' if not detected_trials else f'{median_latency:.1f}ms'}, "
                f"exfil={'n/a' if not detected_trials else f'{median_exfil}B'}, "
                f"cpu={median_cpu:.3f}%, cycles={median_cycles:.0f}"
            )
            print(f"      Violations: {violation_summary}")

            summary_rows.append(
                {
                    "config_key": config_key,
                    "config_name": config.name,
                    "attack_key": attack_key,
                    "attack_name": ATTACK_LABELS[attack_key],
                    "detected_trials": len(detected_trials),
                    "total_trials": len(trials),
                    "median_detection_latency_ms": median_latency if detected_trials else None,
                    "median_exfiltrated_bytes": median_exfil if detected_trials else None,
                    "median_cpu_overhead_percent": median_cpu,
                    "median_attestation_cycles": median_cycles,
                    "sample_violations": violation_samples,
                }
            )
            all_trials.extend(trial.to_dict() for trial in trials)

        print(f"    → Fully detected attacks: {config_detected}/{len(attacks)}")
        print()

    output_path = Path(args.output) if args.output else (
        Path("results") / f"real_ablation_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "interval_s": args.interval,
        "repeats": max(1, args.repeats),
        "attacks": attacks,
        "configs": configs,
        "summary": summary_rows,
        "trials": all_trials,
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n")

    print("=" * 80)
    print("REAL ABLATION SUMMARY")
    print("=" * 80)
    print()
    print(f"{'Config':<24} {'Attack':<28} {'Detected':>10} {'Latency':>12} {'Exfil':>10} {'CPU OH':>9}")
    print("-" * 100)
    for row in summary_rows:
        latency = "n/a" if row["median_detection_latency_ms"] is None else f"{row['median_detection_latency_ms']:.1f}ms"
        exfil = "n/a" if row["median_exfiltrated_bytes"] is None else f"{int(row['median_exfiltrated_bytes'])}B"
        print(
            f"{row['config_name']:<24} {row['attack_name']:<28} "
            f"{row['detected_trials']}/{row['total_trials']:>7} {latency:>12} {exfil:>10} "
            f"{row['median_cpu_overhead_percent']:>8.3f}%"
        )

    print()
    print(f"Results: {output_path}")
    print("Note: only data-access and exfil-budget ablations are expected to materially change the current real attacks.")


if __name__ == "__main__":
    main()
