#!/usr/bin/env python3
"""Measured experiment: detection latency vs. attestation interval."""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .real_latency import ATTACK_LABELS, ATTACK_ORDER, measure_attack_latency

INTERVALS = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]


def median(values: List[float]) -> float:
    return statistics.median(values) if values else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a measured AEGIS latency sweep")
    parser.add_argument("--repeats", type=int, default=1, help="Trials per attack/interval cell")
    parser.add_argument("--max-interval", type=float, default=None, help="Optional upper bound on interval sweep")
    parser.add_argument("--attack-offset", type=float, default=None, help="Seconds from cycle start to launch the attack (default: interval/2)")
    parser.add_argument("--max-wait", type=float, default=None, help="Maximum wait time per trial in seconds")
    parser.add_argument("--output", default=None, help="Optional JSON output path")
    args = parser.parse_args()

    intervals = [interval for interval in INTERVALS if args.max_interval is None or interval <= args.max_interval]

    print("=" * 80)
    print("EXPERIMENT: DETECTION LATENCY vs. ATTESTATION INTERVAL")
    print("=" * 80)
    print()
    print("Measured mode: framework attestation + policy verification")
    print(f"Intervals: {', '.join(f'{interval:.1f}s' for interval in intervals)}")
    print(f"Repeats per cell: {args.repeats}")
    print()

    all_results: List[Dict[str, float]] = []
    summary_rows: List[Dict[str, float]] = []

    print("[1] Sweeping attestation intervals with real verifier cycles...")
    print()

    for interval in intervals:
        print(f"  Interval: {interval}s")
        latency_values: List[float] = []
        exfil_values: List[int] = []
        cpu_values: List[float] = []
        all_detected = True

        for attack_key in ATTACK_ORDER:
            trials = [
                measure_attack_latency(attack_key, interval, args.attack_offset, args.max_wait)
                for _ in range(max(1, args.repeats))
            ]
            detected_trials = [trial for trial in trials if trial.detected]
            detected = len(detected_trials) == len(trials)
            median_latency = median([trial.detection_latency_ms for trial in detected_trials])
            median_exfil = int(median([float(trial.data_exfiltrated_bytes) for trial in detected_trials])) if detected_trials else -1
            median_cpu = median([trial.cpu_overhead_percent for trial in trials])

            if detected_trials:
                latency_values.append(median_latency)
                exfil_values.append(median_exfil)
            cpu_values.append(median_cpu)
            all_detected = all_detected and detected

            status = "detected" if detected else "partial"
            latency_str = f"{median_latency:7.1f}ms" if detected_trials else "   n/a  "
            exfil_str = f"{median_exfil:7d}B" if detected_trials else "   n/a  "
            print(
                f"    {ATTACK_LABELS[attack_key]:<30} {status:<8} latency={latency_str}, "
                f"exfil={exfil_str}, cpu={median_cpu:.3f}%"
            )
            all_results.extend(trial.to_dict() for trial in trials)

        avg_latency = median(latency_values)
        total_exfil_kb = sum(exfil_values) / 1024 if exfil_values else 0.0
        avg_cpu = median(cpu_values)
        summary_rows.append(
            {
                "interval": interval,
                "avg_latency_ms": avg_latency,
                "total_exfil_kb": total_exfil_kb,
                "cpu_overhead": avg_cpu,
                "all_detected": all_detected,
            }
        )
        print(f"    -> Median latency: {avg_latency:.1f}ms, Total exfil: {total_exfil_kb:.1f}KB, All detected: {all_detected}")
        print()

    output_path = Path(args.output) if args.output else (
        Path("results") / f"real_latency_sweep_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "experiment": "real_latency_sweep",
        "repeats": max(1, args.repeats),
        "intervals": intervals,
        "summary": summary_rows,
        "trials": all_results,
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print("=" * 80)
    print("LATENCY SWEEP SUMMARY")
    print("=" * 80)
    print()
    print(f"{'Interval':>10} {'Median Latency':>17} {'Total Exfil':>14} {'CPU OH':>8} {'Detected':>10}")
    print("-" * 70)
    for row in summary_rows:
        detected_str = "ALL" if row["all_detected"] else "PARTIAL"
        print(
            f"{row['interval']:>9.1f}s {row['avg_latency_ms']:>15.1f}ms "
            f"{row['total_exfil_kb']:>11.1f}KB {row['cpu_overhead']:>7.3f}% {detected_str:>10}"
        )

    print()
    print("KEY FINDING: These values come from measured verifier cycles, not synthetic estimators.")
    print("Detection latency depends on the actual attestation interval and the first cycle that sees a violation.")
    print("Exfiltrated bytes are sampled from live agent state at the detection point.")
    print(f"Results: {output_path}")


if __name__ == "__main__":
    main()
