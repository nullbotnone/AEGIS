#!/usr/bin/env python3
"""Collect measured AEGIS latency data for one attack/interval configuration."""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .real_latency import ATTACK_LABELS, ATTACK_ORDER, measure_attack_latency


def median(values: List[float]) -> float:
    return statistics.median(values) if values else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect measured AEGIS detection latency data")
    parser.add_argument("--attack", choices=ATTACK_ORDER, required=True)
    parser.add_argument("--interval", type=float, required=True, help="Attestation interval in seconds")
    parser.add_argument("--repeats", type=int, default=3, help="Number of repeated trials")
    parser.add_argument("--attack-offset", type=float, default=None, help="Seconds from cycle start to launch the attack (default: interval/2)")
    parser.add_argument("--max-wait", type=float, default=None, help="Maximum wait time per trial in seconds")
    parser.add_argument("--output", default=None, help="Optional JSON output path")
    args = parser.parse_args()

    trials = [
        measure_attack_latency(args.attack, args.interval, args.attack_offset, args.max_wait)
        for _ in range(max(1, args.repeats))
    ]

    detected_trials = [trial for trial in trials if trial.detected]
    summary = {
        "attack": args.attack,
        "attack_name": ATTACK_LABELS[args.attack],
        "interval_s": args.interval,
        "repeats": len(trials),
        "detected_trials": len(detected_trials),
        "median_detection_latency_ms": median([trial.detection_latency_ms for trial in detected_trials]),
        "median_exfiltrated_bytes": median([float(trial.data_exfiltrated_bytes) for trial in detected_trials]),
        "median_cpu_overhead_percent": median([trial.cpu_overhead_percent for trial in trials]),
        "median_attestation_cycles": median([float(trial.attestation_cycles) for trial in trials]),
    }

    output_path = Path(args.output) if args.output else (
        Path("results") / f"real_latency_{args.attack}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "trials": [trial.to_dict() for trial in trials],
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n")

    print("=== AEGIS Real Latency Capture ===")
    print(f"Attack: {ATTACK_LABELS[args.attack]}")
    print(f"Interval: {args.interval:.1f}s")
    print(f"Repeats: {len(trials)}")
    print(f"Detected: {len(detected_trials)}/{len(trials)}")
    if detected_trials:
        print(f"Median latency: {summary['median_detection_latency_ms']:.1f}ms")
        print(f"Median exfil before detection: {summary['median_exfiltrated_bytes']:.0f}B")
    print(f"Median CPU overhead: {summary['median_cpu_overhead_percent']:.3f}%")
    print(f"Results: {output_path}")


if __name__ == "__main__":
    main()
