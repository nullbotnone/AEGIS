#!/usr/bin/env python3
"""Run all synthetic attack experiments and write a summary artifact."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


from .run_attack1 import run_experiment as run_attack1
from .run_attack2 import run_experiment as run_attack2
from .run_attack3 import run_experiment as run_attack3
from .run_attack4 import run_experiment as run_attack4


def run_all(output: Optional[str] = None) -> Dict[str, Any]:
    """Run all experiments and generate a structured summary."""
    print("╔" + "═" * 68 + "╗")
    print("║" + " AEGIS: Behavioral Attestation for AI Agents in HPC Environments".center(68) + "║")
    print("║" + " Experimental Evaluation — All Attacks".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    results: List[Dict[str, Any]] = []
    experiment_names = [
        "Filesystem-Mediated Injection",
        "Multi-User Co-Location Injection",
        "Supply Chain Injection via Skills",
        "Coordinated Multi-Agent Exfiltration",
    ]
    runners = [run_attack1, run_attack2, run_attack3, run_attack4]

    total_start = time.time()

    for i, (name, runner) in enumerate(zip(experiment_names, runners), 1):
        print(f"\n{'#' * 70}")
        print(f"# RUNNING EXPERIMENT {i}/4: {name}")
        print(f"{'#' * 70}\n")

        try:
            result = runner()
            result["experiment_name"] = name
            result["experiment_number"] = i
            result["status"] = "completed"
        except Exception as exc:
            result = {
                "experiment_name": name,
                "experiment_number": i,
                "status": "failed",
                "error": str(exc),
                "attack_success": None,
                "detection_success": None,
            }
            print(f"\nERROR: {exc}")

        results.append(result)

    total_end = time.time()

    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " SUMMARY REPORT".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    print(f"{'Experiment':<40} {'Attack':>8} {'Detected':>10} {'Detections':>12} {'Time (ms)':>10}")
    print("─" * 90)

    total_attacks = 0
    total_detected = 0
    total_detections = 0
    total_exfil = 0

    for result in results:
        name = result["experiment_name"]
        if result["status"] == "failed":
            print(f"{name:<40} {'FAILED':>8} {'N/A':>10} {'N/A':>12} {'N/A':>10}")
            continue

        attack_str = "YES" if result.get("attack_success") else "NO"
        detect_str = "YES" if result.get("detection_success") else "NO"
        num_det = result.get("num_detections", 0)
        det_time = result.get("detection_time_ms", 0)

        if result.get("attack_success"):
            total_attacks += 1
        if result.get("detection_success"):
            total_detected += 1
        total_detections += num_det
        total_exfil += result.get("exfiltrated_bytes", 0)

        print(f"{name:<40} {attack_str:>8} {detect_str:>10} {num_det:>12} {det_time:>10.2f}")

    print("─" * 90)

    completed = sum(1 for result in results if result["status"] == "completed")
    aggregate = {
        "experiments_completed": completed,
        "experiments_total": len(results),
        "attacks_successful": total_attacks,
        "attacks_detected": total_detected,
        "detection_rate_percent": (total_detected / max(1, total_attacks)) * 100,
        "total_detections": total_detections,
        "total_exfiltrated_bytes": total_exfil,
        "total_runtime_ms": (total_end - total_start) * 1000,
    }

    print()
    print("AGGREGATE METRICS:")
    print(f"  Experiments completed:  {completed}/{len(results)}")
    print(f"  Attacks successful:     {total_attacks}/{completed}")
    print(f"  Attacks detected:       {total_detected}/{completed}")
    print(f"  Detection rate:         {aggregate['detection_rate_percent']:.0f}%")
    print(f"  Total detections:       {total_detections}")
    print(f"  Total data exfiltrated: {total_exfil} bytes")
    print(f"  Total runtime:          {aggregate['total_runtime_ms']:.0f} ms")
    print()

    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "experiment": "simulated_all_attacks",
        "aggregate": aggregate,
        "results": results,
    }
    output_path = Path(output) if output else (
        Path("results") / f"simulated_all_attacks_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print("PER-EXPERIMENT DETAILS:")
    for result in results:
        if result["status"] == "failed":
            print(f"  Experiment {result['experiment_number']}: FAILED - {result.get('error', 'unknown')}")
            continue
        print(f"  Experiment {result['experiment_number']}: {result['experiment_name']}")
        print(f"    Attack success:    {result.get('attack_success', 'N/A')}")
        print(f"    Detection success: {result.get('detection_success', 'N/A')}")
        print(f"    Exfiltrated:       {result.get('exfiltrated_bytes', 0)} bytes")
        if "covert_channel_detected" in result:
            print(f"    Covert channel:    {result['covert_channel_detected']}")
        print()

    print("=" * 70)
    print("AEGIS EXPERIMENTAL EVALUATION COMPLETE")
    print("=" * 70)
    print(f"Results: {output_path}")

    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Run all simulated AEGIS attack experiments")
    parser.add_argument("--output", default=None, help="Optional JSON output path")
    args = parser.parse_args()
    run_all(args.output)


if __name__ == "__main__":
    main()
