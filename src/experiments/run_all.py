#!/usr/bin/env python3
"""Run all AEGIS experiments and generate summary report.

Executes all four attack experiments and produces a summary showing:
- Attack success rate for each
- Whether attestation detected it
- Time to detection
- Data exfiltrated vs. prevented
"""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from experiments.run_attack1 import run_experiment as run_attack1
from experiments.run_attack2 import run_experiment as run_attack2
from experiments.run_attack3 import run_experiment as run_attack3
from experiments.run_attack4 import run_experiment as run_attack4


def run_all():
    """Run all experiments and generate summary report."""
    print("╔" + "═" * 68 + "╗")
    print("║" + " AEGIS: Behavioral Attestation for AI Agents in HPC Environments".center(68) + "║")
    print("║" + " Experimental Evaluation — All Attacks".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    results = []
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
        except Exception as e:
            result = {
                "experiment_name": name,
                "experiment_number": i,
                "status": "failed",
                "error": str(e),
                "attack_success": None,
                "detection_success": None,
            }
            print(f"\nERROR: {e}")

        results.append(result)

    total_end = time.time()

    # Generate summary report
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " SUMMARY REPORT".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    # Table header
    print(f"{'Experiment':<40} {'Attack':>8} {'Detected':>10} {'Detections':>12} {'Time (ms)':>10}")
    print("─" * 90)

    total_attacks = 0
    total_detected = 0
    total_detections = 0
    total_exfil = 0

    for r in results:
        name = r["experiment_name"]
        if r["status"] == "failed":
            print(f"{name:<40} {'FAILED':>8} {'N/A':>10} {'N/A':>12} {'N/A':>10}")
            continue

        attack_str = "✓ YES" if r.get("attack_success") else "✗ NO"
        detect_str = "✓ YES" if r.get("detection_success") else "✗ NO"
        num_det = r.get("num_detections", 0)
        det_time = r.get("detection_time_ms", 0)

        if r.get("attack_success"):
            total_attacks += 1
        if r.get("detection_success"):
            total_detected += 1
        total_detections += num_det
        total_exfil += r.get("exfiltrated_bytes", 0)

        print(f"{name:<40} {attack_str:>8} {detect_str:>10} {num_det:>12} {det_time:>10.2f}")

    print("─" * 90)

    # Aggregate metrics
    completed = sum(1 for r in results if r["status"] == "completed")
    print()
    print("AGGREGATE METRICS:")
    print(f"  Experiments completed:  {completed}/{len(results)}")
    print(f"  Attacks successful:     {total_attacks}/{completed}")
    print(f"  Attacks detected:       {total_detected}/{completed}")
    print(f"  Detection rate:         {total_detected/max(1,total_attacks)*100:.0f}%")
    print(f"  Total detections:       {total_detections}")
    print(f"  Total data exfiltrated: {total_exfil} bytes")
    print(f"  Total runtime:          {(total_end - total_start)*1000:.0f} ms")
    print()

    # Per-experiment details
    print("PER-EXPERIMENT DETAILS:")
    for r in results:
        if r["status"] == "failed":
            print(f"  Experiment {r['experiment_number']}: FAILED — {r.get('error', 'unknown')}")
            continue
        print(f"  Experiment {r['experiment_number']}: {r['experiment_name']}")
        print(f"    Attack success:    {r.get('attack_success', 'N/A')}")
        print(f"    Detection success: {r.get('detection_success', 'N/A')}")
        print(f"    Exfiltrated:       {r.get('exfiltrated_bytes', 0)} bytes")
        if "covert_channel_detected" in r:
            print(f"    Covert channel:    {r['covert_channel_detected']}")
        print()

    print("=" * 70)
    print("AEGIS EXPERIMENTAL EVALUATION COMPLETE")
    print("=" * 70)

    return results


if __name__ == "__main__":
    run_all()
