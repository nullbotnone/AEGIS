#!/usr/bin/env python3
"""Analyze overhead measurements from AEGIS cluster experiments.

Compares baseline (no monitoring) vs AEGIS (with monitoring) runs
and computes overhead percentages.
"""
import os
import sys
import json
import argparse
import re
from pathlib import Path
from typing import Dict, Any


def parse_hpcg_log(log_path: str) -> Dict[str, Any]:
    """Parse HPCG or sysbench output."""
    results = {"throughput": None, "time": None}
    
    if not os.path.exists(log_path):
        return results
    
    with open(log_path, "r") as f:
        content = f.read()
    
    # Try sysbench format
    time_match = re.search(r"total time:\s*([\d.]+)s", content, re.IGNORECASE)
    if time_match:
        results["time"] = float(time_match.group(1))
    
    events_match = re.search(r"total number of events:\s*(\d+)", content, re.IGNORECASE)
    if events_match:
        results["events"] = int(events_match.group(1))
    
    return results


def parse_ior_log(log_path: str) -> Dict[str, Any]:
    """Parse IOR or dd output."""
    results = {"throughput_mib_s": None, "time": None}
    
    if not os.path.exists(log_path):
        return results
    
    with open(log_path, "r") as f:
        content = f.read()
    
    # Try IOR format
    bw_match = re.search(r"([\d.]+)\s+MiB/s", content)
    if bw_match:
        results["throughput_mib_s"] = float(bw_match.group(1))
    
    # Try dd format
    dd_match = re.search(r"([\d.]+)\s*[MG]B/s", content, re.IGNORECASE)
    if dd_match:
        results["throughput_mib_s"] = float(dd_match.group(1))
    
    time_match = re.search(r"([\d.]+)\s*s(?:econds)?", content)
    if time_match:
        results["time"] = float(time_match.group(1))
    
    return results


def parse_agent_log(log_path: str) -> Dict[str, Any]:
    """Parse agent workflow log."""
    results = {"time": None, "success": False}
    
    if not os.path.exists(log_path):
        return results
    
    with open(log_path, "r") as f:
        content = f.read()
    
    time_match = re.search(r"Total time:\s*([\d.]+)s", content)
    if time_match:
        results["time"] = float(time_match.group(1))
    
    results["success"] = "Done." in content or "Writing results" in content
    
    return results


def analyze_overhead(results_dir: str, output: str):
    """Analyze overhead by comparing baseline vs AEGIS runs."""
    
    report = {
        "results_dir": results_dir,
        "workloads": {},
        "summary": {}
    }
    
    # Analyze each workload type
    workloads = ["hpcg", "ior", "agent-workflow"]
    
    for workload in workloads:
        baseline_log = os.path.join(results_dir, f"{workload}-baseline.log")
        aegis_log = os.path.join(results_dir, f"{workload}-aegis.log")
        
        if workload == "hpcg":
            baseline = parse_hpcg_log(baseline_log)
            aegis = parse_hpcg_log(aegis_log)
        elif workload == "ior":
            baseline = parse_ior_log(baseline_log)
            aegis = parse_ior_log(aegis_log)
        else:
            baseline = parse_agent_log(baseline_log)
            aegis = parse_agent_log(aegis_log)
        
        # Calculate overhead
        overhead = {}
        if baseline.get("time") and aegis.get("time"):
            overhead["time_overhead_pct"] = ((aegis["time"] - baseline["time"]) / baseline["time"]) * 100
        
        if baseline.get("throughput_mib_s") and aegis.get("throughput_mib_s"):
            overhead["throughput_overhead_pct"] = ((baseline["throughput_mib_s"] - aegis["throughput_mib_s"]) / baseline["throughput_mib_s"]) * 100
        
        report["workloads"][workload] = {
            "baseline": baseline,
            "aegis": aegis,
            "overhead": overhead
        }
    
    # Summary
    overheads = [w["overhead"].get("time_overhead_pct") for w in report["workloads"].values() if w["overhead"].get("time_overhead_pct") is not None]
    if overheads:
        report["summary"]["avg_overhead_pct"] = sum(overheads) / len(overheads)
        report["summary"]["max_overhead_pct"] = max(overheads)
        report["summary"]["min_overhead_pct"] = min(overheads)
    
    # Write report
    os.makedirs(os.path.dirname(output) if os.path.dirname(output) else ".", exist_ok=True)
    with open(output, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"Overhead report: {output}")
    for wl_name, wl_data in report["workloads"].items():
        oh = wl_data["overhead"].get("time_overhead_pct")
        if oh is not None:
            print(f"  {wl_name}: {oh:+.1f}% overhead")
        else:
            print(f"  {wl_name}: insufficient data")
    
    if report["summary"].get("avg_overhead_pct"):
        print(f"  Average: {report['summary']['avg_overhead_pct']:+.1f}%")


def main():
    parser = argparse.ArgumentParser(description="Analyze AEGIS overhead")
    parser.add_argument("--results-dir", required=True, help="Results directory")
    parser.add_argument("--output", required=True, help="Output JSON report")
    args = parser.parse_args()
    
    analyze_overhead(args.results_dir, args.output)


if __name__ == "__main__":
    main()
