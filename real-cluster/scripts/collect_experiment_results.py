#!/usr/bin/env python3
"""Collect and analyze experiment results from AEGIS cluster runs.

Reads agent logs, eBPF monitor logs, and Slurm job outputs to produce
a unified results file for each experiment.
"""
import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List


def collect_experiment_results(experiment: str, job_id: str, log_dir: str, output: str):
    """Collect results from an experiment run."""
    
    results = {
        "experiment": experiment,
        "job_id": job_id,
        "log_dir": log_dir,
        "agent_actions": [],
        "monitor_events": [],
        "detections": [],
        "summary": {}
    }
    
    # Read agent log (JSONL format)
    agent_log = os.path.join(log_dir, f"agent-{job_id}.log")
    if os.path.exists(agent_log):
        with open(agent_log, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        entry = json.loads(line)
                        results["agent_actions"].append(entry)
                    except json.JSONDecodeError:
                        pass
    
    # Read eBPF monitor log (JSONL format)
    monitor_log = os.path.join(log_dir, f"ebpf-{job_id}.jsonl")
    if os.path.exists(monitor_log):
        with open(monitor_log, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        entry = json.loads(line)
                        results["monitor_events"].append(entry)
                    except json.JSONDecodeError:
                        pass
    
    # Compute summary
    results["summary"] = {
        "total_agent_actions": len(results["agent_actions"]),
        "total_monitor_events": len(results["monitor_events"]),
        "files_read": len([a for a in results["agent_actions"] if a.get("action") == "FILE_READ"]),
        "llm_calls": len([a for a in results["agent_actions"] if a.get("action") == "LLM_CALL_START"]),
        "violations": len([a for a in results["agent_actions"] if "VIOLATION" in a.get("action", "")]),
    }
    
    # Write results
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results collected: {output}")
    print(f"  Agent actions: {results['summary']['total_agent_actions']}")
    print(f"  Monitor events: {results['summary']['total_monitor_events']}")
    print(f"  Violations: {results['summary']['violations']}")


def main():
    parser = argparse.ArgumentParser(description="Collect AEGIS experiment results")
    parser.add_argument("--experiment", required=True, help="Experiment name")
    parser.add_argument("--job-id", required=True, help="Slurm job ID")
    parser.add_argument("--log-dir", required=True, help="Log directory")
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()
    
    collect_experiment_results(
        experiment=args.experiment,
        job_id=args.job_id,
        log_dir=args.log_dir,
        output=args.output
    )


if __name__ == "__main__":
    main()
