#!/usr/bin/env python3
"""Experiment: Performance Overhead.

Measures AEGIS overhead with varying attestation intervals, agent counts,
and workload types. This benchmark is simulation-based, but it now uses
paired workloads so baseline and AEGIS runs execute the same operations.
"""
import argparse
import json
import statistics
import time
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


from src.deployment.core.attestation import AttestationEngine as FWAttestationEngine, AgentAction, ActionType as FWActionType
from src.deployment.core.constraints import (
    ConstraintProfile as FWConstraintProfile,
    DataAccessConstraints,
    DataFlowConstraints,
    NetworkConstraints,
    ToolConstraints,
)
from src.deployment.core.verifier import PolicyVerifier


random.seed(42)


# Test configurations
ATTESTATION_INTERVALS = [0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
AGENT_COUNTS = [1, 10, 50, 100, 500]
WORKLOAD_TYPES = ["io_heavy", "network_heavy", "compute_heavy", "mixed"]
DEFAULT_REPEATS = 3


@dataclass(frozen=True)
class WorkloadOp:
    """A single synthetic operation to replay in both paired runs."""

    op_type: str
    sleep_s: float
    details: Dict[str, Any]


def create_fw_constraints(agent_id: str) -> FWConstraintProfile:
    """Create framework constraint profile for performance testing."""
    return FWConstraintProfile(
        agent_id=agent_id,
        user_id=f"user_{agent_id}",
        project_id="perf_test",
        session_id=f"session_{agent_id}",
        data_access=DataAccessConstraints(
            allowed_paths={"/projects/perf_test/*", "/scratch/*"},
            denied_paths={"/etc/*", "/root/*"},
            max_read_volume_mb=500,
            max_write_volume_mb=200,
        ),
        network=NetworkConstraints(
            allowed_endpoints={"api.llm-provider.com", "slurm-controller.internal"},
            max_egress_mb_per_hour=100,
        ),
        tools=ToolConstraints(
            allowed_tools={"data_loader", "analyzer", "trainer"},
        ),
        data_flow=DataFlowConstraints(
            max_exfil_budget_mb_per_hour=10,
        ),
    )


def _make_op(rng: random.Random, op_type: str, sleep_s: float) -> WorkloadOp:
    """Create a workload op with all random payloads precomputed."""
    details: Dict[str, Any] = {}

    if op_type == "file_read":
        details = {
            "path": "/projects/perf_test/data.bin",
            "size_mb": rng.uniform(0.1, 10),
        }
    elif op_type == "file_write":
        details = {
            "path": "/scratch/output.bin",
            "size_mb": rng.uniform(0.1, 5),
        }
    elif op_type == "llm_call":
        details = {
            "endpoint": "api.llm-provider.com",
            "prompt_size_kb": rng.uniform(1, 50),
            "data_sent_mb": rng.uniform(0.01, 0.5),
        }
    elif op_type == "network_connect":
        details = {
            "endpoint": "slurm-controller.internal",
            "data_sent_mb": rng.uniform(0.001, 0.1),
        }
    elif op_type == "tool_invoke":
        details = {
            "tool": "data_loader",
            "args": ["data.bin"],
        }

    return WorkloadOp(op_type=op_type, sleep_s=sleep_s, details=details)


def generate_workload_ops(
    workload_type: str,
    duration_s: float,
    rng: random.Random,
) -> List[WorkloadOp]:
    """Generate a deterministic sequence of operations for a workload type."""
    ops: List[WorkloadOp] = []
    elapsed = 0.0

    if workload_type == "io_heavy":
        while elapsed < duration_s:
            ops.append(_make_op(rng, "file_read", rng.uniform(0.001, 0.005) * 0.1))
            ops.append(_make_op(rng, "file_write", rng.uniform(0.001, 0.005) * 0.1))
            elapsed += 0.01
    elif workload_type == "network_heavy":
        while elapsed < duration_s:
            ops.append(_make_op(rng, "llm_call", rng.uniform(0.005, 0.02) * 0.1))
            ops.append(_make_op(rng, "network_connect", rng.uniform(0.001, 0.005) * 0.1))
            elapsed += 0.025
    elif workload_type == "compute_heavy":
        while elapsed < duration_s:
            ops.append(_make_op(rng, "compute", rng.uniform(0.05, 0.1) * 0.1))
            ops.append(_make_op(rng, "file_read", rng.uniform(0.001, 0.003) * 0.1))
            elapsed += 0.08
    else:
        while elapsed < duration_s:
            r = rng.random()
            if r < 0.3:
                ops.append(_make_op(rng, "file_read", rng.uniform(0.001, 0.005) * 0.1))
            elif r < 0.5:
                ops.append(_make_op(rng, "file_write", rng.uniform(0.001, 0.005) * 0.1))
            elif r < 0.75:
                ops.append(_make_op(rng, "llm_call", rng.uniform(0.005, 0.015) * 0.1))
            elif r < 0.85:
                ops.append(_make_op(rng, "tool_invoke", rng.uniform(0.01, 0.03) * 0.1))
            else:
                ops.append(_make_op(rng, "compute", rng.uniform(0.02, 0.05) * 0.1))
            elapsed += 0.02

    return ops


def _record_op(attestation_engine: FWAttestationEngine, agent_id: str, op: WorkloadOp) -> None:
    """Record a precomputed op in the attestation engine."""
    if op.op_type == "file_read":
        action = AgentAction(time.time(), FWActionType.FILE_READ, {
            "path": f"/projects/perf_test/data_{agent_id}.bin",
            "size_mb": op.details["size_mb"],
        })
    elif op.op_type == "file_write":
        action = AgentAction(time.time(), FWActionType.FILE_WRITE, {
            "path": f"/scratch/{agent_id}/output.bin",
            "size_mb": op.details["size_mb"],
        })
    elif op.op_type == "llm_call":
        action = AgentAction(time.time(), FWActionType.LLM_API_CALL, {
            "endpoint": op.details["endpoint"],
            "prompt_size_kb": op.details["prompt_size_kb"],
            "data_sent_mb": op.details["data_sent_mb"],
        })
    elif op.op_type == "network_connect":
        action = AgentAction(time.time(), FWActionType.NETWORK_CONNECTION, {
            "endpoint": op.details["endpoint"],
            "data_sent_mb": op.details["data_sent_mb"],
        })
    elif op.op_type == "tool_invoke":
        action = AgentAction(time.time(), FWActionType.TOOL_INVOCATION, {
            "tool": op.details["tool"],
            "args": [f"data_{agent_id}.bin"],
        })
    else:
        return

    attestation_engine.record_action(agent_id, action)


def _run_attestation_cycle(
    attestation_engine: FWAttestationEngine,
    verifier: PolicyVerifier,
    agent_ids: List[str],
) -> int:
    """Generate and verify evidence for all agents once."""
    for agent_id in agent_ids:
        evidence = attestation_engine.generate_evidence(agent_id)
        verifier.verify(evidence)
    return 1


def run_workload(
    ops_per_agent: List[WorkloadOp],
    agent_count: int,
    with_aegis: bool = False,
    attestation_interval: float = 1.0,
) -> Dict[str, Any]:
    """Run a paired workload with or without AEGIS monitoring."""
    attestation_engine: Optional[FWAttestationEngine] = None
    verifier: Optional[PolicyVerifier] = None
    agent_ids = [f"agent_{i}" for i in range(agent_count)]
    attestation_cycles = 0
    executed_ops = 0

    if with_aegis:
        attestation_engine = FWAttestationEngine(
            node_id="perf_node",
            attestation_interval=attestation_interval,
        )
        verifier = PolicyVerifier()
        for agent_id in agent_ids:
            constraints = create_fw_constraints(agent_id)
            attestation_engine.register_agent(agent_id, constraints)
            verifier.register_agent(constraints)

    start = time.perf_counter()
    next_attestation_at = start + attestation_interval if with_aegis else None

    for agent_id in agent_ids:
        for op in ops_per_agent:
            time.sleep(op.sleep_s)
            if attestation_engine is not None:
                _record_op(attestation_engine, agent_id, op)
            executed_ops += 1

            if attestation_engine is not None and verifier is not None and next_attestation_at is not None:
                now = time.perf_counter()
                while now >= next_attestation_at:
                    attestation_cycles += _run_attestation_cycle(attestation_engine, verifier, agent_ids)
                    next_attestation_at += attestation_interval

    if attestation_engine is not None and verifier is not None:
        attestation_cycles += _run_attestation_cycle(attestation_engine, verifier, agent_ids)

    elapsed_s = time.perf_counter() - start
    throughput = executed_ops / max(elapsed_s, 0.001)

    return {
        "elapsed_s": elapsed_s,
        "executed_ops": executed_ops,
        "throughput": throughput,
        "attestation_cycles": attestation_cycles,
    }


def measure_overhead(
    attestation_interval: float,
    agent_count: int,
    workload_type: str,
    duration: float = 2.0,
    repeats: int = DEFAULT_REPEATS,
) -> Dict[str, Any]:
    """Measure AEGIS overhead for a given configuration using paired trials."""
    trial_records = []
    overheads = []
    throughput_deltas = []
    baseline_times = []
    aegis_times = []
    baseline_throughputs = []
    aegis_throughputs = []
    attestation_cycles = []
    executed_ops = []

    config_seed = hash((round(attestation_interval, 4), agent_count, workload_type)) & 0xFFFFFFFF

    for trial_idx in range(repeats):
        rng = random.Random(config_seed + trial_idx)
        ops_per_agent = generate_workload_ops(workload_type, duration, rng)

        baseline = run_workload(
            ops_per_agent,
            agent_count,
            with_aegis=False,
            attestation_interval=attestation_interval,
        )
        aegis = run_workload(
            ops_per_agent,
            agent_count,
            with_aegis=True,
            attestation_interval=attestation_interval,
        )

        overhead_percent = ((aegis["elapsed_s"] - baseline["elapsed_s"]) / baseline["elapsed_s"]) * 100
        throughput_reduction = ((baseline["throughput"] - aegis["throughput"]) / baseline["throughput"]) * 100

        trial_records.append({
            "trial": trial_idx + 1,
            "baseline_time_s": round(baseline["elapsed_s"], 4),
            "aegis_time_s": round(aegis["elapsed_s"], 4),
            "baseline_throughput": round(baseline["throughput"], 1),
            "aegis_throughput": round(aegis["throughput"], 1),
            "overhead_percent": round(overhead_percent, 2),
            "throughput_reduction_percent": round(throughput_reduction, 2),
            "executed_ops": baseline["executed_ops"],
            "attestation_cycles": aegis["attestation_cycles"],
        })

        overheads.append(overhead_percent)
        throughput_deltas.append(throughput_reduction)
        baseline_times.append(baseline["elapsed_s"])
        aegis_times.append(aegis["elapsed_s"])
        baseline_throughputs.append(baseline["throughput"])
        aegis_throughputs.append(aegis["throughput"])
        attestation_cycles.append(aegis["attestation_cycles"])
        executed_ops.append(baseline["executed_ops"])

    return {
        "attestation_interval": attestation_interval,
        "agent_count": agent_count,
        "workload_type": workload_type,
        "repeats": repeats,
        "baseline_time_s": round(statistics.median(baseline_times), 4),
        "aegis_time_s": round(statistics.median(aegis_times), 4),
        "overhead_percent": round(statistics.median(overheads), 2),
        "throughput_reduction_percent": round(statistics.median(throughput_deltas), 2),
        "baseline_ops": executed_ops[0],
        "aegis_ops": executed_ops[0],
        "baseline_throughput": round(statistics.median(baseline_throughputs), 1),
        "aegis_throughput": round(statistics.median(aegis_throughputs), 1),
        "median_attestation_cycles": int(statistics.median(attestation_cycles)),
        "trial_details": trial_records,
    }


def run_experiment(output: Optional[str] = None) -> Dict[str, Any]:
    """Run the performance overhead experiment."""
    print("=" * 80)
    print("EXPERIMENT: PERFORMANCE OVERHEAD")
    print("=" * 80)
    print()

    all_results = []

    print(f"[1] Overhead vs. Attestation Interval (10 agents, mixed workload)")
    print("-" * 70)
    interval_results = []
    interval_duration = 2.5
    for interval in ATTESTATION_INTERVALS:
        r = measure_overhead(interval, 10, "mixed", duration=interval_duration)
        interval_results.append(r)
        all_results.append(r)
        print(
            f"  Interval {interval:>5.1f}s: overhead={r['overhead_percent']:>6.2f}%, "
            f"throughput_delta={r['throughput_reduction_percent']:>6.2f}%, "
            f"cycles={r['median_attestation_cycles']:>3}"
        )

    print(f"\n[2] Overhead vs. Agent Count (1.0s interval, mixed workload)")
    print("-" * 70)
    agent_count_results = []
    for count in AGENT_COUNTS:
        duration = min(0.5, max(0.04, 5.0 / count))
        r = measure_overhead(1.0, count, "mixed", duration=duration)
        agent_count_results.append(r)
        all_results.append(r)
        print(
            f"  {count:>4} agents: overhead={r['overhead_percent']:>6.2f}%, "
            f"throughput_delta={r['throughput_reduction_percent']:>6.2f}%, "
            f"cycles={r['median_attestation_cycles']:>3}"
        )

    print(f"\n[3] Overhead vs. Workload Type (1.0s interval, 10 agents)")
    print("-" * 70)
    workload_results = []
    for wtype in WORKLOAD_TYPES:
        r = measure_overhead(1.0, 10, wtype, duration=0.5)
        workload_results.append(r)
        all_results.append(r)
        print(
            f"  {wtype:<15}: overhead={r['overhead_percent']:>6.2f}%, "
            f"throughput_delta={r['throughput_reduction_percent']:>6.2f}%, "
            f"cycles={r['median_attestation_cycles']:>3}"
        )

    print(f"\n[4] Configurations with <5% Overhead")
    print("-" * 70)
    low_overhead = [r for r in all_results if abs(r["overhead_percent"]) < 5.0]
    unique_low_overhead: Dict[tuple[float, int, str], Dict[str, Any]] = {}
    for result in low_overhead:
        key = (result["attestation_interval"], result["agent_count"], result["workload_type"])
        best = unique_low_overhead.get(key)
        if best is None or abs(result["overhead_percent"]) < abs(best["overhead_percent"]):
            unique_low_overhead[key] = result

    print(
        f"  Found {len(unique_low_overhead)}/{len(all_results)} unique configurations with <5% overhead"
    )

    if unique_low_overhead:
        print(f"\n  {'Interval':>10} {'Agents':>8} {'Workload':<15} {'Overhead':>10}")
        for r in sorted(unique_low_overhead.values(), key=lambda x: x["overhead_percent"]):
            print(
                f"  {r['attestation_interval']:>9.1f}s {r['agent_count']:>8} "
                f"{r['workload_type']:<15} {r['overhead_percent']:>9.2f}%"
            )

    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "experiment": "simulated_performance",
        "interval_sweep": interval_results,
        "agent_count_sweep": agent_count_results,
        "workload_type_sweep": workload_results,
        "all_results": all_results,
        "low_overhead_count": len(unique_low_overhead),
        "total_configurations": len(all_results),
    }

    output_path = Path(output) if output else (
        Path("results") / f"simulated_performance_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Results: {output_path}")

    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AEGIS performance-overhead study")
    parser.add_argument("--output", default=None, help="Optional JSON output path")
    args = parser.parse_args()
    run_experiment(args.output)


if __name__ == "__main__":
    main()
