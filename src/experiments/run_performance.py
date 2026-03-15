#!/usr/bin/env python3
"""Experiment: Performance Overhead.

Measures AEGIS overhead with varying attestation intervals, agent counts,
and workload types. Validates the "<5% overhead" claim for the paper.
"""
import sys
import os
import time
import random
import math
from typing import Dict, Any, List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.agent import Agent
from common.filesystem import SharedFilesystem
from common.constraints import create_strict_constraints, ConstraintProfile
from common.logger import ActionLogger, ActionType
from framework.attestation import AttestationEngine as FWAttestationEngine, AgentAction, ActionType as FWActionType
from framework.constraints import (
    ConstraintProfile as FWConstraintProfile,
    DataAccessConstraints,
    NetworkConstraints,
    ToolConstraints,
    DataFlowConstraints,
)
from framework.verifier import PolicyVerifier
from framework.agent_monitor import AgentMonitor


random.seed(42)


# Test configurations
ATTESTATION_INTERVALS = [0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
AGENT_COUNTS = [1, 10, 50, 100, 500]
WORKLOAD_TYPES = ["io_heavy", "network_heavy", "compute_heavy", "mixed"]


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


def generate_workload_ops(workload_type: str, duration_s: float) -> List[tuple]:
    """Generate a sequence of operations for a workload type."""
    ops = []
    elapsed = 0.0

    if workload_type == "io_heavy":
        # Many small file I/O operations
        while elapsed < duration_s:
            ops.append(("file_read", random.uniform(0.001, 0.005)))
            ops.append(("file_write", random.uniform(0.001, 0.005)))
            elapsed += 0.01
    elif workload_type == "network_heavy":
        # Frequent network/LLM calls
        while elapsed < duration_s:
            ops.append(("llm_call", random.uniform(0.005, 0.02)))
            ops.append(("network_connect", random.uniform(0.001, 0.005)))
            elapsed += 0.025
    elif workload_type == "compute_heavy":
        # Fewer operations, more compute time
        while elapsed < duration_s:
            ops.append(("compute", random.uniform(0.05, 0.1)))
            ops.append(("file_read", random.uniform(0.001, 0.003)))
            elapsed += 0.08
    else:  # mixed
        while elapsed < duration_s:
            r = random.random()
            if r < 0.3:
                ops.append(("file_read", random.uniform(0.001, 0.005)))
            elif r < 0.5:
                ops.append(("file_write", random.uniform(0.001, 0.005)))
            elif r < 0.75:
                ops.append(("llm_call", random.uniform(0.005, 0.015)))
            elif r < 0.85:
                ops.append(("tool_invoke", random.uniform(0.01, 0.03)))
            else:
                ops.append(("compute", random.uniform(0.02, 0.05)))
            elapsed += 0.02

    return ops


def simulate_operation(op_type: str, sleep_time: float, agent_id: str,
                       attestation_engine: FWAttestationEngine = None):
    """Simulate a single operation with optional AEGIS monitoring."""
    time.sleep(sleep_time)

    if attestation_engine:
        if op_type == "file_read":
            action = AgentAction(time.time(), FWActionType.FILE_READ,
                                 {"path": f"/projects/perf_test/data_{agent_id}.bin",
                                  "size_mb": random.uniform(0.1, 10)})
            attestation_engine.record_action(agent_id, action)
        elif op_type == "file_write":
            action = AgentAction(time.time(), FWActionType.FILE_WRITE,
                                 {"path": f"/scratch/{agent_id}/output.bin",
                                  "size_mb": random.uniform(0.1, 5)})
            attestation_engine.record_action(agent_id, action)
        elif op_type == "llm_call":
            action = AgentAction(time.time(), FWActionType.LLM_API_CALL,
                                 {"endpoint": "api.llm-provider.com",
                                  "prompt_size_kb": random.uniform(1, 50),
                                  "data_sent_mb": random.uniform(0.01, 0.5)})
            attestation_engine.record_action(agent_id, action)
        elif op_type == "network_connect":
            action = AgentAction(time.time(), FWActionType.NETWORK_CONNECTION,
                                 {"endpoint": "slurm-controller.internal",
                                  "data_sent_mb": random.uniform(0.001, 0.1)})
            attestation_engine.record_action(agent_id, action)
        elif op_type == "tool_invoke":
            action = AgentAction(time.time(), FWActionType.TOOL_INVOCATION,
                                 {"tool": "data_loader",
                                  "args": [f"data_{agent_id}.bin"]})
            attestation_engine.record_action(agent_id, action)


def run_workload(workload_type: str, agent_count: int, duration_s: float,
                 with_aegis: bool = False,
                 attestation_interval: float = 1.0) -> int:
    """Run workload with or without AEGIS monitoring.

    Returns the number of operations completed.
    """
    ops_per_agent = generate_workload_ops(workload_type, duration_s)

    attestation_engine = None
    if with_aegis:
        attestation_engine = FWAttestationEngine(
            node_id="perf_node",
            attestation_interval=max(1, int(attestation_interval)),
        )
        for i in range(agent_count):
            agent_id = f"agent_{i}"
            constraints = create_fw_constraints(agent_id)
            attestation_engine.register_agent(agent_id, constraints)

    total_ops = 0
    start_time = time.time()

    for i in range(agent_count):
        agent_id = f"agent_{i}"
        for op_type, sleep_time in ops_per_agent:
            if time.time() - start_time > duration_s * 1.5:  # Safety limit
                break
            simulate_operation(op_type, sleep_time * 0.1, agent_id, attestation_engine)
            total_ops += 1

    return total_ops


def measure_overhead(attestation_interval: float, agent_count: int,
                     workload_type: str, duration: float = 2.0) -> Dict[str, Any]:
    """Measure AEGIS overhead for a given configuration."""
    # Baseline: run workload WITHOUT AEGIS
    baseline_start = time.time()
    baseline_ops = run_workload(workload_type, agent_count, duration, with_aegis=False)
    baseline_time = time.time() - baseline_start
    baseline_throughput = baseline_ops / max(baseline_time, 0.001)

    # With AEGIS
    aegis_start = time.time()
    aegis_ops = run_workload(workload_type, agent_count, duration,
                             with_aegis=True, attestation_interval=attestation_interval)
    aegis_time = time.time() - aegis_start
    aegis_throughput = aegis_ops / max(aegis_time, 0.001)

    if baseline_time > 0:
        overhead_percent = ((aegis_time - baseline_time) / baseline_time) * 100
    else:
        overhead_percent = 0.0

    if baseline_throughput > 0:
        throughput_reduction = ((baseline_throughput - aegis_throughput) / baseline_throughput) * 100
    else:
        throughput_reduction = 0.0

    return {
        "attestation_interval": attestation_interval,
        "agent_count": agent_count,
        "workload_type": workload_type,
        "baseline_time_s": round(baseline_time, 4),
        "aegis_time_s": round(aegis_time, 4),
        "overhead_percent": round(overhead_percent, 2),
        "throughput_reduction_percent": round(throughput_reduction, 2),
        "baseline_ops": baseline_ops,
        "aegis_ops": aegis_ops,
        "baseline_throughput": round(baseline_throughput, 1),
        "aegis_throughput": round(aegis_throughput, 1),
    }


def run_experiment():
    """Run the performance overhead experiment."""
    print("=" * 80)
    print("EXPERIMENT: PERFORMANCE OVERHEAD")
    print("=" * 80)
    print()

    all_results = []

    # 1. Overhead vs. attestation interval (fixed agent count)
    print("[1] Overhead vs. Attestation Interval (10 agents, mixed workload)")
    print("-" * 70)
    interval_results = []
    for interval in ATTESTATION_INTERVALS:
        r = measure_overhead(interval, 10, "mixed", duration=2.0)
        interval_results.append(r)
        all_results.append(r)
        print(f"  Interval {interval:>5.1f}s: overhead={r['overhead_percent']:>6.2f}%, "
              f"throughput_delta={r['throughput_reduction_percent']:>6.2f}%")

    # 2. Overhead vs. agent count (fixed interval)
    print(f"\n[2] Overhead vs. Agent Count (1.0s interval, mixed workload)")
    print("-" * 70)
    agent_count_results = []
    for count in AGENT_COUNTS:
        r = measure_overhead(1.0, count, "mixed", duration=2.0)
        agent_count_results.append(r)
        all_results.append(r)
        print(f"  {count:>4} agents: overhead={r['overhead_percent']:>6.2f}%, "
              f"throughput_delta={r['throughput_reduction_percent']:>6.2f}%")

    # 3. Overhead vs. workload type (fixed interval and agent count)
    print(f"\n[3] Overhead vs. Workload Type (1.0s interval, 10 agents)")
    print("-" * 70)
    workload_results = []
    for wtype in WORKLOAD_TYPES:
        r = measure_overhead(1.0, 10, wtype, duration=2.0)
        workload_results.append(r)
        all_results.append(r)
        print(f"  {wtype:<15}: overhead={r['overhead_percent']:>6.2f}%, "
              f"throughput_delta={r['throughput_reduction_percent']:>6.2f}%")

    # 4. Find <5% overhead configurations
    print(f"\n[4] Configurations with <5% Overhead")
    print("-" * 70)
    low_overhead = [r for r in all_results if abs(r["overhead_percent"]) < 5.0]
    print(f"  Found {len(low_overhead)}/{len(all_results)} configurations with <5% overhead")

    if low_overhead:
        print(f"\n  {'Interval':>10} {'Agents':>8} {'Workload':<15} {'Overhead':>10}")
        for r in sorted(low_overhead, key=lambda x: x["overhead_percent"]):
            print(f"  {r['attestation_interval']:>9.1f}s {r['agent_count']:>8} "
                  f"{r['workload_type']:<15} {r['overhead_percent']:>9.2f}%")

    summary = {
        "interval_sweep": interval_results,
        "agent_count_sweep": agent_count_results,
        "workload_type_sweep": workload_results,
        "all_results": all_results,
        "low_overhead_count": len(low_overhead),
        "total_configurations": len(all_results),
    }

    return summary


if __name__ == "__main__":
    run_experiment()
