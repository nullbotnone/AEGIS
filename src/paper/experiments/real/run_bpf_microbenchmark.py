#!/usr/bin/env python3
"""Run paired direct kernel/eBPF microbenchmarks for the AEGIS probe."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_EVENTS = [
    "task-clock",
    "cycles",
    "instructions",
    "branches",
    "branch-misses",
    "cache-misses",
    "context-switches",
    "cpu-migrations",
]
OPS_RE = re.compile(
    r"mode=(?P<mode>\w+)\s+iters=(?P<iters>\d+)\s+elapsed=(?P<elapsed>[0-9.]+)\s+ops_per_sec=(?P<ops>[0-9.]+)"
)


@dataclass
class TrialResult:
    label: str
    iteration: int
    returncode: int
    workload_seconds: float
    ops_per_sec: float
    perf_events: Dict[str, float]
    stdout: str
    stderr: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a paired baseline vs attached AEGIS kernel/eBPF microbenchmark"
    )
    parser.add_argument("--mode", required=True, choices=["openat", "read", "write", "connect", "execve"])
    parser.add_argument("--iters", type=int, default=200000, help="Benchmark iterations per trial")
    parser.add_argument("--size", type=int, default=4096, help="Buffer size for read/write modes")
    parser.add_argument("--path", default="/tmp/aegis-microbench.dat", help="Benchmark file path")
    parser.add_argument("--host", default="127.0.0.1", help="IPv4 host for connect mode")
    parser.add_argument("--port", type=int, default=9, help="TCP port for connect mode")
    parser.add_argument("--cpu", type=int, default=2, help="CPU core for taskset pinning")
    parser.add_argument("--repeats", type=int, default=9, help="Number of paired baseline/attached trials")
    parser.add_argument(
        "--events",
        default=",".join(DEFAULT_EVENTS),
        help="perf stat event list",
    )
    parser.add_argument("--perf", default="perf", help="perf binary")
    parser.add_argument("--bpf", default=None, help="Path to BPF object file")
    parser.add_argument("--sample-rate", type=int, default=1, help="AEGIS sample rate")
    parser.add_argument("--monitor-uid", type=int, default=0, help="Only track this uid when non-zero")
    parser.add_argument(
        "--probe-scope",
        choices=["auto", "all", "file", "network", "exec"],
        default="auto",
        help="Which AEGIS probe paths to enable during attached trials",
    )
    parser.add_argument(
        "--attach-warmup",
        type=float,
        default=0.25,
        help="Seconds to wait after attaching before starting the workload",
    )
    parser.add_argument("--skip-build", action="store_true", help="Skip make bpfall and make bench")
    parser.add_argument(
        "--output",
        default=None,
        help="Optional JSON output path; defaults to results/bpf_microbenchmark_<timestamp>.json",
    )
    return parser.parse_args()


def run_checked(cmd: List[str], *, cwd: Path) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def parse_perf_stat(stderr: str) -> Dict[str, float]:
    events: Dict[str, float] = {}
    for raw_line in stderr.splitlines():
        line = raw_line.strip()
        if not line or ";" not in line:
            continue
        fields = line.split(";")
        if len(fields) < 3:
            continue
        value = fields[0].strip()
        event = fields[2].strip()
        if not event or value.startswith("<"):
            continue
        try:
            events[event] = float(value)
        except ValueError:
            continue
    return events


def parse_workload_stdout(stdout: str) -> Dict[str, float]:
    for line in stdout.splitlines():
        match = OPS_RE.search(line.strip())
        if match:
            return {
                "elapsed": float(match.group("elapsed")),
                "ops_per_sec": float(match.group("ops")),
            }
    raise RuntimeError(f"unexpected workload output: {stdout.strip()!r}")


def default_probe_scope(mode: str) -> str:
    if mode in {"openat", "read", "write"}:
        return "file"
    if mode == "connect":
        return "network"
    return "exec"


def attach_flags(mode: str, scope: str) -> List[str]:
    selected = default_probe_scope(mode) if scope == "auto" else scope
    if selected == "all":
        return []
    if selected == "file":
        return ["--disable-network", "--disable-exec"]
    if selected == "network":
        return ["--disable-file", "--disable-exec"]
    return ["--disable-file", "--disable-network"]


def workload_cmd(args: argparse.Namespace) -> List[str]:
    cmd = [
        str(REPO_ROOT / "src" / "deployment" / "bpf" / "syscall_microbench"),
        "--mode",
        args.mode,
        "--iters",
        str(args.iters),
    ]
    if args.mode in {"read", "write"}:
        cmd.extend(["--size", str(args.size), "--path", args.path])
    elif args.mode == "openat":
        cmd.extend(["--path", args.path])
    elif args.mode == "connect":
        cmd.extend(["--host", args.host, "--port", str(args.port)])
    return cmd


def perf_cmd(args: argparse.Namespace, workload: List[str]) -> List[str]:
    return [
        "taskset",
        "-c",
        str(args.cpu),
        args.perf,
        "stat",
        "-x",
        ";",
        "--no-big-num",
        "-e",
        args.events,
        "--",
        *workload,
    ]


def run_trial(args: argparse.Namespace, label: str, iteration: int) -> TrialResult:
    completed = subprocess.run(
        perf_cmd(args, workload_cmd(args)),
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    parsed = parse_workload_stdout(completed.stdout)
    return TrialResult(
        label=label,
        iteration=iteration,
        returncode=completed.returncode,
        workload_seconds=parsed["elapsed"],
        ops_per_sec=parsed["ops_per_sec"],
        perf_events=parse_perf_stat(completed.stderr),
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def start_attach(args: argparse.Namespace) -> subprocess.Popen[str]:
    cmd = [
        sys.executable,
        "-m",
        "src.deployment.collector.bpf_attach",
        "--sample-rate",
        str(max(1, args.sample_rate)),
        "--monitor-uid",
        str(max(0, args.monitor_uid)),
        *attach_flags(args.mode, args.probe_scope),
    ]
    if args.bpf:
        cmd.extend(["--bpf", args.bpf])
    proc = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    time.sleep(max(0.0, args.attach_warmup))
    if proc.poll() is not None:
        stderr = proc.stderr.read() if proc.stderr else ""
        stdout = proc.stdout.read() if proc.stdout else ""
        raise RuntimeError(
            "attach-only loader exited before the workload started:\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )
    return proc


def stop_attach(proc: subprocess.Popen[str]) -> Dict[str, object]:
    try:
        os.killpg(proc.pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        stdout, stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        stdout, stderr = proc.communicate(timeout=5)
    return {"stdout": stdout, "stderr": stderr, "returncode": proc.returncode}


def median(values: List[float]) -> float:
    return statistics.median(values) if values else 0.0


def summarize(trials: List[TrialResult]) -> Dict[str, object]:
    event_names = sorted({name for trial in trials for name in trial.perf_events})
    return {
        "median_task_clock": median([trial.perf_events.get("task-clock", 0.0) for trial in trials]),
        "median_ops_per_sec": median([trial.ops_per_sec for trial in trials]),
        "median_elapsed_seconds": median([trial.workload_seconds for trial in trials]),
        "median_perf_events": {
            event: median([trial.perf_events.get(event, 0.0) for trial in trials])
            for event in event_names
        },
    }


def overhead_pct(baseline: float, attached: float) -> float:
    if baseline == 0.0:
        return 0.0
    return 100.0 * (attached - baseline) / baseline


def main() -> None:
    args = parse_args()

    if os.geteuid() != 0:
        raise SystemExit("Run this script as root so it can attach the BPF probe.")

    if not args.skip_build:
        run_checked(["make", "bpfall"], cwd=REPO_ROOT)
        run_checked(["make", "bench"], cwd=REPO_ROOT)

    baseline_trials: List[TrialResult] = []
    attached_trials: List[TrialResult] = []
    attach_logs: List[Dict[str, object]] = []

    for iteration in range(1, args.repeats + 1):
        baseline = run_trial(args, "baseline", iteration)
        if baseline.returncode != 0:
            raise RuntimeError(f"baseline trial {iteration} failed:\n{baseline.stderr}\n{baseline.stdout}")
        baseline_trials.append(baseline)

        attach_proc = start_attach(args)
        try:
            attached = run_trial(args, "attached", iteration)
        finally:
            attach_log = stop_attach(attach_proc)
        attach_logs.append({"iteration": iteration, **attach_log})
        if attached.returncode != 0:
            raise RuntimeError(f"attached trial {iteration} failed:\n{attached.stderr}\n{attached.stdout}")
        attached_trials.append(attached)

    baseline_summary = summarize(baseline_trials)
    attached_summary = summarize(attached_trials)
    event_overhead = {
        event: overhead_pct(
            baseline_summary["median_perf_events"].get(event, 0.0),
            attached_summary["median_perf_events"].get(event, 0.0),
        )
        for event in sorted(
            set(baseline_summary["median_perf_events"]) | set(attached_summary["median_perf_events"])
        )
    }
    throughput_delta_pct = overhead_pct(
        baseline_summary["median_ops_per_sec"],
        attached_summary["median_ops_per_sec"],
    )
    results = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "mode": args.mode,
            "iters": args.iters,
            "size": args.size,
            "path": args.path,
            "host": args.host,
            "port": args.port,
            "cpu": args.cpu,
            "repeats": args.repeats,
            "events": args.events.split(","),
            "bpf": args.bpf,
            "sample_rate": args.sample_rate,
            "monitor_uid": args.monitor_uid,
            "probe_scope": args.probe_scope,
            "attach_warmup": args.attach_warmup,
        },
        "baseline": {
            "summary": baseline_summary,
            "trials": [asdict(trial) for trial in baseline_trials],
        },
        "attached": {
            "summary": attached_summary,
            "trials": [asdict(trial) for trial in attached_trials],
            "attach_logs": attach_logs,
        },
        "overhead": {
            "task_clock_pct": overhead_pct(
                baseline_summary["median_task_clock"],
                attached_summary["median_task_clock"],
            ),
            "elapsed_pct": overhead_pct(
                baseline_summary["median_elapsed_seconds"],
                attached_summary["median_elapsed_seconds"],
            ),
            "ops_per_sec_pct": throughput_delta_pct,
            "throughput_delta_pct": throughput_delta_pct,
            "throughput_loss_pct": max(0.0, -throughput_delta_pct),
            "perf_events_pct": event_overhead,
        },
    }

    output_path = Path(args.output) if args.output else (
        REPO_ROOT / "results" / f"bpf_microbenchmark_{args.mode}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2) + "\n")

    print("=== AEGIS Direct Kernel/eBPF Microbenchmark ===")
    print(f"Mode: {args.mode}")
    print(f"Trials: {args.repeats}")
    print(f"CPU: {args.cpu}")
    print(f"Results: {output_path}")
    print("")
    print("Median baseline:")
    print(f"  task-clock: {baseline_summary['median_task_clock']:.3f}")
    print(f"  elapsed:    {baseline_summary['median_elapsed_seconds']:.6f}s")
    print(f"  ops/sec:    {baseline_summary['median_ops_per_sec']:.2f}")
    print("Median attached:")
    print(f"  task-clock: {attached_summary['median_task_clock']:.3f}")
    print(f"  elapsed:    {attached_summary['median_elapsed_seconds']:.6f}s")
    print(f"  ops/sec:    {attached_summary['median_ops_per_sec']:.2f}")
    print("Overhead:")
    print(f"  task-clock: {results['overhead']['task_clock_pct']:.2f}%")
    print(f"  elapsed:    {results['overhead']['elapsed_pct']:.2f}%")
    print("Throughput:")
    print(f"  delta:      {results['overhead']['throughput_delta_pct']:.2f}%")
    print(f"  loss:       {results['overhead']['throughput_loss_pct']:.2f}%")


if __name__ == "__main__":
    main()
