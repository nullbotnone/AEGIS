#!/usr/bin/env python3
"""Regenerate paper figures with layouts sized for two-column readability."""

from __future__ import annotations

import json
import os
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import ListedColormap
from matplotlib.ticker import FuncFormatter

plt.rcParams.update(
    {
        "figure.dpi": 180,
        "savefig.dpi": 360,
        "font.family": "DejaVu Sans",
        "font.size": 13.5,
        "axes.titlesize": 16,
        "axes.titleweight": "semibold",
        "axes.labelsize": 14,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.14,
        "grid.linewidth": 0.7,
        "xtick.labelsize": 12.5,
        "ytick.labelsize": 12.5,
        "legend.fontsize": 12.5,
        "axes.axisbelow": True,
        "legend.frameon": False,
    }
)

PALETTE = {
    "blue": "#2f5d8a",
    "cyan": "#62a8ac",
    "green": "#4c956c",
    "amber": "#d9911f",
    "red": "#c8553d",
    "purple": "#7c6da8",
    "gray": "#6b7280",
}

ATTACK_ORDER = ["filesystem", "colocation", "supply_chain", "coordinated"]
ATTACK_LABELS = {
    "filesystem": "Filesystem\nInjection",
    "colocation": "Co-location\nInjection",
    "supply_chain": "Supply-chain\nInjection",
    "coordinated": "Coordinated\nExfiltration",
}
ATTACK_COLORS = [PALETTE["blue"], PALETTE["green"], PALETTE["amber"], PALETTE["red"]]


if Path.cwd().name == "figures":
    ROOT = Path.cwd().resolve().parent
else:
    ROOT = Path.cwd().resolve()

FIG_DIR = ROOT / "figures"
RESULTS_ROOT = ROOT / "results"
RESULT_DIR_HINT = os.environ.get("AEGIS_RESULTS_DIR", "").strip()
PERF_ARTIFACT_HINT = os.environ.get("AEGIS_PERF_ARTIFACT", "").strip()


def resolve_result_dir() -> Path:
    if RESULT_DIR_HINT:
        candidate = Path(RESULT_DIR_HINT)
        if not candidate.is_absolute():
            candidate = (ROOT / candidate).resolve()
        if candidate.exists():
            return candidate
        raise FileNotFoundError(f"AEGIS_RESULTS_DIR does not exist: {candidate}")

    candidates = sorted(
        [path for path in RESULTS_ROOT.glob("sc26_run_*") if path.is_dir()],
        key=lambda path: path.name,
    )
    if not candidates:
        raise FileNotFoundError("No results/sc26_run_* directories found under results/")
    return candidates[-1]


def resolve_perf_artifact(result_dir: Path) -> Path | None:
    local = result_dir / "simulated_performance.json"
    if local.exists():
        return local
    if PERF_ARTIFACT_HINT:
        candidate = Path(PERF_ARTIFACT_HINT)
        if not candidate.is_absolute():
            candidate = (ROOT / candidate).resolve()
        if candidate.exists():
            return candidate
        raise FileNotFoundError(f"AEGIS_PERF_ARTIFACT does not exist: {candidate}")

    standalone = sorted(
        [path for path in RESULTS_ROOT.glob("simulated_performance_*.json") if path.is_file()],
        key=lambda path: path.name,
    )
    if standalone:
        return standalone[-1]
    return None


def load_json(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Missing artifact: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_fig(fig: plt.Figure, stem: str) -> None:
    png_path = FIG_DIR / f"{stem}.png"
    pdf_path = FIG_DIR / f"{stem}.pdf"
    fig.savefig(png_path, bbox_inches="tight", facecolor="white")
    fig.savefig(pdf_path, bbox_inches="tight", facecolor="white")
    print(f"Saved {png_path.relative_to(ROOT)} and {pdf_path.relative_to(ROOT)}")


def parse_baseline_table(path: Path) -> list[dict[str, object]]:
    rows = []
    in_table = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("| Defense |"):
            in_table = True
            continue
        if in_table and stripped.startswith("|---------"):
            continue
        if in_table:
            if not stripped.startswith("|"):
                break
            cols = [cell.strip() for cell in stripped.strip("|").split("|")]
            if len(cols) != 7:
                continue
            rows.append(
                {
                    "defense": cols[0],
                    "detections": [1 if "DET" in cell else 0 for cell in cols[1:5]],
                    "rate": float(cols[5].replace("%", "").strip()),
                    "avg_time_ms": float(cols[6].split("±")[0].strip()),
                }
            )
    if not rows:
        raise ValueError(f"Could not parse baseline comparison table: {path}")
    return rows


def collect_real_latency_summaries(result_dir: Path) -> list[dict[str, object]]:
    items = []
    for path in sorted(result_dir.glob("real_latency_*.json")):
        if path.name == "real_latency_sweep.json":
            continue
        payload = load_json(path)
        summary = dict(payload["summary"])
        finding_counts = []
        for trial in payload.get("trials", []):
            cycle_records = trial.get("cycle_records", [])
            if cycle_records:
                finding_counts.append(cycle_records[0].get("violation_count", 0))
            else:
                finding_counts.append(len(trial.get("verification_violations", [])))
        if finding_counts:
            summary["median_finding_count"] = float(np.median(finding_counts))
        items.append(summary)
    items.sort(key=lambda item: ATTACK_ORDER.index(item["attack"]))
    return items


def collect_microbenchmarks(result_dir: Path) -> list[dict[str, object]]:
    items = []
    for path in sorted(result_dir.glob("bpf_microbenchmark_*.json")):
        payload = load_json(path)
        overhead = payload["overhead"]
        throughput_loss = overhead.get("throughput_loss_pct", abs(overhead["ops_per_sec_pct"]))
        items.append(
            {
                "mode": payload["config"]["mode"],
                "elapsed_pct": overhead["elapsed_pct"],
                "task_clock_pct": overhead["task_clock_pct"],
                "throughput_loss_pct": throughput_loss,
            }
        )
    mode_order = {"openat": 0, "read": 1, "connect": 2, "execve": 3}
    items.sort(key=lambda row: mode_order.get(row["mode"], 99))
    return items


def load_simulated_ablation_matrix(payload: dict[str, object]):
    config_names = list(payload["results"].keys())
    attack_names = list(next(iter(payload["results"].values()))["results"].keys())
    matrix = np.zeros((len(config_names), len(attack_names)))
    rates = []
    for row_idx, config_name in enumerate(config_names):
        config_result = payload["results"][config_name]
        rates.append(config_result["detection_rate"])
        for col_idx, attack_name in enumerate(attack_names):
            detected = config_result["results"][attack_name]["detected"]
            matrix[row_idx, col_idx] = 100.0 if detected else 0.0
    return config_names, attack_names, matrix, rates


def emphasize_aegis(labels: list[str]) -> list[str]:
    return ["AEGIS (Ours)" if label == "Full AEGIS" else label for label in labels]


def plot_baseline_comparison(rows: list[dict[str, object]]) -> None:
    ordered = sorted(rows, key=lambda row: 0 if row["defense"] == "AEGIS (Ours)" else 1)
    defenses = [row["defense"] for row in ordered]
    matrix = np.array([row["detections"] for row in ordered], dtype=float)
    rates = np.array([row["rate"] for row in ordered], dtype=float)
    timings = np.array([row["avg_time_ms"] for row in ordered], dtype=float)
    colors = [PALETTE["amber"] if defense == "AEGIS (Ours)" else PALETTE["blue"] for defense in defenses]

    fig, (ax_heatmap, ax_rate, ax_time) = plt.subplots(
        1,
        3,
        figsize=(15.5, 3.0),
        gridspec_kw={"width_ratios": [4.7, 1.45, 1.65]},
        constrained_layout=True,
    )

    heatmap_cmap = ListedColormap(["#e4e7eb", PALETTE["green"]])
    ax_heatmap.imshow(matrix, cmap=heatmap_cmap, vmin=0, vmax=1, aspect="auto")
    ax_heatmap.set_title("Per-attack outcome")
    ax_heatmap.set_xticks(range(4))
    ax_heatmap.set_xticklabels(list(ATTACK_LABELS.values()))
    ax_heatmap.set_yticks(range(len(defenses)))
    ax_heatmap.set_yticklabels(defenses)
    ax_heatmap.tick_params(axis="x", length=0, pad=10)
    ax_heatmap.tick_params(axis="y", length=0)
    ax_heatmap.set_xticks(np.arange(-0.5, 4, 1), minor=True)
    ax_heatmap.set_yticks(np.arange(-0.5, len(defenses), 1), minor=True)
    ax_heatmap.grid(which="minor", color="white", linewidth=2.0)
    ax_heatmap.tick_params(which="minor", bottom=False, left=False)
    for tick in ax_heatmap.get_yticklabels():
        if tick.get_text() == "AEGIS (Ours)":
            tick.set_fontweight("bold")
    for row_idx in range(matrix.shape[0]):
        for col_idx in range(matrix.shape[1]):
            ax_heatmap.text(
                col_idx,
                row_idx,
                "DET" if matrix[row_idx, col_idx] else "MISS",
                ha="center",
                va="center",
                fontsize=11.5,
                fontweight="semibold",
            )

    ypos = np.arange(len(defenses))
    bars_rate = ax_rate.barh(ypos, rates, color=colors)
    ax_rate.set_title("Detection rate")
    ax_rate.set_xlim(0, 108)
    ax_rate.set_xlabel("Percent")
    ax_rate.set_yticks(ypos)
    ax_rate.set_yticklabels([])
    ax_rate.invert_yaxis()
    ax_rate.grid(axis="x", alpha=0.18)
    for bar, rate in zip(bars_rate, rates):
        ax_rate.text(min(rate + 2.0, 101.0), bar.get_y() + bar.get_height() / 2, f"{rate:.0f}%", va="center", ha="left", fontsize=11.5, fontweight="semibold")

    bars_time = ax_time.barh(ypos, timings, color=colors)
    ax_time.set_title("Mean analysis time")
    ax_time.set_xlabel("Milliseconds")
    ax_time.set_yticks(ypos)
    ax_time.set_yticklabels([])
    ax_time.invert_yaxis()
    ax_time.grid(axis="x", alpha=0.18)
    for bar, value in zip(bars_time, timings):
        ax_time.text(value + max(timings) * 0.03, bar.get_y() + bar.get_height() / 2, f"{value:.4f}", va="center", ha="left", fontsize=11.5, fontweight="semibold")

    save_fig(fig, "baseline_comparison")
    plt.close(fig)


def plot_attack_results(rows: list[dict[str, object]]) -> None:
    attack_names = ["Filesystem", "Co-location", "Supply chain", "Coordinated"]
    latencies = [row["median_detection_latency_ms"] for row in rows]
    exfil_bytes = [row["median_exfiltrated_bytes"] for row in rows]
    cpu_overhead = [row["median_cpu_overhead_percent"] for row in rows]
    finding_counts = [row.get("median_finding_count", 0.0) for row in rows]
    detected_trials = [f"{row['detected_trials']}/{row['repeats']}" for row in rows]

    fig, axes = plt.subplots(1, 4, figsize=(17.6, 4.8), constrained_layout=True)

    bars0 = axes[0].bar(attack_names, latencies, color=ATTACK_COLORS)
    axes[0].set_title("Median detection latency")
    axes[0].set_ylabel("Milliseconds")
    axes[0].set_ylim(0, max(latencies) * 1.18)
    for bar, value in zip(bars0, latencies):
        axes[0].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 8, f"{value:.2f}", ha="center", va="bottom", fontsize=11.0, fontweight="semibold")

    bars1 = axes[1].bar(attack_names, exfil_bytes, color=ATTACK_COLORS)
    axes[1].set_title("Bytes emitted before detection")
    axes[1].set_ylabel("Bytes")
    axes[1].set_ylim(0, max(exfil_bytes) * 1.22)
    for bar, value in zip(bars1, exfil_bytes):
        axes[1].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 12, f"{int(value)}", ha="center", va="bottom", fontsize=11.0, fontweight="semibold")

    bars2 = axes[2].bar(attack_names, finding_counts, color=ATTACK_COLORS)
    axes[2].set_title("Median verifier findings")
    axes[2].set_ylabel("Count")
    axes[2].set_ylim(0, max(finding_counts) * 1.28)
    for bar, value in zip(bars2, finding_counts):
        axes[2].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.08, f"{value:.0f}", ha="center", va="bottom", fontsize=11.0, fontweight="semibold")

    for ax in axes:
        ax.tick_params(axis="x", labelsize=9)
        ax.margins(x=0.06)

    bars3 = axes[3].bar(attack_names, cpu_overhead, color=ATTACK_COLORS)
    axes[3].set_title("Median verifier CPU overhead")
    axes[3].set_ylabel("Percent")
    axes[3].set_ylim(0, max(cpu_overhead) * 1.28)
    axes[3].yaxis.set_major_formatter(FuncFormatter(lambda x, _pos: f"{x:.02f}%"))
    for bar, text in zip(bars3, detected_trials):
        axes[3].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.0014, text, ha="center", va="bottom", fontsize=11.0, fontweight="semibold")

    save_fig(fig, "attack_results")
    plt.close(fig)


def plot_real_ablation(payload: dict[str, object]) -> None:
    config_keys = payload["configs"]
    attack_keys = payload["attacks"]
    summary = payload["summary"]
    lookup = {(row["config_key"], row["attack_key"]): row for row in summary}
    config_names = [
        next(row["config_name"] for row in summary if row["config_key"] == key)
        for key in config_keys
    ]
    display_attack_names = list(ATTACK_LABELS.values())

    status_matrix = np.zeros((len(config_keys), len(attack_keys)), dtype=int)
    exfil_matrix = np.full((len(config_keys), len(attack_keys)), np.nan)
    status_text = [["" for _ in attack_keys] for _ in config_keys]
    exfil_text = [["" for _ in attack_keys] for _ in config_keys]

    for row_idx, config_key in enumerate(config_keys):
        for col_idx, attack_key in enumerate(attack_keys):
            row = lookup[(config_key, attack_key)]
            detected = int(row["detected_trials"] == row["total_trials"])
            status_matrix[row_idx, col_idx] = detected
            status_text[row_idx][col_idx] = "DET" if detected else "MISS"
            exfil = row["median_exfiltrated_bytes"]
            if exfil is None:
                exfil_text[row_idx][col_idx] = "N/A"
            else:
                exfil_matrix[row_idx, col_idx] = exfil
                exfil_text[row_idx][col_idx] = f"{int(exfil)} B"

    fig = plt.figure(figsize=(15.3, 5.8), constrained_layout=True)
    gs = fig.add_gridspec(1, 3, width_ratios=[1.02, 1.14, 0.05])
    ax_status = fig.add_subplot(gs[0, 0])
    ax_exfil = fig.add_subplot(gs[0, 1])
    cax = fig.add_subplot(gs[0, 2])

    status_cmap = ListedColormap(["#e4e7eb", PALETTE["green"]])
    ax_status.imshow(status_matrix, cmap=status_cmap, vmin=0, vmax=1, aspect="auto")
    ax_status.set_title("Detection outcome")
    ax_status.set_xticks(range(len(attack_keys)))
    ax_status.set_xticklabels(display_attack_names)
    ax_status.set_yticks(range(len(config_names)))
    ax_status.set_yticklabels(emphasize_aegis(config_names))
    ax_status.tick_params(axis="x", length=0, pad=10)
    ax_status.tick_params(axis="y", length=0)
    ax_status.set_xticks(np.arange(-0.5, len(attack_keys), 1), minor=True)
    ax_status.set_yticks(np.arange(-0.5, len(config_names), 1), minor=True)
    ax_status.grid(which="minor", color="white", linewidth=2.0)
    ax_status.tick_params(which="minor", bottom=False, left=False)
    for tick in ax_status.get_yticklabels():
        if tick.get_text() == "AEGIS (Ours)":
            tick.set_fontweight("bold")
    for row_idx in range(len(config_names)):
        for col_idx in range(len(attack_keys)):
            ax_status.text(col_idx, row_idx, status_text[row_idx][col_idx], ha="center", va="center", fontsize=11.0, fontweight="semibold")

    exfil_cmap = plt.cm.YlOrBr.copy()
    exfil_cmap.set_bad("#ececec")
    image = ax_exfil.imshow(exfil_matrix, cmap=exfil_cmap, aspect="auto")
    ax_exfil.set_title("Median bytes emitted before containment")
    ax_exfil.set_xticks(range(len(attack_keys)))
    ax_exfil.set_xticklabels(display_attack_names)
    ax_exfil.set_yticks(range(len(config_names)))
    ax_exfil.set_yticklabels([])
    ax_exfil.tick_params(axis="x", length=0, pad=10)
    ax_exfil.tick_params(axis="y", length=0)
    ax_exfil.set_xticks(np.arange(-0.5, len(attack_keys), 1), minor=True)
    ax_exfil.set_yticks(np.arange(-0.5, len(config_names), 1), minor=True)
    ax_exfil.grid(which="minor", color="white", linewidth=2.0)
    ax_exfil.tick_params(which="minor", bottom=False, left=False)
    for row_idx in range(len(config_names)):
        for col_idx in range(len(attack_keys)):
            value = exfil_matrix[row_idx, col_idx]
            text_color = "#222222" if np.isnan(value) or value < 220 else "white"
            ax_exfil.text(col_idx, row_idx, exfil_text[row_idx][col_idx], ha="center", va="center", fontsize=11.0, fontweight="semibold", color=text_color)

    cbar = fig.colorbar(image, cax=cax)
    cbar.set_label("Bytes")

    save_fig(fig, "ablation_heatmap")
    plt.close(fig)


def plot_simulated_ablation(payload: dict[str, object]) -> None:
    config_names, _attack_names, matrix, rates = load_simulated_ablation_matrix(payload)
    display_attack_names = [
        "Volume\nlimit",
        "Sensitive\nfile",
        "Covert\nchannel",
        "Injection\nsig",
    ]
    display_config_names = []
    for name in config_names:
        if name == "Full AEGIS":
            display_config_names.append("AEGIS")
        elif name == "No Volume Limits":
            display_config_names.append("No volume")
        elif name == "No Sensitive Detection":
            display_config_names.append("No sensitive")
        elif name == "No Covert Channel":
            display_config_names.append("No covert")
        elif name == "No Injection Sig":
            display_config_names.append("No sig")
        else:
            display_config_names.append("Path-only")

    fig = plt.figure(figsize=(3.35, 5.35), constrained_layout=True)
    gs = fig.add_gridspec(2, 1, height_ratios=[2.55, 1.45])
    ax_heatmap = fig.add_subplot(gs[0, 0])
    ax_rate = fig.add_subplot(gs[1, 0])

    heatmap_cmap = ListedColormap(["#e4e7eb", PALETTE["green"]])
    ax_heatmap.imshow(matrix, cmap=heatmap_cmap, vmin=0, vmax=100, aspect="auto")
    ax_heatmap.set_title("Ablation by attack", fontsize=13.5, pad=6)
    ax_heatmap.set_xticks(range(len(display_attack_names)))
    ax_heatmap.set_xticklabels(display_attack_names, fontsize=10.5)
    ax_heatmap.set_yticks(range(len(display_config_names)))
    ax_heatmap.set_yticklabels(display_config_names, fontsize=10.5)
    ax_heatmap.tick_params(axis="x", length=0, pad=4)
    ax_heatmap.tick_params(axis="y", length=0, pad=3)
    ax_heatmap.set_xticks(np.arange(-0.5, len(display_attack_names), 1), minor=True)
    ax_heatmap.set_yticks(np.arange(-0.5, len(display_config_names), 1), minor=True)
    ax_heatmap.grid(which="minor", color="white", linewidth=1.8)
    ax_heatmap.tick_params(which="minor", bottom=False, left=False)
    for tick in ax_heatmap.get_yticklabels():
        if tick.get_text() == "AEGIS":
            tick.set_fontweight("bold")
    for row_idx in range(len(display_config_names)):
        for col_idx in range(len(display_attack_names)):
            ax_heatmap.text(
                col_idx,
                row_idx,
                "DET" if matrix[row_idx, col_idx] == 100 else "MISS",
                ha="center",
                va="center",
                fontsize=9.2,
                fontweight="semibold",
                color="#111111",
            )

    bar_colors = []
    for name in config_names:
        if name == "Full AEGIS":
            bar_colors.append(PALETTE["amber"])
        elif name == "Minimal (path only)":
            bar_colors.append("#b8c2cc")
        else:
            bar_colors.append(PALETTE["blue"])

    ypos = np.arange(len(display_config_names))
    bars = ax_rate.barh(ypos, rates, color=bar_colors, height=0.72)
    ax_rate.set_title("Overall rate", fontsize=13.5, pad=6)
    ax_rate.set_xlim(0, 100)
    ax_rate.set_xlabel("Detection (%)", fontsize=11.5)
    ax_rate.set_yticks(ypos)
    ax_rate.set_yticklabels(display_config_names, fontsize=10.5)
    ax_rate.invert_yaxis()
    ax_rate.grid(axis="x", alpha=0.18)
    ax_rate.tick_params(axis="x", labelsize=10.0)
    ax_rate.tick_params(axis="y", length=0, pad=3)
    for tick in ax_rate.get_yticklabels():
        if tick.get_text() == "AEGIS":
            tick.set_fontweight("bold")
    for bar, rate in zip(bars, rates):
        xpos = min(rate + 2.0, 98.0) if rate < 100 else 97.0
        halign = "left" if rate < 100 else "right"
        ax_rate.text(
            xpos,
            bar.get_y() + bar.get_height() / 2,
            f"{rate:.0f}%",
            va="center",
            ha=halign,
            fontsize=10.2,
            fontweight="semibold",
            color="#111111",
        )

    save_fig(fig, "simulated_ablation_breakdown")
    plt.close(fig)


def draw_scaling_sweep(axes: list[plt.Axes], payload: dict[str, object]) -> None:
    interval_sweep = sorted(payload["interval_sweep"], key=lambda row: row["attestation_interval"])
    agent_sweep = sorted(payload["agent_count_sweep"], key=lambda row: row["agent_count"])
    workload_sweep = payload["workload_type_sweep"]

    axes[0].plot(
        [row["attestation_interval"] for row in interval_sweep],
        [row["overhead_percent"] for row in interval_sweep],
        marker="o",
        linewidth=2.5,
        markersize=7,
        color=PALETTE["blue"],
    )
    axes[0].set_xscale("log")
    axes[0].set_title("Overhead vs interval")
    axes[0].set_xlabel("Attestation interval (s)")
    axes[0].set_ylabel("Overhead (%)")

    axes[1].plot(
        [row["agent_count"] for row in agent_sweep],
        [row["overhead_percent"] for row in agent_sweep],
        marker="o",
        linewidth=2.5,
        markersize=7,
        color=PALETTE["green"],
    )
    axes[1].set_title("Overhead vs agent count")
    axes[1].set_xlabel("Agent count")
    axes[1].set_ylabel("Overhead (%)")

    workload_labels = [row["workload_type"].replace("_", "-").title() for row in workload_sweep]
    workload_values = [row["overhead_percent"] for row in workload_sweep]
    workload_colors = [PALETTE["blue"], PALETTE["green"], PALETTE["amber"], PALETTE["red"]][: len(workload_sweep)]
    bars = axes[2].bar(workload_labels, workload_values, color=workload_colors)
    axes[2].set_title("Overhead by workload")
    axes[2].set_ylabel("Overhead (%)")
    axes[2].tick_params(axis="x", rotation=15)
    axes[2].set_ylim(0, max(workload_values) * 1.18)
    for bar, value in zip(bars, workload_values):
        axes[2].text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.08,
            f"{value:.2f}%",
            ha="center",
            va="bottom",
            fontsize=11.0,
            fontweight="semibold",
        )


def plot_scaling_sweep(payload: dict[str, object] | None) -> None:
    if payload is None:
        print("Skipping scaling_sweep regeneration because simulated_performance.json is unavailable.")
        return

    fig, axes = plt.subplots(1, 3, figsize=(15.4, 5.4), constrained_layout=True)
    draw_scaling_sweep(list(axes), payload)
    save_fig(fig, "scaling_sweep")
    plt.close(fig)


def draw_performance_overhead(
    ax_bar: plt.Axes,
    ax_line: plt.Axes,
    microbench: list[dict[str, object]],
    sweep_payload: dict[str, object],
    compact_layout: bool = False,
) -> None:
    sweep_summary = sorted(sweep_payload["summary"], key=lambda row: row["interval"])
    intervals = [row["interval"] for row in sweep_summary]
    latencies = [row["avg_latency_ms"] for row in sweep_summary]
    cpu_pct = [row["cpu_overhead"] for row in sweep_summary]

    mode_names = [row["mode"] for row in microbench]
    elapsed_pct = [row["elapsed_pct"] for row in microbench]
    task_clock_pct = [row["task_clock_pct"] for row in microbench]
    throughput_loss = [row["throughput_loss_pct"] for row in microbench]
    xpos = np.arange(len(mode_names))
    width = 0.24

    bars_elapsed = ax_bar.bar(xpos - width, elapsed_pct, width=width, label="Elapsed overhead", color=PALETTE["blue"])
    bars_task = ax_bar.bar(xpos, task_clock_pct, width=width, label="Task-clock overhead", color=PALETTE["green"])
    bars_throughput = ax_bar.bar(xpos + width, throughput_loss, width=width, label="Throughput loss", color=PALETTE["amber"])
    ax_bar.set_xticks(xpos)
    ax_bar.set_xticklabels(mode_names)
    ax_bar.set_ylabel("Percent")
    ax_bar.set_title("Direct probe overhead by syscall family")
    ax_bar.set_ylim(0, max(max(elapsed_pct), max(task_clock_pct), max(throughput_loss)) * 1.24)
    if compact_layout:
        ax_bar.legend(
            loc="upper left",
            bbox_to_anchor=(1.02, 1.0),
            ncol=1,
            fontsize=9.2,
            handlelength=1.4,
            columnspacing=0.8,
            borderaxespad=0.0,
        )
    else:
        ax_bar.legend(loc="upper right")
    for bars, values in [
        (bars_elapsed, elapsed_pct),
        (bars_task, task_clock_pct),
        (bars_throughput, throughput_loss),
    ]:
        for bar, value in zip(bars, values):
            ax_bar.text(
                bar.get_x() + bar.get_width() / 2,
                value + 0.7,
                f"{value:.1f}%",
                ha="center",
                va="bottom",
                fontsize=10.5,
                fontweight="semibold",
            )

    ax_line.plot(intervals, latencies, marker="o", markersize=7, linewidth=2.5, color=PALETTE["red"], label="Detection latency (ms)")
    ax_line.set_xscale("log")
    ax_line.set_xlabel("Attestation interval (s)")
    ax_line.set_ylabel("Detection latency (ms)", color=PALETTE["red"])
    ax_line.tick_params(axis="y", labelcolor=PALETTE["red"])
    ax_line.set_title("Latency and CPU vs attestation interval")
    ax_line.grid(axis="both", alpha=0.16)

    ax_line_cpu = ax_line.twinx()
    ax_line_cpu.plot(intervals, cpu_pct, marker="s", markersize=6, linestyle="--", linewidth=2.2, color=PALETTE["green"], label="CPU overhead (%)")
    ax_line_cpu.set_ylabel("CPU overhead (%)", color=PALETTE["green"])
    ax_line_cpu.tick_params(axis="y", labelcolor=PALETTE["green"])

    highlight_indices = [0, 2, len(intervals) - 1]
    for idx in highlight_indices:
        ax_line.annotate(
            f"{latencies[idx]:.0f} ms",
            (intervals[idx], latencies[idx]),
            textcoords="offset points",
            xytext=(0, 9),
            ha="center",
            fontsize=10.5,
            fontweight="semibold",
            color=PALETTE["red"],
        )
        ax_line_cpu.annotate(
            f"{cpu_pct[idx]:.3f}%",
            (intervals[idx], cpu_pct[idx]),
            textcoords="offset points",
            xytext=(0, -18),
            ha="center",
            fontsize=10.5,
            fontweight="semibold",
            color=PALETTE["green"],
            bbox={"boxstyle": "round,pad=0.18", "facecolor": "white", "edgecolor": "none", "alpha": 0.9},
        )

    lines = ax_line.get_lines() + ax_line_cpu.get_lines()
    labels = [line.get_label() for line in lines]
    if compact_layout:
        ax_line.legend(
            lines,
            labels,
            loc="upper left",
            bbox_to_anchor=(0.03, 0.98),
            ncol=1,
            fontsize=9.2,
            handlelength=1.6,
            columnspacing=0.8,
            borderaxespad=0.0,
        )
    else:
        ax_line.legend(lines, labels, loc="upper center", bbox_to_anchor=(0.5, 0.98), ncol=2)


def plot_performance_overhead(microbench: list[dict[str, object]], sweep_payload: dict[str, object]) -> None:
    fig, (ax_bar, ax_line) = plt.subplots(1, 2, figsize=(15.0, 5.6), constrained_layout=True)
    draw_performance_overhead(ax_bar, ax_line, microbench, sweep_payload)
    save_fig(fig, "performance_overhead")
    plt.close(fig)


def plot_performance_summary(
    microbench: list[dict[str, object]],
    sweep_payload: dict[str, object],
    scaling_payload: dict[str, object] | None,
) -> None:
    if scaling_payload is None:
        print("Skipping performance_summary regeneration because simulated_performance.json is unavailable.")
        return

    fig, axes = plt.subplots(
        1,
        5,
        figsize=(25.8, 5.6),
        gridspec_kw={"width_ratios": [1.45, 1.45, 1.1, 1.1, 1.15]},
        constrained_layout=True,
    )
    ax_bar, ax_line, ax_scale_interval, ax_scale_agents, ax_scale_workload = axes

    draw_performance_overhead(ax_bar, ax_line, microbench, sweep_payload, compact_layout=True)
    draw_scaling_sweep([ax_scale_interval, ax_scale_agents, ax_scale_workload], scaling_payload)

    ax_bar.set_title("(a) Direct probe overhead by syscall family", pad=10)
    ax_line.set_title("(b) Latency and CPU vs. attestation interval", pad=10)
    ax_scale_interval.set_title("(c) Overhead vs. interval", pad=10)
    ax_scale_agents.set_title("(d) Overhead vs. agent count", pad=10)
    ax_scale_workload.set_title("(e) Overhead by workload", pad=10)

    save_fig(fig, "performance_summary")
    plt.close(fig)


def main() -> None:
    result_dir = resolve_result_dir()
    perf_path = resolve_perf_artifact(result_dir)
    print(f"Using results directory: {result_dir.relative_to(ROOT)}")
    if perf_path is None:
        print("Simulated performance artifact: unavailable")
    else:
        try:
            display_perf = perf_path.relative_to(ROOT)
        except ValueError:
            display_perf = perf_path
        print(f"Using simulated performance artifact: {display_perf}")

    baseline_rows = parse_baseline_table(result_dir / "baseline_comparison.md")
    real_latency = collect_real_latency_summaries(result_dir)
    real_ablation = load_json(result_dir / "real_ablation.json")
    simulated_ablation = load_json(result_dir / "simulated_ablation.json")
    real_latency_sweep = load_json(result_dir / "real_latency_sweep.json")
    microbench = collect_microbenchmarks(result_dir)
    simulated_perf = load_json(perf_path) if perf_path else None

    plot_baseline_comparison(baseline_rows)
    plot_attack_results(real_latency)
    plot_real_ablation(real_ablation)
    plot_simulated_ablation(simulated_ablation)
    plot_performance_overhead(microbench, real_latency_sweep)
    plot_scaling_sweep(simulated_perf)
    plot_performance_summary(microbench, real_latency_sweep, simulated_perf)


if __name__ == "__main__":
    main()
