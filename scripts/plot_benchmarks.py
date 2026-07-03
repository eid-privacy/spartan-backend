#!/usr/bin/env python3.14
"""Plot benchmark stats from CSV files, relative to a baseline.

Usage: plot_benchmarks.py stats_dir

Reads all *.txt files in stats_dir, sorted by name.

Baseline: the LAST file (by sorted name). Every series is divided, per input
size, by the baseline's spartan_proof mean, so the y-axis reads as a multiple
of the baseline. Values below 1.0 are improvements over the baseline.

Last file: prove and spartan_proof.
Other files: spartan_proof only.

Output: benchmarks.png in stats_dir.
"""

import csv
import re
import sys

import matplotlib

matplotlib.use("Agg")
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

METRICS = ["prove", "spartan_proof"]
COLORS = {
    "prove": "#f28e2b",
    "spartan_proof": "#76b7b2",
}
# Distinct qualitative palette for the non-baseline Spartan runs
PALETTE = [
    "#4e79a7",
    "#e15759",
    "#59a14f",
    "#b07aa1",
    "#9c755f",
    "#edc948",
    "#ff9da7",
    "#17becf",
]


def parse_file(path):
    data = defaultdict(dict)
    with open(path) as f:
        for row in csv.DictReader(f):
            size = int(row["input_size"])
            metric = row["metric"]
            data[size][metric] = {
                k: float(row[k]) for k in ("min", "max", "mean", "stddev")
            }
    return data


def baseline_mean(baseline_data, size):
    """spartan_proof mean of the baseline at `size`, or None if absent."""
    d = baseline_data.get(size, {}).get("spartan_proof")
    return d["mean"] if d else None


def main():
    if len(sys.argv) != 2:
        print("Usage: plot_benchmarks.py stats_dir", file=sys.stderr)
        sys.exit(1)

    stats_dir = Path(sys.argv[1])
    if not stats_dir.is_dir():
        print(f"Not a directory: {stats_dir}", file=sys.stderr)
        sys.exit(1)

    files = sorted(stats_dir.glob("*.txt"), key=lambda p: p.name)
    if not files:
        print(f"No *.txt files in {stats_dir}", file=sys.stderr)
        sys.exit(1)

    *others, last = [str(f) for f in files]
    last_data = parse_file(last)
    other_parsed = [(Path(f).stem, parse_file(f)) for f in others]

    # Baseline = the last file given overall.
    baseline_name, baseline_data = Path(last).stem, last_data

    # Union of all input sizes, sorted
    all_sizes = sorted(
        {size for d in [last_data] + [d for _, d in other_parsed] for size in d}
    )
    size_to_xi = {size: i for i, size in enumerate(all_sizes)}
    n = len(all_sizes)

    fig, ax = plt.subplots(figsize=(max(10, n * 3.5), 7))

    def plot_series(sizes_dicts_metric, color, ls, label):
        """Plot one metric as a ratio to the baseline spartan_proof."""
        rows = [
            (size_to_xi[size], baseline_mean(baseline_data, size), md)
            for size, md in sizes_dicts_metric
            if baseline_mean(baseline_data, size) is not None
        ]
        if not rows:
            return
        xs = [r[0] for r in rows]
        ys_mean = [r[2]["mean"] / r[1] for r in rows]
        ys_lo = [r[2]["min"] / r[1] for r in rows]
        ys_hi = [r[2]["max"] / r[1] for r in rows]
        ax.plot(
            xs,
            ys_mean,
            color=color,
            linestyle=ls,
            linewidth=1.8,
            marker="D",
            markersize=5,
            label=label,
            zorder=6,
        )
        ax.fill_between(xs, ys_lo, ys_hi, color=color, alpha=0.15)

    # --- Baseline reference line at y = 1.0 ---
    ax.axhline(1.0, color="#333333", linewidth=1.2, linestyle="-", zorder=2)
    ax.text(
        n - 0.5,
        1.0,
        f"  baseline: {baseline_name}",
        color="#333333",
        fontsize=9,
        va="bottom",
        ha="right",
    )

    # --- Last file: prove + spartan_proof ---
    for metric in METRICS:
        series = [
            (size, last_data[size][metric])
            for size in all_sizes
            if size in last_data and metric in last_data[size]
        ]
        label = "barretenberg" if metric == "prove" else f"{metric}  [{Path(last).stem}]"
        plot_series(series, COLORS[metric], "-", label)

    # --- Other files: spartan_proof only ---
    line_styles = ["--", "-.", ":", (0, (3, 1, 1, 1))]
    for i, (name, data) in enumerate(other_parsed):
        series = [
            (size, data[size]["spartan_proof"])
            for size in all_sizes
            if size in data and "spartan_proof" in data[size]
        ]
        plot_series(
            series,
            PALETTE[i % len(PALETTE)],
            line_styles[i % len(line_styles)],
            f"spartan_proof  [{name}]",
        )

    ax.set_xticks(range(n))
    ax.set_xticklabels([str(s) for s in all_sizes], fontsize=11)
    ax.set_xlabel("Input size", fontsize=12)
    ax.set_ylabel("Time relative to baseline", fontsize=12)
    ax.set_title(
        f"Benchmark results relative to baseline ({stats_dir.name})",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_xlim(-0.5, n - 0.5)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}×"))
    ax.grid(axis="both", alpha=0.3, linestyle="--")

    # Sort legend by filename (part inside [...])
    handles, labels = ax.get_legend_handles_labels()

    def _sort_key(hl):
        m = re.search(r"\[(.+)\]", hl[1])
        # Labels without a [...] tag (e.g. "barretenberg") sort last.
        return (0, m.group(1), hl[1]) if m else (1, hl[1], hl[1])

    handles, labels = (
        zip(*sorted(zip(handles, labels), key=_sort_key)) if handles else ([], [])
    )
    ax.legend(handles, labels, loc="lower left", fontsize=9, framealpha=0.9)

    output = str(stats_dir / "benchmarks.png")
    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches="tight")
    print(f"Saved → {output}")


if __name__ == "__main__":
    main()
