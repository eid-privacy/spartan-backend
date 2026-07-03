#!/usr/bin/env python3.14
"""Plot benchmark stats from CSV files.

Usage: plot_benchmarks.py [other_file ...] last_file.txt

Last file: line+band chart for prove and spartan_proof.
Other files: spartan_proof mean line with min/max band only.

Output: benchmarks.png in the current directory.
"""

import sys
import csv
import re
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
from pathlib import Path
from collections import defaultdict

METRICS = ["prove", "spartan_proof"]
COLORS = {
    "prove":         "#f28e2b",
    "spartan_proof": "#76b7b2",
}


def parse_file(path):
    data = defaultdict(dict)
    with open(path) as f:
        for row in csv.DictReader(f):
            size = int(row["input_size"])
            metric = row["metric"]
            data[size][metric] = {k: float(row[k]) for k in ("min", "max", "mean", "stddev")}
    return data


def main():
    if len(sys.argv) < 2:
        print("Usage: plot_benchmarks.py [other_file ...] last_file.txt", file=sys.stderr)
        sys.exit(1)

    *others, last = sys.argv[1:]
    last_data = parse_file(last)
    other_parsed = [(Path(f).stem, parse_file(f)) for f in others]

    # Union of all input sizes, sorted
    all_sizes = sorted({
        size
        for d in [last_data] + [d for _, d in other_parsed]
        for size in d
    })
    size_to_xi = {size: i for i, size in enumerate(all_sizes)}
    n = len(all_sizes)

    fig, ax = plt.subplots(figsize=(max(10, n * 3.5), 7))

    # --- Line plots: last file, prove + spartan_proof ---
    for metric in METRICS:
        color = COLORS[metric]
        rows = [
            (size_to_xi[size], last_data[size][metric])
            for size in all_sizes
            if size in last_data and metric in last_data[size]
        ]
        if not rows:
            continue
        xs      = [r[0] for r in rows]
        ys_mean = [r[1]["mean"] for r in rows]
        ys_lo   = [r[1]["min"]  for r in rows]
        ys_hi   = [r[1]["max"]  for r in rows]
        ax.plot(xs, ys_mean, color=color, linestyle="-", linewidth=1.8,
                marker="D", markersize=5, label=f"{metric}  [{Path(last).stem}]", zorder=6)
        ax.fill_between(xs, ys_lo, ys_hi, color=color, alpha=0.18)

    # --- Line plots: other files, spartan_proof only ---
    line_styles = ["--", "-.", ":", (0, (3, 1, 1, 1))]
    gray_shades = ["#444444", "#777777", "#aaaaaa", "#222222"]

    for i, (name, data) in enumerate(other_parsed):
        rows = [
            (size_to_xi[size], data[size]["spartan_proof"])
            for size in all_sizes
            if size in data and "spartan_proof" in data[size]
        ]
        if not rows:
            continue
        xs       = [r[0] for r in rows]
        ys_mean  = [r[1]["mean"] for r in rows]
        ys_lo    = [r[1]["min"]  for r in rows]
        ys_hi    = [r[1]["max"]  for r in rows]

        c  = gray_shades[i % len(gray_shades)]
        ls = line_styles[i % len(line_styles)]
        ax.plot(xs, ys_mean, color=c, linestyle=ls, linewidth=1.8,
                marker="D", markersize=5, label=f"spartan_proof  [{name}]", zorder=6)
        ax.fill_between(xs, ys_lo, ys_hi, color=c, alpha=0.13)

    ax.set_xticks(range(n))
    ax.set_xticklabels([str(s) for s in all_sizes], fontsize=11)
    ax.set_xlabel("Input size", fontsize=12)
    ax.set_ylabel("Time (s)", fontsize=12)
    ax.set_title("Benchmark results", fontsize=14, fontweight="bold")
    ax.set_xlim(-0.5, n - 0.5)
    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g} s"))
    ax.grid(axis="both", alpha=0.3, linestyle="--")

    # Sort legend by filename (part inside [...])
    handles, labels = ax.get_legend_handles_labels()
    def _sort_key(hl):
        m = re.search(r'\[(.+)\]', hl[1])
        return (m.group(1) if m else hl[1], hl[1])
    handles, labels = zip(*sorted(zip(handles, labels), key=_sort_key)) if handles else ([], [])
    ax.legend(handles, labels, loc="upper left", fontsize=9, framealpha=0.9)

    output = "benchmarks.png"
    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches="tight")
    print(f"Saved → {output}")


if __name__ == "__main__":
    main()
