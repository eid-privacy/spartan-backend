#!/usr/bin/env python3.14
"""Plot spartan benchmark stats across commits, relative to the first commit.

Usage: plot_benchmark_commits.py stats_dir

Reads the CSV files produced by scripts/benchmark_commits.sh in `stats_dir`:
  stats-00-barretenberg.csv   write_vk, prove, verify         (optional, run once)
  stats-NN-<sha>.csv          spartan_proof, spartan_verify   (one per commit)
Each file has the schema: metric,min,max,mean,stddev

X-axis: commits, oldest -> newest (by the NN index encoded in the filename).
Baselines (values below 1.0 are improvements over the first commit):
  - Timing series `spartan_proof`/`spartan_verify` are divided by the FIRST commit's
    `spartan_proof` mean, so they read as multiples of the baseline proof time.
  - `spartan_proof_size` has different units, so it is divided by its OWN first
    available value.
  - `spartan_constraints` is drawn as `frac(log2(c) + 0.5) - 0.5` offset onto the
    baseline: the signed distance in log2 octaves to the nearest power of two. Its
    line crossing the baseline marks constraints crossing a power-of-two boundary
    (where the Spartan R1CS padding jumps).
  Commits that lack a metric (older backends without `--count-constraints` /
  `--proof-size`) are skipped for that series.

Barretenberg does not depend on the spartan-backend code (run once), so the sum of
`write_vk` + `prove` is drawn as a horizontal reference line when the file exists.

Output: benchmarks.png in stats_dir.
"""

import csv
import math
import re
import sys

import matplotlib

matplotlib.use("Agg")
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# Timing series (seconds), all divided by the FIRST commit's spartan_proof mean so
# spartan_verify reads as a fraction of the baseline proof time.
SPARTAN_TIME = {
    "spartan_proof": {"color": "#4e79a7", "label": "spartan_proof", "marker": "D"},
}
# Size series. Different units from the timings, so divided by its OWN first
# available value. Only present on commits whose backend supports `--proof-size`;
# commits without the metric are skipped.
SPARTAN_SIZE = {
    "spartan_proof_size": {"color": "#9c755f", "label": "spartan_proof_size", "marker": "s"},
}
# spartan_constraints gets a special transform (see plot below) rather than a ratio:
# the signed distance in log2 octaves to the nearest power of two, so the line
# crossing the baseline marks a power-of-two boundary (relevant for R1CS padding).
CONSTRAINTS_STYLE = {
    "color": "#b07aa1",
    "label": "spartan_constraints (log₂ boundary)",
    "marker": "o",
}
# barretenberg reference line: sum of write_vk + prove, drawn as one horizontal line.
BARRETENBERG_SUM = {
    "metrics": ("write_vk", "prove"),
    "color": "#f28e2b",
    "label": "barretenberg write_vk + prove",
}


def parse_file(path):
    data = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            data[row["metric"]] = {
                k: float(row[k]) for k in ("min", "max", "mean", "stddev")
            }
    return data


def main():
    if len(sys.argv) != 2:
        print("Usage: plot_benchmark_commits.py stats_dir", file=sys.stderr)
        sys.exit(1)

    stats_dir = Path(sys.argv[1])
    if not stats_dir.is_dir():
        print(f"Not a directory: {stats_dir}", file=sys.stderr)
        sys.exit(1)

    files = sorted(stats_dir.glob("stats-*.csv"), key=lambda p: p.name)
    if not files:
        print(f"No stats-*.csv files in {stats_dir}", file=sys.stderr)
        sys.exit(1)

    # Split files into per-commit spartan runs and the single barretenberg run.
    commits = []  # list of (short_sha, parsed_data), oldest first
    bb = None
    for f in files:
        m = re.match(r"stats-\d+-(.+)\.csv$", f.name)
        if not m:
            continue
        label = m.group(1)
        data = parse_file(f)
        if "spartan_proof" in data or "spartan_verify" in data:
            commits.append((label, data))
        else:
            bb = data  # barretenberg reference (write_vk/prove/verify)

    if not commits:
        print(f"No per-commit spartan stats found in {stats_dir}", file=sys.stderr)
        sys.exit(1)

    # Baseline = spartan_proof mean of the FIRST (oldest) commit.
    baseline_sha, baseline_data = commits[0]
    if "spartan_proof" not in baseline_data:
        print("First commit has no spartan_proof metric; cannot baseline.", file=sys.stderr)
        sys.exit(1)
    baseline = baseline_data["spartan_proof"]["mean"]

    labels = [sha for sha, _ in commits]
    n = len(commits)
    xs = list(range(n))

    fig, ax = plt.subplots(figsize=(max(8, n * 1.6), 6))

    # --- baseline reference line at y = 1.0 ---
    ax.axhline(1.0, color="#333333", linewidth=1.2, linestyle="-", zorder=2)
    ax.text(
        n - 0.5,
        1.0,
        f"  baseline: {baseline_sha}",
        color="#333333",
        fontsize=9,
        va="bottom",
        ha="right",
    )

    def fmt_time(s):
        return f"{s:.1f}s" if s < 60 else f"{s / 60:.1f}m"

    def fmt_size(b):
        if b < 1024:
            return f"{b:.0f}B"
        if b < 1024**2:
            return f"{b / 1024:.1f}KB"
        return f"{b / 1024**2:.1f}MB"

    # --- spartan series across commits ---
    def plot_metric(metric, style, denom, annotate=None, dy=-14):
        pts = [
            (x, data[metric]) for x, (_, data) in zip(xs, commits) if metric in data
        ]
        if not pts:
            return
        px = [p[0] for p in pts]
        ax.plot(
            px,
            [p[1]["mean"] / denom for p in pts],
            color=style["color"],
            linewidth=1.8,
            marker=style["marker"],
            markersize=5,
            label=style["label"],
            zorder=6,
        )
        ax.fill_between(
            px,
            [p[1]["min"] / denom for p in pts],
            [p[1]["max"] / denom for p in pts],
            color=style["color"],
            alpha=0.15,
        )
        if annotate:
            for x, m in pts:
                ax.annotate(
                    annotate(m["mean"]),
                    (x, m["mean"] / denom),
                    textcoords="offset points",
                    xytext=(0, dy),
                    ha="center",
                    fontsize=8,
                    color=style["color"],
                    zorder=7,
                )

    # Timing series: shared baseline = first commit's spartan_proof mean.
    for metric, style in SPARTAN_TIME.items():
        plot_metric(metric, style, baseline, annotate=fmt_time, dy=-14)

    # Size series: each divided by its own first available value.
    for metric, style in SPARTAN_SIZE.items():
        available = [data[metric]["mean"] for _, data in commits if metric in data]
        if available:
            plot_metric(metric, style, available[0], annotate=fmt_size, dy=8)

    # spartan_constraints: plotted on its OWN right-hand y-axis (independent of the
    # left "relative to first commit" scale). The value is `frac(log2(c) + 0.5) - 0.5`,
    # the signed distance in log2 octaves to the nearest power of two (0 exactly at a
    # power of two, negative just below, positive just above). The right axis has its
    # own baseline at 0 — the constraints line crossing it marks crossing a
    # power-of-two boundary (where the Spartan R1CS padding jumps).
    def log2_boundary(c):
        x = math.log2(c) + 0.5
        return (x - math.floor(x)) - 0.5

    ax2 = ax.twinx()
    cpts = [
        (x, data["spartan_constraints"]["mean"])
        for x, (_, data) in zip(xs, commits)
        if "spartan_constraints" in data
    ]
    if cpts:
        cys = [log2_boundary(p[1]) for p in cpts]
        # right-axis baseline at 0 (power-of-two boundary)
        ax2.axhline(0.0, color=CONSTRAINTS_STYLE["color"], linewidth=1.0, linestyle="-", alpha=0.4, zorder=2)
        ax2.plot(
            [p[0] for p in cpts],
            cys,
            color=CONSTRAINTS_STYLE["color"],
            linewidth=1.8,
            linestyle=":",
            marker=CONSTRAINTS_STYLE["marker"],
            markersize=5,
            label=CONSTRAINTS_STYLE["label"],
            zorder=6,
        )
        # annotate each point with the real constraint count
        for (x, c), y in zip(cpts, cys):
            ax2.annotate(
                f"{int(c):,}",
                (x, y),
                textcoords="offset points",
                xytext=(0, 6),
                ha="center",
                fontsize=8,
                color=CONSTRAINTS_STYLE["color"],
                zorder=7,
            )

    # --- barretenberg horizontal reference line (constant across commits) ---
    if bb and all(m in bb for m in BARRETENBERG_SUM["metrics"]):
        total = sum(bb[m]["mean"] for m in BARRETENBERG_SUM["metrics"])
        ax.axhline(
            total / baseline,
            color=BARRETENBERG_SUM["color"],
            linewidth=1.5,
            linestyle="--",
            label=BARRETENBERG_SUM["label"],
            zorder=4,
        )
        ax.text(
            -0.45,
            total / baseline,
            f" {fmt_time(total)}",
            color=BARRETENBERG_SUM["color"],
            fontsize=8,
            va="bottom",
            ha="left",
            zorder=5,
        )

    ax.set_xticks(xs)
    ax.set_xticklabels(labels, fontsize=10, rotation=30, ha="right")
    ax.set_xlabel("Commit (oldest → newest)", fontsize=12)
    ax.set_ylabel("Relative to first commit", fontsize=12)
    ax.set_title(
        f"Spartan benchmark across commits ({stats_dir.name})",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_xlim(-0.5, n - 0.5)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}×"))
    ax.grid(axis="both", alpha=0.3, linestyle="--")

    # --- right y-axis for spartan_constraints (independent scale) ---
    # Fixed to the full [-0.5, 0.5] range of the log2-boundary transform, with its own
    # baseline at 0. Completely decoupled from the left axis, which autoscales on its own.
    ax2.set_ylim(-0.5, 0.5)
    ax2.set_yticks([-0.5, -0.25, 0.0, 0.25, 0.5])
    ax2.set_ylabel(
        "spartan_constraints (log₂ octaves to nearest power of two)",
        fontsize=12,
        color=CONSTRAINTS_STYLE["color"],
    )
    ax2.tick_params(axis="y", colors=CONSTRAINTS_STYLE["color"])
    ax2.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:+.2f}"))

    # two legends: spartan_* + barretenberg (left axis) upper-left,
    # spartan_constraints (right axis) upper-right.
    ax.legend(loc="upper left", fontsize=9, framealpha=0.9)
    ax2.legend(loc="upper right", fontsize=9, framealpha=0.9)

    output = str(stats_dir / "benchmarks.png")
    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches="tight")
    print(f"Saved → {output}")


if __name__ == "__main__":
    main()
