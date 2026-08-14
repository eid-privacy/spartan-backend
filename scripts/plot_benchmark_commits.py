#!/usr/bin/env python3.14
"""Plot noir/barretenberg vs. spartan benchmarks across a shared commit timeline.

Usage: plot_benchmark_commits.py <config.yaml>

Reads the config file (see BENCHMARK_PLAN.md for the full grammar) and the CSV
result files it names under `<config_dir>/results/<leg>-<shortsha>.csv`, written by
scripts/benchmark_commits.sh / scripts/benchmark_run.sh. Each result file has the
schema: metric,min,max,mean,stddev,samples (plus `#`-prefixed metadata lines).

X-axis: the union of `noir_commits` and `spartan_commits`, in git topological order
(oldest -> newest). A commit present in both lists occupies one x position and
carries both series' markers; each series is drawn only where it has a result,
connected across just those points (no interpolation through gaps).

Y-axis: relative to the baseline, the FIRST noir_commits entry's
`bb_write_vk` + `bb_prove` mean. `bb_write_vk+bb_prove` and `spartan_proof` are
solid series. Points are annotated with their absolute time. The axis is
fixed to [0.5, 1.5] so the baseline (y=1.0) always sits in the vertical middle
of the plot.

`spartan_constraints` is also drawn on this axis, not as a ratio to the
baseline but as a measure of how close the constraint count is to a power of
two (relevant because Spartan pads the constraint count up to the next power
of two): 1.0 means it sits exactly on a power of two, values below 1.0 mean
it's just past a power-of-two boundary (wasteful padding), values above 1.0
mean it's approaching the next boundary (efficient use of the padding), with
0.5/1.5 as the extremes reached at the exact midpoint between two boundaries.
Points are annotated with the raw constraint count.

A text box in the upper right lists the latest spartan run's verify time and
proof size — these aren't plotted as time series.

Output: benchmarks.png next to the config file.
"""

import csv
import math
import subprocess
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import yaml
from matplotlib.ticker import FuncFormatter

BARRETENBERG_STYLE = {"color": "#f28e2b", "label": "barretenberg write_vk + prove"}
SPARTAN_STYLE = {"color": "#4e79a7", "label": "spartan_proof"}
CONSTRAINTS_STYLE = {"color": "#59a14f", "label": "spartan_constraints (pow2 distance)"}


def pow2_distance(v):
    """1.0 exactly on a power of two; 0.5/1.5 at the midpoint to the neighboring one."""
    L = math.log2(v)
    return 1 + (L - round(L))


def fmt_time(s):
    if s < 1:
        return f"{s * 1000:.0f}ms"
    return f"{s:.1f}s" if s < 60 else f"{s / 60:.1f}m"


def split_entry(entry):
    parts = entry.split(None, 1)
    ref = parts[0]
    label = parts[1] if len(parts) > 1 else ""
    return ref, label


def flatten_circuit_groups(groups):
    entries = []
    for group in groups or []:
        for e in group.get("commits", []):
            entries.append(split_entry(e))
    return entries


def load_config(path):
    with open(path) as f:
        cfg = yaml.safe_load(f)
    return {
        "name": cfg["name"],
        "noir_commits": flatten_circuit_groups(cfg.get("noir")),
        "spartan_commits": flatten_circuit_groups(cfg.get("spartan")),
    }


def resolve(repo_root, ref):
    full = subprocess.run(
        ["git", "-C", repo_root, "rev-parse", ref],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    short = subprocess.run(
        ["git", "-C", repo_root, "rev-parse", "--short", ref],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return full, short


def topo_order(repo_root, full_shas):
    unique = list(dict.fromkeys(full_shas))
    try:
        out = subprocess.run(
            ["git", "-C", repo_root, "rev-list", "--topo-order", "--reverse", *unique],
            capture_output=True, text=True, check=True,
        ).stdout.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    wanted = set(unique)
    return [sha for sha in out if sha in wanted]


def find_repo_root(config_path):
    try:
        return subprocess.run(
            ["git", "-C", str(config_path.parent), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def parse_csv(path):
    data = {}
    with open(path) as f:
        lines = [line for line in f if not line.lstrip().startswith("#")]
    for row in csv.DictReader(lines):
        data[row["metric"]] = {
            k: float(row[k]) for k in ("min", "max", "mean", "stddev")
        }
    return data


def main():
    if len(sys.argv) != 2:
        print("Usage: plot_benchmark_commits.py <config.yaml>", file=sys.stderr)
        sys.exit(1)

    config_path = Path(sys.argv[1])
    if not config_path.is_file():
        print(f"Not a file: {config_path}", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(config_path)
    results_dir = config_path.parent / "results"
    repo_root = find_repo_root(config_path)

    # Resolve every configured ref to a full + short sha.
    noir_entries = []  # (full, short, label)
    for ref, label in cfg["noir_commits"]:
        full, short = resolve(repo_root, ref) if repo_root else (ref, ref[:7])
        noir_entries.append((full, short, label or short))
    spartan_entries = []
    for ref, label in cfg["spartan_commits"]:
        full, short = resolve(repo_root, ref) if repo_root else (ref, ref[:7])
        spartan_entries.append((full, short, label or short))

    noir_by_full = {full: (short, label) for full, short, label in noir_entries}
    spartan_by_full = {full: (short, label) for full, short, label in spartan_entries}

    all_full = [full for full, _, _ in noir_entries] + [full for full, _, _ in spartan_entries]
    ordered = topo_order(repo_root, all_full) if repo_root else None
    if ordered is None:
        # Fallback: config order, noir first, then spartan-only entries.
        seen = set()
        ordered = []
        for full in all_full:
            if full not in seen:
                seen.add(full)
                ordered.append(full)

    # --- shared x-axis ---
    n = len(ordered)
    xs = list(range(n))
    xtick_labels = []
    noir_x = {}     # full sha -> x position, for shas present in noir_entries
    spartan_x = {}  # full sha -> x position, for shas present in spartan_entries

    missing = []
    for x, full in zip(xs, ordered):
        in_noir = full in noir_by_full
        in_spartan = full in spartan_by_full
        short = (noir_by_full.get(full) or spartan_by_full.get(full))[0]
        noir_label = noir_by_full[full][1] if in_noir else None
        spartan_label = spartan_by_full[full][1] if in_spartan else None
        if in_noir:
            noir_x[full] = x
        if in_spartan:
            spartan_x[full] = x
        if in_noir and in_spartan and noir_label != spartan_label:
            combined = f"{noir_label} / {spartan_label}"
        else:
            combined = noir_label if in_noir else spartan_label
        xtick_labels.append(f"{combined}\n{short}")

    # --- load result CSVs ---
    noir_data = {}
    for full, short, _ in noir_entries:
        path = results_dir / f"noir-{short}.csv"
        if path.is_file():
            noir_data[full] = parse_csv(path)
        else:
            missing.append((full, short, "noir"))

    spartan_data = {}
    for full, short, _ in spartan_entries:
        path = results_dir / f"spartan-{short}.csv"
        if path.is_file():
            spartan_data[full] = parse_csv(path)
        else:
            missing.append((full, short, "spartan"))

    for full, short, leg in missing:
        print(
            f"NOTE: missing {leg} result for {short}; measure with: "
            f"./scripts/benchmark_commits.sh {config_path} --only {short}",
            file=sys.stderr,
        )

    # --- baseline: first noir_commits entry's bb_write_vk + bb_prove ---
    if not noir_entries:
        print("ERROR: config has no noir_commits entries", file=sys.stderr)
        sys.exit(1)
    baseline_full, baseline_short, baseline_label = noir_entries[0]
    baseline_data = noir_data.get(baseline_full)
    if not baseline_data or "bb_write_vk" not in baseline_data or "bb_prove" not in baseline_data:
        print(
            f"ERROR: missing baseline result for {baseline_short}; measure with: "
            f"./scripts/benchmark_commits.sh {config_path} --only {baseline_short}",
            file=sys.stderr,
        )
        sys.exit(1)
    baseline = baseline_data["bb_write_vk"]["mean"] + baseline_data["bb_prove"]["mean"]

    fig, ax = plt.subplots(figsize=(max(8, n * 1.8), 6))

    ax.axhline(1.0, color="#333333", linewidth=1.2, linestyle="-", zorder=2)
    ax.text(
        n - 0.5, 1.0, f"  baseline: {baseline_label}",
        color="#333333", fontsize=9, va="bottom", ha="right",
    )

    def plot_series(x_map, data_by_full, metric, style, denom=baseline):
        pts = [
            (x_map[full], data[metric])
            for full, data in data_by_full.items()
            if full in x_map and metric in data
        ]
        pts.sort(key=lambda p: p[0])
        if not pts:
            return
        px = [p[0] for p in pts]
        py = [p[1]["mean"] / denom for p in pts]
        ax.plot(
            px, py,
            color=style["color"],
            linewidth=1.8,
            marker="o",
            markersize=5,
            label=style["label"],
            zorder=6,
        )
        for x, m in pts:
            ax.annotate(
                fmt_time(m["mean"]),
                (x, m["mean"] / denom),
                textcoords="offset points",
                xytext=(0, -14),
                ha="center",
                fontsize=8,
                color=style["color"],
                zorder=7,
            )

    def bb_combined(full):
        data = noir_data.get(full)
        if not data or "bb_write_vk" not in data or "bb_prove" not in data:
            return None
        wvk, prove = data["bb_write_vk"], data["bb_prove"]
        return {
            "mean": wvk["mean"] + prove["mean"],
            "min": wvk["min"] + prove["min"],
            "max": wvk["max"] + prove["max"],
        }

    bb_sum_by_full = {}
    for full in noir_data:
        combined = bb_combined(full)
        if combined:
            bb_sum_by_full[full] = {"bb_sum": combined}

    plot_series(noir_x, bb_sum_by_full, "bb_sum", BARRETENBERG_STYLE)
    plot_series(spartan_x, spartan_data, "spartan_proof", SPARTAN_STYLE)

    # --- left axis: spartan_constraints as distance to the nearest power of two ---
    def plot_constraints_series(x_map, data_by_full, style):
        pts = [
            (x_map[full], data["spartan_constraints"])
            for full, data in data_by_full.items()
            if full in x_map and "spartan_constraints" in data
        ]
        pts.sort(key=lambda p: p[0])
        if not pts:
            return
        px = [p[0] for p in pts]
        py = [pow2_distance(p[1]["mean"]) for p in pts]
        ax.plot(
            px, py,
            color=style["color"],
            linewidth=1.2,
            linestyle=":",
            marker="^",
            markersize=5,
            label=style["label"],
            zorder=5,
        )
        for (x, m), y in zip(pts, py):
            ax.annotate(
                f"{int(m['mean']):,}",
                (x, y),
                textcoords="offset points",
                xytext=(0, 8),
                ha="center",
                fontsize=8,
                color=style["color"],
                zorder=7,
            )

    plot_constraints_series(spartan_x, spartan_data, CONSTRAINTS_STYLE)

    # --- text: latest spartan run's verify time & proof size (not time series) ---
    def last_metric_mean(x_map, data_by_full, metric):
        pts = [
            (x_map[full], data[metric]["mean"])
            for full, data in data_by_full.items()
            if full in x_map and metric in data
        ]
        if not pts:
            return None
        return max(pts, key=lambda p: p[0])[1]

    last_spartan_verify = last_metric_mean(spartan_x, spartan_data, "spartan_verify")
    last_spartan_size = last_metric_mean(spartan_x, spartan_data, "spartan_proof_size")

    if last_spartan_verify is not None and last_spartan_size is not None:
        ax.text(
            0.98, 0.97,
            f"spartan verify (latest): {fmt_time(last_spartan_verify)}\n"
            f"spartan proof size (latest): {int(last_spartan_size):,} B",
            transform=ax.transAxes,
            fontsize=9,
            va="top",
            ha="right",
            bbox={"boxstyle": "round", "facecolor": "white", "edgecolor": "#999999", "alpha": 0.9},
            zorder=8,
        )

    ax.set_xticks(xs)
    ax.set_xticklabels(xtick_labels, fontsize=9, rotation=30, ha="right")
    ax.set_xlabel("Commit (oldest → newest)", fontsize=12)
    ax.set_ylabel("Relative to baseline", fontsize=12)
    ax.set_title(f"{cfg['name']}: noir/barretenberg vs. spartan", fontsize=14, fontweight="bold")
    ax.set_xlim(-0.5, n - 0.5)
    ax.set_ylim(0.5, 1.5)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}×"))
    ax.grid(axis="both", alpha=0.3, linestyle="--")

    ax.legend(loc="upper left", fontsize=9, framealpha=0.9)

    output = str(config_path.parent / "benchmarks.png")
    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches="tight")
    print(f"Saved → {output}")


if __name__ == "__main__":
    main()
