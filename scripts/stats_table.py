#!/usr/bin/env python3
"""Parse stats.txt and render an ASCII 2D table indexed by INPUT_SIZE x ASSERTS."""

import csv
import re
import sys
from pathlib import Path

STATS_FILE = Path(__file__).parent.parent / "stats.txt"

# Metrics displayed in each cell, in order (one sub-row per metric), using the
# "min" value from the CSV produced by benchmark.sh.
METRICS = ("prove", "spartan_proof", "spartan_verify")


def normalize_time(s: str) -> str:
    s = s.strip().rstrip("s")
    return f"{float(s):.2f}s"


def parse(path: Path):
    # CSV format: input_size,asserts,metric,min,max,mean,stddev
    mins = {}  # (input_size, asserts) -> {metric: min}
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (int(row["input_size"]), int(row["asserts"]))
            mins.setdefault(key, {})[row["metric"]] = row["min"]

    runs = []
    for (input_size, asserts), metrics in mins.items():
        vals = tuple(
            normalize_time(metrics[m]) if m in metrics else "n/a"
            for m in METRICS
        )
        runs.append((input_size, asserts, *vals))
    return runs


def render_table(runs):
    input_sizes = sorted({r[0] for r in runs})
    asserts_vals = sorted({r[1] for r in runs})

    # Build lookup: (input_size, asserts) -> (val2, val4, val5)
    data = {(r[0], r[1]): (r[2], r[3], r[4]) for r in runs}

    # Column widths: each cell holds three values, one per sub-row.
    # Minimum cell width = max of the three value lengths, or the header.
    col_header_label = "ASRT \\ INP"   # row-header column label

    def cell_lines(input_size, asserts):
        key = (input_size, asserts)
        if key not in data:
            return ("n/a", "n/a", "n/a")
        return data[key]

    # Compute column widths (one per INPUT_SIZE).
    col_widths = []
    for is_ in input_sizes:
        w = len(str(is_))
        for a in asserts_vals:
            v2, v4, v5 = cell_lines(is_, a)
            w = max(w, len(v2), len(v4), len(v5))
        col_widths.append(w)

    row_header_w = max(len(col_header_label), max(len(str(a)) for a in asserts_vals))

    def hline(cross="+"):
        parts = ["-" * (row_header_w + 2)]
        for w in col_widths:
            parts.append("-" * (w + 2))
        return cross + (cross).join(parts) + cross

    def row_line(left, *cells):
        parts = [f" {left:<{row_header_w}} "]
        for cell, w in zip(cells, col_widths):
            parts.append(f" {cell:>{w}} ")
        return "|" + "|".join(parts) + "|"

    lines = []
    lines.append(hline())
    # Header row: INPUT_SIZE values
    lines.append(row_line(col_header_label, *[str(is_) for is_ in input_sizes]))
    lines.append(hline())

    for a in asserts_vals:
        v2s = [cell_lines(is_, a)[0] for is_ in input_sizes]
        v4s = [cell_lines(is_, a)[1] for is_ in input_sizes]
        v5s = [cell_lines(is_, a)[2] for is_ in input_sizes]
        lines.append(row_line(str(a), *v2s))
        lines.append(row_line("", *v4s))
        lines.append(row_line("", *v5s))
        lines.append(hline())

    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("stats_file", nargs="?", default=None)
    parser.add_argument("--update-readme", metavar="README", help="Inject table into README between marker comments")
    args = parser.parse_args()

    path = Path(args.stats_file) if args.stats_file else STATS_FILE
    runs = parse(path)
    if not runs:
        print("No runs found.", file=sys.stderr)
        sys.exit(1)
    table = render_table(runs)

    if args.update_readme:
        readme = Path(args.update_readme)
        content = readme.read_text()
        new_content = re.sub(
            r"<!-- BENCHMARK_TABLE_START -->.*?<!-- BENCHMARK_TABLE_END -->",
            f"<!-- BENCHMARK_TABLE_START -->\n```\n{table}\n```\n<!-- BENCHMARK_TABLE_END -->",
            content,
            flags=re.DOTALL,
        )
        readme.write_text(new_content)
    else:
        print(table)


if __name__ == "__main__":
    main()
