#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import re
from pathlib import Path
from typing import Dict, List, Optional

import matplotlib.pyplot as plt


METRIC_PATTERNS = {
    "checks_total": re.compile(r"checks_total\.*:\s*([0-9.]+)"),
    "checks_succeeded_pct": re.compile(r"checks_succeeded\.*:\s*([0-9.]+)%"),
    "checks_failed_pct": re.compile(r"checks_failed\.*:\s*([0-9.]+)%"),
    "hierarkey_error_rate_pct": re.compile(r"hierarkey_error_rate\.*:\s*([0-9.]+)%"),
    "http_req_failed_pct": re.compile(r"http_req_failed\.*:\s*([0-9.]+)%"),
    "http_reqs_total": re.compile(r"http_reqs\.*:\s*([0-9.]+)"),
    "http_reqs_per_sec": re.compile(r"http_reqs\.*:\s*[0-9.]+\s+([0-9.]+)/s"),
    "iterations_total": re.compile(r"iterations\.*:\s*([0-9.]+)"),
    "iterations_per_sec": re.compile(r"iterations\.*:\s*[0-9.]+\s+([0-9.]+)/s"),
    "secrets_created_total": re.compile(r"hierarkey_secrets_created\.*:\s*([0-9.]+)"),
    "secrets_created_per_sec": re.compile(r"hierarkey_secrets_created\.*:\s*[0-9.]+\s+([0-9.]+)/s"),
}

P95_PATTERNS = {
    "auth_p95_ms": re.compile(r"hierarkey_auth_latency\.*:.*?p\(95\)=([0-9.]+)(ms|s)"),
    "create_p95_ms": re.compile(r"hierarkey_create_latency\.*:.*?p\(95\)=([0-9.]+)(ms|s)"),
    "reveal_p95_ms": re.compile(r"hierarkey_reveal_latency\.*:.*?p\(95\)=([0-9.]+)(ms|s)"),
    "search_p95_ms": re.compile(r"hierarkey_search_latency\.*:.*?p\(95\)=([0-9.]+)(ms|s)"),
    "http_p95_ms": re.compile(r"http_req_duration\.*:.*?p\(95\)=([0-9.]+)(ms|s)"),
    "iteration_p95_ms": re.compile(r"iteration_duration\.*:.*?p\(95\)=([0-9.]+)(ms|s)"),
}

AVG_PATTERNS = {
    "auth_avg_ms": re.compile(r"hierarkey_auth_latency\.*:\s*avg=([0-9.]+)(ms|s)"),
    "create_avg_ms": re.compile(r"hierarkey_create_latency\.*:\s*avg=([0-9.]+)(ms|s)"),
    "reveal_avg_ms": re.compile(r"hierarkey_reveal_latency\.*:\s*avg=([0-9.]+)(ms|s)"),
    "search_avg_ms": re.compile(r"hierarkey_search_latency\.*:\s*avg=([0-9.]+)(ms|s)"),
    "http_avg_ms": re.compile(r"http_req_duration\.*:\s*avg=([0-9.]+)(ms|s)"),
    "iteration_avg_ms": re.compile(r"iteration_duration\.*:\s*avg=([0-9.]+)(ms|s)"),
}

SETUP_PATTERNS = {
    "seeded_secrets": re.compile(r"Seeded\s+([0-9]+)\s+secrets"),
    "seed_namespace": re.compile(r"Seeded\s+[0-9]+\s+secrets\s+in\s+([^\.\n]+)"),
}

RESULT_FIELDS = [
    "timestamp",
    "label",
    "run_dir",
    "commit",
    "branch",
    "dirty",
    "seeded_secrets",
    "seed_namespace",
    "checks_total",
    "checks_succeeded_pct",
    "checks_failed_pct",
    "hierarkey_error_rate_pct",
    "http_req_failed_pct",
    "http_reqs_total",
    "http_reqs_per_sec",
    "iterations_total",
    "iterations_per_sec",
    "secrets_created_total",
    "secrets_created_per_sec",
    "auth_avg_ms",
    "auth_p95_ms",
    "create_avg_ms",
    "create_p95_ms",
    "reveal_avg_ms",
    "reveal_p95_ms",
    "search_avg_ms",
    "search_p95_ms",
    "http_avg_ms",
    "http_p95_ms",
    "iteration_avg_ms",
    "iteration_p95_ms",
]


def parse_duration_to_ms(value: str, unit: str) -> float:
    number = float(value)
    if unit == "s":
        return number * 1000.0
    return number



def parse_first(pattern: re.Pattern[str], text: str) -> Optional[str]:
    m = pattern.search(text)
    return m.group(1) if m else None



def parse_float(pattern: re.Pattern[str], text: str) -> Optional[float]:
    m = pattern.search(text)
    if not m:
        return None
    return float(m.group(1))



def parse_duration(pattern: re.Pattern[str], text: str) -> Optional[float]:
    m = pattern.search(text)
    if not m:
        return None
    return parse_duration_to_ms(m.group(1), m.group(2))



def parse_git_info(path: Path) -> Dict[str, str]:
    info = {"commit": "", "branch": "", "dirty": ""}
    if not path.exists():
        return info
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key in info:
            info[key] = value
    return info



def parse_run_dir(run_dir: Path) -> Optional[Dict[str, object]]:
    run_log = run_dir / "run.log"
    if not run_log.exists():
        return None

    text = run_log.read_text(encoding="utf-8", errors="replace")
    row: Dict[str, object] = {field: "" for field in RESULT_FIELDS}

    name = run_dir.name
    if "-" in name and "T" in name:
        ts, label = name.split("-", 1)
        # The above split is too naive for timestamps; do a regex instead.
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)-(.*)$", name)
    row["timestamp"] = m.group(1) if m else name
    row["label"] = m.group(2) if m else name
    row["run_dir"] = str(run_dir)

    git_info = parse_git_info(run_dir / "source" / "git.txt")
    row.update(git_info)

    for key, pattern in METRIC_PATTERNS.items():
        value = parse_float(pattern, text)
        row[key] = value if value is not None else ""

    for key, pattern in P95_PATTERNS.items():
        value = parse_duration(pattern, text)
        row[key] = value if value is not None else ""

    for key, pattern in AVG_PATTERNS.items():
        value = parse_duration(pattern, text)
        row[key] = value if value is not None else ""

    seeded = parse_first(SETUP_PATTERNS["seeded_secrets"], text)
    row["seeded_secrets"] = int(seeded) if seeded else ""
    ns = parse_first(SETUP_PATTERNS["seed_namespace"], text)
    row["seed_namespace"] = ns.strip() if ns else ""

    return row



def as_float(value: object) -> float:
    if value == "" or value is None:
        return math.nan
    return float(value)



def format_num(value: object, decimals: int = 2) -> str:
    if value == "" or value is None:
        return ""
    return f"{float(value):.{decimals}f}"



def generate_csv(rows: List[Dict[str, object]], output_path: Path) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=RESULT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)



def generate_markdown(rows: List[Dict[str, object]], output_path: Path) -> None:
    lines: List[str] = []
    lines.append("# Benchmark Results\n")
    lines.append(
        "| Run | Commit | Dirty | Seeded | Req/s | Iter/s | HTTP p95 (ms) | Iter p95 (ms) | Auth p95 (ms) | Create p95 (ms) | Reveal p95 (ms) | Search p95 (ms) | Error % |"
    )
    lines.append(
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )

    for row in rows:
        lines.append(
            "| {label} | {commit} | {dirty} | {seeded_secrets} | {http_reqs_per_sec} | {iterations_per_sec} | {http_p95_ms} | {iteration_p95_ms} | {auth_p95_ms} | {create_p95_ms} | {reveal_p95_ms} | {search_p95_ms} | {hierarkey_error_rate_pct} |".format(
                label=row["label"],
                commit=(str(row["commit"])[:10] if row["commit"] else ""),
                dirty=row["dirty"],
                seeded_secrets=row["seeded_secrets"],
                http_reqs_per_sec=format_num(row["http_reqs_per_sec"]),
                iterations_per_sec=format_num(row["iterations_per_sec"]),
                http_p95_ms=format_num(row["http_p95_ms"]),
                iteration_p95_ms=format_num(row["iteration_p95_ms"]),
                auth_p95_ms=format_num(row["auth_p95_ms"]),
                create_p95_ms=format_num(row["create_p95_ms"]),
                reveal_p95_ms=format_num(row["reveal_p95_ms"]),
                search_p95_ms=format_num(row["search_p95_ms"]),
                hierarkey_error_rate_pct=format_num(row["hierarkey_error_rate_pct"]),
            )
        )

    if len(rows) >= 2:
        baseline = rows[0]
        latest = rows[-1]
        lines.append("\n## Delta: latest vs first\n")
        lines.append("| Metric | First | Latest | Delta | Delta % |")
        lines.append("|---|---:|---:|---:|---:|")
        for title, key in [
            ("Req/s", "http_reqs_per_sec"),
            ("Iter/s", "iterations_per_sec"),
            ("HTTP p95 (ms)", "http_p95_ms"),
            ("Iter p95 (ms)", "iteration_p95_ms"),
            ("Auth p95 (ms)", "auth_p95_ms"),
            ("Create p95 (ms)", "create_p95_ms"),
            ("Reveal p95 (ms)", "reveal_p95_ms"),
            ("Search p95 (ms)", "search_p95_ms"),
            ("Error %", "hierarkey_error_rate_pct"),
        ]:
            first_v = as_float(baseline[key])
            latest_v = as_float(latest[key])
            if math.isnan(first_v) or math.isnan(latest_v):
                continue
            delta = latest_v - first_v
            delta_pct = (delta / first_v * 100.0) if first_v != 0 else math.nan
            lines.append(
                f"| {title} | {first_v:.2f} | {latest_v:.2f} | {delta:+.2f} | {delta_pct:+.2f}% |"
            )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")



def bar_chart(rows: List[Dict[str, object]], metric_key: str, title: str, ylabel: str, output_path: Path) -> None:
    labels = [str(r["label"]) for r in rows]
    values = [as_float(r[metric_key]) for r in rows]

    plt.figure(figsize=(10, 5))
    plt.bar(labels, values)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()



def grouped_p95_chart(rows: List[Dict[str, object]], output_path: Path) -> None:
    labels = [str(r["label"]) for r in rows]
    metrics = [
        ("Auth", "auth_p95_ms"),
        ("Create", "create_p95_ms"),
        ("Reveal", "reveal_p95_ms"),
        ("Search", "search_p95_ms"),
    ]

    x = list(range(len(labels)))
    width = 0.18
    offsets = [-1.5 * width, -0.5 * width, 0.5 * width, 1.5 * width]

    plt.figure(figsize=(12, 6))
    for offset, (name, key) in zip(offsets, metrics):
        values = [as_float(r[key]) for r in rows]
        plt.bar([xi + offset for xi in x], values, width=width, label=name)

    plt.title("Custom p95 latencies by run")
    plt.ylabel("Latency (ms)")
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()



def discover_runs(results_dir: Path) -> List[Path]:
    return sorted([p for p in results_dir.iterdir() if p.is_dir() and (p / "run.log").exists()])



def main() -> None:
    parser = argparse.ArgumentParser(description="Generate benchmark summary tables and charts.")
    parser.add_argument(
        "--results-dir",
        default="benchmark/results",
        help="Directory containing per-run benchmark result folders.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for index files and charts. Defaults to the results dir.",
    )
    args = parser.parse_args()

    results_dir = Path(args.results_dir).resolve()
    output_dir = Path(args.output_dir).resolve() if args.output_dir else results_dir
    charts_dir = output_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    runs = discover_runs(results_dir)
    rows: List[Dict[str, object]] = []
    for run_dir in runs:
        row = parse_run_dir(run_dir)
        if row is not None:
            rows.append(row)

    if not rows:
        raise SystemExit(f"No benchmark runs with run.log found in {results_dir}")

    generate_csv(rows, output_dir / "index.csv")
    generate_markdown(rows, output_dir / "index.md")

    bar_chart(rows, "http_reqs_per_sec", "HTTP requests per second by run", "Requests/sec", charts_dir / "http_reqs_per_sec.png")
    bar_chart(rows, "iterations_per_sec", "Iterations per second by run", "Iterations/sec", charts_dir / "iterations_per_sec.png")
    bar_chart(rows, "http_p95_ms", "HTTP request p95 by run", "Latency (ms)", charts_dir / "http_p95_ms.png")
    bar_chart(rows, "iteration_p95_ms", "Iteration p95 by run", "Latency (ms)", charts_dir / "iteration_p95_ms.png")
    bar_chart(rows, "secrets_created_per_sec", "Secrets created per second by run", "Secrets/sec", charts_dir / "secrets_created_per_sec.png")
    grouped_p95_chart(rows, charts_dir / "custom_p95s.png")

    print(f"Wrote: {output_dir / 'index.csv'}")
    print(f"Wrote: {output_dir / 'index.md'}")
    print(f"Charts: {charts_dir}")


if __name__ == "__main__":
    main()
