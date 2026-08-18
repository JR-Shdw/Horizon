#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Turn custody-throughput-bench.sh output into the plan's gate verdict.

Gates evaluated:
  - "Rust custody throughput is at least 95% of the current native RPC
    baseline" -- baseline is the `embedded` configuration.
  - "Three idle Rust custodians use no more than 128 MiB RSS combined."

The `python` column is not a gate; it separates the cost of the custody
boundary itself from the cost of the Rust protocol's framing.
"""

import json
import sys
from pathlib import Path

CONFIGS = ("embedded", "python", "rust")
GATE_RATIO = 0.95
RSS_GATE_KIB = 128 * 1024


def load(outdir: Path, config: str, scenario: str) -> dict | None:
    path = outdir / f"{config}-{scenario}.json"
    if not path.exists():
        return None
    report = json.loads(path.read_text())
    results = report.get("results") or []
    return results[0] if results else None


def rss_kib(outdir: Path, config: str) -> int | None:
    path = outdir / f"{config}-rss.kib"
    if not path.exists():
        return None
    text = path.read_text().strip()
    return int(text) if text else None


def main() -> int:
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else ".bench-custody")
    if not outdir.is_dir():
        print(f"no results directory: {outdir}", file=sys.stderr)
        return 2

    scenarios = []
    for path in sorted(outdir.glob("embedded-*.json")):
        scenarios.append(path.stem.split("-", 1)[1])
    if not scenarios:
        print(f"no embedded baseline results in {outdir}", file=sys.stderr)
        return 2

    print("## Custody throughput gate\n")
    print("Baseline = `embedded` (master holds sub-keys in-process; followers")
    print("delegate over the cluster RPC socket). Gate: rust >= 95% of baseline.\n")
    print(
        "| Scenario | embedded rps | python rps | rust rps | rust/embedded | verdict |"
    )
    print("|---|---:|---:|---:|---:|---|")

    verdicts = []
    for scenario in scenarios:
        row = {c: load(outdir, c, scenario) for c in CONFIGS}
        base = row["embedded"]
        rust = row["rust"]
        if not base or not rust:
            continue
        ratio = rust["rps"] / base["rps"] if base["rps"] else 0.0
        ok = ratio >= GATE_RATIO
        verdicts.append(ok)
        py_rps = f"{row['python']['rps']:.1f}" if row["python"] else "-"
        print(
            f"| `{scenario}` | {base['rps']:.1f} | {py_rps} | {rust['rps']:.1f} "
            f"| {ratio * 100:.1f}% | {'PASS' if ok else 'FAIL'} |"
        )

    print("\n### Latency (p50 / p95 / p99 ms)\n")
    print("| Scenario | embedded | python | rust |")
    print("|---|---|---|---|")
    for scenario in scenarios:
        row = {c: load(outdir, c, scenario) for c in CONFIGS}
        cells = []
        for c in CONFIGS:
            r = row[c]
            cells.append(
                f"{r['p50_ms']:.1f} / {r['p95_ms']:.1f} / {r['p99_ms']:.1f}"
                if r
                else "-"
            )
        print(f"| `{scenario}` | " + " | ".join(cells) + " |")

    print("\n### Errors\n")
    for scenario in scenarios:
        for c in CONFIGS:
            r = load(outdir, c, scenario)
            if r and r["requests_err"]:
                print(
                    f"- `{c}`/`{scenario}`: {r['requests_err']} errors "
                    f"of {r['requests_total']} -- {r.get('err_sample')}"
                )
    print("(no line above = zero errors in every configuration)")

    print("\n### Idle custody RSS\n")
    print("| Config | RSS (MiB) | Gate |")
    print("|---|---:|---|")
    for c in CONFIGS:
        kib = rss_kib(outdir, c)
        if kib is None:
            continue
        if c == "rust":
            gate = "PASS" if kib <= RSS_GATE_KIB else "FAIL"
            gate += f" (limit {RSS_GATE_KIB // 1024} MiB)"
        else:
            gate = "n/a"
        print(f"| `{c}` | {kib / 1024:.1f} | {gate} |")

    print()
    if verdicts and all(verdicts):
        print("THROUGHPUT GATE: PASS on every scenario measured.")
    elif verdicts:
        print("THROUGHPUT GATE: FAIL on at least one scenario.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
