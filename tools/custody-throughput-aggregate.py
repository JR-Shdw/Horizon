#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Aggregate several custody-throughput-bench.sh runs into one verdict.

A single run is not enough to call the 95% gate: the `mixed` scenario composes
its request stream at random, so its run-to-run spread is much wider than
`read_secret`'s. This reports per-configuration medians across runs, plus the
observed spread, so the verdict rests on the median and the noise is visible
rather than hidden.

Usage: custody-throughput-aggregate.py .bench-custody-run1 .bench-custody-run2 ...
"""

import json
import statistics
import sys
from pathlib import Path

CONFIGS = ("embedded", "python", "rust")
GATE_RATIO = 0.95
RSS_GATE_KIB = 128 * 1024


def metric(outdir: Path, config: str, scenario: str, key: str) -> float | None:
    path = outdir / f"{config}-{scenario}.json"
    if not path.exists():
        return None
    results = json.loads(path.read_text()).get("results") or []
    return results[0][key] if results else None


def rps(outdir: Path, config: str, scenario: str) -> float | None:
    return metric(outdir, config, scenario, "rps")


def rss_kib(outdir: Path, config: str) -> int | None:
    path = outdir / f"{config}-rss.kib"
    if not path.exists():
        return None
    text = path.read_text().strip()
    return int(text) if text else None


def main() -> int:
    dirs = [Path(a) for a in sys.argv[1:]]
    dirs = [d for d in dirs if d.is_dir()]
    if not dirs:
        print(
            "usage: custody-throughput-aggregate.py <rundir> [<rundir>...]",
            file=sys.stderr,
        )
        return 2

    # `.clientN` files are the per-process shards the harness already summed
    # into the scenario file; treating them as scenarios would compare shards.
    scenarios = sorted(
        {
            name
            for d in dirs
            for p in d.glob("embedded-*.json")
            if ".client" not in (name := p.stem.split("-", 1)[1])
        }
    )
    if not scenarios:
        print("no embedded baseline results found", file=sys.stderr)
        return 2

    print(f"## Custody throughput gate -- median of {len(dirs)} run(s)\n")
    print("Baseline = `embedded` (master holds the sub-keys in-process; followers")
    print("delegate over the cluster RPC socket). Gate: rust >= 95% of baseline.")
    print("`python` is not a gate -- it separates the cost of the custody boundary")
    print("itself from the cost of the Rust protocol's framing.\n")

    header = (
        "| Scenario | "
        + " | ".join(f"{c} med rps (min-max)" for c in CONFIGS)
        + " | rust/embedded | verdict |"
    )
    print(header)
    print("|---|" + "---:|" * len(CONFIGS) + "---:|---|")

    verdicts = []
    for scenario in scenarios:
        cells = {}
        med = {}
        for c in CONFIGS:
            vals = [v for d in dirs if (v := rps(d, c, scenario)) is not None]
            if not vals:
                cells[c] = "-"
                continue
            med[c] = statistics.median(vals)
            cells[c] = (
                f"{med[c]:.1f} ({min(vals):.0f}-{max(vals):.0f})"
                if len(vals) > 1
                else f"{med[c]:.1f}"
            )
        if "embedded" not in med or "rust" not in med or not med["embedded"]:
            continue
        ratio = med["rust"] / med["embedded"]
        ok = ratio >= GATE_RATIO
        verdicts.append((scenario, ok, ratio))
        print(
            f"| `{scenario}` | "
            + " | ".join(cells[c] for c in CONFIGS)
            + f" | {ratio * 100:.1f}% | {'PASS' if ok else 'FAIL'} |"
        )

    # At low concurrency the system is far from saturation, so p50 latency
    # reflects the per-request custody round-trip directly and is far more
    # stable than a saturated RPS number. The delta against `embedded` is the
    # added cost of the custody boundary per request.
    print("\n### Median p50 latency (ms), and delta vs embedded\n")
    print("| Scenario | " + " | ".join(CONFIGS) + " | rust - embedded |")
    print("|---|" + "---:|" * (len(CONFIGS) + 1))
    for scenario in scenarios:
        med = {}
        for c in CONFIGS:
            vals = [
                v for d in dirs if (v := metric(d, c, scenario, "p50_ms")) is not None
            ]
            if vals:
                med[c] = statistics.median(vals)
        if not med:
            continue
        cells = [f"{med[c]:.1f}" if c in med else "-" for c in CONFIGS]
        if "rust" in med and "embedded" in med:
            delta = f"{med['rust'] - med['embedded']:+.1f}"
        else:
            delta = "-"
        print(f"| `{scenario}` | " + " | ".join(cells) + f" | {delta} |")

    print("\n### Idle custody RSS (median)\n")
    print("| Config | RSS (MiB) | Gate |")
    print("|---|---:|---|")
    for c in CONFIGS:
        vals = [v for d in dirs if (v := rss_kib(d, c)) is not None]
        if not vals:
            continue
        m = statistics.median(vals)
        if c == "rust":
            gate = (
                "PASS" if m <= RSS_GATE_KIB else "FAIL"
            ) + f" (limit {RSS_GATE_KIB // 1024} MiB)"
        else:
            gate = "n/a"
        print(f"| `{c}` | {m / 1024:.1f} | {gate} |")

    print()
    failed = [s for s, ok, _ in verdicts if not ok]
    if verdicts and not failed:
        print("THROUGHPUT GATE: PASS on median across every scenario.")
    elif verdicts:
        print(f"THROUGHPUT GATE: FAIL on median for: {', '.join(failed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
