# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""rhorizon load harness - see README.md.

Single-file CLI : seeds N test secrets, drives concurrent async clients
against the four scenarios (whoami / list_secrets / read_secret / mixed),
reports p50 / p95 / p99 latency and RPS. Outputs both JSON (machine) and
Markdown (paste-ready).

Stdlib + httpx only ; no numpy, no locust, no k6. Runs anywhere Python 3.12
runs, ships in the repo so any operator can reproduce on their own infra.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import random
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

import httpx
import typer

app = typer.Typer(add_completion=False, help="rhorizon load harness")

SEED_PREFIX = "bench-"
# `status` is anonymous (no token), exercises HTTP + workers + DB without
# the auth and master-RPC crypto layers, useful as an upper-bound baseline
# and as a smoke run when the operator has no token at hand.
SCENARIOS = ("status", "whoami", "list_secrets", "read_secret", "mixed", "cluster_ha")
ANON_SCENARIOS = ("status",)

# Sprint D, transient transport errors we treat as "retry once".
#
# RemoteProtocolError / ReadError / ConnectError on the bench client are
# typical artefacts of an HTTP/1.1 keep-alive race or a brief socket glitch
# between client and server ; the request never reached the application,
# the server has no record of it. All bench scenarios are idempotent GETs,
# so retrying once is safe and matches what every production HTTP client
# (urllib3, reqwest, Go net/http with retry middleware, etc.) does by
# default. We do NOT retry on 5xx (those are real server errors) nor on
# *Timeout (those may indicate real overload, retry would just amplify).
_TRANSIENT_TRANSPORT_ERRORS = (
    httpx.RemoteProtocolError,
    httpx.ReadError,
    httpx.ConnectError,
)

PROFILES: dict[str, dict[str, int]] = {
    "small": {"concurrency": 10, "duration": 30},
    "medium": {"concurrency": 100, "duration": 60},
    "large": {"concurrency": 500, "duration": 120},
}


@dataclass
class ScenarioResult:
    scenario: str
    concurrency: int
    duration_sec: float
    requests_total: int
    requests_ok: int
    requests_err: int
    rps: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    p999_ms: float
    err_sample: list[str] = field(default_factory=list)


@dataclass
class RunReport:
    profile: str | None
    target_url: str
    started_at: str
    rhorizon_version: str | None
    workers: int | None
    env: dict[str, str]
    results: list[ScenarioResult]


def _percentile(samples_ms: list[float], q: float) -> float:
    if not samples_ms:
        return 0.0
    s = sorted(samples_ms)
    k = max(0, min(len(s) - 1, int(round(q * (len(s) - 1)))))
    return s[k]


def _git_sha() -> str:
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=Path(__file__).resolve().parent,
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
    except Exception:
        return "unknown"


def _env_snapshot() -> dict[str, str]:
    return {
        "kernel": platform.platform(),
        "python": platform.python_version(),
        "cpu": platform.processor() or platform.machine(),
        "harness_sha": _git_sha(),
    }


async def _fetch_status(client: httpx.AsyncClient) -> dict:
    r = await client.get("/api/v1/vault/status")
    r.raise_for_status()
    return r.json()


# --------------------------------------------------------------------- seed --


@app.command()
def seed(
    url: str = typer.Option(..., help="Vault URL, e.g. http://127.0.0.1:8200"),
    token: str = typer.Option(..., help="Bearer token (admin or secrets:rw)"),
    count: int = typer.Option(100, help="Number of bench-* secrets to seed"),
    namespace: str = typer.Option("default", help="Namespace to seed into"),
    insecure: bool = typer.Option(
        False, help="Skip TLS cert verification (self-signed local)"
    ),
):
    """Seed N secrets named bench-0, bench-1, ... in the target vault."""
    asyncio.run(_seed_async(url, token, count, namespace, insecure))


async def _seed_async(
    url: str, token: str, count: int, namespace: str, insecure: bool = False
):
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(
        base_url=url, headers=headers, timeout=10.0, verify=not insecure
    ) as c:
        status = await _fetch_status(c)
        if status.get("sealed", True):
            typer.secho("Vault is sealed - unseal first.", fg=typer.colors.RED)
            raise typer.Exit(1)

        ok, skipped = 0, 0
        for i in range(count):
            name = f"{SEED_PREFIX}{i:04d}"
            payload = {
                "name": name,
                "value": f"bench-value-{i}",
                "namespace": namespace,
            }
            r = await c.post("/api/v1/vault/secrets/", json=payload)
            if r.status_code in (200, 201):
                ok += 1
            elif r.status_code == 409:
                skipped += 1
            else:
                typer.secho(
                    f"  [{name}] HTTP {r.status_code}: {r.text[:120]}",
                    fg=typer.colors.YELLOW,
                )
        typer.secho(
            f"Seeded {ok} new, skipped {skipped} existing.",
            fg=typer.colors.GREEN,
        )


# ------------------------------------------------------------------ cleanup --


@app.command()
def cleanup(
    url: str = typer.Option(..., help="Vault URL"),
    token: str = typer.Option(..., help="Bearer token"),
    insecure: bool = typer.Option(False, help="Skip TLS cert verification"),
):
    """Delete every secret with the bench- prefix."""
    asyncio.run(_cleanup_async(url, token, insecure))


async def _cleanup_async(url: str, token: str, insecure: bool = False):
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(
        base_url=url, headers=headers, timeout=10.0, verify=not insecure
    ) as c:
        r = await c.get("/api/v1/vault/secrets/")
        r.raise_for_status()
        items = r.json().get("items", [])
        targets = [s["name"] for s in items if s["name"].startswith(SEED_PREFIX)]
        for name in targets:
            await c.delete(f"/api/v1/vault/secrets/{name}")
        typer.secho(f"Deleted {len(targets)} bench-* secrets.", fg=typer.colors.GREEN)


# -------------------------------------------------------------- scenarios ---


def _ok_err(r: httpx.Response) -> tuple[bool, str | None]:
    if r.status_code == 200:
        return True, None
    return False, str(r.status_code)


def _build_scenario(name: str, secret_pool: list[str]) -> Callable:
    """Return an async callable (client) -> tuple[bool, str|None] for one op."""
    if name == "status":

        async def op(c: httpx.AsyncClient):
            return _ok_err(await c.get("/api/v1/vault/status"))

        return op

    if name == "whoami":

        async def op(c: httpx.AsyncClient):
            return _ok_err(await c.get("/api/v1/vault/tokens/whoami"))

        return op

    if name == "list_secrets":

        async def op(c: httpx.AsyncClient):
            return _ok_err(await c.get("/api/v1/vault/secrets/"))

        return op

    if name == "read_secret":
        if not secret_pool:
            raise typer.BadParameter(
                "read_secret needs seeded secrets - run `seed` first."
            )

        async def op(c: httpx.AsyncClient):
            n = random.choice(secret_pool)
            return _ok_err(await c.get(f"/api/v1/vault/secrets/{n}"))

        return op

    if name == "mixed":
        if not secret_pool:
            raise typer.BadParameter(
                "mixed scenario needs seeded secrets - run `seed` first."
            )

        async def op(c: httpx.AsyncClient):
            roll = random.random()
            if roll < 0.7:
                n = random.choice(secret_pool)
                return _ok_err(await c.get(f"/api/v1/vault/secrets/{n}"))
            if roll < 0.9:
                return _ok_err(await c.get("/api/v1/vault/secrets/"))
            return _ok_err(await c.get("/api/v1/vault/tokens/whoami"))

        return op

    if name == "cluster_ha":
        # visibility endpoint -- admin:r, exercises master RPC
        # dispatch (`is_loaded_anywhere` -> `cluster_rpc.has_ha_password`
        # when handled by a follower worker) + a SELECT on
        # vault_cluster_nodes. Sensitive to follower-to-master RPC latency,
        # not just DB latency. p99 here is the carryover target for the
        # 3-node Swarm bench.

        async def op(c: httpx.AsyncClient):
            return _ok_err(await c.get("/api/v1/vault/cluster/ha"))

        return op

    raise typer.BadParameter(f"unknown scenario: {name}")


async def _drive(
    url: str,
    token: str | None,
    scenario: str,
    concurrency: int,
    duration: float,
    secret_pool: list[str],
    insecure: bool = False,
) -> ScenarioResult:
    """Run `scenario` with `concurrency` workers for `duration` seconds."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    op = _build_scenario(scenario, secret_pool)

    deadline = time.monotonic() + duration
    samples_ms: list[float] = []
    err_sample: list[str] = []
    ok_count = 0
    err_count = 0

    async with httpx.AsyncClient(
        base_url=url,
        headers=headers,
        timeout=10.0,
        verify=not insecure,
        limits=httpx.Limits(
            max_connections=concurrency * 2,
            max_keepalive_connections=concurrency,
        ),
    ) as client:

        async def worker():
            nonlocal ok_count, err_count
            while time.monotonic() < deadline:
                t0 = time.monotonic()
                try:
                    ok, err = await op(client)
                except _TRANSIENT_TRANSPORT_ERRORS as e:
                    # Transport hiccup, retry once. See _TRANSIENT_TRANSPORT_ERRORS.
                    try:
                        ok, err = await op(client)
                    except Exception as e2:
                        ok, err = False, f"{type(e).__name__}+{type(e2).__name__}"
                except Exception as e:
                    ok, err = False, type(e).__name__
                dt_ms = (time.monotonic() - t0) * 1000
                samples_ms.append(dt_ms)
                if ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if err and len(err_sample) < 5:
                        err_sample.append(err)

        started = time.monotonic()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        elapsed = time.monotonic() - started

    total = ok_count + err_count
    return ScenarioResult(
        scenario=scenario,
        concurrency=concurrency,
        duration_sec=round(elapsed, 2),
        requests_total=total,
        requests_ok=ok_count,
        requests_err=err_count,
        rps=round(total / elapsed, 1) if elapsed > 0 else 0.0,
        p50_ms=round(_percentile(samples_ms, 0.50), 2),
        p95_ms=round(_percentile(samples_ms, 0.95), 2),
        p99_ms=round(_percentile(samples_ms, 0.99), 2),
        p999_ms=round(_percentile(samples_ms, 0.999), 2),
        err_sample=err_sample,
    )


# ---------------------------------------------------------------- commands --


@app.command()
def run(
    url: str = typer.Option(...),
    token: str = typer.Option(...),
    scenario: str = typer.Option("read_secret", help=f"One of {SCENARIOS}"),
    concurrency: int = typer.Option(50),
    duration: int = typer.Option(30, help="Seconds"),
    output: Path | None = typer.Option(None, help="Optional JSON output path"),
    insecure: bool = typer.Option(False, help="Skip TLS cert verification"),
):
    """Run a single scenario and print Markdown + (optional) JSON."""
    if scenario not in SCENARIOS:
        raise typer.BadParameter(f"scenario must be one of {SCENARIOS}")
    asyncio.run(
        _run_async(
            url,
            token,
            [scenario],
            concurrency=concurrency,
            duration=duration,
            profile=None,
            output=output,
            insecure=insecure,
        )
    )


@app.command()
def profile(
    url: str = typer.Option(...),
    token: str = typer.Option(...),
    profile: str = typer.Option("small", help=f"One of {list(PROFILES)}"),
    output: Path | None = typer.Option(None, help="Optional JSON output path"),
    insecure: bool = typer.Option(False, help="Skip TLS cert verification"),
):
    """Run all authenticated scenarios with the given profile."""
    if profile not in PROFILES:
        raise typer.BadParameter(f"profile must be one of {list(PROFILES)}")
    p = PROFILES[profile]
    asyncio.run(
        _run_async(
            url,
            token,
            list(SCENARIOS),
            concurrency=p["concurrency"],
            duration=p["duration"],
            profile=profile,
            output=output,
            insecure=insecure,
        )
    )


@app.command()
def anon(
    url: str = typer.Option(..., help="Vault URL"),
    profile: str = typer.Option("small", help=f"One of {list(PROFILES)}"),
    output: Path | None = typer.Option(None, help="Optional JSON output path"),
    insecure: bool = typer.Option(False, help="Skip TLS cert verification"),
):
    """Anonymous bench - only the unauthenticated scenarios (status).

    Useful when no token is at hand, or as an upper-bound baseline of the
    HTTP+DB pipeline before auth and master-RPC crypto layers kick in.
    """
    if profile not in PROFILES:
        raise typer.BadParameter(f"profile must be one of {list(PROFILES)}")
    p = PROFILES[profile]
    asyncio.run(
        _run_async(
            url,
            token=None,
            scenarios=list(ANON_SCENARIOS),
            concurrency=p["concurrency"],
            duration=p["duration"],
            profile=f"{profile}-anon",
            output=output,
            insecure=insecure,
        )
    )


async def _run_async(
    url: str,
    token: str | None,
    scenarios: list[str],
    concurrency: int,
    duration: int,
    profile: str | None,
    output: Path | None,
    insecure: bool = False,
):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(
        base_url=url, headers=headers, timeout=10.0, verify=not insecure
    ) as c:
        status = await _fetch_status(c)
        if status.get("sealed", True):
            typer.secho("Vault is sealed - unseal first.", fg=typer.colors.RED)
            raise typer.Exit(1)
        version = status.get("version")
        # discover seeded secrets, only when authenticated
        pool: list[str] = []
        if token:
            r = await c.get("/api/v1/vault/secrets/")
            r.raise_for_status()
            items = r.json().get("items", [])
            pool = [s["name"] for s in items if s["name"].startswith(SEED_PREFIX)]

    workers_env = os.environ.get("RHORIZON_WORKERS")
    workers = int(workers_env) if workers_env and workers_env.isdigit() else None

    typer.secho(
        f"\nRunning {len(scenarios)} scenario(s) @ c={concurrency}, d={duration}s "
        f"on {url} ({version or '?'}, workers={workers or '?'})\n",
        fg=typer.colors.CYAN,
    )

    results: list[ScenarioResult] = []
    for sc in scenarios:
        typer.secho(f"  -> {sc} ...", fg=typer.colors.YELLOW, nl=False)
        res = await _drive(
            url, token, sc, concurrency, duration, pool, insecure=insecure
        )
        results.append(res)
        typer.secho(
            f"  rps={res.rps:>7}  p50={res.p50_ms:>5}ms  p95={res.p95_ms:>5}ms  "
            f"p99={res.p99_ms:>5}ms  err={res.requests_err}",
            fg=typer.colors.GREEN if res.requests_err == 0 else typer.colors.RED,
        )

    report = RunReport(
        profile=profile,
        target_url=url,
        started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        rhorizon_version=version,
        workers=workers,
        env=_env_snapshot(),
        results=results,
    )

    print()
    print(_to_markdown(report))

    if output:
        output.write_text(json.dumps(asdict(report), indent=2))
        typer.secho(f"\nJSON written to {output}", fg=typer.colors.GREEN)


def _to_markdown(report: RunReport) -> str:
    ver = report.rhorizon_version or "?"
    workers = report.workers or "?"
    head = (
        f"### rhorizon bench - {report.profile or 'custom'}\n\n"
        f"- **Target** : `{report.target_url}` "
        f"(rhorizon {ver}, workers={workers})\n"
        f"- **Host**   : {report.env['cpu']} - {report.env['kernel']}\n"
        f"- **When**   : {report.started_at}\n"
        f"- **Harness**: rev `{report.env['harness_sha']}`\n\n"
    )
    table = (
        "| Scenario | Conc | Dur (s) | RPS | p50 (ms) | p95 (ms) | "
        "p99 (ms) | p99.9 (ms) | OK | Err |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n"
    )
    for r in report.results:
        table += (
            f"| `{r.scenario}` | {r.concurrency} | {r.duration_sec} | {r.rps} | "
            f"{r.p50_ms} | {r.p95_ms} | {r.p99_ms} | {r.p999_ms} | "
            f"{r.requests_ok} | {r.requests_err} |\n"
        )
    return head + table


if __name__ == "__main__":
    app()
