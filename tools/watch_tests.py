#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""T0 local test watcher: on every save, run the checks relevant to the file.

  *.py under api/ cli/ tests/  -> ruff (changed files) + pytest (mapped tests)
  *.rs under api/rust/src/     -> cargo test (rhorizon_crypto)

Brings up an ephemeral test PG (docker-compose.test.yml, port RH_TEST_PG_PORT,
default 55434) once for the session and tears it down on exit. Zero extra deps:
watchfiles ships with uvicorn[standard].

This is tier T0 (fast, seconds). For the full suite + integration use
`make verify-local` (T1); for the OS/k8s/cluster matrix use `make test-matrix`
(T2). Run: `make watch`  (or  `.venv/bin/python tools/watch_tests.py`).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

try:
    from watchfiles import watch
except ImportError:
    sys.exit("watchfiles missing: activate the project venv")

ROOT = Path(__file__).resolve().parent.parent
PG_PORT = os.environ.get("RH_TEST_PG_PORT", "55434")
DB_URL = f"postgresql+asyncpg://rhorizon_test:rhorizon_test@localhost:{PG_PORT}/rhorizon_test"
COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker-compose.test.yml")]
WATCH_DIRS = [
    ROOT / "api" / "app",
    ROOT / "cli",
    ROOT / "tests",
    ROOT / "api" / "rust" / "src",
]
SMOKE = ["tests/test_security.py", "tests/test_crypto.py"]  # fallback when unmapped

C, R, G, Y, X = "\033[36m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"


def _say(msg: str, color: str = C) -> None:
    print(f"{color}[watch] {msg}{X}", flush=True)


def _run(cmd: list[str], env: dict | None = None) -> int:
    print(f"{C}$ {' '.join(cmd)}{X}", flush=True)
    return subprocess.run(cmd, cwd=ROOT, env=env).returncode


def _pg_up() -> None:
    _say(f"starting test PG on :{PG_PORT}")
    subprocess.run([*COMPOSE, "up", "-d", "postgres-test"], cwd=ROOT, check=True)
    for _ in range(120):
        r = subprocess.run(
            [
                *COMPOSE,
                "exec",
                "-T",
                "postgres-test",
                "pg_isready",
                "-U",
                "rhorizon_test",
                "-d",
                "rhorizon_test",
            ],
            cwd=ROOT,
            capture_output=True,
        )
        if r.returncode == 0:
            _say("test PG ready", G)
            return
        time.sleep(0.5)
    sys.exit("test PG did not become ready")


def _pg_down() -> None:
    _say("stopping test PG")
    subprocess.run([*COMPOSE, "down"], cwd=ROOT)


def _tests_for(py_files: set[str]) -> list[str]:
    """Map changed .py files to the test files worth running.

    A changed test_*.py runs itself; a changed module maps to test_<stem>* and
    test_<first-token>* (so api/app/pki_ca.py -> test_pki*). No match -> SMOKE.
    """
    runset: set[str] = set()
    tests = ROOT / "tests"
    for f in py_files:
        p = Path(f)
        if p.parent.name == "tests" and p.name.startswith("test_"):
            runset.add(f"tests/{p.name}")
            continue
        stem = p.stem
        prefix = stem.split("_")[0]
        for pat in (f"test_{stem}*.py", f"test_{prefix}*.py"):
            runset.update(f"tests/{g.name}" for g in tests.glob(pat))
    return sorted(runset) or SMOKE


def _on_py(py_files: set[str]) -> None:
    changed = sorted(f for f in py_files if Path(f).is_file())
    if changed:
        _run(["ruff", "check", *changed])
    targets = _tests_for(py_files)
    _say(f"pytest {' '.join(targets)}")
    env = {**os.environ, "TEST_DATABASE_URL": DB_URL}
    rc = _run(
        ["pytest", *targets, "-q", "-p", "no:cacheprovider", "--no-cov", "-x"],
        env=env,
    )
    _say("PASS" if rc == 0 else "FAIL", G if rc == 0 else R)


def _on_rust() -> None:
    _say("cargo test (rhorizon_crypto)")
    rc = _run(["make", "rust-test"])
    _say("PASS" if rc == 0 else "FAIL", G if rc == 0 else R)


def main() -> None:
    _pg_up()
    _say("watching api/ cli/ tests/ api/rust/src -- Ctrl-C to stop", Y)
    try:
        for changes in watch(*[str(d) for d in WATCH_DIRS if d.exists()]):
            paths = [p for _, p in changes]
            py = {p for p in paths if p.endswith(".py")}
            rust = any(p.endswith(".rs") for p in paths)
            if py:
                _on_py(py)
            if rust:
                _on_rust()
    except KeyboardInterrupt:
        pass
    finally:
        _pg_down()


if __name__ == "__main__":
    main()
