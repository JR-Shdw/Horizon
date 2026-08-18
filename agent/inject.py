#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""rh-inject - resolve rh:// references in env vars, then exec.

Usage in docker-compose.yml:
  entrypoint: ["python3", "/usr/local/bin/rh-inject", "--", "/app/start.sh"]
  environment:
    RHORIZON_ADDR: https://vault.internal:8200
    RHORIZON_TOKEN: rh_xxx
    DB_PASSWORD: "rh://prod/db-password"
    API_KEY: "rh://staging/api-key"

rh-inject:
  1. Scans all env vars for rh:// prefix
  2. Fetches each secret from the rhorizon API
  3. Replaces the env var value in-memory
  4. Execs the real command (PID 1, no secrets on disk)
"""

import os
import sys

import httpx

RH_PREFIX = "rh://"


def _resolve_secrets(addr: str, token: str, env: dict) -> dict:
    """Resolve all rh:// references in env dict."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    resolved = dict(env)
    to_fetch = {k: v for k, v in env.items() if v.startswith(RH_PREFIX)}

    if not to_fetch:
        return resolved

    print(f"[rh-inject] Resolving {len(to_fetch)} secret(s)...", file=sys.stderr)

    for var_name, ref in to_fetch.items():
        # Parse rh://namespace/secret-name or rh://secret-name
        path = ref[len(RH_PREFIX) :]
        parts = path.split("/", 1)
        if len(parts) == 2:
            # rh://namespace/name: fetch from specific namespace
            namespace, secret_name = parts[0], parts[1]
        else:
            namespace, secret_name = None, parts[0]
        params = {"namespace": namespace} if namespace else None

        url = f"{addr}/api/v1/vault/secrets/{secret_name}"
        try:
            r = httpx.get(url, params=params, headers=headers, timeout=10)
            if r.status_code != 200:
                print(
                    f"[rh-inject] FATAL: cannot fetch {var_name} "
                    f"({secret_name}): {r.status_code}",
                    file=sys.stderr,
                )
                sys.exit(1)
            resolved[var_name] = r.json()["value"]
            print(f"[rh-inject]   {var_name} <- {secret_name}", file=sys.stderr)
        except httpx.ConnectError:
            print(
                f"[rh-inject] FATAL: cannot connect to {addr}",
                file=sys.stderr,
            )
            sys.exit(1)

    print(f"[rh-inject] {len(to_fetch)} secret(s) resolved", file=sys.stderr)
    return resolved


def main():
    # Find -- separator
    try:
        sep = sys.argv.index("--")
    except ValueError:
        print("Usage: rh-inject -- COMMAND [ARGS...]", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[sep + 1 :]
    if not command:
        print("Error: no command after --", file=sys.stderr)
        sys.exit(1)

    addr = os.environ.get("RHORIZON_ADDR")
    token = os.environ.get("RHORIZON_TOKEN")
    if not addr or not token:
        print(
            "Error: RHORIZON_ADDR and RHORIZON_TOKEN must be set",
            file=sys.stderr,
        )
        sys.exit(1)

    # Resolve secrets
    env = _resolve_secrets(addr, token, dict(os.environ))

    # Remove rhorizon config from child env (don't leak credentials)
    env.pop("RHORIZON_TOKEN", None)
    env.pop("RHORIZON_ADDR", None)

    # Exec the real command (replaces this process, PID 1)
    # Note: RHORIZON_TOKEN remains visible in `docker inspect` on the
    # container definition. Use Docker secrets or tmpfs-mounted files
    # for production deployments where inspect access is a concern.
    os.execvpe(command[0], command, env)


if __name__ == "__main__":
    main()
