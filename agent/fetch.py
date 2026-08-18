#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""rh-fetch - pull secrets and write them as files for init containers.

Usage in docker-compose.yml:
  services:
    secrets-init:
      image: rhorizon-agent:latest
      command: ["python3", "/agent/fetch.py"]
      environment:
        RHORIZON_ADDR: https://vault.internal:8200
        RHORIZON_TOKEN: rh_xxx
        RHORIZON_SECRETS: "db-password:/secrets/db-pass,api-key:/secrets/api-key"
      volumes:
        - secrets:/secrets

    app:
      depends_on:
        secrets-init:
          condition: service_completed_successfully
      volumes:
        - secrets:/secrets:ro

  volumes:
    secrets:
      driver_opts:
        type: tmpfs
        device: tmpfs  # RAM-only

RHORIZON_SECRETS format: "[namespace/]name:/path,[namespace/]name:/path,..."
Prefix the secret reference with `namespace/` to disambiguate same-name
secrets across namespaces (the API returns 409 ambiguous otherwise).
"""

import os
import sys

import httpx


def main():
    addr = os.environ.get("RHORIZON_ADDR")
    token = os.environ.get("RHORIZON_TOKEN")
    secrets_spec = os.environ.get("RHORIZON_SECRETS", "")

    if not addr or not token:
        print("Error: RHORIZON_ADDR and RHORIZON_TOKEN required", file=sys.stderr)
        sys.exit(1)

    if not secrets_spec:
        print("Error: RHORIZON_SECRETS is empty", file=sys.stderr)
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    pairs = [p.strip() for p in secrets_spec.split(",") if p.strip()]
    print(f"[rh-fetch] Fetching {len(pairs)} secret(s)...", file=sys.stderr)

    errors = 0
    for pair in pairs:
        if ":" not in pair:
            print(
                f"[rh-fetch] WARN: invalid format '{pair}' - expected name:/path",
                file=sys.stderr,
            )
            errors += 1
            continue

        spec, _, dest_path = pair.partition(":")
        if "/" in spec:
            namespace, _, secret_name = spec.partition("/")
        else:
            namespace, secret_name = None, spec
        params = {"namespace": namespace} if namespace else None

        try:
            r = httpx.get(
                f"{addr}/api/v1/vault/secrets/{secret_name}",
                params=params,
                headers=headers,
                timeout=10,
            )
            if r.status_code != 200:
                print(
                    f"[rh-fetch] ERROR: {secret_name} -> {r.status_code}",
                    file=sys.stderr,
                )
                errors += 1
                continue

            value = r.json()["value"]

            # Ensure parent directory exists
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            # Write with restricted permissions
            fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
            os.write(fd, value.encode())
            os.close(fd)

            print(f"[rh-fetch]   {secret_name} -> {dest_path}", file=sys.stderr)

        except httpx.ConnectError:
            print(f"[rh-fetch] FATAL: cannot connect to {addr}", file=sys.stderr)
            sys.exit(1)

    if errors:
        print(f"[rh-fetch] {errors} error(s)", file=sys.stderr)
        sys.exit(1)

    print(f"[rh-fetch] {len(pairs)} secret(s) written successfully", file=sys.stderr)


if __name__ == "__main__":
    main()
