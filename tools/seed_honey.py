#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Seed honey (or normal) tokens and secrets via the rhorizon API.

Usage:
    # Set your root token + URL once
    export RH_URL=https://rhorizon.internal
    export RH_TOKEN=rh_admin_xxxxx

    # Honey token (decoy, any auth fires CRITICAL alert)
    ./tools/seed_honey.py token --name prod-pgsql-master \
        --perms '{"secrets":"rw"}' --honey

    # Honey secret (decoy value, any read fires alert)
    ./tools/seed_honey.py secret --name wg-server-private \
        --value "$(openssl rand -base64 32)" --namespace infra --honey

    # Same commands without --honey create regular tokens/secrets.

Why this script: faster than crafting curl, doesn't need typer
installed system-wide (uses stdlib argparse), reads RH_URL/RH_TOKEN
from the environment so creds never appear on the command line.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def _post(path: str, body: dict) -> dict:
    url = os.environ["RH_URL"].rstrip("/") + path
    token = os.environ["RH_TOKEN"]
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"HTTP {e.code}: {e.read().decode(errors='replace')}\n")
        sys.exit(1)


def cmd_token(args: argparse.Namespace) -> None:
    perms = json.loads(args.perms)
    body = {"name": args.name, "permissions": perms}
    if args.expires:
        body["expires_at"] = args.expires
    if args.allowed_ips:
        body["allowed_ips"] = args.allowed_ips
    if args.honey:
        body["is_honey"] = True
    r = _post("/api/v1/vault/tokens/", body)
    flag = " (HONEY)" if args.honey else ""
    print(f"created token '{args.name}'{flag}")
    print(f"  token: {r.get('token', '<not returned>')}")
    print("  ^ store it now, can't be retrieved later")
    if args.honey:
        print("  HONEY: do NOT distribute. Place where attackers might find it")
        print("         (bait config, fake backup share, internal misdirection).")


def cmd_secret(args: argparse.Namespace) -> None:
    body = {
        "name": args.name,
        "value": args.value,
        "namespace": args.namespace,
    }
    if args.honey:
        body["is_honey"] = True
    _post("/api/v1/vault/secrets/", body)
    flag = " (HONEY)" if args.honey else ""
    print(f"created secret '{args.name}' in namespace '{args.namespace}'{flag}")
    if args.honey:
        print("  HONEY: any read fires alert. Pick a plausible-looking value")
        print("         (random bytes shaped like a real secret).")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Seed rhorizon tokens or secrets, optionally as honeytokens."
    )
    sub = p.add_subparsers(dest="kind", required=True)

    pt = sub.add_parser("token", help="Create an API token")
    pt.add_argument("--name", required=True)
    pt.add_argument("--perms", required=True, help='JSON, e.g. \'{"secrets":"rw"}\'')
    pt.add_argument("--expires", help="ISO datetime (optional)")
    pt.add_argument(
        "--allowed-ips", dest="allowed_ips", help="Comma-separated CIDRs/IPs (optional)"
    )
    pt.add_argument(
        "--honey",
        action="store_true",
        help="Mark token as decoy - any auth fires alert",
    )
    pt.set_defaults(fn=cmd_token)

    ps = sub.add_parser("secret", help="Create a vault secret")
    ps.add_argument("--name", required=True)
    ps.add_argument(
        "--value", required=True, help="Secret value (use openssl rand for honey)"
    )
    ps.add_argument("--namespace", default="default")
    ps.add_argument(
        "--honey",
        action="store_true",
        help="Mark secret as decoy - any read fires alert",
    )
    ps.set_defaults(fn=cmd_secret)

    args = p.parse_args()
    if not os.environ.get("RH_URL") or not os.environ.get("RH_TOKEN"):
        sys.exit("error: set RH_URL and RH_TOKEN env vars")
    args.fn(args)


if __name__ == "__main__":
    main()
