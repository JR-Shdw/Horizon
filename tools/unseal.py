#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""rhorizon unseal CLI - password + optional YubiKey or TOTP.

Usage:
    # Password only
    ./tools/unseal.py --url http://localhost:8200

    # Password + YubiKey (slot 2)
    ./tools/unseal.py --url http://localhost:8200 --yubikey

    # Password + TOTP
    ./tools/unseal.py --url http://localhost:8200 --totp

    # Check status
    ./tools/unseal.py --url http://localhost:8200 --status

Dependencies (operator's machine, not Docker):
    pip install typer httpx
    pip install python-yubico   # only if using --yubikey
"""

import getpass

import httpx
import typer

app = typer.Typer(help="rhorizon unseal CLI")


def _yubikey_challenge_response(challenge_hex: str) -> str:
    """Send challenge to YubiKey slot 2, return HMAC-SHA1 response hex."""
    try:
        from yubico import yubico_exception
        from yubico.yubikey import YubiKey
    except ImportError:
        typer.echo("Error: python-yubico not installed")
        typer.echo("  pip install python-yubico")
        raise typer.Exit(1)

    try:
        yk = YubiKey()
    except yubico_exception.YubicoError:
        typer.echo("Error: no YubiKey detected - is it plugged in?")
        raise typer.Exit(1)

    challenge = bytes.fromhex(challenge_hex)
    try:
        response = yk.challenge_response(challenge, slot=2)
        return response.hex()
    except Exception as e:
        typer.echo(f"YubiKey error: {e}")
        raise typer.Exit(1)


@app.command()
def unseal(
    url: str = typer.Option("http://localhost:8200", "--url", "-u", help="Vault URL"),
    yubikey: bool = typer.Option(
        False, "--yubikey", "-y", help="Use YubiKey challenge-response"
    ),
    totp: bool = typer.Option(False, "--totp", "-t", help="Use TOTP code"),
    status_only: bool = typer.Option(
        False, "--status", "-s", help="Just check vault status"
    ),
):
    """Unseal the vault with password + optional 2FA."""
    client = httpx.Client(base_url=url, timeout=30)

    # Status check
    try:
        r = client.get("/api/v1/vault/status")
        r.raise_for_status()
    except httpx.HTTPError as e:
        typer.echo(f"Cannot reach vault at {url}: {e}")
        raise typer.Exit(1)

    info = r.json()
    if status_only:
        typer.echo(f"Sealed:    {info['sealed']}")
        typer.echo(f"Version:   {info['version']}")
        typer.echo(f"2FA mode:  {info.get('second_factor', 'none')}")
        typer.echo(f"YubiKeys:  {info.get('yubikeys_registered', 0)}")
        typer.echo(f"TOTP:      {info.get('totp_enabled', False)}")
        if info.get("uptime"):
            typer.echo(f"Uptime:    {info['uptime']}")
        raise typer.Exit(0)

    if not info["sealed"]:
        typer.echo("Vault is already unsealed")
        if info.get("uptime"):
            typer.echo(f"  uptime: {info['uptime']}")
        raise typer.Exit(0)

    # Check 2FA requirement
    mode = info.get("second_factor", "none")
    if mode != "none" and not yubikey and not totp:
        typer.echo(f"2FA required (mode: {mode})")
        if mode in ("yubikey", "any"):
            typer.echo("  --yubikey  Use YubiKey")
        if mode in ("totp", "any"):
            typer.echo("  --totp     Use TOTP code")
        raise typer.Exit(1)

    password = getpass.getpass("Master password: ")
    if not password:
        typer.echo("Password cannot be empty")
        raise typer.Exit(1)

    payload = {"password": password}

    # YubiKey flow
    if yubikey:
        typer.echo("Requesting challenge from vault...")
        r = client.post("/api/v1/vault/challenge")
        r.raise_for_status()
        challenge = r.json()["challenge"]

        typer.echo("Touch your YubiKey...")
        yk_response = _yubikey_challenge_response(challenge)
        payload["yubikey_response"] = yk_response
        payload["challenge"] = challenge

    # TOTP flow
    if totp:
        code = typer.prompt("TOTP code")
        payload["totp_code"] = code

    # Unseal
    typer.echo("Deriving master key (Argon2id 256MB)...")
    r = client.post("/api/v1/vault/unseal", json=payload)

    if r.status_code == 200:
        data = r.json()
        factor = data.get("second_factor", "none")
        typer.echo("Vault unsealed")
        if factor != "none":
            typer.echo(f"  2FA: {factor}")
        # First-boot or post-restore bootstrap returns a fresh root token.
        # Shown once only, surface it loudly so it doesn't get lost in
        # the terminal scrollback.
        if data.get("root_token"):
            kind = data.get("bootstrap_kind", "bootstrap")
            typer.echo("")
            if kind == "restore-recovery":
                typer.echo("Backup restore recovery - fresh root token issued.")
            else:
                typer.echo("First-boot - root token issued.")
            typer.echo(data.get("warning", "Save this token - shown once only"))
            typer.echo("")
            typer.echo(data["root_token"])
    elif r.status_code == 401:
        typer.echo("Invalid credentials")
        raise typer.Exit(1)
    elif r.status_code == 400:
        typer.echo(f"Error: {r.json().get('detail', r.text)}")
        raise typer.Exit(1)
    else:
        typer.echo(f"Unexpected: {r.status_code} {r.text}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
