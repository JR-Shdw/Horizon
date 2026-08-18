#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Forge a legacy rhorizon backup .age file with an arbitrary dek_key_version.

Used by tests/test_legacy_backup.py to validate that a backup taken
under dek_key_version=N can be restored on a vault running at any
version M >= N under the dual-context flow (commit fc57839).

The script does NOT need a running vault. It derives the BACKUP-side
crypto material from --master-password + --salt-hex, constructs the
JSON payload shape expected by /backup/restore (version "3", same
tables layout as create_backup), then encrypts it with age + passphrase.

Regenerate the committed test fixture deterministically :

    .venv/bin/python tools/generate_legacy_backup.py \\
        --out tests/fixtures/backup-legacy-v1.age \\
        --master-password legacy-fixture-mp-1234 \\
        --age-passphrase legacy-fixture-pp-1234 \\
        --salt-hex 0123456789abcdef0123456789abcdef \\
        --dek-key-version 1

The fixture's contents are pinned (3 secrets in namespace `legacy`,
1 group `legacy-admins`) so the test assertions stay stable.
"""

import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import typer
from pyrage import passphrase as age_passphrase

_API = Path(__file__).resolve().parent.parent / "api"
if not (_API / "app" / "crypto.py").is_file():
    sys.stderr.write(f"could not locate api/app at {_API}\n")
    sys.exit(2)
sys.path.insert(0, str(_API))

from app.crypto import (  # noqa: E402
    dek_aad,
    derive_keys,
    derive_master_key,
    encrypt_dek,
    encrypt_secret,
    generate_dek,
    hmac_token,
    secret_aad,
)

_SEED_SECRETS = [
    ("db-pw", "legacy", "secret-value-001"),
    ("api-key", "legacy", "secret-value-002"),
    ("token", "legacy", "secret-value-003"),
]
_SEED_GROUP_NAME = "legacy-admins"
_SEED_NAMESPACE_NAME = "legacy"


def main(
    out: Path = typer.Option(..., help="Output .age file path."),
    master_password: str = typer.Option(..., help="Vault master password (>=8 chars)."),
    age_passphrase_str: str = typer.Option(
        ..., "--age-passphrase", help="age passphrase (>=12 chars)."
    ),
    dek_key_version: int = typer.Option(
        1, help="dek_key_version embedded in vault_config."
    ),
    salt_hex: str = typer.Option(
        ...,
        help="argon2_salt as hex (16 bytes / 32 chars). Pin for reproducible fixtures.",
    ),
):
    """Forge a backup .age file from synthetic data + the given crypto params."""
    if len(master_password) < 8:
        typer.echo("Error: master-password must be at least 8 chars", err=True)
        raise typer.Exit(1)
    if len(age_passphrase_str) < 12:
        typer.echo("Error: age-passphrase must be at least 12 chars", err=True)
        raise typer.Exit(1)
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError as exc:
        typer.echo(f"Error: salt-hex must be valid hex ({exc})", err=True)
        raise typer.Exit(1) from exc
    if len(salt) != 16:
        typer.echo(f"Error: salt must be 16 bytes (got {len(salt)})", err=True)
        raise typer.Exit(1)

    master_key = derive_master_key(master_password.encode(), salt)
    keys = derive_keys(master_key, dek_key_version=dek_key_version)
    master_check = hmac_token(keys["hmac_key"], "master-check-value")

    secrets_rows = []
    for name, namespace, value in _SEED_SECRETS:
        dek = generate_dek()
        dek_id = str(uuid.uuid4())
        dek_enc, dek_nonce = encrypt_dek(dek, keys["dek_key"], None, dek_aad(dek_id))
        ct, nonce = encrypt_secret(value.encode(), dek, secret_aad(name, namespace))
        secrets_rows.append(
            {
                "name": name,
                "namespace": namespace,
                "ciphertext": ct.hex(),
                "nonce": nonce.hex(),
                "version": 1,
                "metadata": {},
                "created_by": "generate-legacy",
                "dek_id": dek_id,
                "dek_encrypted": dek_enc.hex(),
                "dek_nonce": dek_nonce.hex(),
            }
        )

    config_rows = [
        {"key": "argon2_salt", "value": salt_hex},
        {"key": "master_check", "value": master_check},
        {"key": "dek_key_version", "value": str(dek_key_version)},
    ]

    backup_data = {
        "version": "3",
        "format": "age",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tables": {
            "secrets": secrets_rows,
            "namespaces": [
                {
                    "name": _SEED_NAMESPACE_NAME,
                    "owner_group_id": str(uuid.uuid4()),
                    "owner_group_name": _SEED_GROUP_NAME,
                    "enforce_membership": False,
                    "delete_protection": "free",
                    "archived_at": None,
                    "created_by": "generate-legacy",
                }
            ],
            "tokens": [],
            "config": config_rows,
            "groups": [
                {
                    "name": _SEED_GROUP_NAME,
                    "permissions": {"admin": "rw"},
                    "source": "local",
                    "ldap_dn": None,
                }
            ],
            "group_members": [],
        },
    }

    raw = json.dumps(backup_data, default=str).encode()
    checksum = hashlib.sha256(raw).hexdigest()
    backup_data["checksum"] = checksum
    raw = json.dumps(backup_data, default=str).encode()
    encrypted = age_passphrase.encrypt(raw, age_passphrase_str)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(encrypted)
    typer.echo(
        f"Wrote {out} ({len(encrypted)} bytes) "
        f"secrets={len(secrets_rows)} "
        f"dek_key_version={dek_key_version} "
        f"checksum={checksum[:16]}..."
    )


if __name__ == "__main__":
    typer.run(main)
