#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Break-glass: mint a fresh root token directly against the vault DB.

Use case: the operator is locked out with no usable admin token. Typical
triggers: the post-restore bootstrap token (root-restore-<ts>, minted on
the first unseal after /backup/restore) was never saved; a restore flow
failed halfway; argon2_salt was changed by hand; or every admin token was
revoked or lost.

Note: a normal restore does NOT rewrite argon2_salt / master_check -- those
belong to the CURRENT vault and are left untouched (the older overwrite
behaviour was a bug, fixed by the dual-context restore). So the current
master password keeps unsealing; this tool is the fallback for when the
minted bootstrap token itself is gone, not a consequence of restore.

This script does NOT need an root token. It needs:
  - the master password used at backup time
  - direct PostgreSQL access (same network namespace as the API)

It re-derives master_key + hmac_key from argon2_salt + password, verifies
master_check, generates a fresh `rh_*` token, computes its HMAC-SHA512
under the current hmac_key, INSERTs a new admin row in vault_tokens and
prints the plaintext.

The vault can be either sealed or unsealed when you run this - we
touch tables, never RAM. The new token works as soon as the running
API's hmac_key matches the one we re-derive here (i.e., as soon as
the vault is unsealed with the same master password that produced
the argon2_salt and master_check currently stored).

Usage:
    # 1) Copy the script + the api/ tree into the running API container
    #    (it has asyncpg + pynacl + cryptography already installed; /tmp
    #    is a writable tmpfs even with the read-only root fs)
    docker cp tools/emergency_root_token.py rhorizon_api:/tmp/recovery.py
    docker exec -it rhorizon_api env \\
        RHORIZON_DB_URL="postgresql://rhorizon:$$PGPASS@postgres:5432/rhorizon" \\
        python3 /tmp/recovery.py

    # 2) Or from the host venv against a port-forwarded DB
    RHORIZON_DB_URL=postgresql://rhorizon:pwd@localhost:5432/rhorizon \\
        .venv/bin/python3 tools/emergency_root_token.py

Refuse to run if any active root token already exists unless --force is
passed (the operator clearly accepts that the action is logged in the
audit trail as `recovery-token-mint`).
"""

import asyncio
import getpass
import hmac as _hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path

# Locate the `app` package. Two layouts are supported:
#   - dev host: tools/emergency_root_token.py -> ../api/app
#   - inside the API container: /app/app  (the image copies api/ to /app)
_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "api",
    Path("/app"),
]
for _p in _CANDIDATES:
    if (_p / "app" / "crypto.py").is_file():
        sys.path.insert(0, str(_p))
        break
else:
    sys.stderr.write(
        "could not locate the `app` package (tried "
        + ", ".join(str(p) for p in _CANDIDATES)
        + "). Set PYTHONPATH manually.\n"
    )
    sys.exit(2)

import asyncpg  # noqa: E402

from app.crypto import (  # noqa: E402
    derive_keys,
    derive_master_key,
    generate_token,
    hmac_token,
    shamir_combine,
    verify_totp,
    verify_yubikey_response,
)


def _dsn() -> str:
    dsn = os.environ.get("RHORIZON_DB_URL") or os.environ.get("DATABASE_URL")
    if dsn:
        # asyncpg doesn't accept the SQLAlchemy +asyncpg suffix
        return dsn.replace("postgresql+asyncpg://", "postgresql://", 1)
    return "postgresql://rhorizon:rhorizon@postgres:5432/rhorizon"


async def _read_config(conn, key: str) -> str | None:
    row = await conn.fetchrow("SELECT value FROM vault_config WHERE key = $1", key)
    return row["value"] if row else None


async def _has_active_admin(conn) -> bool:
    row = await conn.fetchrow(
        """
        SELECT 1
          FROM vault_tokens
         WHERE active = true
           AND permissions ? 'admin'
         LIMIT 1
        """
    )
    return row is not None


async def _require_totp(conn, keys) -> None:
    """Break-glass second factor (TOTP). Verify a code or exit non-zero.

    Armed via vault_config `break_glass_2fa = totp`. There is NO bypass: once
    armed, a valid code is mandatory (keep a backup of the seed or you lock
    yourself out of recovery too -- see docs/DISASTER-RECOVERY.md).

    Seed source, in order:
      1. RH_BREAK_GLASS_TOTP_SECRET env -- an out-of-band seed NOT stored in the
         DB. This is the only source that resists a master-password+DB attacker
         (they cannot read it) and the one an HA controller injects to drive
         break-glass unattended.
      2. vault_config `totp_secret` -- the enrolled unseal TOTP, decrypted with
         the password-derived dek_key. Convenience/reuse; a master-password+DB
         attacker can also decrypt this, so it gates a password-only misuse but
         is NOT proof against that stronger attacker (use fido2/shamir there).
    """
    seed = os.environ.get("RH_BREAK_GLASS_TOTP_SECRET", "").strip()
    if not seed:
        enc = await _read_config(conn, "totp_secret")
        if not enc:
            sys.stderr.write(
                "break_glass_2fa=totp is armed but no seed found: set "
                "RH_BREAK_GLASS_TOTP_SECRET or enroll the vault TOTP first.\n"
            )
            sys.exit(5)
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            raw = bytes.fromhex(enc)
            seed = AESGCM(keys["dek_key"]).decrypt(raw[:12], raw[12:], None).decode()
        except Exception:
            sys.stderr.write("could not decrypt the enrolled TOTP secret - abort\n")
            sys.exit(5)
    code = getpass.getpass("break-glass TOTP code: ").strip()
    if not verify_totp(seed, code):
        sys.stderr.write("TOTP code rejected - abort\n")
        sys.exit(6)
    sys.stderr.write("break-glass TOTP verified.\n")


async def _require_yubikey(conn, keys) -> None:
    """Break-glass second factor (YubiKey slot 2, HMAC-SHA1).

    Mint a random 32-byte challenge; the operator feeds it to the physical
    token (`ykchalresp -2 -x <hex>`, or `ykman otp calculate 2 <hex>` if
    ykchalresp lacks USB access) and pastes the 20-byte response, verified
    against the registered secret.

    Verifier secret source, in order (mirrors _require_totp):
      1. RH_BREAK_GLASS_YUBIKEY_SECRET (hex, 20B) -- out-of-band, the only
         source that resists a master-password+DB attacker (with the DB secret
         they could recompute the response themselves).
      2. vault_yubikeys.hmac_secret -- decrypted with the password-derived
         dek_key. Convenience; a master-password+DB attacker can also decrypt
         it and forge a response, so it only gates a weaker misuse.
    """
    verifiers: list[bytes] = []
    env_secret = os.environ.get("RH_BREAK_GLASS_YUBIKEY_SECRET", "").strip()
    if env_secret:
        try:
            verifiers.append(bytes.fromhex(env_secret))
        except ValueError:
            sys.stderr.write("RH_BREAK_GLASS_YUBIKEY_SECRET is not hex - abort\n")
            sys.exit(5)
    else:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aes = AESGCM(keys["dek_key"])
        rows = await conn.fetch("SELECT serial, hmac_secret FROM vault_yubikeys")
        if not rows:
            sys.stderr.write(
                "break_glass_2fa=yubikey armed but no YubiKey is registered and "
                "RH_BREAK_GLASS_YUBIKEY_SECRET is unset - abort\n"
            )
            sys.exit(5)
        for row in rows:
            raw = bytes(row["hmac_secret"])
            try:
                verifiers.append(aes.decrypt(raw[:12], raw[12:], None))
            except Exception:
                sys.stderr.write(
                    f"could not decrypt YubiKey secret for serial {row['serial']} "
                    "- skip\n"
                )
    if not verifiers:
        sys.stderr.write("no usable YubiKey verifier secret - abort\n")
        sys.exit(5)

    challenge = secrets.token_bytes(32)
    sys.stderr.write(
        "break-glass YubiKey challenge (slot 2 HMAC-SHA1); run either:\n"
        f"    ykchalresp -2 -x {challenge.hex()}\n"
        f"    ykman otp calculate 2 {challenge.hex()}\n"
        "(use ykman if ykchalresp reports a USB access error -- it needs the\n"
        " yubikey-personalization libusb udev rule; ykman uses the HID interface)\n"
    )
    resp_hex = getpass.getpass("paste the 20-byte hex response: ").strip()
    try:
        response = bytes.fromhex(resp_hex)
    except ValueError:
        sys.stderr.write("response is not hex - abort\n")
        sys.exit(6)
    if len(response) != 20:
        sys.stderr.write("YubiKey response must be 20 bytes - abort\n")
        sys.exit(6)
    if any(verify_yubikey_response(v, challenge, response) for v in verifiers):
        sys.stderr.write("break-glass YubiKey verified.\n")
        return
    sys.stderr.write("YubiKey response rejected - abort\n")
    sys.exit(6)


async def _require_shamir(conn, keys) -> None:
    """Break-glass second factor (Shamir M-of-N).

    Reuses the vault's operator Shamir: prompt for M distinct shares, combine
    them, and prove the reconstructed key material belongs to THIS vault by
    matching the hmac_key against the password-derived one. Unlike totp/yubikey
    the shares live with M humans and are NOT derivable from master-password+DB,
    so this is real against that attacker. No single holder can act alone.
    """
    enabled = (await _read_config(conn, "shamir_enabled")) == "true"
    threshold = int((await _read_config(conn, "shamir_threshold")) or 0)
    if not enabled or threshold < 2:
        sys.stderr.write(
            "break_glass_2fa=shamir armed but the vault Shamir is not "
            "initialized - abort\n"
        )
        sys.exit(5)

    sys.stderr.write(
        f"break-glass Shamir: paste {threshold} distinct shares (hex), one per line.\n"
    )
    shares: list[bytes] = []
    seen_x: set[int] = set()
    while len(shares) < threshold:
        line = getpass.getpass(f"share {len(shares) + 1}/{threshold} (hex): ").strip()
        try:
            share = bytes.fromhex(line)
        except ValueError:
            sys.stderr.write("not hex - retry\n")
            continue
        if len(share) < 2:
            sys.stderr.write("share too short - retry\n")
            continue
        if share[0] in seen_x:
            sys.stderr.write("duplicate share index - retry\n")
            continue
        seen_x.add(share[0])
        shares.append(share)

    try:
        key_material = shamir_combine(shares)
    except Exception as exc:
        sys.stderr.write(f"Shamir reconstruction failed: {exc} - abort\n")
        sys.exit(6)
    # 5x32 = 160B (hmac_key || dek_key || audit_key || ha_wrap_key || pki_wrap_key)
    if len(key_material) != 160 or not _hmac.compare_digest(
        key_material[:32], keys["hmac_key"]
    ):
        sys.stderr.write("shares do not reconstruct the current vault key - abort\n")
        sys.exit(6)
    sys.stderr.write("break-glass Shamir quorum verified.\n")


async def _require_fido2(conn) -> None:
    """Break-glass second factor (FIDO2 / WebAuthn).

    Strongest factor: the private key lives on hardware and never touches the
    DB, so a master-password+DB attacker cannot forge an assertion. Drives a
    CTAP2 getAssertion over USB HID and verifies it with the app's Fido2Server.

    Requires a registered authenticator PHYSICALLY PRESENT on the machine
    running this tool -- it will NOT work inside a container without USB HID
    passthrough. Uses settings.webauthn_rp_id (RHORIZON_WEBAUTHN_RP_ID); it
    MUST match the value used at registration or the assertion is rejected.
    """
    rows = await conn.fetch(
        "SELECT credential_id, credential_data, sign_count FROM vault_webauthn"
    )
    if not rows:
        sys.stderr.write(
            "break_glass_2fa=fido2 armed but no WebAuthn credential is "
            "registered - abort\n"
        )
        sys.exit(5)

    try:
        from fido2.client import (
            DefaultClientDataCollector,
            Fido2Client,
            UserInteraction,
        )
        from fido2.hid import CtapHidDevice
        from fido2.webauthn import (
            AttestedCredentialData,
            PublicKeyCredentialDescriptor,
            PublicKeyCredentialRequestOptions,
            UserVerificationRequirement,
        )

        from app.config import settings
        from app.routes.webauthn import _get_fido2_server
    except Exception as exc:  # pragma: no cover - import guard
        sys.stderr.write(f"FIDO2 support unavailable: {exc} - abort\n")
        sys.exit(5)

    rp_id = settings.webauthn_rp_id
    origin = f"https://{rp_id}"
    challenge = secrets.token_bytes(32)
    allow = [
        PublicKeyCredentialDescriptor(type="public-key", id=bytes(row["credential_id"]))
        for row in rows
    ]

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        sys.stderr.write(
            "no FIDO2 authenticator found on USB HID - plug the key into THIS "
            "machine (the tool cannot reach a key inside a container) - abort\n"
        )
        sys.exit(6)

    class _CliInteraction(UserInteraction):
        def prompt_up(self) -> None:
            sys.stderr.write("touch your security key now...\n")

        def request_pin(self, permissions, rp_id):  # noqa: ARG002
            return getpass.getpass("security key PIN: ")

        def request_uv(self, permissions, rp_id):  # noqa: ARG002
            return True

    options = PublicKeyCredentialRequestOptions(
        challenge=challenge,
        rp_id=rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )
    response = None
    for device in devices:
        try:
            client = Fido2Client(
                device,
                DefaultClientDataCollector(origin),
                user_interaction=_CliInteraction(),
            )
            response = client.get_assertion(options).get_response(0)
            break
        except Exception as exc:
            sys.stderr.write(f"authenticator error: {exc}\n")
            continue
    if response is None:
        sys.stderr.write("no usable assertion produced - abort\n")
        sys.exit(6)

    credentials = [
        AttestedCredentialData(bytes(row["credential_data"])) for row in rows
    ]
    # fido2 2.x internal state: websafe-b64 challenge + explicit
    # user_verification key (authenticate_complete reads both)
    from fido2.utils import websafe_encode

    state = {"challenge": websafe_encode(challenge), "user_verification": None}
    try:
        _get_fido2_server().authenticate_complete(state, credentials, response)
    except Exception as exc:
        sys.stderr.write(f"FIDO2 verification failed: {exc} - abort\n")
        sys.exit(6)
    sys.stderr.write("break-glass FIDO2 verified.\n")


async def main(argv: list[str]) -> int:
    force = "--force" in argv

    dsn = _dsn()
    sys.stderr.write(f"connecting to {dsn.split('@', 1)[-1]}...\n")
    conn = await asyncpg.connect(dsn)
    try:
        salt_hex = await _read_config(conn, "argon2_salt")
        check = await _read_config(conn, "master_check")
        if not salt_hex or not check:
            sys.stderr.write(
                "vault not initialized - argon2_salt or master_check missing\n"
            )
            return 2

        try:
            salt = bytes.fromhex(salt_hex)
        except ValueError:
            sys.stderr.write("argon2_salt is not hex-encoded - abort\n")
            return 2

        if await _has_active_admin(conn) and not force:
            sys.stderr.write(
                "an active root token already exists in vault_tokens. "
                "pass --force to mint another recovery root token anyway.\n"
            )
            return 3

        password = getpass.getpass("master password: ").encode()
        if not password:
            sys.stderr.write("empty password - abort\n")
            return 2

        sys.stderr.write("deriving master key (argon2id, ~1s)...\n")
        master_key = derive_master_key(password, salt)
        keys = derive_keys(master_key)
        computed = hmac_token(keys["hmac_key"], "master-check-value")
        if not _hmac.compare_digest(computed, check):
            sys.stderr.write("master_check mismatch - wrong password\n")
            return 4

        # Break-glass second factor. Armed via vault_config break_glass_2fa;
        # once armed, mandatory (no bypass, by design). Each factor's verifier
        # exits non-zero on failure rather than returning, so a partially
        # configured or unverifiable factor can never fall open.
        bg_2fa = (await _read_config(conn, "break_glass_2fa") or "").strip().lower()
        if bg_2fa == "totp":
            await _require_totp(conn, keys)
        elif bg_2fa == "yubikey":
            await _require_yubikey(conn, keys)
        elif bg_2fa == "fido2":
            await _require_fido2(conn)
        elif bg_2fa == "shamir":
            await _require_shamir(conn, keys)
        elif bg_2fa and bg_2fa != "none":
            sys.stderr.write(f"unknown break_glass_2fa value: {bg_2fa} - abort\n")
            return 5

        token_plain = generate_token()
        token_hash = hmac_token(keys["hmac_key"], token_plain)
        name = f"recovery-{int(time.time())}-{secrets.token_hex(3)}"

        await conn.execute(
            """
            INSERT INTO vault_tokens
                (name, token_hash, permissions, active, created_by)
            VALUES
                ($1, $2, $3::jsonb, true, 'emergency-recovery')
            """,
            name,
            token_hash,
            json.dumps({"admin": "rw"}),
        )

        # leave a critical breadcrumb in the audit
        # chain so an operator running `/audit/verify` later sees this
        # break-glass action in red. We bypass the API's `log_action`
        # helper (vault sealed or master key not derivable from outside
        # the running process), so the row is "unsigned" -- the verify
        # path skips unsigned entries from the chain check, but the row
        # still surfaces in `/audit` and in the daily JSONL via the
        # UI Jets renderer (detail._critical=true wins the red badge).
        await conn.execute(
            """
            INSERT INTO vault_audit
                (actor, action, target, detail, signature)
            VALUES
                ('emergency-recovery', 'recovery-token-mint', $1,
                 $2::jsonb, 'unsigned')
            """,
            name,
            json.dumps(
                {
                    "_critical": True,
                    "reason": "break-glass root token mint via emergency_root_token.py",
                    "force": force,
                    "second_factor": bg_2fa or "none",
                }
            ),
        )

        sys.stderr.write(
            "\nrecovery root token minted. "
            "SAVE THIS - it cannot be retrieved later:\n\n"
        )
        sys.stdout.write(token_plain + "\n")
        sys.stderr.write(f"\nname in vault_tokens: {name}\n")
        sys.stderr.write(
            "next: POST /api/v1/vault/unseal with the same master password.\n"
        )
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
