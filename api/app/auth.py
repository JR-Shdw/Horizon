# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Authentication - HMAC-SHA512 vault tokens + rate limiting.

Token lookup is O(1): compute HMAC first, then direct index lookup
on token_hash. No scanning of all tokens.

Rate limiting: shared DB-backed counter per IP. Invalid tokens
increment the counter - same escalation as unseal brute force.
"""

import logging
import re
import time
import uuid
from typing import Any

from fastapi import Depends, Header, HTTPException, Request
from rhorizon_crypto import secure_zero
from sqlalchemy import text
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession

from .authfail import log_authfail
from .client_ip import get_client_ip
from .cluster_rpc import CustodianRpcClient
from .database import get_db
from .ip_acl import ip_in_allowlist
from .rate_limit import check_rate_limit, record_failure
from .vault_state import vault

_log = logging.getLogger(__name__)

_TOKEN_PATTERN = re.compile(r"rh_[A-Za-z0-9_-]{43}\Z")


def _permission_bits(value: object) -> set[str]:
    if not isinstance(value, str) or value not in {"r", "w", "rw"}:
        return set()
    return set(value)


async def load_prev_hmac_into_ram(db: AsyncSession) -> bool:
    """Reload the previous hmac_key (lazy token migration) after an IN-PLACE
    unseal -- a rekey roll-forward or a failover promotion (``seal()`` drops it,
    the bare ``unseal(keys)`` does not restore it, unlike the /unseal endpoint).

    Without this, a node that adopted a new key generation rejects every token
    minted under the PREVIOUS one -- there is no prev_hmac fallback -- silently
    breaking the ~15-day lazy-migration window on that node cluster-wide. The
    blob is stored under the CURRENT dek_key, so this runs after the new keys
    are installed. No-op when no ``prev_hmac_key`` is stored. Returns True if a
    prev hmac was loaded.
    """
    external_custodian = isinstance(
        getattr(vault, "_rpc_client", None), CustodianRpcClient
    )
    if vault.sealed or (vault.aesgcm is None and not external_custodian):
        return False
    row = (
        await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'prev_hmac_key'")
        )
    ).fetchone()
    if row is None:
        if not external_custodian:
            vault.set_prev_hmac(None)
        return False
    try:
        raw = bytes.fromhex(row.value)
        if external_custodian:
            await vault._call_rpc("install_prev_hmac", {"wrapped_key": raw.hex()})
            return True
        cipher = vault.aesgcm
        if vault.sealed or cipher is None:
            vault.clear_prev_hmac()
            return False
        plain = cipher.decrypt_bytearray(raw[:12], raw[12:], None)
        try:
            if len(plain) != 32:
                raise ValueError("previous HMAC key must be 32 bytes")
            vault.set_prev_hmac(plain)
        finally:
            secure_zero(plain)
        return True
    except Exception:
        import logging

        vault.clear_prev_hmac()
        logging.getLogger("rhorizon.auth").warning(
            "prev_hmac reload after in-place unseal failed", exc_info=True
        )
        return False


async def clear_prev_hmac_if_observed(
    local_generation: int,
    wrapped_envelope: str | None,
) -> bool:
    """Clear only the previous-HMAC generation deleted by the DB transaction."""
    if isinstance(getattr(vault, "_rpc_client", None), CustodianRpcClient):
        if wrapped_envelope is None:
            return False
        try:
            wrapped = bytes.fromhex(wrapped_envelope)
            result = await vault._call_rpc(
                "clear_prev_hmac_if_envelope", {"wrapped_key": wrapped.hex()}
            )
            return result == "cleared"
        except Exception:
            _log.warning("conditional custodian prev_hmac clear failed", exc_info=True)
            return False
    return vault.clear_prev_hmac_if_generation(local_generation)


# --- plaintext-transport warning -------------------------------------------
# A bearer token authenticating over plain HTTP means the token AND the secret
# values it is about to fetch cross the wire unencrypted. Detected server-side
# so it covers EVERY client -- the Rust agents, the CLI, the MCP server and
# hub, the node SDK, the Go providers, and bare curl -- instead of only the
# ones we ship code for.
#
# Loopback is exempt: the API listens plaintext on :8200 by design (nginx
# terminates TLS on :8443), so same-host traffic has no network to sniff.
#
# Deduplicated per (ip, actor) with a bounded, TTL-pruned dict: an agent
# polling every 30s must not flood the log, and the dict must not grow without
# limit under many distinct sources.
_PLAINTEXT_WARN_TTL = 3600.0
_PLAINTEXT_WARN_MAX = 512
_plaintext_warned: dict[str, float] = {}


def _is_loopback(ip: str) -> bool:
    return ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127.")


def warn_if_plaintext_transport(request: Request, client_ip: str, actor: str) -> None:
    """Log a warning on EVERY authenticated call that arrives without TLS.

    No loopback exemption: this is a vault. Same-host plaintext is still
    readable by any process with CAP_NET_RAW, and "same host" inside a pod
    means a sibling container. A CLI call on the vault host carries the root
    token over exactly that hop. The message distinguishes the two cases so
    an operator can triage, but both are reported.
    """
    # TLS can terminate in two supported places, so check both:
    #  1. the API itself (uvicorn --ssl-keyfile), where ASGI reports
    #     scope["scheme"] == "https" and there is no proxy header at all;
    #  2. an nginx/reverse-proxy front, which leaves the scheme http on the
    #     loopback hop and signals TLS with X-Forwarded-Proto (both frontend
    #     configs set it).
    # Checking only the header would have warned falsely on every HA node
    # terminating TLS at uvicorn, which ha_boot_check explicitly supports.
    if request.url.scheme == "https":
        return
    proto = request.headers.get("x-forwarded-proto", "").strip().lower()
    if proto == "https":
        return

    now = time.monotonic()
    key = f"{client_ip}|{actor}"
    last = _plaintext_warned.get(key)
    if last is not None and now - last < _PLAINTEXT_WARN_TTL:
        return

    if len(_plaintext_warned) >= _PLAINTEXT_WARN_MAX:
        for k, t in list(_plaintext_warned.items()):
            if now - t > _PLAINTEXT_WARN_TTL:
                del _plaintext_warned[k]
        if len(_plaintext_warned) >= _PLAINTEXT_WARN_MAX:
            _plaintext_warned.clear()
    _plaintext_warned[key] = now

    scope_note = (
        "same-host hop: still readable by any process on this host with "
        "CAP_NET_RAW, and by a neighbouring container in the same pod"
        if _is_loopback(client_ip)
        else "this crossed the network"
    )
    _log.warning(
        "PLAINTEXT TRANSPORT: token '%s' authenticated from %s over plain "
        "HTTP (%s). The bearer token and every secret value it reads are "
        "unencrypted, and the post-quantum TLS the stack supports "
        "(X25519MLKEM768) is NOT in use on this hop. Point this client at the "
        "TLS endpoint (nginx, :8443 by default). Suppressing repeats for this "
        "source for %ds.",
        actor,
        client_ip,
        scope_note,
        int(_PLAINTEXT_WARN_TTL),
    )


async def require_vault_token(
    request: Request,
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Validate Bearer token, return token record with permissions."""
    vault.require_unsealed()

    client_ip = get_client_ip(request)
    await check_rate_limit(db, client_ip)

    from . import metrics as _m

    if authorization is None or not authorization.startswith("Bearer "):
        await record_failure(db, client_ip)
        log_authfail(client_ip, "invalid_header")
        _m.record_auth_failure("missing")
        raise HTTPException(401, "Invalid authorization header")

    token = authorization[7:]
    if _TOKEN_PATTERN.fullmatch(token) is None:
        await record_failure(db, client_ip)
        log_authfail(client_ip, "invalid_token_format")
        _m.record_auth_failure("invalid_token")
        raise HTTPException(401, "Invalid token format")

    # O(1) lookup: compute hash via Rust (hmac_key never crosses to Python)
    computed_hash = await vault.hmac_sha512_hex(token)
    result = await db.execute(
        text("""
            SELECT id, name, permissions, expires_at, allowed_ips, is_honey
            FROM vault_tokens
            WHERE token_hash = :hash AND active = true
        """),
        {"hash": computed_hash},
    )
    row = result.fetchone()

    # Lazy migration: try previous hmac_key after password rotation
    migrated = False
    old_hash = await vault.hmac_sha512_hex_prev(token) if not row else None
    if old_hash is not None:
        result = await db.execute(
            text("""
                SELECT id, name, permissions, expires_at, allowed_ips, is_honey
                FROM vault_tokens
                WHERE token_hash = :hash AND active = true
                  AND EXISTS (
                      SELECT 1 FROM vault_config
                      WHERE key = 'prev_hmac_key'
                  )
            """),
            {"hash": old_hash},
        )
        row = result.fetchone()
        if row:
            # Re-hash with current key, one-time migration per token
            migration = await db.execute(
                text("""
                    UPDATE vault_tokens
                    SET token_hash = :new_hash
                    WHERE id = CAST(:id AS uuid)
                      AND active = true
                      AND token_hash IN (:old_hash, :new_hash)
                    RETURNING id
                """),
                {
                    "new_hash": computed_hash,
                    "old_hash": old_hash,
                    "id": str(row.id),
                },
            )
            if migration.fetchone() is None:
                row = None
            else:
                migrated = True

    if row is None:
        await record_failure(db, client_ip)
        log_authfail(client_ip, "invalid_token")
        _m.record_auth_failure("invalid_token")
        raise HTTPException(401, "Invalid token")

    # Check expiry
    if row.expires_at is not None:
        from datetime import datetime, timezone

        if datetime.now(timezone.utc) >= row.expires_at:
            await record_failure(db, client_ip)
            log_authfail(client_ip, "token_expired")
            _m.record_auth_failure("revoked")
            raise HTTPException(401, "Token expired")

    # Per-token IP allowlist (NULL/empty = unrestricted, default).
    # Failure here is treated like a scope failure: counted in metrics but
    # NOT in rate-limit (a legitimate token from a wrong IP shouldn't
    # accelerate brute-force lockout for that IP).
    if row.allowed_ips and not ip_in_allowlist(client_ip, row.allowed_ips):
        log_authfail(client_ip, "token_ip_not_allowed")
        _m.record_auth_failure("ip_not_allowed")
        raise HTTPException(403, "Token not allowed from this IP")

    # The token is valid and secrets are about to flow. If this arrived without
    # TLS, say so loudly -- server-side, so it covers every client.
    warn_if_plaintext_transport(request, client_ip, row.name)

    # Side-effects of auth must persist regardless of whether the endpoint
    # commits (most GET endpoints don't): UPDATE last_used_at, lazy-migration
    # rehash, prev_hmac_key cleanup. Commit on the middleware's session.
    # Debounce: skip the UPDATE if last_used_at is fresh (< 60s). Removes
    # the row-lock storm when a hot token serves 1000+ req/s. NULL case
    # is preserved so lazy-migration completion check still works.
    await db.execute(
        text(
            "UPDATE vault_tokens SET last_used_at = NOW() "
            "WHERE id = CAST(:id AS uuid) "
            "AND active = true "
            "AND token_hash = :hash "
            "AND (last_used_at IS NULL "
            "OR last_used_at < NOW() - INTERVAL '60 seconds')"
        ),
        {"id": str(row.id), "hash": computed_hash},
    )

    # After migration: check if all active tokens are migrated (last_used_at != NULL)
    # If so, remove the paired previous-HMAC state. Keep the encrypted in-memory
    # key until the transaction commits: a rollback must leave DB and RAM aligned.
    clear_prev_hmac_after_commit = False
    clear_prev_hmac_envelope = None
    prev_hmac_generation = vault.prev_hmac_generation
    if migrated and vault.has_prev_hmac:
        cleanup_lock = await db.execute(
            text(
                "SELECT pg_try_advisory_xact_lock("
                "hashtext('rhorizon:cluster:rotate_password'))"
            )
        )
        if cleanup_lock.scalar():
            remaining = await db.execute(
                text(
                    "SELECT count(*) FROM vault_tokens "
                    "WHERE active = true AND last_used_at IS NULL"
                )
            )
            if remaining.scalar() == 0:
                envelope_row = (
                    await db.execute(
                        text(
                            "SELECT value FROM vault_config "
                            "WHERE key = 'prev_hmac_key' FOR UPDATE"
                        )
                    )
                ).fetchone()
                clear_prev_hmac_envelope = (
                    envelope_row.value if envelope_row is not None else None
                )
                await db.execute(
                    text(
                        "DELETE FROM vault_config "
                        "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
                    )
                )
                clear_prev_hmac_after_commit = True

    await db.commit()
    if clear_prev_hmac_after_commit:
        await clear_prev_hmac_if_observed(
            prev_hmac_generation, clear_prev_hmac_envelope
        )

    # Honeytoken IDS, fire alert if a decoy token was used to authenticate.
    # Response is unchanged so the attacker doesn't know we noticed.
    # Audit persistence is guaranteed by alert_honey_access (dedicated session).
    if row.is_honey:
        from .honey import alert_honey_access

        await alert_honey_access(
            kind="token",
            name=row.name,
            request=request,
            actor=row.name,
        )

    return {
        "id": str(row.id),
        "name": row.name,
        "permissions": row.permissions,
    }


def require_permission(scope: str, mode: str = "r"):
    """Factory: returns a dependency that checks scope+mode on the token."""
    if mode not in {"r", "w", "rw"}:
        raise ValueError("permission mode must be 'r', 'w', or 'rw'")
    required = set(mode)

    async def _check(token_info: dict = Depends(require_vault_token)) -> dict:
        from . import metrics as _m

        perms = token_info.get("permissions")
        if not isinstance(perms, dict):
            perms = {}
        # Effective grant for this scope = the explicit scope grant unioned
        # with the admin grant (admin applies to every scope). Modes are
        # encoded as substrings of "rw" ("r", "w", "rw"); set membership
        # makes the check honor the mode. So admin:r grants only "r" on
        # every scope (read-only admin for monitoring), and a write-only
        # scope grants only "w" and cannot satisfy a read dependency.
        # Previously the bare presence of "admin" short-circuited to full
        # access (admin:r passed admin:w) and the only reject path was the
        # exact (mode=="w", allowed=="r") case (secrets:w passed a read).
        granted = _permission_bits(perms.get(scope)) | _permission_bits(
            perms.get("admin")
        )
        if not granted:
            _m.record_auth_failure("scope")
            raise HTTPException(403, f"Missing scope: {scope}")
        if not required.issubset(granted):
            _m.record_auth_failure("scope")
            raise HTTPException(403, f"{mode.upper()} access denied for scope: {scope}")
        return token_info

    return _check


def namespace_claim(token_info: dict) -> list[str] | None:
    """Return a validated namespace claim; only an absent key is unrestricted."""
    perms = token_info.get("permissions", {})
    if not isinstance(perms, dict):
        return []
    if "namespaces" not in perms:
        return None
    claim = perms["namespaces"]
    if not isinstance(claim, list):
        return []
    return [entry for entry in claim if isinstance(entry, str)]


def check_namespace(token_info: dict, namespace: str) -> None:
    """Raise 403 when a present namespace claim does not allow the namespace."""
    allowed_ns = namespace_claim(token_info)
    if allowed_ns is None:
        return
    if namespace not in allowed_ns:
        from . import metrics as _m

        _m.record_auth_failure("namespace")
        raise HTTPException(403, f"Access denied for namespace: {namespace}")


# Auth-source prefixes used by LDAP (auth_ldap.py) and SSO proxy
# (auth_proxy.py) to namespace session token names. The prefix exists
# only so the same human can exist in both flows without colliding with
# the `vault_tokens.name UNIQUE` constraint. For audit display, the prefix
# is noise: `proxy:shdw` should appear as `shdw` so logs match the human
# identity known to the operator.
_AUTH_SOURCE_PREFIXES = ("ldap:", "proxy:")


def is_reserved_token_name(name: str) -> bool:
    """True if `name` claims an auth-source prefix (ldap:/proxy:).

    These prefixes are security-significant: is_external_session() selects
    source-qualified external-identity RBAC, while actor_display_name() strips the
    prefix only for audit display. Only LDAP / SSO-proxy flows may mint such
    names. A user-supplied native token carrying one must be refused, else a
    tokens:w holder could forge an external principal and its audit attribution.
    """
    return any((name or "").startswith(p) for p in _AUTH_SOURCE_PREFIXES)


def actor_display_name(token_info: dict) -> str:
    """Human-readable actor name, suitable for the audit `actor` field.

    For SSO/LDAP session tokens (`name="proxy:shdw"` or `"ldap:shdw"`),
    strips the auth-source prefix so audit rows show the human's
    operator-known identity. For regular API tokens the `name` is
    freeform (e.g. `"ansible-prod-runner"`) and is returned unchanged. RBAC
    does not use this display value: native tokens use their stable UUID, while
    external sessions use their full source-qualified name.
    Empty / missing names fall back to an empty string - the caller
    is expected to never pass a malformed token_info dict here.
    """
    name = token_info.get("name") or ""
    for prefix in _AUTH_SOURCE_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def is_external_session(token_info: dict) -> bool:
    """True iff LDAP or the login proxy minted this bearer session token.

    Used to decide between two enforcement modes: human sessions get a
    LIVE typed membership lookup (`vault_group_members`) so removing an
    external identity from a group revokes access at next request. Native API
    tokens are separate RBAC principals keyed by `vault_tokens.id`.
    """
    name = token_info.get("name") or ""
    return any(name.startswith(p) for p in _AUTH_SOURCE_PREFIXES)


async def resolve_namespace_ids(db: AsyncSession, token_info: dict) -> set[str] | None:
    """Resolve `token.permissions.namespaces` (mix of names + UUIDs) to a
    set of UUIDs. None = no `namespaces` claim on the token = unrestricted.

    Backward-compat layer. Existing tokens stored their namespaces as
    strings (`["prod", "claude"]`). Newer tokens
    store UUIDs directly. This helper accepts both forms: names are
    looked up against `vault_namespaces.name`, unknown names are
    dropped (NOT 403) with a warning log. LDAP / proxy mappings may
    legitimately reference namespaces created in the future.
    """
    claim = namespace_claim(token_info)
    if claim is None:
        return None
    names: list[str] = []
    uuids: set[str] = set()
    for entry in claim:
        try:
            namespace_id = str(uuid.UUID(entry))
        except ValueError:
            names.append(entry)
        else:
            uuids.add(namespace_id)
    if names:
        rows = (
            await db.execute(
                text(
                    "SELECT id, name FROM vault_namespaces "
                    "WHERE name = ANY(:names) AND archived_at IS NULL"
                ),
                {"names": names},
            )
        ).fetchall()
        found = {r.name for r in rows}
        for r in rows:
            uuids.add(str(r.id))
        missing = set(names) - found
        if missing:
            import logging as _logging

            _logging.getLogger("rhorizon.auth").warning(
                "Token %r references unknown namespaces %s - dropped",
                token_info.get("name"),
                sorted(missing),
            )
    return uuids


async def resolve_namespace_names(
    db: AsyncSession, token_info: dict
) -> set[str] | None:
    """Resolve a token's `namespaces` claim (mix of names + UUIDs) to a set of
    namespace NAMES. None = no `namespaces` claim = unrestricted.

    Sibling of `resolve_namespace_ids`, for the LISTING endpoints. They filter
    on `vault_secrets.namespace` (the name), which is always set (NOT NULL) --
    unlike the nullable, backfill-dependent `namespace_id`. So names are the
    robust listing key: filtering on them never hides a secret whose
    `namespace_id` was never backfilled. UUID claim entries are looked up
    against `vault_namespaces.id`; an unknown UUID simply contributes no name.

    A claim that resolves to an empty set still means "restricted" -- callers
    must treat `set()` as "list nothing", and only `None` as "unrestricted",
    so a UUID-only claim for unknown namespaces never falls back to list-all.
    """
    claim = namespace_claim(token_info)
    if claim is None:
        return None
    claimed_names: set[str] = set()
    names: set[str] = set()
    uuids: list[str] = []
    for entry in claim:
        try:
            namespace_id = str(uuid.UUID(entry))
        except ValueError:
            claimed_names.add(entry)
        else:
            uuids.append(namespace_id)
    if claimed_names:
        rows = (
            await db.execute(
                text(
                    "SELECT name FROM vault_namespaces "
                    "WHERE name = ANY(:names) AND archived_at IS NULL"
                ),
                {"names": sorted(claimed_names)},
            )
        ).fetchall()
        names.update(r.name for r in rows)
    if uuids:
        rows = (
            await db.execute(
                text(
                    "SELECT name FROM vault_namespaces "
                    "WHERE id = ANY(CAST(:ids AS uuid[])) "
                    "AND archived_at IS NULL"
                ),
                {"ids": uuids},
            )
        ).fetchall()
        for r in rows:
            names.add(r.name)
    return names


async def check_namespace_membership(
    db: AsyncSession,
    token_info: dict[str, object],
    namespace_id: str,
    *,
    write: bool = True,
) -> Row[Any]:
    """Authorize access to a specific namespace by UUID.

    Three-mode decision tree:
        1. Look up the namespace row. If archived -> 404. If not found -> 404.
        2. If `enforce_membership=false` (agnostic):
            - admin scope without a `namespaces` claim bypasses unconditionally.
            - otherwise the token's claim must include this namespace's UUID
              (or its name, via `resolve_namespace_ids`).
        3. If `enforce_membership=true` (RBAC strict):
            - admin scope is the operator escape hatch - bypasses but is
              audited as `admin_bypass_namespace_rbac`. Reserved for break-glass
              operations, not normal traffic.
            - otherwise (including human sessions with an admin claim):
              the typed external/token principal must be in `vault_group_members`
              for `owner_group_id`.

    The check applies on both reads and writes when `enforce_membership=true`,
    and only on writes (caller's choice) when agnostic. The `write=` flag is
    informational for audit - the actual authorization model doesn't differ
    between reads and writes today, but logging it lets us tighten later.

    Raises HTTPException with appropriate status codes; on success returns
    the namespace row (id, name, owner_group_id, enforce_membership,
    delete_protection, archived_at) which callers can reuse.
    """
    from . import metrics as _m

    ns = (
        await db.execute(
            text(
                "SELECT id, name, owner_group_id, enforce_membership, "
                "       delete_protection, archived_at "
                "FROM vault_namespaces "
                "WHERE id = CAST(:nid AS uuid)"
            ),
            {"nid": namespace_id},
        )
    ).fetchone()
    if ns is None:
        _m.record_auth_failure("namespace")
        raise HTTPException(404, "Namespace not found")
    if ns.archived_at is not None:
        _m.record_auth_failure("namespace")
        raise HTTPException(404, "Namespace is archived")

    perms = token_info.get("permissions")
    if not isinstance(perms, dict):
        perms = {}
    admin_value = perms.get("admin")
    admin_granted = _permission_bits(admin_value)
    has_admin = ("w" if write else "r") in admin_granted
    claim = namespace_claim(token_info)
    has_namespace_claim = claim is not None
    claimed_uuids = None
    if has_namespace_claim:
        claimed_uuids = await resolve_namespace_ids(db, token_info)
        if str(ns.id) not in (claimed_uuids or set()):
            _m.record_auth_failure("namespace")
            raise HTTPException(403, f"Access denied for namespace: {ns.name}")

    # Agnostic mode : the existing model.
    if not ns.enforce_membership:
        if has_admin and not has_namespace_claim:
            return ns
        if not has_namespace_claim:
            _m.record_auth_failure("namespace")
            raise HTTPException(403, f"Access denied for namespace: {ns.name}")
        return ns

    # Strict mode: live membership check, even for admin/claim holders
    # who happen to be human sessions (they may have been removed from
    # the owner group between mint time and now). A non-human admin token
    # remains the explicit, audited break-glass path.
    if has_admin and not is_external_session(token_info):
        # Loud audit on operator escape hatch.
        try:
            from .audit import log_action as _log
            from .database import async_session

            async with async_session() as audit_db:
                await _log(
                    audit_db,
                    actor=actor_display_name(token_info),
                    action="admin_bypass_namespace_rbac",
                    target=ns.name,
                    detail={"namespace_id": str(ns.id), "write": write},
                )
                await audit_db.commit()
        except Exception:
            # Never fail authz on audit write failure, but a break-glass
            # bypass must not vanish silently -- record it at CRITICAL.
            import logging as _logging

            _logging.getLogger("rhorizon.auth").critical(
                "admin_bypass_namespace_rbac AUDIT WRITE FAILED "
                "(bypass still granted): actor=%r namespace=%r",
                actor_display_name(token_info),
                ns.name,
                exc_info=True,
            )
        return ns

    # A strict namespace with no owner group denies every principal without
    # the native-admin break-glass permission. Surface the misconfiguration
    # instead of a misleading "not a member" response.
    if ns.owner_group_id is None:
        import logging as _logging

        _logging.getLogger("rhorizon.auth").error(
            "namespace %r has enforce_membership=true but no owner_group_id; "
            "all non-admin access denied (misconfiguration)",
            ns.name,
        )
        _m.record_auth_failure("namespace")
        raise HTTPException(403, f"Namespace '{ns.name}' has no owner group configured")

    if is_external_session(token_info):
        membership_sql = (
            "SELECT 1 FROM vault_group_members "
            "WHERE group_id = :gid AND principal_type = 'external' "
            "AND external_id = :principal"
        )
        principal = token_info.get("name")
    else:
        membership_sql = (
            "SELECT 1 FROM vault_group_members "
            "WHERE group_id = :gid AND principal_type = 'token' "
            "AND token_id = CAST(:principal AS uuid)"
        )
        principal = token_info.get("id")
        if not principal:
            _m.record_auth_failure("namespace")
            raise HTTPException(403, "Authenticated token has no stable principal ID")

    membership = (
        await db.execute(
            text(membership_sql),
            {"gid": str(ns.owner_group_id), "principal": principal},
        )
    ).fetchone()
    if membership is None:
        _m.record_auth_failure("namespace")
        raise HTTPException(
            403,
            f"Access denied for namespace '{ns.name}': "
            "actor is not a member of the owner group",
        )
    return ns
