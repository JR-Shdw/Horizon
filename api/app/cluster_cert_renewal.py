# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Per-node cluster cert renewal loop.

Each cluster member runs one background task that checks at startup and then
periodically checks its own on-disk cert against two trigger conditions :

1. ``cert_not_after - NOW < cluster_cert_renewal_threshold_days``
   (default 30 days remaining) -- the natural threshold-based renewal,
   modelled on Let's Encrypt's 60-day-renewal pattern for 90-day
   certs.
2. ``force_renew_at IS NOT NULL AND force_renew_at <= NOW()`` --
   admin-triggered force renewal (POST /cluster/rotate-cert flips the
   row; the CA rotation broadcast reuses the same primitive).

When either fires, the loop opens an httpx client that presents the
on-disk cert + key as a TLS client cert and POSTs to
``{ha_primary_url}/api/v1/vault/cluster/refresh-cert``. The server
side authenticates via :mod:`api.app.cluster_mtls`, mints a fresh
cert for the same node_uuid, updates the membership table (clears
force_renew_at on the same row), and returns the new
``(node_cert_pem, node_cert_key_pem)`` pair over the already
mTLS-protected channel. The client persists the new pair atomically
via :func:`cluster_cert.save_cluster_cert`.

Loop placement : **per-node**, NOT cluster-wide singleton. Each
node renews its own cert ; the renewal is local data with no
cross-node coordination requirement. Sealed -> skip tick. No cert
on disk -> skip tick (the auto-JOIN flow handles the bootstrap side,
and a node without a cert has nothing to renew).
"""

import asyncio
import fcntl
import logging
import os
import ssl
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from . import cluster_ca, cluster_cert, nginx_reload
from . import metrics as _metrics
from .config import settings
from .database import async_session
from .node_uuid import get_node_uuid
from .vault_state import vault as vs

log = logging.getLogger("rhorizon.cluster_cert_renewal")

# Process-local wake-up for changes that require a prompt certificate refresh
# (for example reconciling a legacy advertised IP). Every API worker owns both
# a heartbeat and renewal task, so the worker that commits the change can wake
# its own renewal loop without polling PostgreSQL aggressively.
_renewal_wake = asyncio.Event()


# httpx timeout shape -- the refresh round-trip is a single short
# request, 10s connect + 30s read is generous. A wedged primary
# cannot stall the loop indefinitely.
_HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _now_utc() -> datetime:
    """Wrapper for ``datetime.now(timezone.utc)``, used for unit tests."""
    return datetime.now(timezone.utc)


def request_renewal() -> None:
    """Wake the local renewal loop before its normal long expiry poll."""
    _renewal_wake.set()


async def _needs_force_renew(db: AsyncSession, node_uuid: str) -> bool:
    """True iff the row for ``node_uuid`` has a pending force_renew_at.

    Read directly from the membership table -- no in-process cache.
    The route /cluster/rotate-cert writes from a different worker, so
    a stale cache would miss the trigger entirely. Per-tick DB read
    is cheap (single-row PK lookup on a small table).
    """
    from sqlalchemy import text

    row = (
        await db.execute(
            text("SELECT force_renew_at FROM vault_cluster_nodes WHERE node_uuid = :u"),
            {"u": node_uuid},
        )
    ).fetchone()
    if row is None or row.force_renew_at is None:
        return False
    # row.force_renew_at is tz-aware (TIMESTAMPTZ) ; compare directly.
    return row.force_renew_at <= _now_utc()


def _needs_threshold_renew(cert_pem: bytes) -> bool:
    """True iff the on-disk cert's NotAfter is within the renewal window.

    Window = ``settings.cluster_cert_renewal_threshold_days``. A cert
    that already expired returns True too (over-due renewal is still
    a renewal). A cert with a parse error raises ; the caller treats
    the corruption as a separate failure mode.
    """
    not_after = cluster_cert.cert_not_after(cert_pem)
    threshold_days = settings.cluster_cert_renewal_threshold_days
    return (not_after - _now_utc()).total_seconds() < threshold_days * 86400


async def _post_refresh(
    cert_path: str, key_path: str
) -> tuple[bytes, bytes, bytes, bytes]:
    """POST /cluster/refresh-cert using the on-disk pair as client cert.

    The cluster member authenticates via mTLS: httpx with an
    SSLContext (``load_cert_chain``) presents the pair.
    Nginx terminates and forwards X-Client-Cert ; the server-side
    dependency :func:`cluster_mtls.require_cluster_member_cert`
    re-verifies + maps to a membership identity.

    Returns ``(new_node_cert_pem, new_node_key_pem, new_server_cert_pem,
    new_server_key_pem)``. The server cert pair is empty when the
    primary has no server cert -- the caller treats that as "skip the
    nginx persist step", not as a failure. Raises :class:`RuntimeError`
    on any transport / non-200 failure.
    """
    base = settings.ha_primary_url.rstrip("/")
    if not base:
        raise RuntimeError("ha_primary_url is not configured")
    url = base + "/api/v1/vault/cluster/refresh-cert"
    # mTLS client cert via an explicit SSLContext (httpx deprecated `cert=`).
    # Server verification stays at the default system trust store; pinning the
    # primary to the cluster CA would be deployment policy, not done here.
    ctx = ssl.create_default_context()
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, verify=ctx) as client:
        try:
            r = await client.post(url, json={})
        except httpx.HTTPError as exc:
            raise RuntimeError(f"refresh-cert transport error: {exc}") from exc
    if r.status_code != 200:
        raise RuntimeError(f"refresh-cert HTTP {r.status_code}: {r.text}")
    body = r.json()
    cert_pem = body.get("node_cert_pem", "").encode("ascii")
    key_pem = body.get("node_cert_key_pem", "").encode("ascii")
    if not cert_pem or not key_pem:
        raise RuntimeError("refresh-cert response missing cert/key fields")
    # Server cert is optional during a version cross-over.
    server_cert_pem = body.get("server_cert_pem", "").encode("ascii")
    server_key_pem = body.get("server_cert_key_pem", "").encode("ascii")
    return cert_pem, key_pem, server_cert_pem, server_key_pem


async def _assert_issued_by_cluster_ca(
    node_cert_pem: bytes, server_cert_pem: bytes | None
) -> None:
    """Refuse a refreshed cert not signed by the cluster CA we already know.

    Server-side TLS auth of the primary is deployment policy (public cert vs
    cluster-CA cert), so we do not pin it here; instead we verify the returned
    identity against the CA cert in the shared DB. Accepts the current CA or, in
    a rotation grace window, the previous one. Raises ``RuntimeError`` otherwise
    (the caller maps it to a "fail" tick + retry).
    """
    async with async_session() as db:
        ca_pem = await cluster_ca.load_cluster_ca_cert(db)
        prev_pem = await cluster_ca.load_cluster_ca_prev_cert(db)
    if ca_pem is None:
        raise RuntimeError("cluster CA cert absent -- cannot verify refreshed cert")
    cas = [ca_pem] + ([prev_pem] if prev_pem else [])
    for cert in (node_cert_pem, server_cert_pem):
        if not cert:
            continue
        if not any(cluster_ca.verify_signed_by_ca(cert, ca) for ca in cas):
            raise RuntimeError("refreshed cert not signed by the known cluster CA")


def _renewal_lock_path() -> Path:
    """Host-local lock next to the node cert on the container volume."""
    return Path(settings.cluster_cert_path).parent / ".cert-renewal.lock"


@contextmanager
def _host_renewal_lock():
    """Non-blocking flock: only one of the N container workers renews.

    Without it they all fire redundant refreshes/writes/reloads (and N-1
    bogus fail metrics). Released on fd close / death. True=holder, else skip.
    """
    path = _renewal_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


async def renew_once() -> str:
    """One tick of the renewal flow. Returns the outcome label.

    Outcomes :

    - ``"skipped_sealed"`` -- vault sealed, no DB access available.
    - ``"skipped_no_cert"`` -- no cert on disk (auto-JOIN not done
      yet, or evict-self has been called).
    - ``"skipped_locked"`` -- a sibling worker holds the renewal lock.
    - ``"skipped_not_needed"`` -- cert valid + no force_renew flag.
    - ``"success"`` -- refresh + persist completed.
    - ``"fail"`` -- refresh attempt errored. Logged + counter bumped,
      next tick retries.

    Counter ``cluster_cert_refreshes_total{outcome}`` mirrors the
    outcome labels (one entry per refresh attempt).
    """
    if vs.sealed:
        return "skipped_sealed"

    cert_path = settings.cluster_cert_path
    key_path = settings.cluster_cert_key_path
    pair = cluster_cert.load_cluster_cert(cert_path, key_path)
    if pair is None:
        return "skipped_no_cert"

    with _host_renewal_lock() as acquired:
        if not acquired:
            return "skipped_locked"
        return await _renew_locked(pair, cert_path, key_path)


async def _renew_locked(
    pair: tuple[bytes, bytes], cert_path: str, key_path: str
) -> str:
    cert_pem, _key_pem = pair
    node_uuid = get_node_uuid()
    try:
        async with async_session() as db:
            force = await _needs_force_renew(db, node_uuid)
    except Exception:
        log.warning("cluster_cert_renewal: force_renew check failed", exc_info=True)
        force = False

    threshold = _needs_threshold_renew(cert_pem)

    # The server cert lives alongside the node cert on disk.
    # We piggy-back its renewal on the same trigger flags -- the
    # cluster CA signs both, the renewal threshold is the same, and
    # the renewal round-trip already returns both pairs. Two paths
    # would mean two HTTP calls + two reload windows.
    server_threshold = _server_cert_needs_renew(settings.cluster_server_cert_path)

    if not (force or threshold or server_threshold):
        return "skipped_not_needed"

    log.info(
        "cluster_cert_renewal: refresh triggered "
        "(force=%s node_threshold=%s server_threshold=%s uuid=%s)",
        force,
        threshold,
        server_threshold,
        node_uuid,
    )

    try:
        (
            new_cert_pem,
            new_key_pem,
            new_server_cert_pem,
            new_server_key_pem,
        ) = await _post_refresh(cert_path, key_path)
        await _assert_issued_by_cluster_ca(new_cert_pem, new_server_cert_pem or None)
        cluster_cert.save_cluster_cert(new_cert_pem, new_key_pem, cert_path, key_path)
        if new_server_cert_pem and new_server_key_pem:
            nginx_reload.save_server_cert(
                new_server_cert_pem,
                new_server_key_pem,
                settings.cluster_server_cert_path,
                settings.cluster_server_cert_key_path,
            )
            nginx_reload.reload_nginx(settings.cluster_nginx_reload_cmd)
    except Exception:
        log.warning(
            "cluster_cert_renewal: refresh failed for uuid=%s",
            node_uuid,
            exc_info=True,
        )
        _metrics.cluster_cert_refreshes.labels(outcome="fail").inc()
        return "fail"

    _metrics.cluster_cert_refreshes.labels(outcome="success").inc()
    log.info(
        "cluster_cert_renewal: refreshed cert for uuid=%s (trigger=%s)",
        node_uuid,
        "force" if force else "threshold",
    )
    return "success"


def _server_cert_needs_renew(server_cert_path: str) -> bool:
    """True iff the on-disk nginx server cert should be replaced.

    Two triggers, not one:

    1. Still self-signed -- the boot-time placeholder from the
       nginx-frontend role. Only the primary gets a CA-signed cert from
       ``bootstrap-init.yml`` (step 3b is ``hosts: rhorizon_primary``), so
       for every joiner this loop is the *only* path to a real cert.
    2. Within the renewal window of its expiry.

    Trigger 1 exists because expiry alone silently fails closed the wrong
    way: the placeholder is valid for 10 years, so ``not_after - now`` is
    never inside the threshold and a joiner kept a self-signed cert
    indefinitely. nginx served it happily, and the cluster mTLS it was
    supposed to anchor validated against nothing. Observed on a lab
    cluster where two of three nodes had run for months that way.

    Returns False if the file is absent (no server cert to renew yet --
    typically a primary that has not run the bootstrap hot-swap, or a
    joiner that joined against a primary without a server cert). The
    renewal threshold reuses ``cluster_cert_renewal_threshold_days`` --
    one knob, one mental model, since the validity floors are identical.
    """
    p = Path(server_cert_path)
    if not p.is_file():
        return False
    try:
        pem = p.read_bytes()
        if cluster_cert.cert_is_self_signed(pem):
            log.info(
                "cluster_cert_renewal: server cert at %s is self-signed, renewing",
                server_cert_path,
            )
            return True
        not_after = cluster_cert.cert_not_after(pem)
    except Exception:
        log.warning(
            "cluster_cert_renewal: server cert at %s failed to parse, forcing renew",
            server_cert_path,
            exc_info=True,
        )
        return True
    threshold_days = settings.cluster_cert_renewal_threshold_days
    return (not_after - _now_utc()).total_seconds() < threshold_days * 86400


async def cluster_cert_renewal_loop():  # pragma: no cover  (daemon loop)
    """Per-node renewal loop. Started from the lifespan when HA is on."""
    interval = settings.cluster_cert_renewal_poll_secs
    first_check = True
    while True:
        if first_check:
            # Recover pending admin/CA/address rotations immediately after a
            # restart instead of extending them by the normal 12-hour poll.
            first_check = False
        else:
            try:
                await asyncio.wait_for(_renewal_wake.wait(), timeout=interval)
            except TimeoutError:
                pass
            else:
                # Clear before renewing. A request arriving during renew_once
                # stays set and causes another pass instead of being lost.
                _renewal_wake.clear()
        try:
            outcome = await renew_once()
        except Exception:
            log.warning("cluster_cert_renewal_loop tick error", exc_info=True)
            continue
        if outcome in {"skipped_sealed", "skipped_no_cert"}:
            # Startup commonly precedes unseal and auto-JOIN. Do not turn that
            # normal ordering into a 12-hour delay before the first usable
            # certificate check; retry cheaply until key/cert state exists.
            await asyncio.sleep(min(interval, 5))
            first_check = True
