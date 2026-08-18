# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Auto-JOIN background task.

At container boot, if this node is configured as an HA secondary that
has never joined the cluster (no on-disk ``cluster-cert.pem``), this
task drives the JOIN flow against ``ha_primary_url`` with no operator
ceremony beyond providing :

- ``RHORIZON_HA_PASSWORD_FILE`` -- path to a tmpfs file (mode 0400)
  holding the cluster ha_password (32+ bytes) ;
- ``RHORIZON_HA_PRIMARY_URL`` -- base URL of any already-initialised
  cluster member (the primary, or any secondary -- /cluster/challenge
  and /cluster/join are served by every cluster member).

Lifecycle (one shot, not a recurring loop) :

1. Wait for ``vault.sealed`` to flip to ``False`` (operator-driven
   /unseal). The auto-JOIN cannot start before unseal because the
   server-side ``vault.ha_password_hmac`` plus the cluster primary's
   HMAC verification both require an unsealed vault.
2. Check the gating conditions (``cluster_ha_enabled``,
   ``ha_auto_join``, ``ha_primary_url``, ``ha_password_file`` file
   present, no on-disk cluster cert yet).
3. POST /cluster/challenge against the primary to get a nonce +
   ``observed_source_ip`` echo.
4. Compute HMAC-SHA512(ha_password, canonical_message) client-side
   (pure Python -- the joiner has the plaintext briefly in RAM).
5. POST /cluster/join with the proof + node_uuid.
6. Unwrap the returned private key via
   :func:`ha_password.unwrap_node_key_for_joiner`.
7. Persist cert + key to ``cluster_cert_path`` / ``cluster_cert_key_path``
   (mode 0400, atomic).
8. Log success ; the operator can now unlink the ha_password file.

Failure handling : up to ``ha_auto_join_max_attempts`` retries with
``ha_auto_join_retry_secs`` backoff between attempts. After exhausting
retries, the task exits without raising.

Scope: initial JOIN only -- the task returns early if a cert is already
persisted. No retry on permanent 4xx errors (401 bad password, 403
revoked uuid, 409 cluster version mismatch); those need operator
intervention.
"""

import asyncio
import hashlib
import hmac
import logging
from pathlib import Path

import httpx

from . import cluster_cert, ha_bootstrap, ha_password, nginx_reload
from .config import settings
from .node_uuid import get_node_uuid
from .vault_state import vault

log = logging.getLogger("rhorizon.cluster_auto_join")

# httpx defaults are generous (none) ; clamp to a reasonable shape so a
# wedged primary cannot stall the boot path indefinitely. The JOIN flow
# is two short round-trips, 10s connect + 30s read total is plenty.
_HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# Permanent failures -- retrying does not help, surface once and exit.
# The operator must intervene (fix the ha_password, unrevoke the uuid,
# upgrade rhorizon, etc.).
#
# 409 is NOT blanket-permanent: a recoverable class exists where a
# previous /cluster/join landed the row server-side, the wire response
# was lost, the joiner retried, and the row had moved beyond 'joining'
# (typically to 'secondary' once the quarantine elapsed) so the
# refresh_joining_row path refused. 409s are discriminated at the call
# site (see _post_join + _attempt_join_once): a 409 with a cert on disk
# is success; a 409 against a row still in 'joining' is transient; a 409
# against a row beyond 'joining' with no cert on disk is the only
# permanent path (R1 recovery -- operator evict + unrevoke + restart).
_PERMANENT_STATUSES = (401, 403)


class AutoJoinError(RuntimeError):
    """Recoverable auto-JOIN failure -- caller decides whether to retry."""


class AutoJoinPermanentError(AutoJoinError):
    """Non-recoverable auto-JOIN failure -- exit the task without retrying."""


class AutoJoin409Error(AutoJoinError):
    """/cluster/join returned 409.

    Carries the raw server-side response body so the caller in
    :func:`_attempt_join_once` can pair it with a
    /cluster/ha/membership lookup and a cert-on-disk check before
    deciding between transient retry and permanent giveup. Subclass
    of :class:`AutoJoinError` so any caller that does not opt into the
    dedicated handling defaults to the recoverable retry path.
    """

    def __init__(self, body: str) -> None:
        super().__init__(f"join 409: {body}")
        self.body = body


def _should_attempt(check_cert: bool = True) -> tuple[bool, str]:
    """Decide whether the auto-JOIN task has anything to do.

    Returns ``(attempt, reason)``. When ``attempt`` is False, ``reason``
    is a short log line explaining why the task is a no-op (HA off,
    auto-JOIN disabled, no primary URL, no password file / age artifacts,
    cert already on disk).

    Dispatches on ``ha_password_storage`` : "file" uses the
    tmpfs path, "age_vault" uses the ciphertext + bootstrap
    token path. Cluster-cert-on-disk check stays LAST so the surface
    reason matches the invariant (operator sees a "storage
    artifact missing" reason before "cert already present").

    ``check_cert`` -- when False, the cluster-cert-on-disk gate is
    skipped. The task uses this at boot so a node that holds a cert but
    is NOT actually in cluster membership (evicted / half-joined / cert
    left over from a previous cluster after a DB wipe) is not silently
    parked forever; the task verifies membership post-unseal and clears a
    stale cert before re-checking the full gate.
    """
    if not settings.cluster_ha_enabled:
        return False, "cluster_ha_enabled=false"
    if not settings.ha_auto_join:
        return False, "ha_auto_join=false"
    if not settings.ha_primary_url:
        return False, "ha_primary_url not set"
    if settings.ha_password_storage == "age_vault":
        ok, reason = _should_attempt_age_vault()
    else:
        ok, reason = _should_attempt_file()
    if not ok:
        return False, reason
    if check_cert and cluster_cert.has_cluster_cert(
        settings.cluster_cert_path, settings.cluster_cert_key_path
    ):
        return False, "cluster-cert already on disk (REJOIN will use it)"
    return True, ""


async def _reconcile_stale_cert(node_uuid: str) -> None:
    """Clear an on-disk cluster cert that no longer corresponds to live
    membership, so the auto-JOIN gate stops parking this node.

    A cert on disk normally means "already a member, the rejoin/renewal
    path covers it". But an **evicted** node (e.g. its cluster-cert nginx
    reload failed, so the primary dropped it over mTLS), a **half-joined**
    node (cert persisted but the membership row never committed), or a
    node carrying a cert from a **previous cluster** after a DB wipe all
    hold a cert while being absent from ``/cluster/ha`` -- and the
    cert-on-disk gate would otherwise skip their auto-JOIN on every boot.

    Queries the public membership endpoint for this node_uuid. On a
    definitive 404 (unknown/evicted), removes the stale cert so the caller
    can JOIN fresh. On a transient lookup error, leaves the cert in place
    and lets the rejoin/renewal path try later (fail-safe: never discard a
    cert we cannot prove is stale).
    """
    if not cluster_cert.has_cluster_cert(
        settings.cluster_cert_path, settings.cluster_cert_key_path
    ):
        return
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        try:
            member = await _get_membership(client, node_uuid)
        except AutoJoinError as exc:
            log.warning(
                "cluster_auto_join: membership check failed (%s) -- keeping "
                "on-disk cert, deferring to rejoin/renewal path",
                exc,
            )
            return
    if member is not None:
        return  # genuine member; the cert is current
    log.warning(
        "cluster_auto_join: cert on disk but node_uuid=%s is absent from "
        "cluster membership (evicted / half-join / stale-cluster cert) -- "
        "removing the stale cert and re-joining",
        node_uuid,
    )
    cluster_cert.remove_cluster_cert(
        settings.cluster_cert_path, settings.cluster_cert_key_path
    )


def _should_attempt_file() -> tuple[bool, str]:
    """Gating : tmpfs ha_password_file."""
    if not settings.ha_password_file:
        return False, "ha_password_file not set"
    if not Path(settings.ha_password_file).is_file():
        return False, f"ha_password_file {settings.ha_password_file} not present"
    return True, ""


def _should_attempt_age_vault() -> tuple[bool, str]:
    """Gating : age ciphertext + bootstrap token + vault URL."""
    if not settings.ha_password_age_path:
        return False, "ha_password_age_path not set"
    if not Path(settings.ha_password_age_path).is_file():
        return False, (
            f"ha_password_age_path {settings.ha_password_age_path} not present"
        )
    if not settings.ha_bootstrap_token_file:
        return False, "ha_bootstrap_token_file not set"
    if not Path(settings.ha_bootstrap_token_file).is_file():
        return False, (
            f"ha_bootstrap_token_file {settings.ha_bootstrap_token_file} not present"
        )
    return True, ""


def _read_ha_password() -> bytes:
    """Read the ha_password plaintext from the tmpfs file.

    Validates length floor (``settings.ha_password_min_length``). The
    plaintext stays on the Python heap until the JOIN completes ; the
    caller is expected to overwrite the local reference once persisted
    (see :func:`_zero_bytes`).
    """
    p = Path(settings.ha_password_file)
    data = p.read_bytes()
    # Strip a trailing newline an operator might have added with `echo` -- but
    # ONLY when what remains is still a valid password.
    #
    # The wire format is raw bytes from secrets.token_bytes(), so 1 time in
    # 256 the last byte IS 0x0A. An unconditional strip ate that byte and left
    # 31, which trips the floor below and raises a PERMANENT error: that node
    # could never join. The automated path writes exactly these raw bytes with
    # no terminator (ansible add-joiner.yml b64decodes into the file), so the
    # unconditional strip was corrupting the real case to serve a hypothetical
    # hand-typed one.
    #
    # The length check disambiguates the two: a genuine `echo` file is one
    # byte longer than the password, so dropping its newline still satisfies
    # the floor, while a raw password ending in 0x0A would fall below it and
    # is therefore kept whole. That reasoning holds exactly while the minted
    # length equals the floor (both 32). A password longer than the floor is
    # still ambiguous -- there is no way to tell raw-ending-in-0x0A from
    # text-plus-newline -- which is why the file should eventually carry
    # base64 instead of raw bytes.
    if data.endswith(b"\n") and len(data) - 1 >= settings.ha_password_min_length:
        data = data[:-1]
    if len(data) < settings.ha_password_min_length:
        raise AutoJoinPermanentError(
            f"ha_password_file at {p} is too short: {len(data)} bytes "
            f"(min {settings.ha_password_min_length})"
        )
    return data


def _zero_bytes(buf: bytes | bytearray) -> None:
    """Best-effort overwrite of a bytes/bytearray buffer.

    Python bytes are immutable so this only works on bytearray. The
    caller pre-promotes to bytearray when the buffer is reusable.
    """
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def _compute_proof(
    ha_password_plain: bytes,
    cluster_id: str,
    node_uuid: str,
    source_ip: str,
    nonce: str,
    issued_at_epoch_secs: int,
) -> str:
    """HMAC-SHA512(ha_password, canonical_message) -> hex.

    Mirror of :func:`vault.ha_password_hmac` server-side (Rust primitive).
    The canonical message is fixed by the /cluster/join
    handler -- any drift breaks the proof.
    """
    msg = (
        cluster_id.encode()
        + node_uuid.encode()
        + source_ip.encode()
        + nonce.encode()
        + str(issued_at_epoch_secs).encode()
    )
    return hmac.new(ha_password_plain, msg, hashlib.sha512).hexdigest()


async def _post_challenge(client: httpx.AsyncClient, node_uuid: str) -> dict:
    """POST /cluster/challenge against the configured primary URL.

    Returns the parsed JSON response. Raises
    :class:`AutoJoinPermanentError` on a permanent HTTP status (401,
    403, 409) and :class:`AutoJoinError` on any other failure.
    """
    url = settings.ha_primary_url.rstrip("/") + "/api/v1/vault/cluster/challenge"
    body = {"node_uuid": node_uuid, "rhorizon_version": settings.version}
    try:
        r = await client.post(url, json=body)
    except httpx.HTTPError as exc:
        raise AutoJoinError(f"challenge transport error: {exc}") from exc
    if r.status_code in _PERMANENT_STATUSES:
        raise AutoJoinPermanentError(f"challenge rejected ({r.status_code}): {r.text}")
    if r.status_code != 200:
        raise AutoJoinError(f"challenge unexpected {r.status_code}: {r.text}")
    return r.json()


async def _post_join(client: httpx.AsyncClient, body: dict) -> dict:
    """POST /cluster/join. Maps statuses to AutoJoin* exceptions.

    409 surfaces as a dedicated :class:`AutoJoin409Error` so the caller can
    pair it with a /cluster/ha/membership lookup and a cert-on-disk check
    before classifying transient (retry) vs permanent (operator R1).
    """
    url = settings.ha_primary_url.rstrip("/") + "/api/v1/vault/cluster/join"
    try:
        r = await client.post(url, json=body)
    except httpx.HTTPError as exc:
        raise AutoJoinError(f"join transport error: {exc}") from exc
    if r.status_code == 409:
        raise AutoJoin409Error(r.text)
    if r.status_code in _PERMANENT_STATUSES:
        raise AutoJoinPermanentError(f"join rejected ({r.status_code}): {r.text}")
    if r.status_code != 200:
        raise AutoJoinError(f"join unexpected {r.status_code}: {r.text}")
    return r.json()


async def _get_membership(client: httpx.AsyncClient, node_uuid: str) -> dict | None:
    """GET /cluster/ha/membership/<uuid> -- public-minimal lookup.

    The endpoint has no auth and no PII so the joiner can
    discriminate a 409 from /cluster/join without growing a bootstrap
    token surface. Returns the parsed payload on 200, ``None`` on 404
    (unknown uuid OR evicted -- the server hides which on purpose).
    Any other status raises :class:`AutoJoinError` so the caller
    treats it as a transient fault and retries the surrounding loop.
    """
    url = (
        settings.ha_primary_url.rstrip("/")
        + f"/api/v1/vault/cluster/ha/membership/{node_uuid}"
    )
    try:
        r = await client.get(url)
    except httpx.HTTPError as exc:
        raise AutoJoinError(f"membership lookup transport error: {exc}") from exc
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise AutoJoinError(f"membership lookup unexpected {r.status_code}: {r.text}")
    return r.json()


async def _attempt_join_once(node_uuid: str) -> bool:
    """One full JOIN attempt. Returns True on success, raises on failure.

    Composes : read ha_password -> challenge -> compute proof -> join ->
    unwrap key -> persist. The ha_password buffer is overwritten before
    return on the happy path ; the error paths leak briefly into GC
    (acceptable -- the file is unlinked by the operator
    after success regardless).

    When ``ha_password_storage == "age_vault"`` the plaintext is fetched via
    :mod:`ha_bootstrap` (HTTPS fetch + age decrypt) instead of read from the
    tmpfs file. The http client is
    opened upfront so the same connection pool can serve the
    ha-bootstrap fetch and the subsequent challenge / join calls.
    """
    async with httpx.AsyncClient(
        timeout=_HTTP_TIMEOUT,
        # No verify=False -- we expect TLS termination in front of
        # the primary's API. The CA bundle is the system default ;
        # an operator running self-signed primary TLS sets
        # SSL_CERT_FILE or REQUESTS_CA_BUNDLE in the env.
    ) as client:
        if settings.ha_password_storage == "age_vault":
            try:
                ha_pw = bytearray(
                    await ha_bootstrap.read_ha_password_from_vault(client)
                )
            except ha_bootstrap.HaBootstrapPermanentError as exc:
                raise AutoJoinPermanentError(str(exc)) from exc
            except ha_bootstrap.HaBootstrapError as exc:
                raise AutoJoinError(str(exc)) from exc
        else:
            ha_pw = bytearray(_read_ha_password())
        try:
            challenge = await _post_challenge(client, node_uuid)
            observed_source_ip = challenge.get("observed_source_ip")
            if not observed_source_ip:
                raise AutoJoinPermanentError(
                    "challenge response missing observed_source_ip "
                    "(legacy primary without per-node cert storage)"
                )
            issued_at_epoch = _parse_issued_at_epoch(challenge["issued_at"])

            # The challenge response carries cluster_id (ChallengeResponse
            # field); prefer the wire value, fall back to the
            # RHORIZON_HA_CLUSTER_ID env for primaries that predate it.
            cluster_id = challenge.get("cluster_id") or settings.ha_cluster_id
            if not cluster_id:
                raise AutoJoinPermanentError(
                    "cluster_id not returned by /cluster/challenge and "
                    "RHORIZON_HA_CLUSTER_ID env not set (older primary)."
                )

            proof_hex = _compute_proof(
                bytes(ha_pw),
                cluster_id,
                node_uuid,
                observed_source_ip,
                challenge["nonce"],
                issued_at_epoch,
            )
            join_body = {
                "cluster_id": cluster_id,
                "node_uuid": node_uuid,
                "nonce": challenge["nonce"],
                "ha_password_proof": proof_hex,
                "rhorizon_version": settings.version,
            }
            try:
                join_resp = await _post_join(client, join_body)
            except AutoJoin409Error as exc:
                # Discriminate the 409. Four sub-cases :
                # (a) cert already on disk -- a prior /cluster/join succeeded on
                #     the wire but the surrounding code (nginx_reload, cert save)
                #     raised after the cert write. Row integrated server-side
                #     (refresh_joining_row refused); we have everything. Exit happy.
                # (b) row ha_state='joining' -- our refresh_joining_row raced the
                #     state-machine flip; the next attempt's fresh nonce + UPDATE
                #     refreshes it. Transient, retry.
                # (c) row 'secondary'/'primary'/'draining' AND no cert on disk :
                #     the wrapped key is unrecoverable from this window. Operator R1
                #     is the only path forward (a JOIN-idempotency-cache closes this).
                # (d) 404 -- row absent server-side (reaper raced the JOIN?).
                #     Transient; the next attempt INSERTs fresh.
                membership = await _get_membership(client, node_uuid)
                have_cert = cluster_cert.has_cluster_cert(
                    settings.cluster_cert_path, settings.cluster_cert_key_path
                )
                if have_cert:
                    log.info(
                        "cluster_auto_join: 409 from /cluster/join but "
                        "cert already on disk -- treating as success "
                        "(membership=%s)",
                        membership,
                    )
                    return True
                if membership is None:
                    raise AutoJoinError(
                        "join 409 but membership 404 -- transient drift, retrying"
                    ) from exc
                state = membership.get("ha_state")
                if state == "joining":
                    raise AutoJoinError(
                        f"join 409 with membership ha_state='joining' "
                        f"(fpr={membership.get('cert_fingerprint', '')[:16]}) "
                        "-- retrying"
                    ) from exc
                raise AutoJoinPermanentError(
                    "join 409 + membership ha_state="
                    f"{state} + no cert on disk -- the wrapped key minted "
                    "by the original JOIN is unrecoverable. Operator "
                    f"recovery R1 : POST /cluster/evict/{node_uuid} + "
                    f"POST /cluster/unrevoke/{node_uuid} on the primary, "
                    "then restart the joiner. A future slice (O) will "
                    "cache JOIN payloads primary-side and eliminate this "
                    "path."
                ) from exc

            wrapped_hex = join_resp["node_cert_key_wrapped_hex"]
            cert_pem = join_resp["node_cert_pem"].encode()
            wrapped = bytes.fromhex(wrapped_hex)
            key_pem = ha_password.unwrap_node_key_for_joiner(
                wrapped, bytes(ha_pw), node_uuid
            )

            cluster_cert.save_cluster_cert(
                cert_pem,
                key_pem,
                settings.cluster_cert_path,
                settings.cluster_cert_key_path,
            )

            # Same flow for the nginx server cert. A primary that predates
            # the server-cert change won't populate the field; we log + skip
            # silently so a mixed-version cluster does not
            # block the JOIN. The renewal loop picks up the server cert
            # at the next refresh-cert tick once the primary upgrades.
            server_cert_str = join_resp.get("server_cert_pem")
            server_wrapped_hex = join_resp.get("server_cert_key_wrapped_hex")
            if server_cert_str and server_wrapped_hex:
                server_cert_pem = server_cert_str.encode()
                server_wrapped = bytes.fromhex(server_wrapped_hex)
                server_key_pem = ha_password.unwrap_server_key_for_joiner(
                    server_wrapped, bytes(ha_pw), node_uuid
                )
                nginx_reload.save_server_cert(
                    server_cert_pem,
                    server_key_pem,
                    settings.cluster_server_cert_path,
                    settings.cluster_server_cert_key_path,
                )
                nginx_reload.reload_nginx(settings.cluster_nginx_reload_cmd)
            else:
                log.info(
                    "cluster_auto_join: primary did not ship a server cert "
                    "(no stored cert yet) ; renewal loop will pick it up later"
                )

            # Unlink the age ciphertext + bootstrap token now that the
            # cluster cert is the long-lived credential. File-storage mode
            # keeps the legacy behavior: operator unlinks ha_password_file
            # manually.
            if settings.ha_password_storage == "age_vault":
                ha_bootstrap.cleanup_on_join_success()

            log.info(
                "cluster_auto_join: persisted cert (ha_state=%s primary=%s)",
                join_resp.get("ha_state"),
                join_resp.get("primary_uuid"),
            )
            return True
        finally:
            _zero_bytes(ha_pw)


def _parse_issued_at_epoch(iso: str) -> int:
    """Parse an ISO 8601 timestamp string and return epoch seconds (int).

    The /cluster/join handler reconstructs the canonical message using
    ``int(challenge_row.issued_at.timestamp())``. Asyncpg returns a
    ``datetime`` with microsecond precision ; ``int(...)`` truncates
    sub-second. We mirror exactly that semantics on the joiner side --
    parse the ISO string, drop sub-second, take epoch seconds.
    """
    from datetime import datetime

    # asyncpg surfaces tz-aware ISO 8601 ; Python 3.11+ handles
    # "+00:00" suffix natively.
    dt = datetime.fromisoformat(iso)
    return int(dt.timestamp())


async def cluster_auto_join_task() -> None:
    """Lifespan-launched background task driving the one-shot JOIN.

    Polls ``vault.sealed`` every 5 s ; once unsealed, runs the gating
    check then up to ``ha_auto_join_max_attempts`` JOIN attempts with
    ``ha_auto_join_retry_secs`` backoff between attempts. Exits silently
    on success, on permanent failure, or after exhausting retries.

    Cancellation-safe : an ``asyncio.CancelledError`` at any point in
    the loop propagates without leaving residue (the ha_password buffer
    is zeroed in a ``finally`` inside :func:`_attempt_join_once`).
    """
    # Step 0 : check the gating once, before the unseal wait. Avoids
    # holding a wakeup loop forever on a single-node deployment. We skip
    # the cert-on-disk gate here (check_cert=False): a cert on disk does
    # NOT mean "done" until we have confirmed membership post-unseal (an
    # evicted / half-joined / stale-cluster cert must trigger a re-JOIN,
    # not park the node forever).
    attempt, reason = _should_attempt(check_cert=False)
    if not attempt:
        log.info("cluster_auto_join: not running (%s)", reason)
        return

    # Step 1 : wait for unseal. 5s poll matches the heartbeat
    # cadence -- the joiner is in the same operational-time domain as
    # the rest of the cluster.
    while vault.sealed:
        await asyncio.sleep(5)

    node_uuid = get_node_uuid()

    # Step 2 : reconcile any on-disk cert against live membership. If a
    # cert is present but this node is absent from /cluster/ha (evicted,
    # half-join, or a cert left from a previous cluster after a DB wipe),
    # the stale cert is removed so the gate below lets us JOIN fresh. A
    # genuine member keeps its cert and we return.
    await _reconcile_stale_cert(node_uuid)

    # Step 3 : re-check the full gating (now including the cert) -- the
    # cert could have been provisioned by a parallel admin curl during the
    # unseal wait, or _reconcile_stale_cert just cleared a stale one.
    attempt, reason = _should_attempt()
    if not attempt:
        log.info("cluster_auto_join: cancelled post-unseal (%s)", reason)
        return

    max_attempts = settings.ha_auto_join_max_attempts
    backoff = settings.ha_auto_join_retry_secs

    for attempt_no in range(1, max_attempts + 1):
        try:
            await _attempt_join_once(node_uuid)
            return
        except AutoJoinPermanentError as exc:
            log.error("cluster_auto_join: permanent failure (%s) -- exiting", exc)
            return
        except AutoJoinError as exc:
            log.warning(
                "cluster_auto_join: attempt %d/%d failed (%s) ; retrying in %ds",
                attempt_no,
                max_attempts,
                exc,
                backoff,
            )
        except Exception:
            log.exception(
                "cluster_auto_join: attempt %d/%d crashed ; retrying in %ds",
                attempt_no,
                max_attempts,
                backoff,
            )
        if attempt_no < max_attempts:
            await asyncio.sleep(backoff)

    log.error(
        "cluster_auto_join: exhausted %d attempts -- no cert persisted",
        max_attempts,
    )
