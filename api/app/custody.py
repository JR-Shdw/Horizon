# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Process boundary for separated local crypto custody.

The public API pool remains the network-facing application. A fixed UDS-only
custodian pool owns the existing Rust RPC master and Shamir shares. Only the
small set of operations that creates, replaces, exports, or destroys the
runtime key generation crosses this control boundary; ordinary vault traffic
stays on disposable API workers and delegates crypto through native RPC.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import stat
from pathlib import Path

import httpx
from rhorizon_crypto import secure_zero

from .config import settings

log = logging.getLogger("rhorizon.custody")

_TOKEN_HEADER = b"x-rhorizon-custody-token"
_CLIENT_IP_HEADER = b"x-rhorizon-custody-client-ip"
_MAX_CONTROL_TOKEN_BYTES = 256

# These handlers either establish/destroy the local key generation or require
# direct access to multiple generations at once. Keeping this list closed is a
# security property: ordinary high-volume requests never enter the Python
# control plane of the custodian pool.
_CUSTODY_ROUTES = frozenset(
    {
        ("POST", "/api/v1/vault/unseal"),
        ("POST", "/api/v1/vault/seal"),
        ("POST", "/api/v1/vault/rotate-password"),
        ("POST", "/api/v1/vault/admin/rotate-dek-key"),
        ("POST", "/api/v1/vault/shamir/init"),
        ("DELETE", "/api/v1/vault/shamir"),
        ("POST", "/api/v1/vault/backup/restore"),
        ("POST", "/api/v1/vault/oneshot"),
    }
)

# Pre-dispatch pinning is required for operations that mutate or export the
# active key generation. A shared UDS listener can hand a request to any
# custodian; followers reject before reading the route body and the API opens a
# fresh connection until the elected master accepts it. Unseal/oneshot are
# deliberately excluded because they establish an initial generation while no
# operational master exists.
_MASTER_ONLY_ROUTES = _CUSTODY_ROUTES - {
    ("POST", "/api/v1/vault/unseal"),
    ("POST", "/api/v1/vault/oneshot"),
}
_MASTER_RETRY_HEADER = b"x-rhorizon-custody-retry-master"
# A shared Uvicorn listener assigns each new connection to one custodian. Only
# the elected master accepts generation-changing routes. The expected number
# of probes is the pool size; the high cap makes the worst allowed 9-process
# pool's all-follower miss probability negligible without slowing the normal
# case.
_MASTER_ROUTE_ATTEMPTS = 256

_DROP_REQUEST_HEADERS = {
    b"connection",
    b"content-length",
    b"host",
    _TOKEN_HEADER,
    _CLIENT_IP_HEADER,
}
_DROP_RESPONSE_HEADERS = {
    b"connection",
    b"content-encoding",
    b"content-length",
    b"transfer-encoding",
}


def is_separated_api() -> bool:
    return settings.custody_mode == "separated" and settings.process_role == "api"


def is_rust_custody_api() -> bool:
    return is_separated_api() and settings.custody_backend == "rust"


def is_custodian() -> bool:
    return settings.custody_mode == "separated" and settings.process_role == "custodian"


def is_custody_route(method: str, path: str) -> bool:
    return (method.upper(), path) in _CUSTODY_ROUTES


def _read_control_token() -> bytes:
    path = Path(settings.custodian_token_file)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError("custodian control token is not a regular file")
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RuntimeError("custodian control token must not be group/world accessible")
    raw = path.read_bytes().strip()
    if not 32 <= len(raw) <= _MAX_CONTROL_TOKEN_BYTES:
        raise RuntimeError("custodian control token must contain 32..256 bytes")
    return raw


def _header_value(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def _direct_client_ip(scope: dict) -> str:
    client = scope.get("client")
    if not client:
        return "unknown"
    candidate = str(client[0])
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "unknown"


async def _read_request_body(receive) -> bytearray:
    body = bytearray()
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            raise ConnectionError("client disconnected during custody request")
        if message["type"] != "http.request":
            continue
        body.extend(message.get("body", b""))
        if not message.get("more_body", False):
            return body


class _WipableBodyStream(httpx.AsyncByteStream):
    """Expose a mutable request buffer through HTTPX's async interface."""

    def __init__(self, body: bytearray):
        self._body = body

    async def __aiter__(self):
        yield memoryview(self._body)


async def _json_error(
    send,
    status: int,
    error: str,
    detail: str,
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    payload = json.dumps({"error": error, "detail": detail}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                *(headers or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


class CustodyBoundaryMiddleware:
    """Authenticate the custodian UDS and proxy key-lifecycle requests."""

    def __init__(self, app):
        self.app = app
        self._token: bytes | None = None

    def _token_bytes(self) -> bytes:
        if self._token is None:
            self._token = _read_control_token()
        return self._token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or settings.custody_mode != "separated":
            await self.app(scope, receive, send)
            return

        if is_rust_custody_api():
            from .custody_routing import rust_route_decision

            decision = rust_route_decision(
                scope.get("method", ""), scope.get("path", "")
            )
            if decision == "refuse":
                await _json_error(
                    send,
                    503,
                    "rust_custody_control_unavailable",
                    "this key-generation operation is not enabled for the Rust canary",
                )
                return
            await self.app(scope, receive, send)
            return

        if is_custodian():
            await self._serve_custodian(scope, receive, send)
            return

        if is_custody_route(scope.get("method", ""), scope.get("path", "")):
            await self._proxy_to_custodian(scope, receive, send)
            return

        await self.app(scope, receive, send)

    async def _serve_custodian(self, scope, receive, send) -> None:
        headers = list(scope.get("headers", ()))
        supplied = _header_value(headers, _TOKEN_HEADER)
        expected = self._token_bytes()
        if supplied is None or not hmac.compare_digest(supplied, expected):
            await _json_error(
                send, 403, "custody_access_denied", "invalid control capability"
            )
            return

        # Preserve the real remote identity for rate limits and audit. This
        # header is accepted only after the file-backed capability check and
        # the custodian listener is a mode-0600 Unix socket.
        forwarded_ip = _header_value(headers, _CLIENT_IP_HEADER)
        if forwarded_ip is not None:
            try:
                client_ip = str(ipaddress.ip_address(forwarded_ip.decode("ascii")))
            except (UnicodeDecodeError, ValueError):
                await _json_error(
                    send, 400, "invalid_custody_client_ip", "invalid client IP"
                )
                return
            scope = dict(scope)
            scope["client"] = (client_ip, 0)
        route = (scope.get("method", "").upper(), scope.get("path", ""))
        if route in _MASTER_ONLY_ROUTES:
            from .vault_state import vault

            if not vault.is_master:
                await _json_error(
                    send,
                    409,
                    "custodian_not_master",
                    "retry against elected local custodian",
                    headers=[(_MASTER_RETRY_HEADER, b"1")],
                )
                return
        scope["headers"] = [
            (key, value)
            for key, value in headers
            if key.lower() not in {_TOKEN_HEADER, _CLIENT_IP_HEADER}
        ]
        await self.app(scope, receive, send)

    async def _proxy_to_custodian(self, scope, receive, send) -> None:
        from . import metrics

        body = bytearray()
        try:
            body = await _read_request_body(receive)
            headers = [
                (key, value)
                for key, value in scope.get("headers", ())
                if key.lower() not in _DROP_REQUEST_HEADERS
            ]
            headers.extend(
                [
                    (_TOKEN_HEADER, self._token_bytes()),
                    (_CLIENT_IP_HEADER, _direct_client_ip(scope).encode()),
                ]
            )
            query = scope.get("query_string", b"").decode("ascii", errors="strict")
            path = scope.get("path", "/")
            url = f"http://rhorizon-custodian{path}"
            if query:
                url = f"{url}?{query}"
            timeout = httpx.Timeout(600.0, connect=5.0)
            response = None

            # Address the elected custodian directly when the pool publishes
            # per-slot sockets. Rejection sampling only exists because a shared
            # listener cannot name a process: measured on three custodians,
            # the same workload cost 4, 5, 7 and 41 re-dials across four runs,
            # each re-sending the whole body -- which here is the master
            # password. None means "not addressable yet" (no master elected, or
            # a pool still on the shared listener), and the loop below is the
            # correct, slower fallback.
            from .custody_routing import elected_custodian_socket
            from .database import async_session

            try:
                target_uds = await elected_custodian_socket(async_session)
            except Exception:
                # A routing hint must never be the reason a control-plane
                # request fails; the fallback path is always available.
                log.debug("custody: master socket lookup failed", exc_info=True)
                target_uds = None
            attempts = 1 if target_uds else _MASTER_ROUTE_ATTEMPTS
            if target_uds:
                metrics.custody_direct_routes.inc()

            for _attempt in range(attempts):
                # A new connection is load-balanced independently across the
                # fixed UDS pool. Reusing one keep-alive connection would pin
                # every retry to the same follower forever.
                transport = httpx.AsyncHTTPTransport(
                    uds=target_uds or settings.custodian_uds_path
                )
                async with httpx.AsyncClient(
                    transport=transport, timeout=timeout
                ) as client:
                    candidate = await client.request(
                        scope.get("method", "GET"),
                        url,
                        headers=headers,
                        content=_WipableBodyStream(body),
                    )
                if candidate.headers.get(_MASTER_RETRY_HEADER.decode()) != "1":
                    response = candidate
                    break
                metrics.custody_master_retries.inc()
            if response is None:
                metrics.custody_control_requests.labels(
                    result="master_unavailable"
                ).inc()
                await _json_error(
                    send,
                    503,
                    "custodian_master_unavailable",
                    "elected local crypto custodian did not accept the request",
                )
                return
            metrics.custody_control_requests.labels(result="success").inc()
            response_headers = [
                (key, value)
                for key, value in response.headers.raw
                if key.lower() not in _DROP_RESPONSE_HEADERS
            ]
            await send(
                {
                    "type": "http.response.start",
                    "status": response.status_code,
                    "headers": response_headers,
                }
            )
            await send({"type": "http.response.body", "body": response.content})
        except (
            ConnectionError,
            OSError,
            RuntimeError,
            UnicodeDecodeError,
            httpx.HTTPError,
        ) as exc:
            metrics.custody_control_requests.labels(result="transport_error").inc()
            log.warning("custodian control request failed: %s", exc)
            await _json_error(
                send,
                503,
                "custodian_unavailable",
                "local crypto custody service is unavailable",
            )
        finally:
            if body:
                secure_zero(body)
