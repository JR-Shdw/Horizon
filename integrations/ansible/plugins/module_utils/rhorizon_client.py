# SPDX-License-Identifier: AGPL-3.0-or-later
"""Small stdlib-only Horizon API client used by the Ansible collection."""

import json
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class HorizonClientError(RuntimeError):
    """Sanitized error safe to expose through Ansible."""


def _ssl_context(ca_cert, validate_certs):
    if not validate_certs:
        return ssl._create_unverified_context()  # noqa: SLF001
    return ssl.create_default_context(cafile=ca_cert)


def _validate_address(address):
    parsed = urlparse(address)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise HorizonClientError(
            "Horizon address must use HTTPS (HTTP is accepted only on loopback)"
        )
    if not parsed.hostname or parsed.username or parsed.password:
        raise HorizonClientError(
            "Horizon address must contain a host and no embedded credentials"
        )
    return address.rstrip("/")


def request_json(
    address,
    token,
    method,
    path,
    *,
    body=None,
    ca_cert=None,
    validate_certs=True,
    timeout=10,
):
    """Call Horizon without ever returning response bodies on an error."""
    base = _validate_address(address)
    payload = None
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + token,
    }
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(base + path, data=payload, headers=headers, method=method)
    try:
        with urlopen(
            req,
            timeout=timeout,
            context=_ssl_context(ca_cert, validate_certs),
        ) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        # A backend or proxy response could contain a reflected credential.
        # Status is enough for the operator and safe for Ansible logs.
        raise HorizonClientError(f"Horizon API returned HTTP {exc.code}") from None
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        raise HorizonClientError(
            f"Horizon API connection failed ({type(exc).__name__})"
        ) from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HorizonClientError("Horizon API returned invalid JSON") from None
