# SPDX-License-Identifier: AGPL-3.0-or-later
"""Keep the hand-written API index aligned with the FastAPI route table."""

import re
from pathlib import Path

from api.app.main import app

_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}
_VAULT_PREFIX = "/api/v1/vault"
_DOC_ROW = re.compile(r"\|\s*(GET|POST|PUT|DELETE|PATCH)\s*\|\s*`([^`]+)`")


def _shape(path: str) -> str:
    """Ignore parameter names while retaining the endpoint shape."""
    path = path.split("?", 1)[0].rstrip("/") or "/"
    return re.sub(r"\{[^}]+\}", "{}", path)


def test_api_reference_lists_every_route_and_no_removed_route():
    documented = {
        (method, _shape(path))
        for method, path in _DOC_ROW.findall(
            (
                Path(__file__).parents[1] / "docs" / "docs" / "reference" / "api.md"
            ).read_text(encoding="utf-8")
        )
    }

    implemented = set()
    for route in app.routes:
        path = getattr(route, "path", "")
        if path in {
            "/metrics",
            "/openapi.json",
            "/docs",
            "/docs/oauth2-redirect",
            "/redoc",
        }:
            # Metrics is described separately because it uses a CIDR allowlist;
            # FastAPI's optional schema and UI routes are not product APIs.
            continue
        if path.startswith(_VAULT_PREFIX):
            path = path[len(_VAULT_PREFIX) :] or "/"
        for method in getattr(route, "methods", set()) & _METHODS:
            implemented.add((method, _shape(path)))

    assert documented == implemented
