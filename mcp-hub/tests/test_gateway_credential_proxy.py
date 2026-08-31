# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""The credential proxy on the hub path (rhorizon_mcp_hub/gateway.py).

Two things to pin: `allow_read = false` refuses `vault_get_secret` here too, and
every refusal precedes the sidecar call -- the recording sidecar proves it. The
destination is checked again inside the Rust sidecar against
RH_MCP_EGRESS_ALLOW, which has its own tests.
"""

import json

from rhorizon_mcp_hub.gateway import VaultBackend
from rhorizon_mcp_hub.sidecar import SidecarError

CONFIG = {
    "proxy": {
        "github-prod": {
            "namespace": "mcp",
            "allow_read": False,
            "allow_proxy": True,
            "base_url": "https://api.github.com",
            "methods": ["GET"],
            "inject": {
                "type": "header",
                "name": "Authorization",
                "format": "Bearer {value}",
            },
        },
        "readable-too": {
            "namespace": "mcp",
            "allow_read": True,
            "allow_proxy": True,
            "base_url": "https://api.example.test",
        },
        "not-proxyable": {
            "namespace": "mcp",
            "allow_proxy": False,
            "base_url": "https://api.example.test",
        },
    }
}

CTX = {"bearer": "rh_test", "client_ip": "203.0.113.7"}


class _RecordingSidecar:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.proxies = []
        self._result = result or {"status": 200, "body": {"ok": True}}
        self._error = error

    def request(self, bearer, method, path, body=None, client_ip=None):
        self.calls.append({"path": path, "bearer": bearer, "client_ip": client_ip})
        return 200, {"value": "should-not-be-read"}

    def proxy(self, bearer, **kwargs):
        self.proxies.append({"bearer": bearer, **kwargs})
        if self._error is not None:
            raise self._error
        return self._result


def _payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


def test_a_bound_credential_is_not_readable_through_get_secret():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    out = _payload(
        be.call("vault_get_secret", {"name": "github-prod", "namespace": "mcp"}, CTX)
    )

    assert out["error"] == "policy_denied"
    assert sidecar.calls == []  # refused before the vault was asked


def test_allow_read_true_leaves_the_credential_readable():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    be.call("vault_get_secret", {"name": "readable-too", "namespace": "mcp"}, CTX)

    assert len(sidecar.calls) == 1


def test_a_binding_in_another_namespace_does_not_withhold_reads():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    be.call("vault_get_secret", {"name": "github-prod", "namespace": "prod"}, CTX)

    assert len(sidecar.calls) == 1


def test_a_permitted_call_reaches_the_sidecar_with_the_bound_destination():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    out = _payload(
        be.call(
            "vault_call_api",
            {"credential": "github-prod", "path": "/user/repos", "query": {"n": "1"}},
            CTX,
        )
    )

    assert out == {"status": 200, "body": {"ok": True}}
    sent = sidecar.proxies[0]
    assert sent["url"] == "https://api.github.com/user/repos?n=1"
    assert sent["namespace"] == "mcp"
    assert sent["credential"] == "github-prod"
    assert sent["inject"]["format"] == "Bearer {value}"
    assert sent["bearer"] == "rh_test"  # the AGENT's token, not the hub's
    assert sent["client_ip"] == "203.0.113.7"


def test_the_hub_only_ever_sends_names_never_a_value():
    """Pinning the key set catches a change that starts routing the plaintext
    back through this process."""
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    be.call("vault_call_api", {"credential": "github-prod", "path": "/user"}, CTX)

    assert set(sidecar.proxies[0]) == {
        "bearer",
        "namespace",
        "credential",
        "url",
        "method",
        "inject",
        "max_response_bytes",
        "client_ip",
    }


def test_an_unbound_credential_is_refused_before_the_sidecar_is_asked():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    out = _payload(
        be.call("vault_call_api", {"credential": "nope", "path": "/user"}, CTX)
    )

    assert out["error"] == "policy_denied"
    assert sidecar.proxies == []


def test_allow_proxy_false_is_not_a_binding():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    out = _payload(
        be.call("vault_call_api", {"credential": "not-proxyable", "path": "/x"}, CTX)
    )

    assert out["error"] == "policy_denied"
    assert sidecar.proxies == []


def test_a_path_that_would_move_the_host_is_refused():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    for path in ("//evil.test/", "/x/../../admin", "user/repos"):
        out = _payload(
            be.call("vault_call_api", {"credential": "github-prod", "path": path}, CTX)
        )
        assert out["error"] == "policy_denied", path
    assert sidecar.proxies == []


def test_a_method_outside_the_binding_is_refused():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    out = _payload(
        be.call(
            "vault_call_api",
            {"credential": "github-prod", "path": "/user", "method": "POST"},
            CTX,
        )
    )

    assert out["error"] == "policy_denied"
    assert sidecar.proxies == []


def test_a_hub_without_a_proxy_table_refuses_every_proxied_call():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar)  # no config at all

    out = _payload(
        be.call("vault_call_api", {"credential": "github-prod", "path": "/user"}, CTX)
    )

    assert out["error"] == "policy_denied"
    assert sidecar.proxies == []


def test_a_malformed_binding_is_refused_before_the_sidecar_is_asked():
    """Same ordering rule as the stdio path: a typo in hub.toml must not spend
    a vault read before it is caught."""
    cfg = {
        "proxy": {
            "broken": {
                "namespace": "mcp",
                "allow_proxy": True,
                "base_url": "https://api.github.com",
                "inject": {"type": "header", "format": "token NOPLACEHOLDER"},
            }
        }
    }
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=cfg)

    out = _payload(
        be.call("vault_call_api", {"credential": "broken", "path": "/user"}, CTX)
    )

    assert out["error"] == "policy_denied"
    assert "{value}" in out["message"]
    assert sidecar.proxies == []
    assert sidecar.calls == []


def test_refusals_name_the_fix():
    sidecar = _RecordingSidecar()
    be = VaultBackend(sidecar, config=CONFIG)

    exists = _payload(
        be.call("vault_call_api", {"credential": "not-proxyable", "path": "/x"}, CTX)
    )
    assert "allow_proxy = false" in exists["message"]

    unknown = _payload(
        be.call("vault_call_api", {"credential": "typo", "path": "/x"}, CTX)
    )
    assert "github-prod" in unknown["message"]  # lists what IS bound

    method = _payload(
        be.call(
            "vault_call_api",
            {"credential": "github-prod", "path": "/x", "method": "POST"},
            CTX,
        )
    )
    assert "allowed: GET" in method["message"]


def test_a_sidecar_refusal_surfaces_as_an_error_not_a_result():
    """A refusal must not be mistaken for an upstream reply."""
    sidecar = _RecordingSidecar(
        error=SidecarError("destination not in RH_MCP_EGRESS_ALLOW")
    )
    be = VaultBackend(sidecar, config=CONFIG)

    out = _payload(
        be.call("vault_call_api", {"credential": "github-prod", "path": "/user"}, CTX)
    )

    assert out["error"] == "proxy_refused"
    assert "RH_MCP_EGRESS_ALLOW" in out["message"]
