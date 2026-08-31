# SPDX-License-Identifier: AGPL-3.0-or-later

from rhorizon_mcp.policy import Policy
from rhorizon_mcp.server import VaultClient, _dispatch


def test_cluster_preflight_is_passive_and_summary_only(monkeypatch):
    client = VaultClient("https://vault.example", "token")
    calls = []
    monkeypatch.setattr(
        client,
        "_get",
        lambda path, params=None: calls.append((path, params)) or {"ready": True},
    )
    assert client.cluster_preflight() == {"ready": True}
    assert calls == [
        (
            "/api/v1/vault/cluster/preflight",
            {"summary": "true", "live": "false"},
        )
    ]


def test_dispatch_exposes_preflight_without_a_raw_http_tool():
    class Client:
        def cluster_preflight(self):
            return {"overall": "warn", "live_mtls_requested": False}

    result = _dispatch(
        "vault_cluster_preflight",
        {},
        Client(),
        Policy(allow_tools={"vault_cluster_preflight"}),
    )
    assert result == {"overall": "warn", "live_mtls_requested": False}
