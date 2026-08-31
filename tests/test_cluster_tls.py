# SPDX-License-Identifier: AGPL-3.0-or-later

import pytest
from api.app import cluster_tls


def test_server_context_uses_optional_private_ca_and_client_pair(monkeypatch):
    calls = []

    class Context:
        def load_cert_chain(self, **kwargs):
            calls.append(("cert", kwargs))

    def create_default_context(**kwargs):
        calls.append(("context", kwargs))
        return Context()

    monkeypatch.setattr(cluster_tls.settings, "ha_server_ca_file", "/ca.pem")
    monkeypatch.setattr(
        cluster_tls.ssl, "create_default_context", create_default_context
    )
    context = cluster_tls.server_context(
        client_cert="/node.pem", client_key="/node.key"
    )
    assert isinstance(context, Context)
    assert calls == [
        ("context", {"cafile": "/ca.pem"}),
        ("cert", {"certfile": "/node.pem", "keyfile": "/node.key"}),
    ]


def test_server_context_rejects_half_client_identity(monkeypatch):
    monkeypatch.setattr(cluster_tls.settings, "ha_server_ca_file", "")
    monkeypatch.setattr(
        cluster_tls.ssl, "create_default_context", lambda **_kwargs: object()
    )
    with pytest.raises(ValueError, match="both HA client"):
        cluster_tls.server_context(client_cert="/node.pem")
