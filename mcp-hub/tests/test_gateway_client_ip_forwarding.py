# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""client_ip forwarding through the daemon-mode hub (mcp-hub).

Regression coverage for the "MCP HTTP token IP binding" finding
(docs/SECURITY-AUDIT.md): the vault only ever saw the rh-mcp-gateway
sidecar's own connecting IP, so a per-token allowed_ips ACL could not
distinguish one agent behind the hub from another. The fix threads the
real agent IP (captured in gateway.py's HTTP handler from the socket
peer address) through ctx -> VaultBackend.call / emit_mcp_audit ->
SidecarClient.request -> the Rust sidecar, which forwards it to the
vault as X-Forwarded-For (honoured only if the vault operator has
listed the sidecar's IP in xff_trusted_ips/proxy_trusted_ips).

These tests cover the Python side of that chain with a fake sidecar
that records what it was asked to send. The Rust sidecar's header
forwarding is covered by compilation + code inspection (mcp_gateway.rs
has no existing test harness; see docs/SECURITY-AUDIT.md for the
verification notes).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rhorizon_mcp_hub.gateway import VaultBackend, emit_mcp_audit


class _RecordingSidecar:
    def __init__(self):
        self.calls = []

    def request(self, bearer, method, path, body=None, client_ip=None):
        self.calls.append(
            {
                "bearer": bearer,
                "method": method,
                "path": path,
                "body": body,
                "client_ip": client_ip,
            }
        )
        return 200, {"id": "tok-1", "name": "agent-1", "sealed": False}


def test_vault_backend_forwards_client_ip_from_ctx():
    sidecar = _RecordingSidecar()
    backend = VaultBackend(sidecar)

    backend.call(
        "vault_status",
        {},
        ctx={"bearer": "rh_test", "client_ip": "203.0.113.7"},
    )

    assert len(sidecar.calls) == 1
    assert sidecar.calls[0]["client_ip"] == "203.0.113.7"
    assert sidecar.calls[0]["bearer"] == "rh_test"


def test_vault_backend_get_secret_forwards_client_ip():
    sidecar = _RecordingSidecar()
    backend = VaultBackend(sidecar)

    backend.call(
        "vault_get_secret",
        {"name": "db-password", "namespace": "prod"},
        ctx={"bearer": "rh_test", "client_ip": "198.51.100.9"},
    )

    assert sidecar.calls[0]["client_ip"] == "198.51.100.9"
    assert "db-password" in sidecar.calls[0]["path"]


def test_vault_backend_without_client_ip_passes_none():
    """A ctx with no client_ip (e.g. stdio-adjacent callers) must not
    crash and must not synthesize a fake IP."""
    sidecar = _RecordingSidecar()
    backend = VaultBackend(sidecar)

    backend.call("vault_status", {}, ctx={"bearer": "rh_test"})

    assert sidecar.calls[0]["client_ip"] is None


def test_emit_mcp_audit_forwards_client_ip():
    sidecar = _RecordingSidecar()

    emit_mcp_audit(
        sidecar,
        "rh_test",
        backend="rhorizon",
        tool="vault_get_secret",
        decision="allowed",
        client_ip="203.0.113.7",
    )

    assert len(sidecar.calls) == 1
    assert sidecar.calls[0]["client_ip"] == "203.0.113.7"
    assert sidecar.calls[0]["path"] == "/api/v1/vault/audit/mcp"


def test_sidecar_client_omits_client_ip_key_when_absent(monkeypatch):
    """SidecarClient.request must not add a client_ip key to the wire
    payload at all when none is given -- an explicit null would still
    be a value the Rust side has to special-case."""
    import json

    from rhorizon_mcp_hub.sidecar import SidecarClient

    captured = {}

    class _FakeSocket:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def connect(self, path):
            pass

        def sendall(self, data):
            captured["sent"] = json.loads(data.decode().strip())

        def recv(self, n):
            return json.dumps({"status": 200, "body": {}}).encode() + b"\n"

    monkeypatch.setattr("socket.socket", lambda *a, **k: _FakeSocket())

    client = SidecarClient("/tmp/fake.sock")
    client.request("rh_test", "GET", "/api/v1/vault/status")
    assert "client_ip" not in captured["sent"]

    client.request("rh_test", "GET", "/api/v1/vault/status", client_ip="203.0.113.7")
    assert captured["sent"]["client_ip"] == "203.0.113.7"


if __name__ == "__main__":
    test_vault_backend_forwards_client_ip_from_ctx()
    test_vault_backend_get_secret_forwards_client_ip()
    test_vault_backend_without_client_ip_passes_none()
    test_emit_mcp_audit_forwards_client_ip()
    print("all tests passed (sidecar-client test needs pytest's monkeypatch)")
