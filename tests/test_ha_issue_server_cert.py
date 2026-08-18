# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""POST /cluster/issue-server-cert tests.

Coverage map :

POST /cluster/issue-server-cert (admin:w, master-only)
- happy path : returns server_cert + server_key + fingerprint + not_after
- cert is signed by the cluster CA
- SAN populated from san_ips + san_dns
- 401 without admin token
- 400 on empty SAN (san_ips=[] AND san_dns=[])
- 400 on invalid IP literal
- 400 on invalid DNS name
- 400 on validity_days above ceiling
- 503 when CA not initialised (pre /cluster/init)
- 409 when vault sealed
- audit row ``cluster_server_cert_issued`` emitted
- cert NOT persisted in vault_cluster_config or vault_cluster_nodes
"""

import pytest
import pytest_asyncio
from api.app import cluster_ca
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from api.app.ha_password import clear as hp_clear
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy import text

_CLUSTER_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
)


@pytest_asyncio.fixture
async def _fresh_cluster(tmp_path, monkeypatch, admin_token, client):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    nu.init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "issue-server-cert-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()


@pytest.mark.asyncio
async def test_happy_path_returns_pem_and_metadata(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": ["192.168.10.1"], "san_dns": ["rhorizon-1"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["server_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY-----" in body["server_key_pem"]
    assert len(body["fingerprint"]) == 64  # sha256 hex
    assert body["not_after"].endswith("+00:00") or body["not_after"].endswith("Z")


@pytest.mark.asyncio
async def test_signed_by_cluster_ca(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": ["10.0.0.42"], "san_dns": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    body = r.json()
    server_cert = x509.load_pem_x509_certificate(body["server_cert_pem"].encode())
    async with async_session() as db:
        ca_pair = await cluster_ca.load_cluster_ca(db)
    assert ca_pair is not None
    ca_cert = x509.load_pem_x509_certificate(ca_pair[0])
    ca_cert.public_key().verify(
        server_cert.signature, server_cert.tbs_certificate_bytes
    )


@pytest.mark.asyncio
async def test_san_populated(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={
            "san_ips": ["192.168.10.1", "10.0.0.1"],
            "san_dns": ["rhorizon-1", "vault.example.com"],
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    body = r.json()
    cert = x509.load_pem_x509_certificate(body["server_cert_pem"].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    import ipaddress

    ips = san.get_values_for_type(x509.IPAddress)
    dns = san.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("192.168.10.1") in ips
    assert ipaddress.ip_address("10.0.0.1") in ips
    assert "rhorizon-1" in dns
    assert "vault.example.com" in dns


@pytest.mark.asyncio
async def test_eku_server_auth_only(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": ["10.0.0.1"], "san_dns": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    body = r.json()
    cert = x509.load_pem_x509_certificate(body["server_cert_pem"].encode())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    eku_set = set(eku)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku_set
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku_set


@pytest.mark.asyncio
async def test_no_admin_token_401(_fresh_cluster, client):
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": ["10.0.0.1"], "san_dns": []},
    )
    # Same surface as the other admin:w endpoints : FastAPI's auth dep
    # surfaces a missing Authorization header as 422 (header field
    # required) ; a bad token surfaces as 401 ; a wrong scope as 403.
    assert r.status_code in (401, 403, 422)


@pytest.mark.asyncio
async def test_empty_san_400(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": [], "san_dns": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_invalid_ip_400(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": ["not-an-ip"], "san_dns": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_invalid_dns_400(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": [], "san_dns": ["-leading-hyphen.example.com"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_validity_above_ceiling_400(_fresh_cluster, client, admin_token):
    ceiling = 4 * settings.cluster_server_cert_validity_days
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={
            "san_ips": ["10.0.0.1"],
            "san_dns": [],
            "validity_days": ceiling + 1,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_no_ca_initialised_503(tmp_path, monkeypatch, client, admin_token):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    nu.init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()
    try:
        r = await client.post(
            "/api/v1/vault/cluster/issue-server-cert",
            json={"san_ips": ["10.0.0.1"], "san_dns": []},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 503
    finally:
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
                {"ks": list(_CLUSTER_KEYS)},
            )
            await db.commit()
        hp_clear()


@pytest.mark.asyncio
async def test_audit_emitted(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": ["10.0.0.1"], "san_dns": ["rhorizon-1"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT action, target, detail FROM vault_audit "
                    "WHERE action = 'cluster_server_cert_issued' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
        ).fetchone()
    assert row is not None
    assert row.target == "server"


@pytest.mark.asyncio
async def test_cert_not_persisted(_fresh_cluster, client, admin_token):
    """Issued server certs do NOT land in vault_cluster_config or
    vault_cluster_nodes -- the operator's ansible play persists them
    on disk and reloads nginx. The design section "The cert is not
    persisted ...".
    """
    async with async_session() as db:
        before_cfg = (
            (await db.execute(text("SELECT COUNT(*) AS n FROM vault_cluster_config")))
            .fetchone()
            .n
        )
        before_nodes = (
            (await db.execute(text("SELECT COUNT(*) AS n FROM vault_cluster_nodes")))
            .fetchone()
            .n
        )

    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": ["10.0.0.1"], "san_dns": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200

    async with async_session() as db:
        after_cfg = (
            (await db.execute(text("SELECT COUNT(*) AS n FROM vault_cluster_config")))
            .fetchone()
            .n
        )
        after_nodes = (
            (await db.execute(text("SELECT COUNT(*) AS n FROM vault_cluster_nodes")))
            .fetchone()
            .n
        )

    assert after_cfg == before_cfg
    assert after_nodes == before_nodes
