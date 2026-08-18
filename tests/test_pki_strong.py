# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Strong PKI tests: cert structure, chain crypto, auth/scope, validation,
rotation grace, revocation, namespace isolation, and custody (reseal +
master-password rotation rewrap).

ed25519 certs are parsed/verified with cryptography; ML-DSA via verify_ml_dsa
(cryptography <49 can't parse ML-DSA X.509).
"""

import datetime
import json

import pytest
import rhorizon_crypto as rc
from api.app import pki_asn1
from api.app.crypto import generate_token
from api.app.database import async_session
from api.app.vault_state import vault
from cryptography import x509
from sqlalchemy import text

PKI = "/api/v1/vault/pki"
_ML_DSA_65_OID_DER = bytes.fromhex("0609608648016503040312")


async def _make_token(name: str, perms: dict) -> str:
    raw = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_tokens WHERE name = :n"), {"n": name})
        await db.execute(
            text(
                "INSERT INTO vault_tokens (name, token_hash, permissions, created_by) "
                "VALUES (:n, :h, CAST(:p AS jsonb), 'test')"
            ),
            {"n": name, "h": token_hash, "p": json.dumps(perms)},
        )
        await db.commit()
    return raw


async def _reset_pki():
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_pki_config"))
        await db.execute(text("DELETE FROM vault_pki_certs"))
        await db.commit()


async def _init(
    client, h, *, namespace="default", algorithm="ed25519", cn="rhorizon-pki"
):
    return await client.post(
        f"{PKI}/init",
        json={"namespace": namespace, "algorithm": algorithm, "common_name": cn},
        headers=h,
    )


async def _issue(client, h, **kw):
    return await client.post(f"{PKI}/issue", json=kw, headers=h)


def _parse(pem: str):
    return x509.load_pem_x509_certificate(pem.encode())


# --- cert structure / extensions (ed25519, parseable) -----------------------


def test_x509_time_utctime_vs_generalizedtime():
    # RFC 5280: UTCTime (0x17, 2-digit year) through 2049, GeneralizedTime
    # (0x18, 4-digit year) from 2050 on.
    utc = pki_asn1._x509_time(datetime.datetime(2049, 12, 31, 23, 59, 59))
    assert utc[0] == 0x17 and utc[2:] == b"491231235959Z"
    gen = pki_asn1._x509_time(datetime.datetime(2050, 1, 1, 0, 0, 0))
    assert gen[0] == 0x18 and gen[2:] == b"20500101000000Z"


@pytest.mark.asyncio
async def test_ca_and_leaf_extensions(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, h)
    ca = _parse((await client.get(f"{PKI}/ca", headers=h)).json()["certificate"])

    # CA cert: basicConstraints ca=True pathlen=0 (critical), keyUsage cert+crl sign
    bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True and bc.value.path_length == 0 and bc.critical
    ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign and ku.crl_sign
    ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)  # present

    r = await _issue(
        client,
        h,
        common_name="svc.internal",
        san_dns=["svc.internal", "svc"],
        san_ips=["10.0.0.1"],
        ttl_days=30,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    leaf = _parse(body["certificate"])

    # leaf: NOT a CA, has SKI + AKI, SAN dns+ip, validity ~ ttl, serial matches
    lbc = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
    assert lbc.value.ca is False and lbc.critical
    leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(san.get_values_for_type(x509.DNSName)) == {"svc.internal", "svc"}
    assert "10.0.0.1" in {str(i) for i in san.get_values_for_type(x509.IPAddress)}
    assert format(leaf.serial_number, "x") == body["serial"]
    span = leaf.not_valid_after_utc - leaf.not_valid_before_utc
    assert datetime.timedelta(days=29) < span < datetime.timedelta(days=31)
    # chain
    ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)


@pytest.mark.asyncio
async def test_eku_toggles(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, h)
    SERVER, CLIENT = pki_asn1.EKU_SERVER_AUTH, pki_asn1.EKU_CLIENT_AUTH

    async def _eku(server, client_):
        r = await _issue(
            client, h, common_name="x", eku_server=server, eku_client=client_
        )
        assert r.status_code == 201, r.text
        leaf = _parse(r.json()["certificate"])
        try:
            ext = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            return {o.dotted_string for o in ext}
        except x509.ExtensionNotFound:
            return set()

    assert await _eku(True, False) == {SERVER}
    assert await _eku(False, True) == {CLIENT}
    assert await _eku(True, True) == {SERVER, CLIENT}
    assert await _eku(False, False) == set()


# --- chain crypto: cross-CA + tamper -----------------------------------------


@pytest.mark.asyncio
async def test_cross_ca_does_not_verify(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, h, namespace="alpha")
    await _init(client, h, namespace="beta")
    ca_beta = _parse(
        (await client.get(f"{PKI}/ca?namespace=beta", headers=h)).json()["certificate"]
    )
    leaf = _parse(
        (await _issue(client, h, common_name="x", namespace="alpha")).json()[
            "certificate"
        ]
    )
    # a leaf from alpha's CA must NOT verify under beta's CA
    with pytest.raises(Exception):
        ca_beta.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)


@pytest.mark.asyncio
async def test_tampered_leaf_fails(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, h)
    ca = _parse((await client.get(f"{PKI}/ca", headers=h)).json()["certificate"])
    leaf = _parse((await _issue(client, h, common_name="x")).json()["certificate"])
    bad_sig = bytes(leaf.signature[:-1] + bytes([leaf.signature[-1] ^ 0x01]))
    with pytest.raises(Exception):
        ca.public_key().verify(bad_sig, leaf.tbs_certificate_bytes)


# --- auth / scope matrix -----------------------------------------------------


@pytest.mark.asyncio
async def test_scope_matrix(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    admin_h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, admin_h)  # admin seeds a CA

    sr = {"Authorization": f"Bearer {await _make_token('pki-sr', {'secrets': 'r'})}"}
    sw = {"Authorization": f"Bearer {await _make_token('pki-sw', {'secrets': 'rw'})}"}

    # secrets:r -> read OK, every mutation 403
    assert (await client.get(f"{PKI}/ca", headers=sr)).status_code == 200
    assert (await client.get(f"{PKI}/cas", headers=sr)).status_code == 200
    assert (await client.get(f"{PKI}/certs", headers=sr)).status_code == 200
    assert (await _init(client, sr, namespace="x")).status_code == 403
    assert (await _issue(client, sr, common_name="x")).status_code == 403
    assert (
        await client.post(f"{PKI}/revoke", json={"serial": "00"}, headers=sr)
    ).status_code == 403
    assert (await client.post(f"{PKI}/rotate", json={}, headers=sr)).status_code == 403

    # secrets:w -> issue OK, admin-only ops still 403
    assert (await _issue(client, sw, common_name="x")).status_code == 201
    assert (await _init(client, sw, namespace="y")).status_code == 403
    assert (
        await client.post(f"{PKI}/revoke", json={"serial": "00"}, headers=sw)
    ).status_code == 403
    assert (await client.post(f"{PKI}/rotate", json={}, headers=sw)).status_code == 403


# --- validation edges --------------------------------------------------------


@pytest.mark.asyncio
async def test_validation_edges(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, h)
    # re-init same namespace -> 409
    assert (await _init(client, h)).status_code == 409
    # TTL out of bounds -> 422 (ceiling is 398d; record-only revocation)
    assert (await _issue(client, h, common_name="x", ttl_days=10000)).status_code == 422
    assert (await _issue(client, h, common_name="x", ttl_days=399)).status_code == 422
    assert (await _issue(client, h, common_name="x", ttl_days=398)).status_code == 201
    assert (await _issue(client, h, common_name="x", ttl_days=0)).status_code == 422
    # empty common name -> 422
    assert (await _issue(client, h, common_name="")).status_code == 422


# --- rotation grace window ---------------------------------------------------


@pytest.mark.asyncio
async def test_rotation_grace_window(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, h)
    old_fpr = (await client.get(f"{PKI}/ca", headers=h)).json()["fingerprint"]
    leaf_old = _parse(
        (await _issue(client, h, common_name="old")).json()["certificate"]
    )

    await client.post(f"{PKI}/rotate", json={}, headers=h)
    ca_resp = (await client.get(f"{PKI}/ca", headers=h)).json()
    ca_new = _parse(ca_resp["certificate"])
    assert ca_resp["fingerprint"] != old_fpr
    assert "previous_certificate" in ca_resp
    ca_prev = _parse(ca_resp["previous_certificate"])
    leaf_new = _parse(
        (await _issue(client, h, common_name="new")).json()["certificate"]
    )

    # old leaf verifies under the previous cert (grace), not under the new CA
    ca_prev.public_key().verify(leaf_old.signature, leaf_old.tbs_certificate_bytes)
    with pytest.raises(Exception):
        ca_new.public_key().verify(leaf_old.signature, leaf_old.tbs_certificate_bytes)
    # new leaf verifies under the new CA
    ca_new.public_key().verify(leaf_new.signature, leaf_new.tbs_certificate_bytes)


# --- revocation edges --------------------------------------------------------


@pytest.mark.asyncio
async def test_revocation_edges(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, h)
    serial = (await _issue(client, h, common_name="x")).json()["serial"]

    assert (
        await client.post(f"{PKI}/revoke", json={"serial": serial}, headers=h)
    ).status_code == 200
    # double revoke -> 404 (already revoked)
    assert (
        await client.post(f"{PKI}/revoke", json={"serial": serial}, headers=h)
    ).status_code == 404
    # unknown serial -> 404
    assert (
        await client.post(f"{PKI}/revoke", json={"serial": "deadbeef"}, headers=h)
    ).status_code == 404


# --- ML-DSA leaf correctness -------------------------------------------------


@pytest.mark.asyncio
async def test_mldsa_leaf_correctness(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, h, algorithm="ml-dsa-65")
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT value FROM vault_pki_config WHERE key='pki_ca_pub:default'"
                )
            )
        ).fetchone()
    ca_pub = bytes.fromhex(row.value)

    body = (await _issue(client, h, common_name="pq", san_dns=["pq.internal"])).json()
    der = pki_asn1.pem_to_der(body["certificate"].encode())
    tbs, sig = pki_asn1.extract_tbs_and_sig(der)
    # it is really ML-DSA, verifies under the CA, and not under a random key
    assert _ML_DSA_65_OID_DER in der
    assert rc.verify_ml_dsa(ca_pub, tbs, sig)
    other = bytes(rc.MlDsaSigner.generate().public_key())
    assert not rc.verify_ml_dsa(other, tbs, sig)


# --- custody: survives a seal/unseal cycle -----------------------------------


@pytest.mark.asyncio
async def test_custody_survives_reseal(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await _init(client, h, algorithm="ml-dsa-65")
    # seal, then unseal again: the CA key must unwrap under the re-derived
    # pki_wrap_key and still issue.
    vault.seal()
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200
    r = await _issue(client, h, common_name="after-reseal")
    assert r.status_code == 201, r.text


# --- custody: master-rotation rewrap (isolated crypto, no full vault rotation) --


@pytest.mark.asyncio
async def test_rewrap_for_master_rotation(client, master_password, admin_token):
    """rewrap_for_master_rotation re-wraps EVERY namespace CA key from the old
    pki_wrap_key to the new one. Tested in isolation (seed a known-wrapped blob,
    rewrap, confirm it now decrypts under the new key) so it can't desync the
    shared session's master password the way a full /rotate-password would.
    """
    import os

    from api.app import pki_ca
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    k_old, k_new = os.urandom(32), os.urandom(32)
    secret = b"fake-ca-private-material"
    nonce = os.urandom(12)
    blob = (nonce + AESGCM(k_old).encrypt(nonce, secret, pki_ca._AAD)).hex()
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_pki_config"))
        await db.execute(
            text(
                "INSERT INTO vault_pki_config (key, value) "
                "VALUES ('pki_ca_key:prod', :v)"
            ),
            {"v": blob},
        )
        await db.commit()
        assert await pki_ca.rewrap_for_master_rotation(db, k_old, k_new) is True
        await db.commit()
        row = (
            await db.execute(
                text("SELECT value FROM vault_pki_config WHERE key='pki_ca_key:prod'")
            )
        ).fetchone()
    new_blob = bytes.fromhex(row.value)
    # now decrypts under the NEW key, and no longer under the OLD one
    assert AESGCM(k_new).decrypt(new_blob[:12], new_blob[12:], pki_ca._AAD) == secret
    with pytest.raises(Exception):
        AESGCM(k_old).decrypt(new_blob[:12], new_blob[12:], pki_ca._AAD)
    await _reset_pki()
