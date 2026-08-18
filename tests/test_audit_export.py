# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Signed audit evidence bundle API contracts."""

import hashlib
import io
import json
import tarfile
from uuid import uuid4

from api.app.audit_export import EXPORT_SCHEMA, canonical_export_manifest
from api.app.audit_identity import ensure_audit_identity
from api.app.audit_mtree import create_audit_lite_checkpoint
from api.app.database import async_session
from cli.rhorizon.audit_bundle import verify_bundle
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _bundle_members(content: bytes) -> dict[str, bytes]:
    result = {}
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        for member in archive.getmembers():
            assert member.isfile()
            handle = archive.extractfile(member)
            assert handle is not None
            result[member.name] = handle.read()
    return result


async def test_export_contains_both_logs_and_signed_manifest(
    client, master_password, admin_token, tmp_path
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    async with async_session() as db:
        await ensure_audit_identity(db)
        await db.commit()

    name = f"export-{uuid4().hex}"
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": name, "value": "not-exported"},
        headers=headers,
    )
    assert created.status_code in (200, 201), created.text
    read = await client.get(f"/api/v1/vault/secrets/{name}", headers=headers)
    assert read.status_code == 200, read.text
    async with async_session() as db:
        checkpoint = await create_audit_lite_checkpoint(db, actor="export-test")
        await db.commit()
    assert checkpoint["created"] is True
    verified = await client.get("/api/v1/vault/audit/verify", headers=headers)
    assert verified.status_code == 200, verified.text
    assert verified.json()["evidence_intact"] is True

    response = await client.post("/api/v1/vault/audit/export", json={}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/gzip")
    assert response.headers["content-disposition"].endswith('.tar.gz"')

    members = _bundle_members(response.content)
    manifest = json.loads(members["manifest.json"])
    assert manifest["schema"] == EXPORT_SCHEMA
    assert manifest["counts"]["main_live_rows"] >= 1
    assert manifest["counts"]["lite_live_rows"] >= 1
    assert manifest["source_verification"]["evidence_intact"] is True
    expected_members = {item["path"] for item in manifest["members"]}
    assert set(members) == expected_members | {"manifest.json"}
    for item in manifest["members"]:
        value = members[item["path"]]
        assert item["size"] == len(value)
        assert item["sha256"] == "sha256:" + hashlib.sha256(value).hexdigest()

    main_rows = [json.loads(line) for line in members["audit/main.jsonl"].splitlines()]
    lite_rows = [json.loads(line) for line in members["audit/lite.jsonl"].splitlines()]
    assert any(
        row["action"] == "create_secret" and row["target"] == name for row in main_rows
    )
    read_row = next(
        row
        for row in lite_rows
        if row["action"] == "read_secret" and row["target"] == name
    )
    assert set(read_row) == {
        "id",
        "timestamp",
        "actor",
        "action",
        "target",
        "detail",
        "ip_address",
    }
    assert b"not-exported" not in b"".join(members.values())

    signers = json.loads(members["proofs/signers.json"])
    signature = manifest["signature"]
    signer = next(
        item for item in signers if item["fingerprint"] == signature["signer_fpr"]
    )
    public_key = bytes.fromhex(signer["public_key"])
    assert hashlib.sha256(public_key).hexdigest() == signature["signer_fpr"]
    Ed25519PublicKey.from_public_bytes(public_key).verify(
        bytes.fromhex(signature["value"]),
        canonical_export_manifest(manifest).encode("ascii"),
    )
    saved = tmp_path / "api-export.tar.gz"
    saved.write_bytes(response.content)
    offline = verify_bundle(saved, expected_signer_fpr=signature["signer_fpr"])
    assert offline["counts"] == manifest["counts"]


async def test_export_rejects_empty_or_reversed_range(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    response = await client.post(
        "/api/v1/vault/audit/export",
        json={
            "since": "2026-08-17T10:00:00Z",
            "until": "2026-08-17T09:00:00Z",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "since must be earlier than the effective until"


async def test_export_refuses_unverified_evidence(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    async def incomplete_preflight(*, db, token_info):
        assert db is not None
        assert token_info["name"] == "test-admin"
        return {
            "preflight_ready": False,
            "evidence_status": "incomplete",
            "full_verification_job": {"job_id": "job-123"},
        }

    monkeypatch.setattr(
        "api.app.routes.audit.audit_verify_preflight", incomplete_preflight
    )
    response = await client.post(
        "/api/v1/vault/audit/export",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 409
    assert "job job-123 was queued" in response.json()["detail"]
