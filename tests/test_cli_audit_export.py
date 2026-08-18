# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""CLI audit export download and offline verification contracts."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

from cli.rhorizon.audit_bundle import (
    EXPORT_SCHEMA,
    AuditBundleError,
    canonical_manifest,
    verify_bundle,
)
from cli.rhorizon.client import VaultClient
from cli.rhorizon.main import app
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner


def _bundle(path: Path, *, tamper: bool = False) -> str:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    fingerprint = hashlib.sha256(public).hexdigest()
    signers = json.dumps(
        [{"fingerprint": fingerprint, "public_key": public.hex()}],
        separators=(",", ":"),
    ).encode()
    audit = b'{"action":"read_secret","actor":"test"}\n'
    files = {
        "audit/lite.jsonl": audit,
        "proofs/signers.json": signers,
    }
    manifest = {
        "schema": EXPORT_SCHEMA,
        "created_at": "2026-08-17T00:00:00Z",
        "requested_by": "test",
        "range": {"since": None, "until": "2026-08-17T00:00:00Z"},
        "counts": {
            "main_live_rows": 0,
            "main_archived_rows": 0,
            "lite_live_rows": 1,
            "lite_archived_rows": 0,
        },
        "members": [
            {
                "path": name,
                "size": len(value),
                "sha256": "sha256:" + hashlib.sha256(value).hexdigest(),
            }
            for name, value in sorted(files.items())
        ],
        "signature": {
            "algorithm": "ed25519",
            "signer_fpr": fingerprint,
            "value": "",
        },
    }
    manifest["signature"]["value"] = key.sign(canonical_manifest(manifest)).hex()
    files["manifest.json"] = json.dumps(manifest, separators=(",", ":")).encode()
    if tamper:
        files["audit/lite.jsonl"] = audit + b"tampered\n"
    with tarfile.open(path, "w:gz") as archive:
        for name, value in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
    return fingerprint


def test_offline_bundle_verification_and_signer_pin(tmp_path):
    path = tmp_path / "evidence.tar.gz"
    fingerprint = _bundle(path)
    result = verify_bundle(path, expected_signer_fpr=fingerprint)
    assert result["signer_fpr"] == fingerprint
    assert result["signer_pinned"] is True
    assert result["counts"]["lite_live_rows"] == 1


def test_offline_bundle_rejects_member_tamper(tmp_path):
    path = tmp_path / "evidence.tar.gz"
    _bundle(path, tamper=True)
    try:
        verify_bundle(path)
    except AuditBundleError as error:
        assert "size mismatch" in str(error) or "digest mismatch" in str(error)
    else:  # pragma: no cover - explicit security assertion
        raise AssertionError("tampered bundle was accepted")


def test_cli_export_uses_only_tar_gz_format(monkeypatch, tmp_path):
    class Client:
        def export_audit_evidence(self, output, *, since, until):
            assert since == "2026-08-01T00:00:00Z"
            assert until is None
            return {"size_bytes": 1024, "signer_fpr": "a" * 64}

    monkeypatch.setattr("cli.rhorizon.main._client", lambda: Client())
    output = tmp_path / "audit.tar.gz"
    result = CliRunner().invoke(
        app, ["audit", "export", str(output), "--since", "2026-08-01T00:00:00Z"]
    )
    assert result.exit_code == 0, result.output
    assert "Signed audit evidence exported" in result.output

    rejected = CliRunner().invoke(app, ["audit", "export", str(tmp_path / "audit.csv")])
    assert rejected.exit_code == 1
    assert "format is .tar.gz" in rejected.output


def test_cli_verify_export_reports_integrity(tmp_path):
    path = tmp_path / "evidence.tar.gz"
    fingerprint = _bundle(path)
    result = CliRunner().invoke(
        app,
        ["audit", "verify-export", str(path), "--trusted-signer", fingerprint],
    )
    assert result.exit_code == 0, result.output
    assert "member digests intact" in result.output
    assert "authenticity is not pinned" not in result.output


def test_client_download_is_authenticated_and_atomic(monkeypatch, tmp_path):
    class Response:
        status_code = 200
        headers = {"X-Rhorizon-Audit-Signer": "b" * 64}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def iter_bytes(self, _size):
            yield b"signed-"
            yield b"bundle"

    def stream(method, url, **kwargs):
        assert method == "POST"
        assert url.endswith("/api/v1/vault/audit/export")
        assert kwargs["headers"]["Authorization"] == "Bearer rh_test"
        assert kwargs["json"]["since"] == "2026-08-01T00:00:00Z"
        return Response()

    monkeypatch.setattr("cli.rhorizon.client.httpx.stream", stream)
    output = tmp_path / "evidence.tar.gz"
    result = VaultClient("https://vault.test", "rh_test").export_audit_evidence(
        output, since="2026-08-01T00:00:00Z"
    )
    assert output.read_bytes() == b"signed-bundle"
    assert result["size_bytes"] == 13
    assert result["signer_fpr"] == "b" * 64
    assert not list(tmp_path.glob("*.part"))
