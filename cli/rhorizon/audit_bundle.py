# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Offline verification for signed rhorizon audit evidence bundles."""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EXPORT_SCHEMA = "rhorizon.audit_evidence_export.v1"
_MANIFEST_PREFIX = EXPORT_SCHEMA + "\0"
_MAX_METADATA_BYTES = 16 * 1024 * 1024
_MAX_MEMBERS = 10_000


class AuditBundleError(ValueError):
    """The bundle is malformed, incomplete, or fails authentication."""


def canonical_manifest(manifest: dict[str, Any]) -> bytes:
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    if unsigned.get("schema") != EXPORT_SCHEMA:
        raise AuditBundleError("unsupported audit export schema")
    return (
        _MANIFEST_PREFIX
        + json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    ).encode("ascii")


def _safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts


def _read_small(archive: tarfile.TarFile, name: str) -> bytes:
    try:
        member = archive.getmember(name)
    except KeyError as error:
        raise AuditBundleError(f"missing {name}") from error
    if not member.isfile() or member.size > _MAX_METADATA_BYTES:
        raise AuditBundleError(f"invalid {name}")
    handle = archive.extractfile(member)
    if handle is None:
        raise AuditBundleError(f"unreadable {name}")
    return handle.read()


def verify_bundle(
    path: Path, *, expected_signer_fpr: str | None = None
) -> dict[str, Any]:
    """Verify member digests and the Ed25519-signed manifest without extraction."""
    try:
        archive = tarfile.open(path, "r:gz")
    except (OSError, tarfile.TarError) as error:
        raise AuditBundleError("not a valid tar.gz audit bundle") from error

    with archive:
        members = archive.getmembers()
        if len(members) > _MAX_MEMBERS:
            raise AuditBundleError("bundle contains too many members")
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise AuditBundleError("bundle contains duplicate member names")
        if any(not _safe_name(name) for name in names):
            raise AuditBundleError("bundle contains an unsafe member name")
        if any(not member.isfile() for member in members):
            raise AuditBundleError("bundle contains a non-regular member")

        try:
            manifest = json.loads(_read_small(archive, "manifest.json"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuditBundleError("manifest.json is not valid JSON") from error
        if not isinstance(manifest, dict):
            raise AuditBundleError("manifest.json must contain an object")
        manifest_payload = canonical_manifest(manifest)

        listed = manifest.get("members")
        if not isinstance(listed, list):
            raise AuditBundleError("manifest member list is missing")
        expected_names = {"manifest.json"}
        for item in listed:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise AuditBundleError("manifest contains an invalid member")
            name = item["path"]
            if name in expected_names or not _safe_name(name):
                raise AuditBundleError("manifest contains a duplicate or unsafe path")
            expected_names.add(name)
            try:
                expected_size = int(item["size"])
                expected_digest = str(item["sha256"])
                member = archive.getmember(name)
            except (KeyError, TypeError, ValueError) as error:
                raise AuditBundleError(f"invalid manifest entry for {name}") from error
            if not member.isfile() or member.size != expected_size:
                raise AuditBundleError(f"size mismatch for {name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise AuditBundleError(f"unreadable member {name}")
            digest = hashlib.sha256()
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            if expected_digest != "sha256:" + digest.hexdigest():
                raise AuditBundleError(f"digest mismatch for {name}")
        if set(names) != expected_names:
            raise AuditBundleError("bundle contains an unlisted or missing member")

        try:
            signers = json.loads(_read_small(archive, "proofs/signers.json"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuditBundleError("signers metadata is not valid JSON") from error
        if not isinstance(signers, list):
            raise AuditBundleError("signers metadata must contain a list")
        signature = manifest.get("signature")
        if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
            raise AuditBundleError("manifest has no supported signature")
        signer_fpr = str(signature.get("signer_fpr") or "")
        if expected_signer_fpr is not None and signer_fpr != expected_signer_fpr:
            raise AuditBundleError(
                "manifest signer does not match the pinned fingerprint"
            )
        signer = next(
            (
                item
                for item in signers
                if isinstance(item, dict) and item.get("fingerprint") == signer_fpr
            ),
            None,
        )
        if signer is None:
            raise AuditBundleError("manifest signer is absent from signers metadata")
        try:
            public_key = bytes.fromhex(str(signer["public_key"]))
            signature_bytes = bytes.fromhex(str(signature["value"]))
        except (KeyError, TypeError, ValueError) as error:
            raise AuditBundleError("manifest signer metadata is malformed") from error
        if (
            len(public_key) != 32
            or hashlib.sha256(public_key).hexdigest() != signer_fpr
        ):
            raise AuditBundleError("manifest signer fingerprint is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature_bytes, manifest_payload
            )
        except (InvalidSignature, ValueError) as error:
            raise AuditBundleError("manifest signature is invalid") from error

    return {
        "schema": manifest["schema"],
        "created_at": manifest.get("created_at"),
        "signer_fpr": signer_fpr,
        "member_count": len(listed),
        "counts": manifest.get("counts", {}),
        "signer_pinned": expected_signer_fpr is not None,
    }
