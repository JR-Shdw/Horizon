# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Coverage targete sur api/app/routes/audit.py (86 % -> ~95 %).

Cible :
  - L158-168, L175 : /audit/lite avec filtres (actor, action, since, until)
  - L332-335 : /audit/verify fallback quand vault_audit_lite absent (try/except)
  - L352-354 : signature legacy fallback (chain verify)
  - L411-412 : /audit/files/{date} regex invalide (400)
  - L420-426 : /audit/files/{date} read compressed gzip
  - L445-461 : /audit/files/{date} delete retention check + 403
  - L477-525 : compress_old_files (tmp cleanup + OSError handler)
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest


@pytest.mark.asyncio
async def test_audit_lite_filters_actor(client, master_password, admin_token):
    """GET /audit/lite?actor=X - exercise the where_parts.append('actor=:actor')."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    # Une action exercices /audit (creation de token p.ex.) genere une entree.
    await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "cov-audit-actor", "permissions": {"secrets": "r"}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    r = await client.get(
        "/api/v1/vault/audit/lite?actor=admin",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.asyncio
async def test_audit_lite_filters_action(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.get(
        "/api/v1/vault/audit/lite?action=unseal",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_audit_lite_filters_since_until(client, master_password, admin_token):
    """L163-168 : filtres timestamp."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.get(
        "/api/v1/vault/audit/lite?since=2020-01-01T00:00:00Z&until=2099-01-01T00:00:00Z",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_audit_lite_combined_filters(client, master_password, admin_token):
    """L175 : where_parts joined avec AND."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.get(
        "/api/v1/vault/audit/lite?actor=admin&action=unseal",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_audit_files_date_invalid_format(client, master_password, admin_token):
    """L411-412 + L445-446 : regex date refuse les formats invalides."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.get(
        "/api/v1/vault/audit/files/not-a-date",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 400
    assert "YYYY-MM-DD" in r.json()["detail"]


@pytest.mark.asyncio
async def test_audit_files_date_404(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.get(
        "/api/v1/vault/audit/files/1999-01-01",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_audit_delete_file_within_retention_403(
    client, master_password, admin_token, tmp_path
):
    """L455-461: refuses to delete a file within the retention window."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Create a file with today's date in the audit directory.
    from api.app.routes.audit import _audit_dir

    audit_path = _audit_dir()
    fpath = audit_path / f"audit-{today}.jsonl"
    audit_path.mkdir(parents=True, exist_ok=True)
    fpath.write_text('{"actor":"test"}\n')

    try:
        r = await client.request(
            "DELETE",
            f"/api/v1/vault/audit/files/{today}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 403
        assert "retention" in r.json()["detail"]
    finally:
        if fpath.exists():
            fpath.unlink()


@pytest.mark.asyncio
async def test_audit_delete_file_is_logged(client, master_password, admin_token):
    """Deleting an audit file (past retention) records a delete_audit_file row
    in the chained log -- destroying audit evidence must leave a trace."""
    from api.app.database import async_session
    from api.app.routes.audit import _audit_dir
    from sqlalchemy import text

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    old_date = "2020-01-01"  # well past the 365d retention floor
    audit_path = _audit_dir()
    audit_path.mkdir(parents=True, exist_ok=True)
    fpath = audit_path / f"audit-{old_date}.jsonl"
    fpath.write_text('{"actor":"test"}\n')

    r = await client.request(
        "DELETE",
        f"/api/v1/vault/audit/files/{old_date}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    assert not fpath.exists()

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT target FROM vault_audit "
                    "WHERE action = 'delete_audit_file' AND target = :d"
                ),
                {"d": old_date},
            )
        ).fetchone()
    assert row is not None, "audit-file deletion must be logged"


@pytest.mark.asyncio
async def test_list_audit_content_filter_skips_chain(
    client, master_password, admin_token
):
    """A content (actor/action) filter returns a non-contiguous subset, so the
    chain can't be threaded: chain_intact is None and per-row verified is None."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "audit-filter-probe", "value": "v"},
        headers=headers,
    )

    r = await client.get("/api/v1/vault/audit/?action=create_secret", headers=headers)
    body = r.json()
    assert body["chain_intact"] is None
    assert body["count"] >= 1
    assert all(item["verified"] is None for item in body["items"])

    # Unfiltered list still verifies the chain (real bool, not None).
    r2 = await client.get("/api/v1/vault/audit/", headers=headers)
    assert r2.json()["chain_intact"] is True


@pytest.mark.asyncio
async def test_list_audit_offset_seeds_prev_sig(client, master_password, admin_token):
    """A paginated (offset>0) unfiltered page seeds prev_sig from the row before
    it, so the first row verifies instead of spuriously failing against ''."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    for n in range(3):
        await client.post(
            "/api/v1/vault/secrets/",
            json={"name": f"audit-page-{n}", "value": "v"},
            headers=headers,
        )

    r = await client.get("/api/v1/vault/audit/?limit=1&offset=1", headers=headers)
    body = r.json()
    assert body["count"] == 1
    assert body["items"][0]["verified"] is True
    assert body["chain_intact"] is True


@pytest.mark.asyncio
async def test_verify_sealed_ip_allowed(
    client, master_password, admin_token, monkeypatch
):
    """Sealed /verify is reachable (no bearer) from an allowed CIDR and verifies
    the ed25519 portion of the chain."""
    from api.app.config import settings
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "sealed-verify-probe", "value": "v"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    vault.seal()
    monkeypatch.setattr(settings, "audit_verify_allowed_cidrs", "127.0.0.1/32")

    r = await client.get("/api/v1/vault/audit/verify")  # no bearer
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["chain_intact"] is True
    assert "unverifiable_while_sealed" in body


@pytest.mark.asyncio
async def test_verify_sealed_ip_denied(
    client, master_password, admin_token, monkeypatch
):
    """Sealed /verify with an empty CIDR list is 503 (fail-closed)."""
    from api.app.config import settings
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    vault.seal()
    monkeypatch.setattr(settings, "audit_verify_allowed_cidrs", "")  # disabled

    r = await client.get("/api/v1/vault/audit/verify")
    assert r.status_code == 503


@pytest.mark.asyncio
async def test_verify_unsealed_requires_bearer(client, master_password, admin_token):
    """Unsealed /verify still demands an audit:r bearer - the CIDR gate is a
    sealed-only fallback, not a bypass."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.get("/api/v1/vault/audit/verify")  # no bearer, unsealed
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_audit_delete_file_invalid_date_400(client, master_password, admin_token):
    """L451-452 : datetime.strptime raise ValueError -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    # Date au bon format regex mais semantiquement invalide (2026-13-99).
    # Cependant _DATE_RE pourrait deja l'attraper. Test plus secure : 2026-99-99.
    r = await client.request(
        "DELETE",
        "/api/v1/vault/audit/files/2026-13-45",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # 400 attendu (soit regex soit strptime).
    assert r.status_code == 400


def test_compress_old_files_cleanup_orphan_tmp(tmp_path, monkeypatch):
    """L490-493: .gz.tmp orphans from a previous crash are deleted."""
    monkeypatch.setattr(
        "api.app.routes.audit._audit_dir",
        lambda: tmp_path,
    )
    monkeypatch.setattr("api.app.routes.audit.settings.audit_compress_days", 0)
    # Create an orphan .gz.tmp.
    orphan = tmp_path / "audit-2020-01-01.jsonl.gz.tmp"
    orphan.write_bytes(b"partial")
    assert orphan.exists()

    from api.app.routes.audit import compress_old_files

    compress_old_files()
    assert not orphan.exists()


def test_compress_old_files_compresses(tmp_path, monkeypatch):
    """L495-516: old .jsonl file -> compressed to .gz, original deleted."""
    monkeypatch.setattr("api.app.routes.audit._audit_dir", lambda: tmp_path)
    monkeypatch.setattr("api.app.routes.audit.settings.audit_compress_days", 0)

    plain = tmp_path / "audit-2020-06-01.jsonl"
    plain.write_text('{"actor":"x"}\n')

    from api.app.routes.audit import compress_old_files

    n = compress_old_files()
    assert n == 1
    assert not plain.exists()
    gz = tmp_path / "audit-2020-06-01.jsonl.gz"
    assert gz.exists()


def test_compress_old_files_skips_invalid_date(tmp_path, monkeypatch):
    """L503-504: file with an unparsable date -> skip via continue."""
    monkeypatch.setattr("api.app.routes.audit._audit_dir", lambda: tmp_path)
    monkeypatch.setattr("api.app.routes.audit.settings.audit_compress_days", 0)

    bad_name = tmp_path / "audit-not-a-date.jsonl"
    bad_name.write_text("noise")

    from api.app.routes.audit import compress_old_files

    n = compress_old_files()
    assert n == 0
    # The file remains because the date could not be parsed.
    assert bad_name.exists()


def test_compress_old_files_oserror_handler(tmp_path, monkeypatch):
    """L518-523: OSError during gzip -> cleans up .gz.tmp, does not crash."""
    monkeypatch.setattr("api.app.routes.audit._audit_dir", lambda: tmp_path)
    monkeypatch.setattr("api.app.routes.audit.settings.audit_compress_days", 0)

    plain = tmp_path / "audit-2020-01-15.jsonl"
    plain.write_text('{"actor":"x"}\n')

    # Mock gzip.open to raise OSError -> we fall into the except path.
    with patch(
        "api.app.routes.audit.gzip.open", side_effect=OSError("disk full simulated")
    ):
        from api.app.routes.audit import compress_old_files

        n = compress_old_files()
        # Le crash est swallow, n reste a 0.
        assert n == 0
    # Original .jsonl preserve (atomic-rename pattern).
    assert plain.exists()
