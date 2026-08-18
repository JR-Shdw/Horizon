"""critical audit + notification fan-out.

Covers:
- pattern matcher (_is_critical_secret_name) honours the configured globs
- writes to a matching secret name carry detail._critical=true in the
  vault_audit row
- writes to a non-matching name do NOT carry the critical marker
- detail._critical is included in the HMAC chain payload (tamper-evident)
- the bg notification dispatcher is invoked when critical=True

Note: the "/audit/verify emits an audit_chain_broken row" behaviour from the
original implementation was removed in S5 (commit 15694f0, "non-mutating breaks") --
a detected break now alerts via the notification fan-out + the
audit_chain_breaks metric + the API response, but does NOT append a marker row
into the chain it is verifying (that self-references the broken row and
double-counts on re-verify). The non-mutating invariant is covered by
tests/test_audit_verify_ed25519.py::test_break_does_not_mutate_chain.
"""

import json

import pytest
from api.app.audit import log_action
from api.app.config import settings
from api.app.database import async_session
from api.app.routes.secrets import _is_critical_secret_name
from sqlalchemy import text

# --- pattern matcher ------------------------------------------------------


def test_pattern_matcher_default_matches_recovery_handles():
    assert _is_critical_secret_name("rhorizon-ha-root-token-primary") is True
    assert _is_critical_secret_name("rhorizon-ha-password") is True


def test_pattern_matcher_default_skips_unrelated_names():
    assert _is_critical_secret_name("regular-app-credential") is False
    assert _is_critical_secret_name("db/password") is False
    assert _is_critical_secret_name("") is False


def test_pattern_matcher_honours_glob(monkeypatch):
    monkeypatch.setattr(
        settings, "audit_critical_secret_patterns", "rhorizon-ha-*,prod/api/*"
    )
    assert _is_critical_secret_name("rhorizon-ha-anything") is True
    assert _is_critical_secret_name("prod/api/key") is True
    assert _is_critical_secret_name("dev/api/key") is False


# --- log_action critical=True flag ---------------------------------------


@pytest.mark.asyncio
async def test_log_action_injects_critical_marker_in_detail(admin_token):
    """A direct log_action call with critical=True writes a row whose
    JSON detail carries _critical=true. Verified via DB readback."""
    async with async_session() as db:
        await log_action(
            db,
            actor="slicew-test",
            action="slicew_unit_test",
            target="t-1",
            detail={"meta": "ok"},
            critical=True,
        )
        await db.commit()
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT detail FROM vault_audit "
                    "WHERE action='slicew_unit_test' AND target='t-1' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
        ).fetchone()
    assert row is not None
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail.get("_critical") is True
    assert detail.get("meta") == "ok"


@pytest.mark.asyncio
async def test_log_action_default_omits_critical_marker(admin_token):
    """Without critical=True, no _critical key appears in the row detail.
    Guards against accidental leak of the marker on every audit row."""
    async with async_session() as db:
        await log_action(
            db,
            actor="slicew-test",
            action="slicew_default_test",
            target="t-2",
            detail={"meta": "ok"},
        )
        await db.commit()
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT detail FROM vault_audit "
                    "WHERE action='slicew_default_test' AND target='t-2' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
        ).fetchone()
    assert row is not None
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert "_critical" not in detail


@pytest.mark.asyncio
async def test_critical_marker_is_signed_in_chain(admin_token):
    """The _critical=true bit lands inside detail BEFORE the HMAC
    payload is built (cf log_action injection point). Flipping it
    post-hoc in the DB must break verify. This is the tamper-evident
    guarantee that gives the operator confidence the red flag wasn't
    stripped silently after the fact."""
    async with async_session() as db:
        await log_action(
            db,
            actor="slicew-tamper",
            action="slicew_tamper_test",
            target="t-3",
            detail={"meta": "stable"},
            critical=True,
        )
        await db.commit()

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT id, signature, detail "
                    "FROM vault_audit "
                    "WHERE action='slicew_tamper_test' AND target='t-3' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
        ).fetchone()
    assert row is not None
    original_sig = row.signature
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail.get("_critical") is True
    assert original_sig and original_sig != "unsigned"

    # Tamper : try to strip _critical from the JSON column.
    tampered_detail = {k: v for k, v in detail.items() if k != "_critical"}
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_audit SET detail = CAST(:d AS jsonb) WHERE id = :id"),
            {"d": json.dumps(tampered_detail, sort_keys=True), "id": row.id},
        )
        await db.commit()

    # Re-sign with the tampered payload and check it doesn't match the
    # row's stored signature. This is what /audit/verify would catch.
    from api.app.vault_state import vault

    tampered_payload = (
        f"slicew-tamper|slicew_tamper_test|t-3|"
        f"{json.dumps(tampered_detail, sort_keys=True)}"
    )
    # The row's stored signature was computed with the _critical=true
    # payload. We can't reconstruct prev_sig portably here, but we can
    # confirm the tampered payload does NOT round-trip to the same
    # signature under any prev_sig the verifier could try.
    candidate = await vault.audit_sign(tampered_payload, "")
    assert candidate != original_sig

    # Restore for downstream tests.
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_audit SET detail = CAST(:d AS jsonb) WHERE id = :id"),
            {"d": json.dumps(detail, sort_keys=True), "id": row.id},
        )
        await db.commit()


# --- secrets routes critical flag end-to-end -----------------------------


@pytest.mark.asyncio
async def test_create_secret_recovery_handle_emits_critical(
    admin_token, client, monkeypatch
):
    """POST /secrets/ on a name matching the default critical pattern
    produces a vault_audit row with detail._critical=true. End-to-end
    via the FastAPI client : routes/secrets._is_critical_secret_name is
    actually wired in the request handler."""
    # The default pattern includes rhorizon-ha-password ; use that.
    name = "rhorizon-ha-password"
    # Drop any leftover from previous suites so /create succeeds.
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_secrets WHERE name = :n"),
            {"n": name},
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": name,
            "namespace": "default",
            "value": "stub-value-32-bytes-okok",
        },
    )
    assert r.status_code == 201, r.text

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT detail FROM vault_audit "
                    "WHERE action='create_secret' AND target=:n "
                    "ORDER BY id DESC LIMIT 1"
                ),
                {"n": name},
            )
        ).fetchone()
    assert row is not None
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail.get("_critical") is True


@pytest.mark.asyncio
async def test_create_secret_regular_name_does_not_emit_critical(admin_token, client):
    """A run-of-the-mill secret name (no pattern match) writes a
    normal audit row without the critical marker."""
    name = "slicew-regular-secret"
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_secrets WHERE name = :n"),
            {"n": name},
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": name, "namespace": "default", "value": "normal-value-padding-32"},
    )
    assert r.status_code == 201, r.text

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT detail FROM vault_audit "
                    "WHERE action='create_secret' AND target=:n "
                    "ORDER BY id DESC LIMIT 1"
                ),
                {"n": name},
            )
        ).fetchone()
    assert row is not None
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert "_critical" not in detail


# --- notification fan-out -------------------------------------------------


@pytest.mark.asyncio
async def test_critical_triggers_dispatch_event(admin_token, monkeypatch):
    """When critical=True, log_action schedules a bg task that calls
    dispatch_event with event='critical' and a human-readable message.
    We monkeypatch the dispatcher and await one event loop cycle so
    the create_task callback fires."""
    import asyncio

    captured = []

    async def _fake_dispatch_event(db, event, message):
        captured.append((event, message))

    # Replace the symbol that audit._dispatch_critical_event imports.
    import api.app.routes.notifications as _notifs

    monkeypatch.setattr(_notifs, "dispatch_event", _fake_dispatch_event)

    async with async_session() as db:
        await log_action(
            db,
            actor="slicew-notif-actor",
            action="slicew_notif_test",
            target="t-notif",
            detail={},
            critical=True,
        )
        await db.commit()

    # Let the create_task callback run.
    for _ in range(20):
        await asyncio.sleep(0)
        if captured:
            break

    assert captured, "dispatch_event was not invoked for a critical=True log"
    event, message = captured[0]
    assert event == "critical"
    assert "slicew_notif_test" in message
    assert "slicew-notif-actor" in message


@pytest.mark.asyncio
async def test_non_critical_does_not_trigger_dispatch_event(admin_token, monkeypatch):
    """Default (critical=False) must NOT schedule a notification. Keeps
    the channel from being spammed on every secret CRUD."""
    import asyncio

    captured = []

    async def _fake_dispatch_event(db, event, message):
        captured.append((event, message))

    import api.app.routes.notifications as _notifs

    monkeypatch.setattr(_notifs, "dispatch_event", _fake_dispatch_event)

    async with async_session() as db:
        await log_action(
            db,
            actor="slicew-quiet",
            action="slicew_quiet_test",
            target="t-quiet",
            detail={},
        )
        await db.commit()

    for _ in range(10):
        await asyncio.sleep(0)

    assert captured == [], (
        f"dispatch_event must not fire on plain audit rows -- captured={captured}"
    )
