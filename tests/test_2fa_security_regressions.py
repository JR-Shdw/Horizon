# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Unit regressions for 2FA-protected mutation paths."""

import pytest


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar(self):
        return self.value


class _FakeDB:
    async def execute(self, *args, **kwargs):
        return _ScalarResult(0)


@pytest.mark.asyncio
async def test_namespace_mutation_2fa_delegates_decrypt(monkeypatch):
    """B6: the namespace 2FA gate must pass aesgcm=None so 2FA-secret decrypt is
    RPC-delegated (follower-safe), NOT the master-only vault.aesgcm property."""
    from api.app.routes import namespaces
    from api.app.routes import vault as vault_routes
    from api.app.vault_state import vault

    sentinel_aesgcm = object()
    monkeypatch.setattr(vault, "_aesgcm", sentinel_aesgcm)

    calls = {}

    async def fake_get_2fa_mode(db):
        return "totp"

    async def fake_verify_2fa(db, mode, body, client_ip, aesgcm=None, purpose="unseal"):
        calls["mode"] = mode
        calls["aesgcm"] = aesgcm
        calls["purpose"] = purpose
        return "totp"

    monkeypatch.setattr(vault_routes, "_get_2fa_mode", fake_get_2fa_mode)
    monkeypatch.setattr(vault_routes, "_verify_2fa", fake_verify_2fa)

    body = namespaces.NamespaceCreate(
        name="unit-2fa",
        owner_group_id="00000000-0000-0000-0000-000000000001",
        totp_code="123456",
    )
    await namespaces._gate_mutation(
        _FakeDB(), body, {"name": "unit-admin"}, "127.0.0.1"
    )

    assert calls == {
        "mode": "totp",
        "aesgcm": None,  # delegated, not the master-only sentinel
        "purpose": "namespace_mutation",
    }


@pytest.mark.asyncio
async def test_protected_secret_delete_2fa_delegates_decrypt(monkeypatch):
    """B6: protected-delete 2FA must pass aesgcm=None so 2FA-secret decrypt is
    RPC-delegated (follower-safe), NOT the master-only vault.aesgcm property."""
    from api.app.routes import secrets
    from api.app.routes import vault as vault_routes
    from api.app.vault_state import vault

    sentinel_aesgcm = object()
    monkeypatch.setattr(vault, "_aesgcm", sentinel_aesgcm)

    calls = {}

    async def fake_get_2fa_mode(db):
        return "totp"

    async def fake_verify_2fa(db, mode, body, client_ip, aesgcm=None, purpose="unseal"):
        calls["mode"] = mode
        calls["aesgcm"] = aesgcm
        calls["purpose"] = purpose
        return "totp"

    monkeypatch.setattr(vault_routes, "_get_2fa_mode", fake_get_2fa_mode)
    monkeypatch.setattr(vault_routes, "_verify_2fa", fake_verify_2fa)

    await secrets._verify_protected_delete_2fa(
        _FakeDB(),
        secrets._DeleteBody(totp_code="123456"),
        {"permissions": {"admin": "rw"}},
        "127.0.0.1",
    )

    assert calls == {
        "mode": "totp",
        "aesgcm": None,  # delegated, not the master-only sentinel
        "purpose": "delete_protected_secret",
    }
