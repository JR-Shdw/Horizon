# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Tests for the policy whitelist - the security-critical part of MCP."""

from rhorizon_mcp.policy import Policy, load_policy


def test_empty_policy_denies_all_secrets():
    p = Policy()
    assert p.secret_allowed("default", "anything") is False
    assert p.secret_allowed("mcp/mail", "imap-password") is False


def test_whitelist_allows_specific_secrets():
    p = Policy(whitelist_secrets={"mcp/mail/imap-password", "default/api-key"})
    assert p.secret_allowed("mcp/mail", "imap-password") is True
    assert p.secret_allowed("default", "api-key") is True
    assert p.secret_allowed("mcp/mail", "other-secret") is False
    assert p.secret_allowed("prod", "api-key") is False  # different namespace


def test_namespace_wildcard():
    p = Policy(allow_namespaces={"mcp/demo"})
    assert p.secret_allowed("mcp/demo", "any-name") is True
    assert p.secret_allowed("mcp/demo", "another") is True
    assert p.secret_allowed("mcp/prod", "demo") is False  # wrong ns


def test_deny_all_overrides_whitelist():
    """Even if whitelist has entries, deny_all=True must refuse everything."""
    p = Policy(
        whitelist_secrets={"mcp/mail/imap-password"},
        allow_namespaces={"mcp/demo"},
        deny_all=True,
    )
    assert p.secret_allowed("mcp/mail", "imap-password") is False
    assert p.secret_allowed("mcp/demo", "x") is False


def test_tool_allow_list():
    p = Policy(allow_tools={"vault_get_secret", "vault_status"})
    assert p.tool_allowed("vault_get_secret") is True
    assert p.tool_allowed("vault_status") is True
    assert p.tool_allowed("vault_set_secret") is False
    assert p.tool_allowed("vault_audit_tail") is False


def test_load_policy_missing_file_returns_deny_all(tmp_path):
    nonexistent = tmp_path / "nope.toml"
    p = load_policy(nonexistent)
    assert p.deny_all is True


def test_load_policy_valid_file(tmp_path):
    f = tmp_path / "policy.toml"
    f.write_text(
        """
[secrets]
whitelist = ["mcp/mail/imap-password", "default/api-key"]

[namespaces]
allow = ["mcp/demo"]

[tools]
allow = ["vault_get_secret", "vault_whoami"]
"""
    )
    p = load_policy(f)
    assert p.deny_all is False
    assert "mcp/mail/imap-password" in p.whitelist_secrets
    assert "mcp/demo" in p.allow_namespaces
    assert p.tool_allowed("vault_get_secret") is True
    assert p.tool_allowed("vault_whoami") is True
    assert p.tool_allowed("vault_set_secret") is False


def test_load_policy_malformed_file_returns_deny_all(tmp_path):
    f = tmp_path / "broken.toml"
    f.write_text("this is [ not valid toml at all !@#$")
    p = load_policy(f)
    assert p.deny_all is True


def test_namespace_with_trailing_slash():
    """Edge case: secret_allowed must be tolerant of trailing/leading slashes."""
    p = Policy(whitelist_secrets={"mcp/mail/imap-password"})
    assert p.secret_allowed("mcp/mail", "imap-password") is True
    assert p.secret_allowed("mcp/mail/", "imap-password") is True
