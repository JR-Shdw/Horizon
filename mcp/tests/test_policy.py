# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Tests for the policy whitelist - the security-critical part of MCP."""

from rhorizon_mcp.policy import Policy, ProxyBinding, load_policy


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


def test_default_read_surface_includes_passive_ha_preflight():
    policy = Policy()
    assert policy.tool_allowed("vault_cluster_health") is True
    assert policy.tool_allowed("vault_cluster_preflight") is True


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


# --- credential proxy: use without read -------------------------------------


def test_proxy_binding_requires_allow_proxy():
    p = Policy(
        proxy={"gh": ProxyBinding(credential="gh", base_url="https://api.github.com")}
    )
    assert p.proxy_binding("gh") is None  # allow_proxy defaults False
    p.proxy["gh"].allow_proxy = True
    assert p.proxy_binding("gh") is not None


def test_proxy_binding_denied_when_deny_all():
    p = Policy(
        deny_all=True,
        proxy={
            "gh": ProxyBinding(
                credential="gh", allow_proxy=True, base_url="https://a.test"
            )
        },
    )
    assert p.proxy_binding("gh") is None


def test_allow_read_false_withholds_the_value_even_if_whitelisted():
    """The whole point: usable, not readable."""
    p = Policy(
        whitelist_secrets={"default/gh"},
        proxy={
            "gh": ProxyBinding(
                credential="gh",
                allow_proxy=True,
                allow_read=False,
                base_url="https://api.github.com",
            )
        },
    )
    assert p.secret_allowed("default", "gh") is False
    assert p.proxy_binding("gh") is not None


def test_allow_read_true_leaves_the_secret_readable():
    p = Policy(
        whitelist_secrets={"default/legacy"},
        proxy={
            "legacy": ProxyBinding(
                credential="legacy",
                allow_proxy=True,
                allow_read=True,
                base_url="https://api.example.test",
            )
        },
    )
    assert p.secret_allowed("default", "legacy") is True


def test_binding_in_another_namespace_does_not_withhold_reads():
    p = Policy(
        whitelist_secrets={"prod/gh"},
        proxy={
            "gh": ProxyBinding(credential="gh", namespace="staging", allow_proxy=True)
        },
    )
    assert p.secret_allowed("prod", "gh") is True


def test_url_allowed_rejects_prefix_lookalikes_and_plaintext():
    b = ProxyBinding(
        credential="gh", allow_proxy=True, base_url="https://api.github.com"
    )
    assert b.url_allowed("https://api.github.com/user/repos") is True
    assert b.url_allowed("https://api.github.com.evil.test/x") is False
    assert b.url_allowed("https://evil.test/api.github.com") is False
    assert (
        ProxyBinding(credential="x", base_url="http://api.test").url_allowed(
            "http://api.test/y"
        )
        is False
    )


def test_binding_without_base_url_permits_nothing():
    b = ProxyBinding(credential="x", allow_proxy=True)
    assert b.url_allowed("https://a.test/") is False


def test_methods_default_to_get_only():
    b = ProxyBinding(credential="x")
    assert b.method_allowed("get") is True
    assert b.method_allowed("DELETE") is False


def test_missing_proxy_table_yields_no_bindings(tmp_path):
    f = tmp_path / "policy.toml"
    f.write_text('[secrets]\nwhitelist = ["a/b"]\n')
    assert load_policy(f).proxy == {}


def test_proxy_table_round_trips(tmp_path):
    f = tmp_path / "policy.toml"
    f.write_text(
        "[proxy.github-prod]\n"
        'namespace = "mcp"\n'
        "allow_read = false\n"
        "allow_proxy = true\n"
        'base_url = "https://api.github.com"\n'
        'methods = ["get"]\n'
        'inject = { type = "header", name = "Authorization", '
        'format = "Bearer {value}" }\n'
    )
    pol = load_policy(f)
    b = pol.proxy_binding("github-prod")
    assert b is not None
    assert b.namespace == "mcp"
    assert b.methods == frozenset({"GET"})
    assert b.inject_format == "Bearer {value}"
    assert pol.secret_allowed("mcp", "github-prod") is False
