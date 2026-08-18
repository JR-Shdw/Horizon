# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Unit tests for `actor_display_name()` - the audit display helper.

This guards the contract used by `log_action(actor=actor_display_name(token_info))`
across all routes : sessions minted by LDAP / SSO proxy carry a prefixed
token name (`ldap:shdw`, `proxy:shdw`) for uniqueness across auth sources,
but the prefix is noise for human-facing audit. API tokens have freeform
names that should pass through unchanged.
"""

from api.app.auth import actor_display_name


def test_proxy_session_strips_prefix():
    assert actor_display_name({"name": "proxy:shdw"}) == "shdw"


def test_ldap_session_strips_prefix():
    assert actor_display_name({"name": "ldap:alice"}) == "alice"


def test_api_token_freeform_name_preserved():
    # Long-lived API tokens have freeform names, return as-is.
    assert actor_display_name({"name": "ansible-prod-runner"}) == "ansible-prod-runner"


def test_name_with_colon_but_unknown_prefix_preserved():
    # Defensive : only the two known auth-source prefixes get stripped.
    # A token literally named `service:foo` keeps both halves.
    assert actor_display_name({"name": "service:foo"}) == "service:foo"


def test_empty_name_returns_empty_string():
    assert actor_display_name({"name": ""}) == ""


def test_missing_name_returns_empty_string():
    assert actor_display_name({}) == ""


def test_none_name_returns_empty_string():
    # Defensive: token_info dicts from upstream may have None entries.
    assert actor_display_name({"name": None}) == ""


def test_name_containing_known_prefix_substring_unaffected():
    # `proxylab` happens to start with `proxy` but not `proxy:`, leave it.
    assert actor_display_name({"name": "proxylab"}) == "proxylab"
    # And in the middle of the name : stripping is anchored to the start.
    assert (
        actor_display_name({"name": "user-with-proxy:in-the-middle"})
        == "user-with-proxy:in-the-middle"
    )


def test_double_prefix_only_strips_once():
    # Defensive edge case: if an external identifier itself starts with a
    # reserved source prefix, keep deterministic display semantics. Only the
    # outermost prefix is removed.
    assert actor_display_name({"name": "ldap:ldap:alice"}) == "ldap:alice"
