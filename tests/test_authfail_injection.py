# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Auth-failure log integrity: no forged lines via X-Forwarded-For.

Covers the source fix (client_ip never returns an unvalidated header value)
and the sink fix (authfail sanitizes fields), and asserts the emitted line
still matches the shipped fail2ban filter (contrib/fail2ban/filter.d).
"""

import re
import types

import pytest
from api.app import authfail, client_ip


def _req(peer, xff=None):
    headers = {"x-forwarded-for": xff} if xff is not None else {}
    return types.SimpleNamespace(
        client=types.SimpleNamespace(host=peer), headers=headers
    )


@pytest.fixture(autouse=True)
def _restore_trusted():
    orig = client_ip.get_identity_trusted_proxies()
    yield
    client_ip.set_trusted_proxies(",".join(str(n) for n in orig) or None)


# --- source fix: client_ip.get_client_ip ---


def test_untrusted_peer_ignores_xff():
    client_ip.set_trusted_proxies("10.0.0.0/8")
    assert client_ip.get_client_ip(_req("203.0.113.5", "1.1.1.1")) == "203.0.113.5"


def test_trusted_peer_returns_real_client():
    client_ip.set_trusted_proxies("10.0.0.0/8")
    assert client_ip.get_client_ip(_req("10.0.0.2", "203.0.113.9")) == "203.0.113.9"


def test_all_trusted_returns_valid_leftmost():
    client_ip.set_trusted_proxies("10.0.0.0/8")
    assert client_ip.get_client_ip(_req("10.0.0.2", "10.0.0.7, 10.0.0.3")) == "10.0.0.7"


def test_garbage_leftmost_falls_back_to_peer():
    # Default-style wide trust: every real hop is trusted, so line (E) is
    # reached. A newline-laced leftmost must NOT be returned.
    client_ip.set_trusted_proxies("10.0.0.0/8")
    forged = "10.0.0.9\n2099-01-01T00:00:00+0000 rhorizon AUTH_FAIL ip=9.9.9.9 type=x"
    out = client_ip.get_client_ip(_req("10.0.0.2", forged))
    assert "\n" not in out
    assert out == "10.0.0.2"


# --- sink fix: authfail.log_authfail ---


def _point_log(tmp_path, monkeypatch):
    logf = tmp_path / "authfail.log"
    monkeypatch.setattr(authfail.settings, "authfail_log", str(logf))
    monkeypatch.setattr(authfail, "_log_path", None)
    return logf


def test_sanitize_blocks_forged_second_line(tmp_path, monkeypatch):
    logf = _point_log(tmp_path, monkeypatch)
    authfail.log_authfail(
        "1.2.3.4\n2099 rhorizon AUTH_FAIL ip=9.9.9.9 type=x", "invalid_token"
    )
    data = logf.read_text()
    # The newline and the '='/' ' that a forged line needs are stripped, so the
    # payload collapses into the single ip= token: exactly one physical line,
    # and the ip=/type= fields stay unique -> fail2ban sees one record, not two.
    assert data.count("\n") == 1
    assert data.count("ip=") == 1
    assert data.count("type=") == 1


def test_emitted_line_matches_shipped_filter(tmp_path, monkeypatch):
    logf = _point_log(tmp_path, monkeypatch)
    authfail.log_authfail("192.168.1.42", "invalid_token")
    line = logf.read_text().strip()
    # mirror contrib/fail2ban/filter.d/rhorizon.conf (<HOST> -> ip capture).
    host = r"(?P<host>[0-9a-fA-F:.]+)"
    failregex = re.compile(rf"^.*rhorizon AUTH_FAIL ip={host} type=\S+\s*$")
    m = failregex.match(line)
    assert m and m.group("host") == "192.168.1.42"
