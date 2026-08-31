# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""The credential proxy on the stdio path (rhorizon_mcp/proxy.py).

Two properties carry the feature: the caller cannot choose the destination, and
the value does not come back by the reply path.
"""

import io
import json
import subprocess
import urllib.error

import pytest

from rhorizon_mcp import proxy, server
from rhorizon_mcp.policy import (
    Policy,
    ProxyBinding,
    ProxyDenied,
    same_authority,
)

BINDING = ProxyBinding(
    credential="github-prod",
    namespace="mcp",
    allow_read=False,
    allow_proxy=True,
    base_url="https://api.github.com",
    methods=frozenset({"GET"}),
)


# --- destination: the binding decides, the caller does not -------------------


def test_a_plain_path_lands_on_the_bound_host():
    assert BINDING.build_url("/user/repos") == "https://api.github.com/user/repos"


def test_query_is_appended_and_encoded():
    url = BINDING.build_url("/search", {"q": "a b&c"})
    assert url == "https://api.github.com/search?q=a+b%26c"


def test_query_merges_into_a_path_that_already_has_one():
    url = BINDING.build_url("/search?sort=stars", {"q": "x"})
    assert url == "https://api.github.com/search?sort=stars&q=x"


@pytest.mark.parametrize(
    "path",
    [
        "//evil.test/x",  # protocol-relative: re-authorities the URL
        "@evil.test/",  # userinfo trick, and does not start with '/'
        "user/repos",  # relative: would concatenate onto the host
        "/x/../../admin",  # climbs out of a base that pins a path
        "/x/%2e%2e/admin",  # same, percent-encoded
        "/x/%2E%2E/admin",
        "/user repos",  # space splits the request line
        "/user\r\nX-Evil: 1",
        "/user#frag",
    ],
)
def test_a_path_that_could_move_the_host_is_refused(path):
    with pytest.raises(ProxyDenied):
        BINDING.build_url(path)


def test_a_base_pinning_a_path_confines_the_caller_to_it():
    b = ProxyBinding(
        credential="gl",
        allow_proxy=True,
        base_url="https://gitlab.example/api/v4",
    )
    assert b.build_url("/projects") == "https://gitlab.example/api/v4/projects"
    with pytest.raises(ProxyDenied):
        b.build_url("/../../admin")


def test_a_binding_without_a_base_url_builds_nothing():
    with pytest.raises(ProxyDenied):
        ProxyBinding(credential="x", allow_proxy=True).build_url("/a")


# --- execution ---------------------------------------------------------------


class _FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class _RecordingOpener:
    """Records the request, replays a canned reply."""

    def __init__(self, body=b"{}", status=200, error=None):
        self.body = body
        self.status = status
        self.error = error
        self.requests = []

    def open(self, req, timeout=None):
        self.requests.append(req)
        if self.error is not None:
            raise self.error
        return _FakeResponse(self.body, self.status)


def test_the_credential_is_attached_in_the_bound_header():
    opener = _RecordingOpener(body=b'{"login":"octocat"}')
    out = proxy.call(
        BINDING, "ghp_secret", "https://api.github.com/user", opener=opener
    )
    req = opener.requests[0]
    assert req.get_header("Authorization") == "Bearer ghp_secret"
    assert req.get_method() == "GET"
    assert out == {"status": 200, "body": {"login": "octocat"}, "truncated": False}


def test_a_credential_carrying_crlf_cannot_split_the_request():
    with pytest.raises(ProxyDenied):
        proxy.call(
            BINDING,
            "abc\r\nX-Evil: 1",
            "https://api.github.com/user",
            opener=_RecordingOpener(),
        )


def test_a_body_echoing_the_credential_is_withheld():
    opener = _RecordingOpener(body=b'{"message":"bad credentials: ghp_secret"}')
    with pytest.raises(ProxyDenied, match="echoed"):
        proxy.call(BINDING, "ghp_secret", "https://api.github.com/user", opener=opener)


def test_an_error_body_echoing_the_credential_is_withheld_too():
    err = urllib.error.HTTPError(
        "https://api.github.com/user",
        401,
        "Unauthorized",
        {},
        io.BytesIO(b'{"token":"ghp_secret"}'),
    )
    opener = _RecordingOpener(error=err)
    with pytest.raises(ProxyDenied, match="echoed"):
        proxy.call(BINDING, "ghp_secret", "https://api.github.com/user", opener=opener)


def test_an_upstream_error_without_an_echo_comes_back_as_a_status():
    err = urllib.error.HTTPError(
        "https://api.github.com/user",
        404,
        "Not Found",
        {},
        io.BytesIO(b'{"message":"Not Found"}'),
    )
    out = proxy.call(
        BINDING,
        "ghp_secret",
        "https://api.github.com/user",
        opener=_RecordingOpener(error=err),
    )
    assert out["status"] == 404
    assert out["body"] == {"message": "Not Found"}


def test_a_redirect_is_refused_rather_than_followed():
    err = urllib.error.HTTPError(
        "https://api.github.com/user",
        302,
        "Found",
        {"Location": "https://evil.test/"},
        io.BytesIO(b""),
    )
    with pytest.raises(ProxyDenied, match="redirect"):
        proxy.call(
            BINDING,
            "ghp_secret",
            "https://api.github.com/user",
            opener=_RecordingOpener(error=err),
        )


def test_an_oversized_response_is_capped_and_flagged():
    b = ProxyBinding(
        credential="x",
        allow_proxy=True,
        base_url="https://api.github.com",
        max_response_bytes=16,
    )
    opener = _RecordingOpener(body=b"x" * 500)
    out = proxy.call(b, "ghp_secret", "https://api.github.com/user", opener=opener)
    assert out["truncated"] is True
    assert len(out["body"]) == 16


def test_the_upstream_leg_verifies_against_the_system_store():
    ctx = proxy.upstream_context()
    assert ctx.verify_mode.name == "CERT_REQUIRED"
    assert ctx.check_hostname is True


def test_an_egress_ca_is_added_to_the_system_store_not_swapped_for_it(
    tmp_path, monkeypatch
):
    """`create_default_context(cafile=...)` loads that file INSTEAD of the
    system store. Pinning an internal API's CA that way would silently stop
    every public API from verifying."""
    ca = tmp_path / "internal-ca.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=internal-e2e-ca",
            # get_ca_certs() lists CA-flagged certs only, and `req -x509`
            # defaults to CA:TRUE on OpenSSL 3.x but not on LibreSSL.
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            str(tmp_path / "ca.key"),
            "-out",
            str(ca),
        ],
        check=True,
        capture_output=True,
    )
    monkeypatch.setattr(proxy, "_upstream_ctx", None)
    ctx = proxy.upstream_context(str(ca))
    subjects = str(ctx.get_ca_certs())
    assert "internal-e2e-ca" in subjects
    assert len(ctx.get_ca_certs()) > 1  # the public roots are still there


def test_rate_limiter_stops_at_the_configured_ceiling():
    rl = proxy.RateLimiter()
    assert [rl.allow("gh", 3) for _ in range(4)] == [True, True, True, False]
    assert rl.allow("other", 3) is True  # counted per credential
    assert rl.allow("gh", 0) is False  # zero means no calls, not unlimited


# --- the tool as the model reaches it ----------------------------------------


class _FakeVaultClient:
    def __init__(self, value="ghp_secret", base="http://127.0.0.1:8200"):
        self.reads = []
        self._value = value
        self.base = base  # the real VaultClient exposes this; the guard reads it

    def get_secret(self, name, namespace):
        self.reads.append((namespace, name))
        return {"name": name, "value": self._value}


def _policy(**overrides) -> Policy:
    b = ProxyBinding(**{**BINDING.__dict__, **overrides})
    return Policy(proxy={b.credential: b})


def test_an_unbound_credential_is_refused_without_reading_anything():
    client = _FakeVaultClient()
    out = server._dispatch(
        "vault_call_api",
        {"credential": "not-bound", "path": "/user"},
        client,
        _policy(),
    )
    assert out["error"] == "policy_denied"
    assert client.reads == []


def test_a_method_outside_the_binding_is_refused_before_the_read():
    client = _FakeVaultClient()
    out = server._dispatch(
        "vault_call_api",
        {"credential": "github-prod", "path": "/user", "method": "DELETE"},
        client,
        _policy(),
    )
    assert out["error"] == "policy_denied"
    assert client.reads == []


def test_a_bad_path_is_refused_before_the_read():
    client = _FakeVaultClient()
    out = server._dispatch(
        "vault_call_api",
        {"credential": "github-prod", "path": "//evil.test/"},
        client,
        _policy(),
    )
    assert out["error"] == "policy_denied"
    assert client.reads == []


def test_a_permitted_call_reads_the_credential_from_its_bound_namespace(monkeypatch):
    client = _FakeVaultClient()
    seen = {}

    def fake_call(binding, value, url, *, method="GET", opener=None):
        seen.update(binding=binding, value=value, url=url, method=method)
        return {"status": 200, "body": {"ok": True}, "truncated": False}

    monkeypatch.setattr(proxy, "call", fake_call)
    out = server._dispatch(
        "vault_call_api",
        {"credential": "github-prod", "path": "/user/repos"},
        client,
        _policy(),
    )
    assert client.reads == [("mcp", "github-prod")]
    assert seen["url"] == "https://api.github.com/user/repos"
    assert seen["value"] == "ghp_secret"
    assert out["body"] == {"ok": True}


def test_the_same_credential_is_not_readable_through_get_secret():
    client = _FakeVaultClient()
    out = server._dispatch(
        "vault_get_secret",
        {"name": "github-prod", "namespace": "mcp"},
        client,
        _policy(),
    )
    assert out["error"] == "policy_denied"
    assert "vault_call_api" in out["message"]  # not "add it to the whitelist"
    assert client.reads == []


def test_a_secret_that_is_merely_unlisted_still_says_so():
    """One refusal is an oversight to fix, the other is the binding working."""
    client = _FakeVaultClient()
    out = server._dispatch(
        "vault_get_secret", {"name": "other", "namespace": "mcp"}, client, _policy()
    )
    assert out["error"] == "policy_denied"
    assert "whitelist" in out["message"]


# --- refusals name the fix ---------------------------------------------------


def _binding(**over) -> ProxyBinding:
    return ProxyBinding(**{**BINDING.__dict__, **over})


@pytest.mark.parametrize(
    "over,fragment",
    [
        ({"inject_format": "token NOPLACEHOLDER"}, "{value} placeholder"),
        ({"inject_type": "query"}, 'only "header" is supported'),
    ],
)
def test_a_malformed_binding_is_refused_before_the_credential_is_read(over, fragment):
    """Left until injection time, a typo in the operator's table would spend a
    vault read and then report itself as whatever that read returned -- which is
    how it surfaced as 'secret not found'."""
    client = _FakeVaultClient()
    b = _binding(**over)
    out = server._dispatch(
        "vault_call_api",
        {"credential": b.credential, "path": "/user"},
        client,
        Policy(proxy={b.credential: b}),
    )
    assert out["error"] == "policy_denied"
    assert fragment in out["message"]
    assert client.reads == []


def test_a_binding_that_exists_but_forbids_proxying_says_so():
    """Telling the operator to add a table they already wrote sends them
    looking for the wrong thing."""
    b = _binding(allow_proxy=False)
    out = server._dispatch(
        "vault_call_api",
        {"credential": b.credential, "path": "/user"},
        _FakeVaultClient(),
        Policy(proxy={b.credential: b}),
    )
    assert "allow_proxy = false" in out["message"]


def test_a_method_refusal_names_the_methods_that_are_allowed():
    out = server._dispatch(
        "vault_call_api",
        {"credential": "github-prod", "path": "/user", "method": "DELETE"},
        _FakeVaultClient(),
        _policy(),
    )
    assert "allowed: GET" in out["message"]


def test_an_unknown_credential_lists_the_ones_that_are_bound():
    out = server._dispatch(
        "vault_call_api",
        {"credential": "typo", "path": "/user"},
        _FakeVaultClient(),
        _policy(),
    )
    assert "github-prod" in out["message"]


@pytest.mark.parametrize(
    "args,fragment",
    [
        ({"credential": "github-prod"}, "path is required"),
        ({"path": "/user"}, "credential is required"),
        ({"credential": "github-prod", "path": "//evil.test/"}, "another host"),
        ({"credential": "github-prod", "path": "user"}, "must start with '/'"),
    ],
)
def test_a_bad_argument_says_which_one_and_why(args, fragment):
    out = server._dispatch("vault_call_api", args, _FakeVaultClient(), _policy())
    assert out["error"] == "policy_denied"
    assert fragment in out["message"]


@pytest.mark.parametrize(
    "base,fragment",
    [
        ("http://127.0.0.1:8090", "must be https"),
        ("", "has no base_url"),
    ],
)
def test_an_unusable_base_url_says_which_way_it_is_unusable(base, fragment):
    b = _binding(base_url=base)
    out = server._dispatch(
        "vault_call_api",
        {"credential": b.credential, "path": "/user"},
        _FakeVaultClient(),
        Policy(proxy={b.credential: b}),
    )
    assert fragment in out["message"]


def test_a_vault_refusal_keeps_the_tool_error_shape():
    """Every other refusal is {error: <code>, message: <text>}; a vault HTTP
    error used to come back as one human sentence under `error`."""

    class _Refusing(_FakeVaultClient):
        def get_secret(self, name, namespace):
            raise server.VaultHTTPError(403, "forbidden")

    out = server._dispatch(
        "vault_call_api",
        {"credential": "github-prod", "path": "/user"},
        _Refusing(),
        _policy(),
    )
    assert out["error"] == "vault_error"
    assert "secrets:r" in out["message"]


# --- the confused deputy -----------------------------------------------------


def test_a_binding_aimed_at_the_vault_is_refused_before_the_read():
    """The whole point of hiding the token is lost if the agent can ask the
    holder to use it. A binding pointed at the vault would make this tool the
    vault's own authenticated client."""
    client = _FakeVaultClient()
    b = _binding(base_url="http://127.0.0.1:8200")
    out = server._dispatch(
        "vault_call_api",
        {"credential": b.credential, "path": "/api/v1/vault/secrets/other"},
        client,
        Policy(proxy={b.credential: b}),
    )
    assert out["error"] == "policy_denied"
    assert "vault itself" in out["message"]
    assert client.reads == []


@pytest.mark.parametrize(
    "base,vault,same",
    [
        ("https://127.0.0.1:8200", "http://127.0.0.1:8200", True),  # scheme differs
        ("https://V.Lab:443", "https://v.lab", True),  # case + default port
        ("https://127.0.0.1:9000", "https://127.0.0.1:8443", False),  # other port
        ("https://api.github.com", "https://127.0.0.1:8200", False),
        ("https://user@127.0.0.1:8200", "https://127.0.0.1:8200", False),  # userinfo
        ("ftp://127.0.0.1:8200", "https://127.0.0.1:8200", False),  # unparseable
    ],
)
def test_the_vault_is_matched_by_authority_not_by_string(base, vault, same):
    assert same_authority(base, vault) is same


def test_the_tool_result_never_carries_the_credential(monkeypatch):
    """Through _call_tool, which is what reaches the model."""
    client = _FakeVaultClient()
    monkeypatch.setattr(
        proxy,
        "call",
        lambda *a, **k: {
            "status": 200,
            "body": {"login": "octocat"},
            "truncated": False,
        },
    )
    result = server._call_tool(
        "vault_call_api",
        {"credential": "github-prod", "path": "/user"},
        client,
        _policy(),
    )
    text = json.dumps(result)
    assert "octocat" in text
    assert "ghp_secret" not in text
