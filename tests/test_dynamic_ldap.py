"""LDAP dynamic backend. No real directory in CI: bonsai's LDAPClient is faked
so the connection never leaves the process, while the real LDAPEntry / template
rendering / LDIF parsing are exercised end to end.
"""

import asyncio
import json

import bonsai
import pytest
from api.app.dynamic_engines import ldap
from api.app.routes import dynamic

_LDAP_CONN = json.dumps(
    {
        "url": "ldap://localhost:389",
        "bind_dn": "cn=admin,dc=example,dc=com",
        "bind_pw": "admin-secret",
    }
)

_CREATE_LDIF = (
    "dn: cn={{name}},ou=people,dc=example,dc=com\n"
    "objectClass: inetOrgPerson\n"
    "objectClass: simpleSecurityObject\n"
    "cn: {{name}}\n"
    "sn: {{name}}\n"
    "userPassword: {{password}}\n"
)
_REVOKE_DN = "cn={{name}},ou=people,dc=example,dc=com"


class _FakeLDAPConn:
    def __init__(self, ops):
        self._ops = ops

    async def add(self, entry):
        self._ops.append(("add", entry))

    async def modify_password(self, user=None, new_password=None):
        self._ops.append(("modify_password", (user, new_password)))

    async def delete(self, dn):
        self._ops.append(("delete", dn))

    async def search(self, *args, **kwargs):
        self._ops.append(("search", (args, kwargs)))
        return [{"vendorName": ["lldap"], "vendorVersion": ["0.6.2"]}]

    def close(self):
        self._ops.append(("close", None))


class _FakeLDAPClient:
    ops: list = []

    def __init__(self, url):
        self.url = url

    def set_credentials(self, *args, **kwargs):
        pass

    async def connect(self, is_async=True, timeout=None):
        return _FakeLDAPConn(_FakeLDAPClient.ops)


@pytest.fixture
def fake_ldap(monkeypatch):
    _FakeLDAPClient.ops = []
    monkeypatch.setattr(bonsai, "LDAPClient", _FakeLDAPClient)
    return _FakeLDAPClient.ops


# -- pure helpers ------------------------------------------------------------


def test_parse_ldap_conn_ok():
    cfg = ldap.parse_connection(_LDAP_CONN)
    assert cfg["url"] == "ldap://localhost:389"
    assert cfg["bind_dn"] == "cn=admin,dc=example,dc=com"


@pytest.mark.parametrize(
    "blob",
    [
        "not json",
        json.dumps({"url": "x"}),
        "[]",
        json.dumps(
            {
                "url": "ldaps://directory.example:636",
                "bind_dn": "cn=admin",
                "bind_pw": "secret",
                "verify_tls": True,
            }
        ),
        json.dumps(
            {
                "url": "ldaps://",
                "bind_dn": "cn=admin",
                "bind_pw": "secret",
            }
        ),
        json.dumps(
            {
                "url": "ldaps://user:pw@directory.example",
                "bind_dn": "cn=admin",
                "bind_pw": "secret",
            }
        ),
        json.dumps(
            {
                "url": "ldaps://directory.example:0",
                "bind_dn": "cn=admin",
                "bind_pw": "secret",
            }
        ),
        json.dumps(
            {
                "url": "ldaps://directory.example?ignored=true",
                "bind_dn": "cn=admin",
                "bind_pw": "secret",
            }
        ),
    ],
)
def test_parse_ldap_conn_rejects_bad(blob):
    with pytest.raises(ValueError):
        ldap.parse_connection(blob)


def test_parse_ldap_conn_rejects_duplicate_keys_without_echoing_values():
    blob = (
        '{"url":"ldaps://expected","url":"ldap://unexpected",'
        '"bind_dn":"cn=admin","bind_pw":"secret"}'
    )
    with pytest.raises(ValueError) as exc:
        ldap.parse_connection(blob)

    assert "duplicate" in str(exc.value)
    assert "expected" not in str(exc.value)
    assert "unexpected" not in str(exc.value)
    assert "secret" not in str(exc.value)


def test_parse_ldif_ok():
    dn, attrs = ldap.parse_ldif(
        _CREATE_LDIF.replace("{{name}}", "rh_x").replace("{{password}}", "pw")
    )
    assert dn == "cn=rh_x,ou=people,dc=example,dc=com"
    assert attrs["objectClass"] == ["inetOrgPerson", "simpleSecurityObject"]
    assert attrs["userPassword"] == ["pw"]
    assert attrs["cn"] == ["rh_x"]


def test_parse_ldif_missing_dn():
    with pytest.raises(ValueError):
        ldap.parse_ldif("cn: x\nsn: y\n")


def test_parse_ldif_malformed_line():
    with pytest.raises(ValueError):
        ldap.parse_ldif("dn: cn=x\nnocolonhere\n")


@pytest.mark.parametrize(
    "ldif",
    [
        "dn: cn=first,dc=example\nDN: cn=second,dc=example\ncn: user\n",
        "dn: cn=user,dc=example\nuserPassword:: c2VjcmV0\n",
        "dn: cn=user,dc=example\njpegPhoto:< file:///tmp/photo\n",
        "dn: cn=user,dc=example\n: empty-name\n",
    ],
)
def test_parse_ldif_rejects_ambiguous_or_unsupported_forms(ldif):
    with pytest.raises(ValueError):
        ldap.parse_ldif(ldif)


def test_parse_ldif_error_does_not_echo_rendered_secret():
    with pytest.raises(ValueError) as exc:
        ldap.parse_ldif("dn: cn=user,dc=example\nuserPassword secret-value\n")

    assert "secret-value" not in str(exc.value)


def test_password_attribute_is_case_insensitive_and_unique():
    assert ldap._password({"UserPassword": ["one"]}) == "one"
    with pytest.raises(ValueError):
        ldap._password(
            {
                "userPassword": ["one"],
                "UserPassword": ["two"],
            }
        )


# -- helper dispatch (faked connection) --------------------------------------


@pytest.mark.asyncio
async def test_ldap_add_builds_entry(fake_ldap):
    rendered = _CREATE_LDIF.replace("{{name}}", "rh_a").replace(
        "{{password}}", "s3cr3t"
    )
    await ldap.add_entry(_LDAP_CONN, rendered)
    kinds = [op[0] for op in fake_ldap]
    assert "add" in kinds and kinds[-1] == "close"
    entry = next(op[1] for op in fake_ldap if op[0] == "add")
    assert str(entry.dn) == "cn=rh_a,ou=people,dc=example,dc=com"
    assert list(entry["userPassword"]) == ["s3cr3t"]


@pytest.mark.asyncio
async def test_ldap_rejects_multiple_passwords_before_target_mutation(fake_ldap):
    rendered = (
        "dn: cn=rh_a,ou=people,dc=example,dc=com\n"
        "objectClass: inetOrgPerson\n"
        "userPassword: one\n"
        "UserPassword: two\n"
    )

    with pytest.raises(ValueError):
        await ldap.add_entry(_LDAP_CONN, rendered)

    assert fake_ldap == []


@pytest.mark.asyncio
async def test_ldap_add_timeout_closes_connection(monkeypatch):
    class SlowConnection(_FakeLDAPConn):
        async def add(self, _entry):
            await asyncio.sleep(1)

    connection = SlowConnection([])

    class Client(_FakeLDAPClient):
        async def connect(self, is_async=True, timeout=None):
            return connection

    monkeypatch.setattr(bonsai, "LDAPClient", Client)
    monkeypatch.setattr(ldap, "ENGINE_CONNECT_TIMEOUT", 0.01)

    with pytest.raises(TimeoutError):
        await ldap.add_entry(
            _LDAP_CONN,
            _CREATE_LDIF.replace("{{name}}", "rh_a").replace(
                "{{password}}",
                "secret",
            ),
        )

    assert ("close", None) in connection._ops


@pytest.mark.asyncio
async def test_ldap_password_modify_warning_never_logs_rendered_dn(
    monkeypatch,
    caplog,
):
    class UnsupportedConnection(_FakeLDAPConn):
        async def modify_password(self, user=None, new_password=None):
            raise bonsai.LDAPError("unsupported")

    connection = UnsupportedConnection([])

    class Client(_FakeLDAPClient):
        async def connect(self, is_async=True, timeout=None):
            return connection

    monkeypatch.setattr(bonsai, "LDAPClient", Client)
    rendered = (
        "dn: cn=rendered-secret,ou=people,dc=example,dc=com\n"
        "objectClass: inetOrgPerson\n"
        "userPassword: rendered-secret\n"
    )

    await ldap.add_entry(_LDAP_CONN, rendered)

    assert "password-modify unsupported" in caplog.text
    assert "rendered-secret" not in caplog.text


@pytest.mark.asyncio
async def test_ldap_delete_strips_dn_prefix(fake_ldap):
    await ldap.delete_entry(_LDAP_CONN, "dn: cn=rh_a,dc=example,dc=com")
    deleted = [op[1] for op in fake_ldap if op[0] == "delete"]
    assert deleted == ["cn=rh_a,dc=example,dc=com"]


@pytest.mark.asyncio
@pytest.mark.parametrize("rendered_dn", ["", "dn:", "cn=one\ncn=two"])
async def test_ldap_delete_rejects_invalid_dn_before_target_mutation(
    fake_ldap,
    rendered_dn,
):
    with pytest.raises(ValueError):
        await ldap.delete_entry(_LDAP_CONN, rendered_dn)

    assert fake_ldap == []


@pytest.mark.asyncio
async def test_ldap_delete_is_idempotent_when_entry_is_absent(monkeypatch):
    class MissingConnection(_FakeLDAPConn):
        async def delete(self, _dn):
            raise bonsai.NoSuchObjectError("already absent")

    connection = MissingConnection([])

    class Client(_FakeLDAPClient):
        async def connect(self, is_async=True, timeout=None):
            return connection

    monkeypatch.setattr(bonsai, "LDAPClient", Client)

    await ldap.delete_entry(_LDAP_CONN, "cn=missing,dc=example")

    assert ("close", None) in connection._ops


@pytest.mark.asyncio
async def test_ldap_delete_timeout_closes_connection(monkeypatch):
    class SlowConnection(_FakeLDAPConn):
        async def delete(self, _dn):
            await asyncio.sleep(1)

    connection = SlowConnection([])

    class Client(_FakeLDAPClient):
        async def connect(self, is_async=True, timeout=None):
            return connection

    monkeypatch.setattr(bonsai, "LDAPClient", Client)
    monkeypatch.setattr(ldap, "ENGINE_CONNECT_TIMEOUT", 0.01)

    with pytest.raises(TimeoutError):
        await ldap.delete_entry(_LDAP_CONN, "cn=slow,dc=example")

    assert ("close", None) in connection._ops


@pytest.mark.asyncio
async def test_ldap_probe_timeout_closes_connection(monkeypatch):
    class SlowConnection(_FakeLDAPConn):
        async def search(self, *_args, **_kwargs):
            await asyncio.sleep(1)

    connection = SlowConnection([])

    class Client(_FakeLDAPClient):
        async def connect(self, is_async=True, timeout=None):
            return connection

    monkeypatch.setattr(bonsai, "LDAPClient", Client)
    monkeypatch.setattr(ldap, "ENGINE_CONNECT_TIMEOUT", 0.01)

    with pytest.raises(TimeoutError):
        await ldap.probe_directory(_LDAP_CONN)

    assert ("close", None) in connection._ops


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type",
    [
        bonsai.AuthenticationError,
        bonsai.ConnectionError,
        bonsai.PasswordPolicyError,
        bonsai.ProtocolError,
        bonsai.TimeoutError,
    ],
)
async def test_ldap_probe_propagates_security_and_transport_errors(
    monkeypatch,
    error_type,
):
    class FailedSearchConnection(_FakeLDAPConn):
        async def search(self, *_args, **_kwargs):
            raise error_type("probe failed")

    connection = FailedSearchConnection([])

    class Client(_FakeLDAPClient):
        async def connect(self, is_async=True, timeout=None):
            return connection

    monkeypatch.setattr(bonsai, "LDAPClient", Client)

    with pytest.raises(error_type):
        await ldap.probe_directory(_LDAP_CONN)

    assert ("close", None) in connection._ops


@pytest.mark.asyncio
async def test_ldap_probe_tolerates_unavailable_vendor_metadata(monkeypatch):
    class MetadataDeniedConnection(_FakeLDAPConn):
        async def search(self, *_args, **_kwargs):
            raise bonsai.LDAPError("metadata unavailable")

    connection = MetadataDeniedConnection([])

    class Client(_FakeLDAPClient):
        async def connect(self, is_async=True, timeout=None):
            return connection

    monkeypatch.setattr(bonsai, "LDAPClient", Client)

    assert await ldap.probe_directory(_LDAP_CONN) == (None, None)
    assert ("close", None) in connection._ops


@pytest.mark.asyncio
async def test_revoke_credential_ldap_dispatch(fake_ldap):
    await dynamic._revoke_credential("ldap", _LDAP_CONN, _REVOKE_DN, "rh_role_xyz")
    deleted = [op[1] for op in fake_ldap if op[0] == "delete"]
    assert deleted == ["cn=rh_role_xyz,ou=people,dc=example,dc=com"]


@pytest.mark.asyncio
async def test_ldap_probe_reads_root_dse(fake_ldap):
    product, version = await ldap.probe_directory(_LDAP_CONN)
    assert (product, version) == ("lldap", "0.6.2")
    assert any(op[0] == "search" for op in fake_ldap)
    assert fake_ldap[-1][0] == "close"


# -- full route lifecycle (faked connection) ---------------------------------


@pytest.mark.asyncio
async def test_ldap_engine_full_lifecycle(
    client, master_password, admin_token, fake_ldap
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "ldap-eng",
            "engine_type": "ldap",
            "connection_url": _LDAP_CONN,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    engine_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "dir-user",
            "creation_sql": _CREATE_LDIF,
            "revocation_sql": _REVOKE_DN,
            "default_ttl_seconds": 120,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text

    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/creds/dir-user",
        json={"ttl_seconds": 120},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    username = r.json()["username"]
    password = r.json()["password"]
    lease_id = r.json()["lease_id"]
    expected_dn = f"cn={username},ou=people,dc=example,dc=com"

    # The response carries the bind DN (cn alone can't bind).
    assert r.json()["dn"] == expected_dn

    # The entry was added with the rendered DN + password.
    entry = next(op[1] for op in fake_ldap if op[0] == "add")
    assert str(entry.dn) == expected_dn
    assert list(entry["userPassword"]) == [password]

    # And the password was set via the RFC 3062 Password-Modify extended op.
    mp = next(op[1] for op in fake_ldap if op[0] == "modify_password")
    assert mp == (expected_dn, password)

    # Revoke deletes that exact DN.
    r = await client.post(
        f"/api/v1/vault/dynamic/leases/{lease_id}/revoke", headers=headers
    )
    assert r.status_code == 200, r.text
    deleted = [op[1] for op in fake_ldap if op[0] == "delete"]
    assert f"cn={username},ou=people,dc=example,dc=com" in deleted

    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_ldap_engine_rejects_bad_conn(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "ldap-bad",
            "engine_type": "ldap",
            "connection_url": "not-json",
        },
        headers=headers,
    )
    assert r.status_code == 400
