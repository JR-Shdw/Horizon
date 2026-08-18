"""Dynamic LDAP backend against a REAL directory (lldap in the itsm-lab).

Skipped unless RH_LLDAP_URL is set, so CI (no directory) ignores it. Run with:

  RH_LLDAP_URL=ldap://192.168.10.1:3890 \
  RH_LLDAP_BIND_DN='uid=admin,ou=people,dc=c0re,dc=me' \
  RH_LLDAP_BIND_PW="$(cat .../.credentials/lldap_admin_password)" \
  RH_LLDAP_BASE='dc=c0re,dc=me' \
  RHORIZON_DATABASE_URL=... RHORIZON_AUDIT_DIR=... \
  .venv/bin/python -m pytest tests/test_dynamic_ldap_real.py -q --no-cov

Exercises the full endpoint lifecycle end to end: create engine -> create role
(lldap LDIF) -> generate creds -> the entry exists in LDAP -> the generated
password actually BINDS as the new user -> revoke -> the entry is gone.
"""

import json
import os

import bonsai
import pytest

URL = os.environ.get("RH_LLDAP_URL")
BIND_DN = os.environ.get("RH_LLDAP_BIND_DN", "")
BIND_PW = os.environ.get("RH_LLDAP_BIND_PW", "")
BASE = os.environ.get("RH_LLDAP_BASE", "dc=c0re,dc=me")

pytestmark = pytest.mark.skipif(
    not URL, reason="RH_LLDAP_URL not set (no real LDAP directory)"
)

_CONN_JSON = json.dumps({"url": URL, "bind_dn": BIND_DN, "bind_pw": BIND_PW})

# lldap requires inetOrgPerson + a unique mail; {{name}} (the generated rh_<...>
# username) keeps the mail unique per credential.
_CREATE_LDIF = (
    "dn: uid={{name}},ou=people," + BASE + "\n"
    "objectClass: inetOrgPerson\n"
    "cn: {{name}}\n"
    "sn: {{name}}\n"
    "mail: {{name}}@example.com\n"
    "userPassword: {{password}}\n"
)
_REVOKE_DN = "uid={{name}},ou=people," + BASE


async def _entry_count(uid: str) -> int:
    c = bonsai.LDAPClient(URL)
    c.set_credentials("SIMPLE", BIND_DN, BIND_PW)
    conn = await c.connect(is_async=True, timeout=6)
    try:
        res = await conn.search(f"ou=people,{BASE}", 1, f"(uid={uid})")
        return len(res)
    finally:
        conn.close()


async def _bind_as(dn: str, password: str) -> bool:
    c = bonsai.LDAPClient(URL)
    c.set_credentials("SIMPLE", dn, password)
    try:
        conn = await c.connect(is_async=True, timeout=6)
        conn.close()
        return True
    except bonsai.errors.AuthenticationError:
        return False


@pytest.mark.asyncio
async def test_dynamic_ldap_real_lifecycle(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "lldap-real",
            "engine_type": "ldap",
            "connection_url": _CONN_JSON,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    engine_id = r.json()["id"]
    try:
        r = await client.post(
            f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
            json={
                "name": "dir-user",
                "creation_sql": _CREATE_LDIF,
                "revocation_sql": _REVOKE_DN,
                "default_ttl_seconds": 300,
            },
            headers=headers,
        )
        assert r.status_code == 201, r.text

        # Generate a credential -> a real lldap user is created.
        r = await client.post(
            f"/api/v1/vault/dynamic/engines/{engine_id}/creds/dir-user",
            json={"ttl_seconds": 300},
            headers=headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        username, password, dn, lease_id = (
            body["username"],
            body["password"],
            body["dn"],
            body["lease_id"],
        )
        assert dn == f"uid={username},ou=people,{BASE}"

        # The entry exists, and the generated password actually authenticates.
        assert await _entry_count(username) == 1
        assert await _bind_as(dn, password) is True
        assert await _bind_as(dn, "wrong-password") is False

        # Revoke -> the entry is deleted from the directory.
        r = await client.post(
            f"/api/v1/vault/dynamic/leases/{lease_id}/revoke", headers=headers
        )
        assert r.status_code == 200, r.text
        assert await _entry_count(username) == 0
        assert await _bind_as(dn, password) is False
    finally:
        await client.delete(
            f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers
        )
