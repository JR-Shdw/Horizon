# SPDX-License-Identifier: AGPL-3.0-or-later
"""LDAP dynamic entries."""

import asyncio
import json
import logging
from urllib.parse import urlparse

from ..base import ENGINE_CONNECT_TIMEOUT, DynamicEngine, EngineProbe, EngineSupport

log = logging.getLogger("rhorizon.dynamic.ldap")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ldap connection JSON contains duplicate keys")
        result[key] = value
    return result


def parse_connection(conn_url: str) -> dict:
    try:
        cfg = json.loads(conn_url, object_pairs_hook=_unique_json_object)
        if not isinstance(cfg, dict) or set(cfg) != {"url", "bind_dn", "bind_pw"}:
            raise TypeError
        url, bind_dn, bind_pw = cfg["url"], cfg["bind_dn"], cfg["bind_pw"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(
            'ldap connection_url must be JSON {"url","bind_dn","bind_pw"}'
        ) from exc
    if not all(isinstance(value, str) and value for value in (url, bind_dn, bind_pw)):
        raise ValueError("ldap url, bind_dn and bind_pw must be non-empty strings")
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("ldap url is malformed") from exc
    if parsed.scheme not in {"ldap", "ldaps"} or not parsed.hostname:
        raise ValueError("ldap url must use ldap:// or ldaps:// with a hostname")
    if port == 0:
        raise ValueError("ldap url contains an invalid port")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("ldap url must not contain embedded credentials")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("ldap url must contain only the server endpoint")
    return {"url": url, "bind_dn": bind_dn, "bind_pw": bind_pw}


def parse_ldif(ldif: str) -> tuple[str, dict[str, list[str]]]:
    """Parse one minimal LDIF add block without base64 or line folding."""
    dn = None
    attrs: dict[str, list[str]] = {}
    for raw in ldif.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, val = line.partition(":")
        if not sep:
            raise ValueError("LDIF contains a malformed line")
        key = key.strip()
        if not key:
            raise ValueError("LDIF contains an empty attribute name")
        if val.lstrip().startswith((":", "<")):
            raise ValueError("LDIF base64 and URL values are not supported")
        val = val.strip()
        if key.lower() == "dn":
            if dn is not None:
                raise ValueError("LDIF must contain exactly one dn line")
            dn = val
        else:
            attrs.setdefault(key, []).append(val)
    if not dn:
        raise ValueError("LDIF is missing a dn line")
    return dn, attrs


def _password(attrs: dict[str, list[str]]) -> str | None:
    passwords = []
    for key, values in attrs.items():
        if key.lower() == "userpassword":
            passwords.extend(values)
    if len(passwords) > 1:
        raise ValueError("LDIF must contain at most one userPassword value")
    return passwords[0] if passwords else None


async def add_entry(conn_url: str, rendered_ldif: str) -> str:
    import bonsai

    cfg = parse_connection(conn_url)
    dn, attrs = parse_ldif(rendered_ldif)
    password = _password(attrs)
    client = bonsai.LDAPClient(cfg["url"])
    client.set_credentials("SIMPLE", cfg["bind_dn"], cfg["bind_pw"])
    async with asyncio.timeout(ENGINE_CONNECT_TIMEOUT):
        conn = await client.connect(is_async=True, timeout=ENGINE_CONNECT_TIMEOUT)
        try:
            entry = bonsai.LDAPEntry(dn)
            for key, values in attrs.items():
                entry[key] = values
            await conn.add(entry)
            if password is not None:
                try:
                    await conn.modify_password(user=dn, new_password=password)
                except bonsai.LDAPError:
                    # Some directories do not expose RFC 3062. The LDIF value
                    # is already present. Never log rendered LDAP material.
                    log.warning("ldap password-modify unsupported")
            return dn
        finally:
            conn.close()


async def delete_entry(conn_url: str, rendered_dn: str) -> None:
    import bonsai

    cfg = parse_connection(conn_url)
    dn = rendered_dn.strip()
    if dn.lower().startswith("dn:"):
        dn = dn.partition(":")[2].strip()
    if not dn or "\n" in dn or "\r" in dn:
        raise ValueError("LDAP revocation must contain exactly one non-empty DN")
    client = bonsai.LDAPClient(cfg["url"])
    client.set_credentials("SIMPLE", cfg["bind_dn"], cfg["bind_pw"])
    async with asyncio.timeout(ENGINE_CONNECT_TIMEOUT):
        conn = await client.connect(is_async=True, timeout=ENGINE_CONNECT_TIMEOUT)
        try:
            try:
                await conn.delete(dn)
            except bonsai.NoSuchObjectError:
                pass
        finally:
            conn.close()


def _attribute(entry, name: str) -> str | None:
    for key, values in entry.items():
        if str(key).lower() == name.lower() and values:
            return str(values[0])
    return None


async def probe_directory(conn_url: str) -> tuple[str | None, str | None]:
    import bonsai

    cfg = parse_connection(conn_url)
    client = bonsai.LDAPClient(cfg["url"])
    client.set_credentials("SIMPLE", cfg["bind_dn"], cfg["bind_pw"])
    async with asyncio.timeout(ENGINE_CONNECT_TIMEOUT):
        conn = await client.connect(is_async=True, timeout=ENGINE_CONNECT_TIMEOUT)
        try:
            try:
                entries = await conn.search(
                    "",
                    bonsai.LDAPSearchScope.BASE,
                    "(objectClass=*)",
                    ["vendorName", "vendorVersion"],
                    timeout=ENGINE_CONNECT_TIMEOUT,
                    sizelimit=1,
                )
            except (
                bonsai.AuthenticationError,
                bonsai.ConnectionError,
                bonsai.PasswordPolicyError,
                bonsai.ProtocolError,
                bonsai.TimeoutError,
            ):
                raise
            except bonsai.LDAPError:
                return None, None
            if not entries:
                return None, None
            return (
                _attribute(entries[0], "vendorName"),
                _attribute(entries[0], "vendorVersion"),
            )
        finally:
            conn.close()


class LdapEngine(DynamicEngine):
    engine_type = "ldap"
    support = EngineSupport(
        display_name="LDAP",
        driver_module="bonsai",
        validated_targets=("lldap",),
        implementation_targets=("LDAPv3 directory",),
        creation_example=(
            "dn: cn={{name}},ou=people,dc=example,dc=com\n"
            "objectClass: inetOrgPerson\n"
            "cn: {{name}}\n"
            "sn: {{name}}\n"
            "userPassword: {{password}}"
        ),
        revocation_example="cn={{name}},ou=people,dc=example,dc=com",
    )

    def validate_conn(self, conn_url: str) -> None:
        parse_connection(conn_url)

    async def provision(self, conn_url: str, rendered: str) -> str | None:
        return await add_entry(conn_url, rendered)

    async def revoke(self, conn_url: str, rendered: str) -> None:
        await delete_entry(conn_url, rendered)

    async def probe(self, conn_url: str) -> EngineProbe:
        product, version = await probe_directory(conn_url)
        return EngineProbe(product or "LDAP", version)

    def compatibility_status(self, probe: EngineProbe) -> str:
        product = probe.product.strip().casefold()
        return "validated" if product == "lldap" else "connected_unvalidated"


ENGINE = LdapEngine()
