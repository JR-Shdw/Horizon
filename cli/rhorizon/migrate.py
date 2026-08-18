# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Migration helpers for importing external secret stores into rhorizon.

The migration path intentionally never writes a plaintext export file. Source
adapters stream secrets into this neutral shape, then the CLI writes them through
the normal rhorizon secret API so every imported secret gets regular audit.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import quote

import httpx

from .client import VaultClient

MAX_RHORIZON_NAME = 256
MAX_RHORIZON_VALUE = 1_000_000


class MigrationError(RuntimeError):
    """Operator-facing migration failure."""


class ConflictPolicy(StrEnum):
    RENAME = "rename"
    SKIP = "skip"
    UPDATE_VERSION = "update-version"
    FAIL = "fail"


@dataclass(frozen=True)
class SourceSecret:
    source: str
    value: Any
    mount: str = ""
    path: str = ""
    key: str = ""
    source_namespace: str | None = None
    version: str | int | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlannedSecret:
    source: SourceSecret
    namespace: str
    name: str
    value: str
    metadata: dict[str, Any]
    action: str
    reason: str = ""


def _clean_part(value: str | None, *, separator: str = ".") -> str:
    """Make a source path component safe for rhorizon names/templates."""
    raw = str(value or "").strip().strip("/")
    if not raw:
        return ""
    raw = raw.replace("/", separator)
    raw = re.sub(r"[^A-Za-z0-9_.:-]+", separator, raw)
    raw = re.sub(rf"{re.escape(separator)}+", separator, raw)
    return raw.strip(separator) or "root"


def _collapse_name(value: str, *, separator: str = ".") -> str:
    value = re.sub(rf"{re.escape(separator)}+", separator, value)
    return value.strip(separator) or "imported"


def stringify_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def render_target(
    item: SourceSecret,
    *,
    rh_namespace: str,
    namespace_template: str | None,
    name_template: str,
    separator: str = ".",
) -> tuple[str, str]:
    ctx = {
        "source": _clean_part(item.source, separator=separator),
        "source_namespace": _clean_part(item.source_namespace, separator=separator),
        "mount": _clean_part(item.mount, separator=separator),
        "path": _clean_part(item.path, separator=separator),
        "source_path": _clean_part(item.path, separator=separator),
        "key": _clean_part(item.key, separator=separator),
        "version": _clean_part(str(item.version or ""), separator=separator),
    }
    namespace = namespace_template.format(**ctx) if namespace_template else rh_namespace
    name = name_template.format(**ctx)
    namespace = _collapse_name(
        _clean_part(namespace, separator=separator), separator=separator
    )
    name = _collapse_name(_clean_part(name, separator=separator), separator=separator)
    if len(name) > MAX_RHORIZON_NAME:
        name = name[:MAX_RHORIZON_NAME].rstrip(separator) or "imported"
    return namespace, name


def _with_suffix(base: str, n: int, *, separator: str = ".") -> str:
    suffix = f"{separator}imported-{n}"
    keep = MAX_RHORIZON_NAME - len(suffix)
    if keep <= 0:
        raise MigrationError("conflict suffix leaves no room for secret name")
    return f"{base[:keep].rstrip(separator)}{suffix}"


def _unique_name(base: str, used: set[str], *, separator: str = ".") -> str:
    if base not in used:
        return base
    n = 2
    while True:
        candidate = _with_suffix(base, n, separator=separator)
        if candidate not in used:
            return candidate
        n += 1


def source_metadata(item: SourceSecret) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "migrated_from": item.source,
        "source_path": item.path,
        "source_key": item.key,
        "source_imported_at": datetime.now(UTC).isoformat(),
    }
    if item.mount:
        meta["source_mount"] = item.mount
    if item.source_namespace:
        meta["source_namespace"] = item.source_namespace
    if item.version is not None:
        meta["source_version"] = item.version
    if item.tags:
        meta["source_tags"] = item.tags
    if item.metadata:
        meta["source_metadata"] = item.metadata
    return meta


def plan_migration(
    items: list[SourceSecret],
    *,
    existing_by_namespace: dict[str, set[str]],
    rh_namespace: str,
    namespace_template: str | None,
    name_template: str,
    on_conflict: ConflictPolicy = ConflictPolicy.RENAME,
    separator: str = ".",
) -> list[PlannedSecret]:
    planned: list[PlannedSecret] = []
    used = {ns: set(names) for ns, names in existing_by_namespace.items()}

    for item in items:
        namespace, base_name = render_target(
            item,
            rh_namespace=rh_namespace,
            namespace_template=namespace_template,
            name_template=name_template,
            separator=separator,
        )
        value = stringify_value(item.value)
        if len(value.encode("utf-8")) > MAX_RHORIZON_VALUE:
            planned.append(
                PlannedSecret(
                    item,
                    namespace,
                    base_name,
                    "",
                    {},
                    "skip",
                    f"value exceeds {MAX_RHORIZON_VALUE} bytes",
                )
            )
            continue

        ns_used = used.setdefault(namespace, set())
        exists = base_name in ns_used
        if exists and on_conflict == ConflictPolicy.SKIP:
            planned.append(
                PlannedSecret(
                    item,
                    namespace,
                    base_name,
                    "",
                    {},
                    "skip",
                    "target exists",
                )
            )
            continue
        if exists and on_conflict == ConflictPolicy.FAIL:
            raise MigrationError(f"target exists: {namespace}/{base_name}")
        if exists and on_conflict == ConflictPolicy.UPDATE_VERSION:
            ns_used.add(base_name)
            planned.append(
                PlannedSecret(
                    item,
                    namespace,
                    base_name,
                    value,
                    source_metadata(item),
                    "update",
                    "target exists",
                )
            )
            continue

        name = (
            _unique_name(base_name, ns_used, separator=separator)
            if on_conflict == ConflictPolicy.RENAME
            else base_name
        )
        ns_used.add(name)
        action = "create-renamed" if name != base_name else "create"
        planned.append(
            PlannedSecret(item, namespace, name, value, source_metadata(item), action)
        )

    return planned


def apply_plan(client: VaultClient, planned: list[PlannedSecret]) -> dict[str, int]:
    counts = {"created": 0, "updated": 0, "skipped": 0}
    for item in planned:
        if item.action == "skip":
            counts["skipped"] += 1
            continue
        if item.action == "update":
            client.update_secret(item.name, item.value, item.namespace)
            counts["updated"] += 1
        else:
            client.create_secret(
                item.name,
                item.value,
                item.namespace,
                metadata=item.metadata,
            )
            counts["created"] += 1
    return counts


class VaultHttp:
    def __init__(
        self,
        addr: str,
        token: str,
        *,
        namespace: str | None = None,
        verify: bool = True,
    ):
        self.addr = addr.rstrip("/")
        self.token = token
        self.namespace = namespace
        self.verify = verify

    def _headers(self) -> dict[str, str]:
        headers = {
            "X-Vault-Token": self.token,
            "X-Vault-Request": "true",
        }
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        allow_404: bool = False,
    ) -> dict[str, Any] | None:
        url = f"{self.addr}/v1/{path.lstrip('/')}"
        try:
            resp = httpx.request(
                method,
                url,
                headers=self._headers(),
                params=params,
                timeout=30,
                verify=self.verify,
            )
        except httpx.HTTPError as exc:
            raise MigrationError(f"Vault request failed: {exc}") from exc
        if resp.status_code == 404 and allow_404:
            return None
        if resp.status_code >= 400:
            try:
                detail = "; ".join(resp.json().get("errors", [])) or resp.text
            except (ValueError, AttributeError, TypeError):
                # Not JSON / not an object / "errors" not a list of str.
                detail = resp.text
            raise MigrationError(
                f"Vault {method} {path} failed: {resp.status_code} {detail}"
            )
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()


@dataclass(frozen=True)
class VaultMount:
    path: str
    version: int


class VaultSource:
    def __init__(
        self,
        http: VaultHttp,
        *,
        mounts: list[VaultMount] | None = None,
    ):
        self.http = http
        self.mounts = mounts

    def discover_mounts(self) -> list[VaultMount]:
        if self.mounts:
            return self.mounts
        body = self.http.request("GET", "sys/mounts") or {}
        mounts: list[VaultMount] = []
        for raw_path, cfg in (body.get("data") or {}).items():
            if cfg.get("type") != "kv":
                continue
            path = str(raw_path).strip("/")
            options = cfg.get("options") or {}
            version = 2 if str(options.get("version")) == "2" else 1
            mounts.append(VaultMount(path, version))
        if not mounts:
            raise MigrationError("no KV mounts found in Vault /sys/mounts")
        return mounts

    def iter_secrets(self) -> list[SourceSecret]:
        items: list[SourceSecret] = []
        for mount in self.discover_mounts():
            paths = self._walk(mount, "")
            for path in paths:
                data, meta = self._read(mount, path)
                for key, value in data.items():
                    items.append(
                        SourceSecret(
                            source="vault",
                            source_namespace=self.http.namespace,
                            mount=mount.path,
                            path=path,
                            key=str(key),
                            value=value,
                            version=meta.get("version") or meta.get("current_version"),
                            metadata=meta,
                        )
                    )
        return items

    def _list_path(self, mount: VaultMount, prefix: str) -> list[str]:
        prefix = prefix.strip("/")
        if mount.version == 2:
            api_path = f"{quote(mount.path, safe='/')}/metadata"
            if prefix:
                api_path += f"/{quote(prefix, safe='/')}"
        else:
            api_path = quote(mount.path, safe="/")
            if prefix:
                api_path += f"/{quote(prefix, safe='/')}"
        body = self.http.request("LIST", api_path, allow_404=True)
        if body is None:
            return []
        return list((body.get("data") or {}).get("keys") or [])

    def _walk(self, mount: VaultMount, prefix: str) -> list[str]:
        out: list[str] = []
        for key in self._list_path(mount, prefix):
            if key.endswith("/"):
                out.extend(self._walk(mount, f"{prefix}{key}"))
            else:
                out.append(f"{prefix}{key}".strip("/"))
        return out

    def _read(
        self, mount: VaultMount, path: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        enc_mount = quote(mount.path, safe="/")
        enc_path = quote(path, safe="/")
        if mount.version == 2:
            body = self.http.request("GET", f"{enc_mount}/data/{enc_path}") or {}
            wrapper = body.get("data") or {}
            data = wrapper.get("data") or {}
            meta = dict(wrapper.get("metadata") or {})
            meta_body = self.http.request(
                "GET", f"{enc_mount}/metadata/{enc_path}", allow_404=True
            )
            if meta_body is not None:
                public_meta = meta_body.get("data") or {}
                if public_meta.get("custom_metadata"):
                    meta["custom_metadata"] = public_meta["custom_metadata"]
                if public_meta.get("current_version") is not None:
                    meta["current_version"] = public_meta["current_version"]
            return dict(data), meta
        body = self.http.request("GET", f"{enc_mount}/{enc_path}") or {}
        data = body.get("data") or {}
        return dict(data), {}


def parse_vault_mounts(specs: list[str] | None) -> list[VaultMount] | None:
    if not specs:
        return None
    mounts: list[VaultMount] = []
    for spec in specs:
        path, _, raw_version = spec.partition(":")
        path = path.strip().strip("/")
        if not path:
            raise MigrationError(f"invalid mount spec: {spec!r}")
        if raw_version:
            raw = raw_version.lower()
            if raw in {"1", "v1", "kv1"}:
                version = 1
            elif raw in {"2", "v2", "kv2"}:
                version = 2
            else:
                raise MigrationError(f"mount version must be v1 or v2: {spec!r}")
        else:
            version = 2
        mounts.append(VaultMount(path, version))
    return mounts


class InfisicalHttp:
    def __init__(
        self,
        addr: str,
        token: str | None = None,
        *,
        verify: bool = True,
    ):
        self.addr = addr.rstrip("/")
        self.token = token
        self.verify = verify

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        auth_required: bool = True,
    ) -> dict[str, Any]:
        if auth_required and not self.token:
            raise MigrationError("Infisical access token is required")
        url = f"{self.addr}/{path.lstrip('/')}"
        try:
            resp = httpx.request(
                method,
                url,
                headers=self._headers(),
                params=params,
                json=json_body,
                timeout=30,
                verify=self.verify,
            )
        except httpx.HTTPError as exc:
            raise MigrationError(f"Infisical request failed: {exc}") from exc
        if resp.status_code >= 400:
            try:
                body = resp.json()
                detail = body.get("message") or body.get("error") or resp.text
            except (ValueError, AttributeError):
                # Body is not JSON, or is JSON but not an object.
                detail = resp.text
            raise MigrationError(
                f"Infisical {method} {path} failed: {resp.status_code} {detail}"
            )
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    def login_universal(
        self,
        *,
        client_id: str,
        client_secret: str,
        organization_slug: str | None = None,
    ) -> str:
        body = {"clientId": client_id, "clientSecret": client_secret}
        if organization_slug:
            body["organizationSlug"] = organization_slug
        resp = self.request(
            "POST",
            "/api/v1/auth/universal-auth/login",
            json_body=body,
            auth_required=False,
        )
        token = resp.get("accessToken")
        if not token:
            raise MigrationError("Infisical Universal Auth did not return a token")
        self.token = str(token)
        return self.token


class InfisicalSource:
    def __init__(
        self,
        http: InfisicalHttp,
        *,
        project_id: str,
        environment: str,
        secret_path: str = "/",
        include_imports: bool = True,
        expand_secret_references: bool = True,
    ):
        self.http = http
        self.project_id = project_id
        self.environment = environment
        self.secret_path = secret_path or "/"
        self.include_imports = include_imports
        self.expand_secret_references = expand_secret_references

    def iter_secrets(self) -> list[SourceSecret]:
        body = self.http.request(
            "GET",
            "/api/v4/secrets",
            params={
                "projectId": self.project_id,
                "environment": self.environment,
                "secretPath": self.secret_path,
                "viewSecretValue": "true",
                "expandSecretReferences": _bool_str(self.expand_secret_references),
                "recursive": "true",
                "includeImports": _bool_str(self.include_imports),
            },
        )
        items = [
            self._from_secret(secret, path_hint=self.secret_path)
            for secret in body.get("secrets") or []
        ]
        for imported in body.get("imports") or []:
            import_path = str(imported.get("secretPath") or self.secret_path)
            import_env = str(imported.get("environment") or self.environment)
            for secret in imported.get("secrets") or []:
                items.append(
                    self._from_secret(
                        secret,
                        path_hint=import_path,
                        environment_hint=import_env,
                        import_context=imported,
                    )
                )
        return items

    def _from_secret(
        self,
        secret: dict[str, Any],
        *,
        path_hint: str,
        environment_hint: str | None = None,
        import_context: dict[str, Any] | None = None,
    ) -> SourceSecret:
        key = secret.get("secretKey")
        if not key:
            raise MigrationError("Infisical secret response is missing secretKey")
        value = secret.get("secretValue")
        if secret.get("secretValueHidden") and value in (None, ""):
            raise MigrationError(
                "Infisical returned a hidden value for "
                f"{path_hint}/{key}; check token read permissions"
            )
        path = str(secret.get("secretPath") or path_hint or "/")
        env = str(environment_hint or secret.get("environment") or self.environment)
        tags = [
            str(tag.get("slug") or tag.get("name"))
            for tag in secret.get("tags") or []
            if tag.get("slug") or tag.get("name")
        ]
        metadata = _pick(
            secret,
            [
                "id",
                "_id",
                "workspace",
                "environment",
                "type",
                "secretComment",
                "createdAt",
                "updatedAt",
                "secretMetadata",
                "secretValueHidden",
            ],
        )
        if import_context:
            metadata["import_context"] = _pick(
                import_context,
                ["secretPath", "environment", "folderId"],
            )
        if tags:
            metadata["tags"] = tags
        return SourceSecret(
            source="infisical",
            source_namespace=env,
            mount=self.project_id,
            path=path,
            key=str(key),
            value="" if value is None else value,
            version=secret.get("version"),
            tags=tags,
            metadata=metadata,
        )


def _bool_str(value: bool) -> str:
    return "true" if value else "false"


def _pick(data: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    return {key: data[key] for key in keys if key in data}
