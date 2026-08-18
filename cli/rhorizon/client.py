# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""HTTP client wrapper for rhorizon API."""

import os
import sys
import tempfile
import time
from pathlib import Path

import httpx

# Master-only endpoints can land on a follower and return 503+Retry-After
# (~1/N hit chance on master). Budget absorbs that storm so callers need no
# retry loop. Also retries 429 (transient backpressure: load-shed /
# cluster_recovering) so a passive LB doesn't eject a busy node. Both are
# "retry shortly"; server-jittered Retry-After is honoured.
_MASTER_ONLY_RETRY_BUDGET_SECS = 15
_MASTER_ONLY_RETRY_DELAY_SECS = 0.5
_MASTER_ONLY_RETRY_STATUSES = (429, 503)


def _ca_bundle() -> str | bool:
    """CA to verify the vault's TLS cert against.

    A self-signed or private-CA vault (the quickstart generates one) is not in
    the system trust store, so point at its PEM. Mirrors the agent sidecar's
    RH_VAULT_CAFILE, and accepts that name too so one export covers both.

    Returns a path when set, else True (default system trust). Verification is
    never disabled -- there is deliberately no insecure switch.
    """
    for var in ("RH_CA_FILE", "RH_VAULT_CAFILE", "RHORIZON_CA_FILE"):
        path = os.environ.get(var, "").strip()
        if path:
            if not os.path.isfile(path):
                print(f"Error: {var}={path} does not exist", file=sys.stderr)
                raise SystemExit(1)
            return path
    return True


class VaultClient:
    def __init__(self, url: str, token: str | None = None):
        self.url = url.rstrip("/")
        self.token = token

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _request(
        self,
        method: str,
        path: str,
        json: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        url = f"{self.url}{path}"
        try:
            r = httpx.request(
                method,
                url,
                json=json,
                params=params,
                headers=self._headers(),
                timeout=30,
                verify=_ca_bundle(),
            )
        except httpx.ConnectError:
            print(f"Error: cannot connect to {self.url}", file=sys.stderr)
            raise SystemExit(1)

        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except (ValueError, AttributeError):
                # Body is not JSON, or is JSON but not an object.
                detail = r.text
            print(f"Error {r.status_code}: {detail}", file=sys.stderr)
            raise SystemExit(1)

        if r.status_code == 204:
            return {}
        return r.json()

    def _request_with_master_retry(
        self,
        method: str,
        path: str,
        json: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """Wraps :func:`_request` with 429/503-Retry-After backoff.

        Used by cluster master-only methods (init, ca-bundle, rotate-cert,
        rotate-ca, etc.). Walls clients off from the 1/N worker hit
        lottery while preserving the per-call status semantics for callers
        that want raw control. Retries 503 (follower-hit) and 429 (transient
        backpressure: load-shed / cluster_recovering), honouring Retry-After.
        """
        url = f"{self.url}{path}"
        deadline = time.monotonic() + _MASTER_ONLY_RETRY_BUDGET_SECS
        last_resp = None
        while True:
            try:
                r = httpx.request(
                    method,
                    url,
                    json=json,
                    params=params,
                    headers=self._headers(),
                    timeout=30,
                    verify=_ca_bundle(),
                )
            except httpx.ConnectError:
                print(f"Error: cannot connect to {self.url}", file=sys.stderr)
                raise SystemExit(1)
            last_resp = r
            if (
                r.status_code not in _MASTER_ONLY_RETRY_STATUSES
                or time.monotonic() >= deadline
            ):
                break
            # Honour the server's (jittered) Retry-After when present, capped so
            # a hostile/huge value can't park the CLI past its budget.
            ra = r.headers.get("Retry-After")
            try:
                delay = (
                    min(float(ra), _MASTER_ONLY_RETRY_DELAY_SECS * 8)
                    if ra
                    else _MASTER_ONLY_RETRY_DELAY_SECS
                )
            except ValueError:
                delay = _MASTER_ONLY_RETRY_DELAY_SECS
            time.sleep(delay)

        if last_resp.status_code >= 400:
            try:
                detail = last_resp.json().get("detail", last_resp.text)
            except (ValueError, AttributeError):
                # Body is not JSON, or is JSON but not an object.
                detail = last_resp.text
            print(f"Error {last_resp.status_code}: {detail}", file=sys.stderr)
            raise SystemExit(1)

        if last_resp.status_code == 204:
            return {}
        return last_resp.json()

    def get(self, path: str, **kw) -> dict:
        return self._request("GET", path, **kw)

    def post(self, path: str, **kw) -> dict:
        return self._request("POST", path, **kw)

    def put(self, path: str, **kw) -> dict:
        return self._request("PUT", path, **kw)

    def delete(self, path: str, **kw) -> dict:
        return self._request("DELETE", path, **kw)

    # -- Convenience methods --

    def status(self) -> dict:
        return self.get("/api/v1/vault/status")

    def unseal(self, password: str, totp_code: str | None = None) -> dict:
        body: dict = {"password": password}
        if totp_code:
            body["totp_code"] = totp_code
        return self.post("/api/v1/vault/unseal", json=body)

    def seal(self) -> dict:
        return self.post("/api/v1/vault/seal")

    def get_secret(
        self, name: str, namespace: str | None = None, previous: bool = False
    ) -> dict:
        params = {}
        if namespace:
            params["namespace"] = namespace
        if previous:
            params["previous"] = "true"
        return self.get(f"/api/v1/vault/secrets/{name}", params=params or None)

    def create_secret(
        self,
        name: str,
        value: str,
        namespace: str = "default",
        metadata: dict | None = None,
    ) -> dict:
        return self.post(
            "/api/v1/vault/secrets/",
            json={
                "name": name,
                "value": value,
                "namespace": namespace,
                "metadata": metadata or {},
            },
        )

    def update_secret(
        self,
        name: str,
        value: str,
        namespace: str | None = None,
        emergency: bool = False,
    ) -> dict:
        params = {"namespace": namespace} if namespace else None
        return self.put(
            f"/api/v1/vault/secrets/{name}",
            json={"value": value, "emergency": emergency},
            params=params,
        )

    def delete_secret(self, name: str, namespace: str | None = None) -> dict:
        params = {"namespace": namespace} if namespace else None
        return self.delete(f"/api/v1/vault/secrets/{name}", params=params)

    def list_secrets(self, namespace: str | None = None) -> dict:
        params = {"namespace": namespace} if namespace else None
        return self.get("/api/v1/vault/secrets/", params=params)

    def rotate_secret(self, name: str, namespace: str | None = None) -> dict:
        params = {"namespace": namespace} if namespace else None
        return self.post(f"/api/v1/vault/secrets/{name}/rotate", params=params)

    def rotate_all(self) -> dict:
        return self.post("/api/v1/vault/secrets/rotate-all")

    def list_versions(self, name: str, namespace: str | None = None) -> dict:
        params = {"namespace": namespace} if namespace else None
        return self.get(f"/api/v1/vault/secrets/{name}/versions", params=params)

    def get_version(
        self, name: str, version: int, namespace: str | None = None
    ) -> dict:
        params = {"namespace": namespace} if namespace else None
        return self.get(
            f"/api/v1/vault/secrets/{name}/versions/{version}", params=params
        )

    def rollback(self, name: str, version: int, namespace: str | None = None) -> dict:
        params = {"namespace": namespace} if namespace else None
        return self.post(
            f"/api/v1/vault/secrets/{name}/rollback/{version}", params=params
        )

    def create_token(self, name: str, permissions: dict) -> dict:
        return self.post(
            "/api/v1/vault/tokens/",
            json={"name": name, "permissions": permissions},
        )

    def list_tokens(self) -> dict:
        return self.get("/api/v1/vault/tokens/")

    def revoke_token(self, token_id: str) -> dict:
        return self.post(f"/api/v1/vault/tokens/{token_id}/revoke")

    def rotate_token(self, token_id: str) -> dict:
        return self.post(f"/api/v1/vault/tokens/{token_id}/rotate")

    def set_token_allowed_ips(self, token_id: str, allowed_ips: str | None) -> dict:
        return self.post(
            f"/api/v1/vault/tokens/{token_id}/allowed-ips",
            json={"allowed_ips": allowed_ips},
        )

    def list_namespaces(self) -> dict:
        return self.get("/api/v1/vault/secrets/namespaces")

    def delete_namespace(self, namespace: str) -> dict:
        return self.delete(f"/api/v1/vault/secrets/namespaces/{namespace}")

    # -- Audit --

    def list_audit(self, limit: int = 20, after_id: str | None = None) -> dict:
        """List recent audit entries. `after_id` returns only entries newer
        than the given UUID (for tail -f-style follow)."""
        params: dict = {"limit": limit}
        if after_id:
            params["after_id"] = after_id
        return self.get("/api/v1/vault/audit/", params=params)

    def verify_audit(self) -> dict:
        return self.get("/api/v1/vault/audit/verify")

    def list_audit_files(self) -> dict:
        return self.get("/api/v1/vault/audit/files")

    def read_audit_file(self, date: str) -> dict:
        """date format: YYYY-MM-DD."""
        return self.get(f"/api/v1/vault/audit/files/{date}")

    def export_audit_evidence(
        self,
        output: Path,
        *,
        since: str | None = None,
        until: str | None = None,
    ) -> dict:
        """Download the single signed tar.gz audit evidence format atomically."""
        payload = {
            key: value
            for key, value in {"since": since, "until": until}.items()
            if value
        }
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".part", dir=output.parent
        )
        os.close(fd)
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o600)
        written = 0
        try:
            try:
                with httpx.stream(
                    "POST",
                    f"{self.url}/api/v1/vault/audit/export",
                    json=payload,
                    headers=self._headers(),
                    timeout=httpx.Timeout(connect=30, read=None, write=30, pool=30),
                    verify=_ca_bundle(),
                ) as response:
                    if response.status_code >= 400:
                        response.read()
                        try:
                            detail = response.json().get("detail", response.text)
                        except (ValueError, AttributeError):
                            detail = response.text
                        print(
                            f"Error {response.status_code}: {detail}", file=sys.stderr
                        )
                        raise SystemExit(1)
                    with temporary.open("wb") as handle:
                        for chunk in response.iter_bytes(1024 * 1024):
                            handle.write(chunk)
                            written += len(chunk)
                        handle.flush()
                        os.fsync(handle.fileno())
                    signer = response.headers.get("X-Rhorizon-Audit-Signer")
            except httpx.ConnectError:
                print(f"Error: cannot connect to {self.url}", file=sys.stderr)
                raise SystemExit(1) from None
            if written == 0:
                print("Error: server returned an empty audit bundle", file=sys.stderr)
                raise SystemExit(1)
            os.replace(temporary, output)
            return {"path": str(output), "size_bytes": written, "signer_fpr": signer}
        finally:
            temporary.unlink(missing_ok=True)

    # -- Master password rotation --

    def rotate_master_password(
        self,
        current_password: str,
        new_password: str,
        emergency: bool = False,
    ) -> dict:
        return self.post(
            "/api/v1/vault/rotate-password",
            json={
                "current_password": current_password,
                "new_password": new_password,
                "emergency": emergency,
            },
        )

    # -- Ephemeral tokens --

    def create_ephemeral_token(
        self,
        permissions: dict,
        ttl_seconds: int = 3600,
        label: str = "",
    ) -> dict:
        return self.post(
            "/api/v1/vault/tokens/ephemeral",
            json={
                "permissions": permissions,
                "ttl_seconds": ttl_seconds,
                "label": label,
            },
        )

    # -- Oneshot decrypt-and-die --

    def oneshot(
        self,
        password: str,
        name: str,
        namespace: str = "default",
        totp_code: str | None = None,
    ) -> dict:
        body: dict = {"password": password, "name": name, "namespace": namespace}
        if totp_code:
            body["totp_code"] = totp_code
        return self.post("/api/v1/vault/oneshot", json=body)

    # -- Whoami / introspection --

    def whoami(self) -> dict:
        return self.get("/api/v1/vault/tokens/whoami")

    # -- Token renew --

    def renew_token(self, token_id: str, ttl_seconds: int) -> dict:
        return self.post(
            f"/api/v1/vault/tokens/{token_id}/renew",
            json={"ttl_seconds": ttl_seconds},
        )

    # -- Backup / restore (age passphrase) --

    def create_backup(self, passphrase: str) -> dict:
        return self.post(
            "/api/v1/vault/backup/create",
            json={"passphrase": passphrase},
        )

    def restore_backup(
        self,
        payload_b64: str,
        passphrase: str,
        master_password_backup: str,
        confirm_phrase: str,
    ) -> dict:
        return self.post(
            "/api/v1/vault/backup/restore",
            json={
                "payload": payload_b64,
                "passphrase": passphrase,
                "master_password_backup": master_password_backup,
                "confirm_phrase": confirm_phrase,
            },
        )

    # -- Cluster --

    def cluster_init(self, cluster_name: str | None = None) -> dict:
        body: dict = {}
        if cluster_name:
            body["cluster_name"] = cluster_name
        # Master-only endpoint -- 503 storms get absorbed by the budget.
        return self._request_with_master_retry(
            "POST", "/api/v1/vault/cluster/init", json=body
        )

    def cluster_ha(self) -> dict:
        return self.get("/api/v1/vault/cluster/ha")

    def cluster_health(self) -> dict:
        return self.get("/api/v1/vault/cluster/health")

    def cluster_ha_self(self) -> dict:
        return self.get("/api/v1/vault/cluster/ha/self")

    def cluster_promote(self, node_uuid: str) -> dict:
        return self.post(f"/api/v1/vault/cluster/promote/{node_uuid}")

    def cluster_demote(self, node_uuid: str) -> dict:
        return self.post(f"/api/v1/vault/cluster/demote/{node_uuid}")

    def cluster_drain(self, node_uuid: str) -> dict:
        return self.post(f"/api/v1/vault/cluster/drain/{node_uuid}")

    def cluster_evict(self, node_uuid: str) -> dict:
        return self.post(f"/api/v1/vault/cluster/evict/{node_uuid}")

    def cluster_unrevoke(self, node_uuid: str) -> dict:
        return self.post(f"/api/v1/vault/cluster/unrevoke/{node_uuid}")

    def cluster_rotate_cert(self, target: str) -> dict:
        # Master-only -- absorb 503 storm.
        return self._request_with_master_retry(
            "POST", f"/api/v1/vault/cluster/rotate-cert/{target}"
        )

    def cluster_ca_bundle(self) -> dict:
        # Master-only -- absorb 503 storm.
        return self._request_with_master_retry("GET", "/api/v1/vault/cluster/ca-bundle")

    def cluster_rotate_ca(self) -> dict:
        # Master-only -- absorb 503 storm.
        return self._request_with_master_retry(
            "POST", "/api/v1/vault/cluster/rotate-ca"
        )

    # -- Dynamic secrets --

    def list_dynamic_engines(self) -> dict:
        return self.get("/api/v1/vault/dynamic/engines")

    def create_dynamic_engine(
        self,
        name: str,
        engine_type: str,
        connection_url: str,
        namespace: str = "default",
        max_ttl_seconds: int = 86400,
    ) -> dict:
        return self.post(
            "/api/v1/vault/dynamic/engines",
            json={
                "name": name,
                "engine_type": engine_type,
                "connection_url": connection_url,
                "namespace": namespace,
                "max_ttl_seconds": max_ttl_seconds,
            },
        )

    def delete_dynamic_engine(self, engine_id: str) -> dict:
        return self.delete(f"/api/v1/vault/dynamic/engines/{engine_id}")

    def list_dynamic_roles(self, engine_id: str) -> dict:
        return self.get(f"/api/v1/vault/dynamic/engines/{engine_id}/roles")

    def create_dynamic_role(
        self,
        engine_id: str,
        name: str,
        creation_sql: str,
        revocation_sql: str,
        default_ttl_seconds: int = 3600,
        max_ttl_seconds: int = 86400,
    ) -> dict:
        return self.post(
            f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
            json={
                "name": name,
                "creation_sql": creation_sql,
                "revocation_sql": revocation_sql,
                "default_ttl_seconds": default_ttl_seconds,
                "max_ttl_seconds": max_ttl_seconds,
            },
        )

    def generate_dynamic_creds(
        self, engine_id: str, role_name: str, ttl_seconds: int | None = None
    ) -> dict:
        body: dict = {}
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        return self.post(
            f"/api/v1/vault/dynamic/engines/{engine_id}/creds/{role_name}",
            json=body,
        )

    def list_dynamic_leases(self) -> dict:
        return self.get("/api/v1/vault/dynamic/leases")

    def renew_dynamic_lease(self, lease_id: str, ttl_seconds: int = 3600) -> dict:
        return self.post(
            f"/api/v1/vault/dynamic/leases/{lease_id}/renew",
            json={"ttl_seconds": ttl_seconds},
        )

    def revoke_dynamic_lease(self, lease_id: str) -> dict:
        return self.post(f"/api/v1/vault/dynamic/leases/{lease_id}/revoke")

    # -- Audit time-range --

    def audit_range(
        self,
        since: str | None = None,
        until: str | None = None,
        actor: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> dict:
        params: dict = {"limit": limit}
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        if actor:
            params["actor"] = actor
        if action:
            params["action"] = action
        return self.get("/api/v1/vault/audit/", params=params)

    # -- PKI engine --

    def pki_init(
        self,
        algorithm: str = "ed25519",
        common_name: str = "rhorizon-pki",
        validity_days: int = 3650,
    ) -> dict:
        return self.post(
            "/api/v1/vault/pki/init",
            json={
                "algorithm": algorithm,
                "common_name": common_name,
                "validity_days": validity_days,
            },
        )

    def pki_ca(self) -> dict:
        return self.get("/api/v1/vault/pki/ca")

    def pki_issue(
        self,
        common_name: str,
        san_ips: list[str],
        san_dns: list[str],
        ttl_days: int = 30,
        eku_client: bool = True,
        eku_server: bool = True,
        namespace: str = "default",
    ) -> dict:
        return self.post(
            "/api/v1/vault/pki/issue",
            json={
                "common_name": common_name,
                "san_ips": san_ips,
                "san_dns": san_dns,
                "ttl_days": ttl_days,
                "eku_client": eku_client,
                "eku_server": eku_server,
                "namespace": namespace,
            },
        )

    def pki_kem_issue(
        self,
        common_name: str,
        san_ips: list[str],
        san_dns: list[str],
        ttl_days: int = 30,
        kem_algorithm: str = "ml-kem-768",
        namespace: str = "default",
        kem_mode: str = "ml-kem",
    ) -> dict:
        return self.post(
            "/api/v1/vault/pki/kem/issue",
            json={
                "common_name": common_name,
                "san_ips": san_ips,
                "san_dns": san_dns,
                "ttl_days": ttl_days,
                "kem_algorithm": kem_algorithm,
                "kem_mode": kem_mode,
                "namespace": namespace,
            },
        )

    def pki_revoke(self, serial: str, reason: str = "unspecified") -> dict:
        return self.post(
            "/api/v1/vault/pki/revoke", json={"serial": serial, "reason": reason}
        )

    def pki_rotate(self, validity_days: int = 3650) -> dict:
        return self.post(
            "/api/v1/vault/pki/rotate", json={"validity_days": validity_days}
        )

    def pki_list_certs(self) -> dict:
        return self.get("/api/v1/vault/pki/certs")
