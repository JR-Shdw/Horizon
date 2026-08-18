"""Tests for CLI client and config modules."""

import os
import tempfile

import httpx
from cli.rhorizon.config import (
    get_profile,
    get_url,
    load_config,
    load_token,
    save_token,
    set_profile,
)


class TestCliConfig:
    def test_save_load_config(self):
        with tempfile.TemporaryDirectory() as d:
            import cli.rhorizon.config as cfg

            orig = cfg.CONFIG_DIR
            cfg.CONFIG_DIR = __import__("pathlib").Path(d)
            cfg.CONFIG_FILE = cfg.CONFIG_DIR / "config.toml"
            try:
                set_profile("default", "https://vault.test:8200")
                c = load_config()
                assert c["default"]["url"] == "https://vault.test:8200"
                assert get_profile("default")["url"] == "https://vault.test:8200"
            finally:
                cfg.CONFIG_DIR = orig
                cfg.CONFIG_FILE = orig / "config.toml"

    def test_save_load_token(self):
        with tempfile.TemporaryDirectory() as d:
            import cli.rhorizon.config as cfg

            orig = cfg.CONFIG_DIR
            cfg.CONFIG_DIR = __import__("pathlib").Path(d)
            try:
                save_token("rh_test_token_123")
                assert load_token() == "rh_test_token_123"
            finally:
                cfg.CONFIG_DIR = orig

    def test_token_env_priority(self):
        os.environ["HKV_TOKEN"] = "rh_env_token"
        try:
            assert load_token() == "rh_env_token"
        finally:
            del os.environ["HKV_TOKEN"]

    def test_url_env_priority(self):
        os.environ["HKV_ADDR"] = "https://env.vault:8200"
        try:
            assert get_url() == "https://env.vault:8200"
        finally:
            del os.environ["HKV_ADDR"]

    def test_url_none_when_not_configured(self):
        assert get_url("nonexistent-profile") is None

    def test_token_none_when_not_saved(self):
        with tempfile.TemporaryDirectory() as d:
            import cli.rhorizon.config as cfg

            orig = cfg.CONFIG_DIR
            cfg.CONFIG_DIR = __import__("pathlib").Path(d)
            try:
                assert load_token("nonexistent") is None
            finally:
                cfg.CONFIG_DIR = orig


class TestCliClient:
    def test_client_init(self):
        from cli.rhorizon.client import VaultClient

        c = VaultClient("https://vault.test:8200", "rh_token")
        assert c.url == "https://vault.test:8200"
        assert c.token == "rh_token"

    def test_client_headers(self):
        from cli.rhorizon.client import VaultClient

        c = VaultClient("https://vault.test", "rh_abc")
        h = c._headers()
        assert h["Authorization"] == "Bearer rh_abc"
        assert h["Content-Type"] == "application/json"

    def test_client_no_token(self):
        from cli.rhorizon.client import VaultClient

        c = VaultClient("https://vault.test")
        h = c._headers()
        assert "Authorization" not in h

    def test_client_url_strip_trailing_slash(self):
        from cli.rhorizon.client import VaultClient

        c = VaultClient("https://vault.test:8200/")
        assert c.url == "https://vault.test:8200"


class _FakeResponse:
    def __init__(self, status_code: int, body: dict | None = None):
        self.status_code = status_code
        self._body = body or {}
        self.content = b"{}" if body is not None else b""
        self.text = ""

    def json(self):
        return self._body


class TestCliMigrate:
    def test_plan_default_renames_conflicts(self):
        from cli.rhorizon.migrate import SourceSecret, plan_migration

        items = [
            SourceSecret(
                source="vault",
                mount="secret",
                path="prod/db",
                key="password",
                value="a",
            ),
            SourceSecret(
                source="vault",
                mount="secret",
                path="prod/db",
                key="password",
                value="b",
            ),
        ]
        plan = plan_migration(
            items,
            existing_by_namespace={"imported": {"secret.prod.db.password"}},
            rh_namespace="imported",
            namespace_template=None,
            name_template="{mount}.{path}.{key}",
        )

        assert [p.name for p in plan] == [
            "secret.prod.db.password.imported-2",
            "secret.prod.db.password.imported-3",
        ]
        assert [p.action for p in plan] == ["create-renamed", "create-renamed"]

    def test_plan_compacts_json_values_and_metadata(self):
        from cli.rhorizon.migrate import SourceSecret, plan_migration

        [planned] = plan_migration(
            [
                SourceSecret(
                    source="vault",
                    mount="kv",
                    path="app",
                    key="config",
                    value={"b": 2, "a": True},
                    version=7,
                    metadata={"custom_metadata": {"owner": "ops"}},
                )
            ],
            existing_by_namespace={},
            rh_namespace="imported",
            namespace_template=None,
            name_template="{mount}.{path}.{key}",
        )

        assert planned.value == '{"a":true,"b":2}'
        assert planned.metadata["migrated_from"] == "vault"
        assert planned.metadata["source_version"] == 7
        assert planned.metadata["source_metadata"]["custom_metadata"]["owner"] == "ops"

    def test_parse_vault_mounts(self):
        from cli.rhorizon.migrate import parse_vault_mounts

        mounts = parse_vault_mounts(["secret:v2", "legacy:v1", "shared:kv2"])
        assert [(m.path, m.version) for m in mounts] == [
            ("secret", 2),
            ("legacy", 1),
            ("shared", 2),
        ]

    def test_vault_source_reads_kv2(self, monkeypatch):
        from cli.rhorizon.migrate import VaultHttp, VaultSource

        def fake_request(method, url, **kwargs):
            assert kwargs["headers"]["X-Vault-Token"] == "tok"
            if url.endswith("/v1/sys/mounts"):
                return _FakeResponse(
                    200,
                    {
                        "data": {
                            "secret/": {
                                "type": "kv",
                                "options": {"version": "2"},
                            }
                        }
                    },
                )
            if method == "LIST" and url.endswith("/v1/secret/metadata"):
                return _FakeResponse(200, {"data": {"keys": ["prod/"]}})
            if method == "LIST" and url.endswith("/v1/secret/metadata/prod"):
                return _FakeResponse(200, {"data": {"keys": ["db"]}})
            if url.endswith("/v1/secret/data/prod/db"):
                return _FakeResponse(
                    200,
                    {
                        "data": {
                            "data": {"password": "s3cret"},
                            "metadata": {"version": 4},
                        }
                    },
                )
            if url.endswith("/v1/secret/metadata/prod/db"):
                return _FakeResponse(
                    200,
                    {
                        "data": {
                            "current_version": 4,
                            "custom_metadata": {"owner": "platform"},
                        }
                    },
                )
            raise AssertionError(f"unexpected request {method} {url}")

        monkeypatch.setattr(httpx, "request", fake_request)
        items = VaultSource(VaultHttp("https://vault.test", "tok")).iter_secrets()

        assert len(items) == 1
        item = items[0]
        assert item.mount == "secret"
        assert item.path == "prod/db"
        assert item.key == "password"
        assert item.value == "s3cret"
        assert item.metadata["custom_metadata"]["owner"] == "platform"

    def test_infisical_source_reads_recursive_secrets(self, monkeypatch):
        from cli.rhorizon.migrate import InfisicalHttp, InfisicalSource

        def fake_request(method, url, **kwargs):
            if url.endswith("/api/v1/auth/universal-auth/login"):
                assert method == "POST"
                assert kwargs["json"]["clientId"] == "cid"
                assert kwargs["json"]["clientSecret"] == "sec"
                return _FakeResponse(200, {"accessToken": "inf_tok"})
            if url.endswith("/api/v4/secrets"):
                assert kwargs["headers"]["Authorization"] == "Bearer inf_tok"
                assert kwargs["params"]["projectId"] == "project-1"
                assert kwargs["params"]["environment"] == "prod"
                assert kwargs["params"]["secretPath"] == "/app"
                assert kwargs["params"]["recursive"] == "true"
                assert kwargs["params"]["includeImports"] == "true"
                return _FakeResponse(
                    200,
                    {
                        "secrets": [
                            {
                                "id": "sec-1",
                                "workspace": "project-1",
                                "environment": "prod",
                                "version": 3,
                                "type": "shared",
                                "secretKey": "DB_PASSWORD",
                                "secretValue": "s3cret",
                                "secretPath": "/app",
                                "secretValueHidden": False,
                                "secretMetadata": [
                                    {"key": "owner", "value": "platform"}
                                ],
                                "tags": [{"slug": "database", "name": "Database"}],
                            }
                        ],
                        "imports": [
                            {
                                "secretPath": "/shared",
                                "environment": "prod",
                                "folderId": "folder-1",
                                "secrets": [
                                    {
                                        "id": "sec-2",
                                        "environment": "prod",
                                        "version": 1,
                                        "type": "shared",
                                        "secretKey": "API_KEY",
                                        "secretValue": "key",
                                        "secretValueHidden": False,
                                    }
                                ],
                            }
                        ],
                    },
                )
            raise AssertionError(f"unexpected request {method} {url}")

        monkeypatch.setattr(httpx, "request", fake_request)
        http = InfisicalHttp("https://us.infisical.com")
        http.login_universal(client_id="cid", client_secret="sec")

        items = InfisicalSource(
            http,
            project_id="project-1",
            environment="prod",
            secret_path="/app",
        ).iter_secrets()

        assert len(items) == 2
        assert items[0].source == "infisical"
        assert items[0].source_namespace == "prod"
        assert items[0].path == "/app"
        assert items[0].key == "DB_PASSWORD"
        assert items[0].value == "s3cret"
        assert items[0].tags == ["database"]
        assert items[0].metadata["secretMetadata"][0]["key"] == "owner"
        assert items[1].path == "/shared"
        assert items[1].metadata["import_context"]["folderId"] == "folder-1"
