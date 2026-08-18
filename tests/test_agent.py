"""Tests for agent inject and fetch modules."""

import os
from unittest.mock import MagicMock, patch

import pytest


class TestInject:
    def test_resolve_no_rh_refs(self):
        from agent.inject import _resolve_secrets

        env = {"PATH": "/usr/bin", "HOME": "/root"}
        result = _resolve_secrets("http://vault:8200", "rh_tok", env)
        assert result == env

    def test_resolve_strips_prefix(self):
        from agent.inject import RH_PREFIX

        assert RH_PREFIX == "rh://"

    @patch("agent.inject.httpx.get")
    def test_resolve_fetches_secret(self, mock_get):
        from agent.inject import _resolve_secrets

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"value": "s3cret"}
        mock_get.return_value = mock_resp

        env = {"DB_PASS": "rh://db-password", "HOME": "/root"}
        result = _resolve_secrets("http://vault:8200", "tok", env)
        assert result["DB_PASS"] == "s3cret"
        assert result["HOME"] == "/root"
        mock_get.assert_called_once()

    @patch("agent.inject.httpx.get")
    def test_resolve_fatal_on_failure(self, mock_get):
        from agent.inject import _resolve_secrets

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        env = {"KEY": "rh://missing-secret"}
        with pytest.raises(SystemExit):
            _resolve_secrets("http://vault:8200", "tok", env)


class TestFetch:
    def test_main_missing_env(self):
        from agent.fetch import main

        # Clear required env vars
        for k in ("RHORIZON_ADDR", "RHORIZON_TOKEN", "RHORIZON_SECRETS"):
            os.environ.pop(k, None)

        with pytest.raises(SystemExit):
            main()
