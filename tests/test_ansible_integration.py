# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security properties of the stdlib-only Ansible integration client."""

import importlib.util
import io
from pathlib import Path
from urllib.error import HTTPError

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "integrations"
    / "ansible"
    / "plugins"
    / "module_utils"
    / "rhorizon_client.py"
)
SPEC = importlib.util.spec_from_file_location("rhorizon_ansible_client", MODULE_PATH)
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


def test_ansible_client_rejects_remote_plain_http_and_embedded_credentials():
    with pytest.raises(client.HorizonClientError, match="HTTPS"):
        client._validate_address("http://vault.example")
    with pytest.raises(client.HorizonClientError, match="embedded"):
        client._validate_address("https://admin:secret@vault.example")
    assert client._validate_address("http://127.0.0.1:8200") == (
        "http://127.0.0.1:8200"
    )


def test_ansible_client_never_exposes_error_response_or_token(monkeypatch):
    secret = "never-print-this"

    def fail(*_args, **_kwargs):
        raise HTTPError(
            "https://vault.example",
            502,
            "bad gateway " + secret,
            {},
            io.BytesIO(("reflected " + secret).encode()),
        )

    monkeypatch.setattr(client, "urlopen", fail)
    with pytest.raises(client.HorizonClientError) as error:
        client.request_json(
            "https://vault.example",
            secret,
            "POST",
            "/api/v1/vault/dynamic/test",
            body={},
        )
    assert str(error.value) == "Horizon API returned HTTP 502"
    assert secret not in str(error.value)
