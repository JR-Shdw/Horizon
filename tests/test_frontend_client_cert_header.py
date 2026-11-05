"""No frontend listener may forward a client-supplied X-Client-Cert."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLEAR = 'proxy_set_header X-Client-Cert "";'
SET = "proxy_set_header X-Client-Cert $ssl_client_escaped_cert;"


def proxied_locations(config: str) -> list[str]:
    """Return every location block that proxies to the API."""
    blocks = re.findall(r"location [^{]*\{.*?\n\s*\}", config, re.S)
    return [
        block
        for block in blocks
        if "proxy_pass" in block and not re.match(r"location /health", block)
    ]


def test_plain_listener_clears_the_header():
    blocks = proxied_locations((ROOT / "frontend/nginx.conf").read_text())
    assert len(blocks) >= 2
    for block in blocks:
        assert CLEAR in block, block


def test_tls_listener_renders_the_header_in_every_identity_location():
    config = (ROOT / "frontend/nginx-tls.conf").read_text()
    for block in proxied_locations(config):
        if "/internal/ha/status" in block:
            continue
        assert "${CLIENT_CERT_HEADER}" in block, block


@pytest.mark.parametrize("path", ["frontend/15-tls-setup.sh", "tools/lib/common.sh"])
def test_tls_renderers_clear_the_header_when_mtls_is_off(path):
    source = (ROOT / path).read_text()
    assert SET in source
    assert CLEAR in source


@pytest.mark.skipif(not shutil.which("helm"), reason="helm is required")
@pytest.mark.parametrize("cluster", ["true", "false"])
def test_helm_proxy_mode_never_forwards_a_client_header(cluster):
    rendered = subprocess.run(
        ["helm", "template", "rh", str(ROOT / "helm/rhorizon")]
        + ["--set", "frontend.mode=proxy", "--set", f"api.clusterEnabled={cluster}"]
        + ["--set", "frontend.tls.enabled=true"]
        + ["--set", "api.proxyTrustedIps=10.0.0.0/24"]
        + ["--set", "api.haPrimaryUrl=https://rh.example:8443"]
        + ["--show-only", "templates/frontend-proxy-configmap.yaml"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    blocks = proxied_locations(rendered)
    assert len(blocks) == 2
    assert CLEAR in blocks[0]
    expected = SET if cluster == "true" else CLEAR
    assert expected in blocks[1]
    assert ("ssl_verify_client optional_no_ca" in rendered) is (cluster == "true")
