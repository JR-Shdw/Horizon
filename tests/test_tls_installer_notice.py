"""The home-install TLS warning and fingerprint are part of the UX contract."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools" / "lib" / "tls-cert-info.sh"


def test_tls_notice_reports_the_generated_certificate_fingerprint(
    tmp_path: Path,
) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=rhorizon-test",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    script = f"""
set -eu
. '{HELPER}'
tls_cert_is_self_signed '{cert}'
tls_print_browser_notice '{cert}' 'https://127.0.0.1:8443/' 'docs/TLS.md'
"""
    result = subprocess.run(
        ["sh", "-c", script], check=True, capture_output=True, text=True
    )

    assert "FIRST BROWSER VISIT" in result.stdout
    assert "If the fingerprints differ, stop." in result.stdout
    assert re.search(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", result.stdout)


def test_every_home_installer_uses_the_shared_tls_notice() -> None:
    for relative in (
        "tools/install-container.sh",
        "tools/install-native.sh",
        "tools/install-macos.sh",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "tls-cert-info.sh" in source, relative
        assert "tls_cert_fingerprint_sha256" in source, relative
        assert "tls_print_browser_notice" in source, relative


def test_tls_docs_cover_supported_home_environments() -> None:
    for relative, headings in (
        (
            "docs/TLS.md",
            ("### macOS", "### Linux", "### BSD", "### WSL", "### Docker and Podman"),
        ),
        (
            "docs/fr/TLS.md",
            ("### macOS", "### Linux", "### BSD", "### WSL", "### Docker et Podman"),
        ),
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "fingerprint" in source.lower() or "empreinte" in source.lower()
        for heading in headings:
            assert heading in source, f"{relative}: missing {heading}"
