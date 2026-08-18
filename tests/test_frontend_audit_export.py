# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Jets exposes only the signed evidence bundle export."""

from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_jets_uses_one_signed_tar_gz_export():
    source = (ROOT / "frontend/js/views/jets.js").read_text()
    assert "Export evidence" in source
    assert "Download .tar.gz" in source
    assert "apiDownload('POST', '/audit/export'" in source
    assert "Export JSON" not in source
    assert "Export CSV" not in source
    assert "function exportAudit(" not in source
    assert "signed Merkle checkpoints" in source


def test_frontend_binary_download_keeps_bearer_auth():
    source = (ROOT / "frontend/js/api.js").read_text()
    body = source.split("async function apiDownload", 1)[1].split("\nfunction esc", 1)[
        0
    ]
    assert "Authorization" in body
    assert "response.blob()" in body
    assert "Content-Disposition" in body
