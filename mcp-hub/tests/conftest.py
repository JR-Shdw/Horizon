# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Make `rhorizon_mcp_hub` importable without installing the package.

`mcp-hub/` is a separate, zero-dependency distribution from the API, so the
repo venv does not have it installed. The existing test modules each do this
insertion inline; doing it here means new test files do not have to remember.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
