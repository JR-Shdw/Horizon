# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Make `rhorizon_mcp` importable without installing the package.

`mcp/` is a separate, zero-dependency distribution from the API, so the repo
venv does not have it installed. Without this, collecting `mcp/tests/` fails
outright with ModuleNotFoundError rather than reporting a test result -- which
is how the policy tests sat uncollected.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
