# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""The two MCP paths must expose one identical tool catalog.

Regression coverage for a real divergence: `mcp/rhorizon_mcp/server.py` and
`mcp-hub/rhorizon_mcp_hub/gateway.py` each carried their own hand-maintained
copy of the same six vault tools, and they drifted -- different descriptions,
and the hub's `vault_get_secret` had lost the `default: "default"` on its
`namespace` property.

That matters more than an ordinary copy-paste bug:

* Tool descriptions are **prompt material**. The model reads them and steers
  on them. Two texts under one tool name means the same call behaves
  differently depending on which path an agent happens to be on.
* The catalog is the security boundary. It is the entire list of vault
  operations an LLM can reach; a silent divergence here is a silent change
  to what agents can do.

The two packages install independently and are zero-dependency, so neither
may import the other. The canonical file therefore lives in `mcp/` and is
vendored byte-for-byte into `mcp-hub/`. This test is what makes the copy
safe: divergence fails the build instead of shipping.
"""

import json
from pathlib import Path

# tests/ -> mcp-hub/ -> repo root
_ROOT = Path(__file__).resolve().parent.parent.parent
CANONICAL = _ROOT / "mcp" / "rhorizon_mcp" / "tools.json"
VENDORED = _ROOT / "mcp-hub" / "rhorizon_mcp_hub" / "tools.json"

EXPECTED_TOOLS = [
    "vault_status",
    "vault_whoami",
    "vault_list_namespaces",
    "vault_list_secrets",
    "vault_get_secret",
    "vault_audit_tail",
    # Added deliberately: read-only cluster/PG HA health, so an operator can
    # ask an agent "is my cluster healthy?" without holding admin. Gated on
    # the `cluster:r` scope and served as a summary projection (states and
    # reasons only, no member names or lag figures).
    "vault_cluster_health",
]


def test_vendored_copy_is_byte_identical():
    """The whole point: one catalog, two files, zero divergence."""
    assert CANONICAL.exists(), f"canonical catalog missing: {CANONICAL}"
    assert VENDORED.exists(), f"vendored catalog missing: {VENDORED}"
    canon = CANONICAL.read_bytes()
    vend = VENDORED.read_bytes()
    assert canon == vend, (
        "mcp/ and mcp-hub/ tool catalogs have diverged.\n"
        f"Re-sync with:  cp {CANONICAL} {VENDORED}\n"
        "Never edit the vendored copy directly."
    )


def test_both_modules_load_the_same_catalog():
    """Load through each package's own accessor, not just the raw files.

    Catches a module that stops reading tools.json and reintroduces an inline
    literal -- the exact regression this file exists to prevent.
    """
    canon = json.loads(CANONICAL.read_text(encoding="utf-8"))["tools"]

    import sys

    sys.path.insert(0, str(_ROOT / "mcp-hub"))
    from rhorizon_mcp_hub.gateway import VAULT_TOOLS

    assert VAULT_TOOLS == canon, "hub catalog differs from tools.json"

    server_py = (_ROOT / "mcp" / "rhorizon_mcp" / "server.py").read_text("utf-8")
    assert "tools.json" in server_py, (
        "mcp/server.py no longer reads tools.json -- an inline tool literal "
        "was probably reintroduced, which is how the catalogs drifted before"
    )
    assert "TOOLS: list[dict] = [" not in server_py, (
        "mcp/server.py has an inline TOOLS literal again"
    )


def test_catalog_shape_is_intact():
    """Guard the surface itself: read-only, six tools, valid MCP schemas."""
    tools = json.loads(CANONICAL.read_text(encoding="utf-8"))["tools"]
    names = [t["name"] for t in tools]

    assert names == EXPECTED_TOOLS, (
        f"tool catalog changed: {names}\n"
        "Adding a tool widens what every LLM agent can reach. If that is "
        "intended, update EXPECTED_TOOLS deliberately and review the docs."
    )

    for tool in tools:
        assert set(tool) == {"name", "description", "inputSchema"}, tool["name"]
        assert tool["description"].strip(), f"{tool['name']} has no description"
        schema = tool["inputSchema"]
        assert schema["type"] == "object", tool["name"]
        assert isinstance(schema.get("properties", {}), dict), tool["name"]
        for req in schema.get("required", []):
            assert req in schema["properties"], (
                f"{tool['name']}: required '{req}' is not a declared property"
            )


def test_no_write_tools_are_exposed():
    """The catalog is deliberately read-only. Keep it that way."""
    forbidden = ("create", "delete", "write", "put", "seal", "unseal", "rotate")
    for tool in json.loads(CANONICAL.read_text(encoding="utf-8"))["tools"]:
        lowered = tool["name"].lower()
        for word in forbidden:
            assert word not in lowered, (
                f"{tool['name']} looks like a mutating tool. The MCP surface "
                "is read-only by design: no writes, no seal/unseal, no token "
                "management."
            )


def test_descriptions_are_true_on_both_paths():
    """Descriptions serve both paths, so they must not name a one-path control.

    The stdio server enforces a local policy.toml allow-list; the hub daemon
    does not (it is bounded by the agent token's scopes + namespaces). A
    description asserting the policy unconditionally would be false on the
    daemon path -- and the model would act on it.
    """
    tools = json.loads(CANONICAL.read_text(encoding="utf-8"))["tools"]
    for tool in tools:
        desc = tool["description"]
        if "policy" in desc.lower() or "allow-list" in desc.lower():
            hedged = any(
                phrase in desc.lower()
                for phrase in ("where one is configured", "may be", "and by the")
            )
            assert hedged, (
                f"{tool['name']}: description asserts a policy/allow-list "
                "unconditionally, but only the stdio path has one. Hedge it "
                "so the text is true on the daemon path too."
            )


if __name__ == "__main__":
    for fn in (
        test_vendored_copy_is_byte_identical,
        test_both_modules_load_the_same_catalog,
        test_catalog_shape_is_intact,
        test_no_write_tools_are_exposed,
        test_descriptions_are_true_on_both_paths,
    ):
        fn()
        print(f"ok  {fn.__name__}")
    print("all tests passed")
