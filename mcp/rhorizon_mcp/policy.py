# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Policy whitelist - filter which secrets the LLM is allowed to ask for.

The vault token already restricts what's reachable (scope + namespaces).
Policy is an EXTRA layer on top: even if the token can read 100 secrets,
the LLM might only need 3 of them. By default the MCP server refuses
anything not explicitly whitelisted - fail-closed.

Two policy modes:

  - **whitelist** (default, recommended): explicit list of fully-qualified
    secret names. Anything not listed -> denied.

  - **namespace**: allow a whole namespace (e.g. `mcp/mail/*`). Coarser
    but useful when the agent legitimately needs everything in a slice.

Config file (TOML) at $RH_MCP_POLICY (deprecated alias:
$RHORIZON_MCP_POLICY) (default
~/.config/rhorizon-mcp/policy.toml):

    [secrets]
    whitelist = [
        "mcp/mail/imap-host",
        "mcp/mail/imap-user",
        "mcp/mail/imap-password",
    ]

    [namespaces]
    allow = ["mcp/demo"]      # all secrets in mcp/demo/*

    [tools]
    allow = ["vault_get_secret", "vault_list_secrets", "vault_whoami"]
    # Optional: defaults to all tools the server exposes minus
    # destructive ones. See server.py for the canonical tool list.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_POLICY_PATH = Path(
    os.environ.get("RH_MCP_POLICY")
    or os.environ.get("RHORIZON_MCP_POLICY")  # deprecated alias
    or "~/.config/rhorizon-mcp/policy.toml"
).expanduser()

# Tools that read state vs. mutate it. Default-allow read, default-deny
# mutate: the operator must opt in explicitly.
READ_TOOLS = {
    "vault_get_secret",
    "vault_list_secrets",
    "vault_list_namespaces",
    "vault_whoami",
    "vault_audit_tail",
    "vault_status",
    "vault_cluster_health",
}
MUTATE_TOOLS = {
    "vault_set_secret",
    "vault_delete_secret",
    "vault_create_ephemeral_token",
}


@dataclass
class Policy:
    """In-memory policy. Built from the TOML file at startup."""

    whitelist_secrets: set[str] = field(default_factory=set)
    allow_namespaces: set[str] = field(default_factory=set)
    allow_tools: set[str] = field(default_factory=lambda: set(READ_TOOLS))
    deny_all: bool = False  # set when the file exists but is empty/invalid

    def secret_allowed(self, namespace: str, name: str) -> bool:
        """Resolve a secret access request.

        - Fully qualified name in whitelist_secrets -> allowed
        - Bare name in whitelist_secrets where the entry equals "ns/name" -> allowed
        - Namespace in allow_namespaces -> all names allowed
        - Otherwise -> denied

        Tolerant of leading/trailing slashes in namespace and name.
        """
        if self.deny_all:
            return False
        ns = namespace.strip("/")
        nm = name.strip("/")
        full = f"{ns}/{nm}" if ns else nm
        if full in self.whitelist_secrets:
            return True
        if ns in self.allow_namespaces:
            return True
        return False

    def tool_allowed(self, tool_name: str) -> bool:
        if self.deny_all:
            return False
        return tool_name in self.allow_tools


def load_policy(path: Path | None = None) -> Policy:
    """Read the policy TOML. Missing file -> empty policy (deny everything).

    Returning an empty Policy with deny_all=True is the safe default -
    the operator MUST configure the policy explicitly before the agent
    can do anything. Better than implicitly granting access.
    """
    p = path or DEFAULT_POLICY_PATH
    if not p.exists():
        return Policy(deny_all=True)

    try:
        data = tomllib.loads(p.read_text())
    except (tomllib.TOMLDecodeError, OSError):
        return Policy(deny_all=True)

    secrets_cfg = data.get("secrets", {})
    ns_cfg = data.get("namespaces", {})
    tools_cfg = data.get("tools", {})

    pol = Policy(
        whitelist_secrets=set(secrets_cfg.get("whitelist", [])),
        allow_namespaces=set(ns_cfg.get("allow", [])),
        allow_tools=set(tools_cfg.get("allow", READ_TOOLS)),
    )
    # Empty whitelist + no allowed namespaces + READ tools only = effectively
    # deny everything except metadata. That's a reasonable fallback -
    # don't flip deny_all here.
    return pol
