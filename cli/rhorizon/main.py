# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""rhorizon - CLI for rhorizon secrets manager.

Usage:
  rhorizon login URL                     # Save vault address + authenticate
  rhorizon status                        # Vault status
  rhorizon unseal                        # Unseal (prompts password + optional TOTP)
  rhorizon seal                          # Seal vault
  rhorizon get NAME                      # Print one secret value
  rhorizon set NAME VALUE                # Create or update secret
  rhorizon delete NAME                   # Delete secret
  rhorizon list                          # List secrets
  rhorizon rotate NAME                   # Rotate DEK
  rhorizon rotate --all                  # Bulk DEK rotation
  rhorizon versions NAME                 # List versions
  rhorizon rollback NAME VERSION         # Restore old version
  rhorizon token create NAME PERMS       # Create token
  rhorizon token list                    # List tokens
  rhorizon token revoke ID               # Revoke token
  rhorizon ns list                       # List namespaces
  rhorizon ns delete NAME                # Delete namespace
  rhorizon import dotenv FILE            # Import .env file
  rhorizon import age FILE               # Alias of `backup restore FILE`
  rhorizon migrate vault --dry-run       # Plan Vault -> rhorizon migration
  rhorizon migrate infisical --dry-run   # Plan Infisical migration (experimental)
  rhorizon backup export FILE            # Age-encrypted backup to FILE
  rhorizon backup restore FILE           # Restore age backup from FILE

Environment variables:
  RH_ADDR     Vault URL (overrides config; HKV_ADDR accepted as legacy)
  RH_TOKEN    Auth token (overrides saved token; HKV_TOKEN accepted as legacy)
"""

import base64
import json
import sys
from datetime import UTC
from getpass import getpass
from pathlib import Path

import typer

from . import __version__
from .client import VaultClient
from .config import get_url, load_token, save_token, set_profile
from .migrate import (
    ConflictPolicy,
    InfisicalHttp,
    InfisicalSource,
    MigrationError,
    VaultHttp,
    VaultSource,
    apply_plan,
    parse_vault_mounts,
    plan_migration,
    render_target,
)

app = typer.Typer(
    name="rhorizon",
    help="CLI for rhorizon secrets manager.",
    no_args_is_help=True,
    add_completion=False,
)
token_app = typer.Typer(help="Token management.", no_args_is_help=True)
ns_app = typer.Typer(help="Namespace management.", no_args_is_help=True)
import_app = typer.Typer(help="Import secrets.", no_args_is_help=True)
migrate_app = typer.Typer(
    help="Migrate from external secret stores.",
    no_args_is_help=True,
)
audit_app = typer.Typer(help="Audit log inspection.", no_args_is_help=True)
master_app = typer.Typer(help="Master password operations.", no_args_is_help=True)
backup_app = typer.Typer(
    help="Encrypted backup export / restore (age passphrase).",
    no_args_is_help=True,
)
cluster_app = typer.Typer(
    help="HA cluster membership operations.",
    no_args_is_help=True,
)
dynamic_app = typer.Typer(
    help="Dynamic secrets: on-demand DB/LDAP credentials with leases.",
    no_args_is_help=True,
)
pki_app = typer.Typer(
    help="PKI engine: issue short-lived X.509 certs (ed25519 or ML-DSA).",
    no_args_is_help=True,
)

app.add_typer(token_app, name="token")
app.add_typer(ns_app, name="ns")
app.add_typer(import_app, name="import")
app.add_typer(migrate_app, name="migrate")
app.add_typer(audit_app, name="audit")
app.add_typer(master_app, name="master")
app.add_typer(backup_app, name="backup")
app.add_typer(cluster_app, name="cluster")
app.add_typer(dynamic_app, name="dynamic")
app.add_typer(pki_app, name="pki")


def _client(need_token: bool = True) -> VaultClient:
    url = get_url()
    if not url:
        print("Error: no vault configured. Run: rhorizon login URL", file=sys.stderr)
        raise typer.Exit(1)
    token = load_token() if need_token else None
    return VaultClient(url, token)


# -- Core commands --


@app.command()
def login(url: str):
    """Save vault address and authenticate.

    A bare host defaults to https. TLS is the supported transport: the vault
    logs a PLAINTEXT TRANSPORT warning for every call that arrives without it,
    because the bearer token and the secret values are on that wire. Pass an
    explicit http:// if you really mean plaintext.
    """
    if "://" not in url:
        url = f"https://{url}"
    if url.startswith("http://"):
        print(
            "Warning: http:// selected. The token and every secret value will "
            "cross this connection unencrypted.",
            file=sys.stderr,
        )
    set_profile("default", url)
    client = VaultClient(url)
    st = client.status()
    print(f"Connected to rhorizon {st.get('version', '?')} (sealed={st['sealed']})")

    token = typer.prompt("Token (rh_...)", hide_input=True)
    save_token(token)
    print("Token saved.")


@app.command()
def status(as_json: bool = typer.Option(False, "--json")):
    """Show vault status."""
    r = _client(need_token=False).status()
    if as_json:
        print(json.dumps(r))
        return
    sealed = "SEALED" if r["sealed"] else "UNSEALED"
    print(f"Status:   {sealed}")
    print(f"Version:  {r.get('version', '?')}")
    if r.get("uptime"):
        print(f"Uptime:   {r['uptime']}")
    memory = r.get("memory_protection", "unknown")
    process_memory = r.get("process_memory_protection", "unknown")
    swap = r.get("swap_protection", "unknown")
    print(f"Buffers:  {memory}")
    print(f"Process:  {process_memory}")
    print(f"Swap:     {swap}")
    memory_at_risk = swap != "protected" and (
        memory == "zeroize-only" or process_memory == "swappable"
    )
    if memory_at_risk:
        print(
            "Warning: sensitive memory is wiped after use but is not locked "
            "against unencrypted or unknown swap."
        )
        print(
            "To enforce locking, grant IPC_LOCK or raise the memlock limit, then "
            "set RH_MEMORY_LOCK_MODE=required."
        )
    print(f"2FA:      {r.get('second_factor', 'none')}")
    if r.get("shamir_enabled"):
        print(
            f"Shamir:   {r['shamir_progress']}/{r['shamir_threshold']} "
            f"(total {r['shamir_total']})"
        )


@app.command()
def whoami(as_json: bool = typer.Option(False, "--json")):
    """Introspect the current token: scope, namespaces, expiry, last use.

    Useful for an automation/agent to discover its own permissions
    before acting. Any valid token can call this - no scope required.
    """
    r = _client().whoami()
    if as_json:
        print(json.dumps(r, indent=2))
        return
    print(f"Token:        {r['name']}")
    print(f"ID:           {r['id']}")
    print(f"Scopes:       {', '.join(r.get('scopes', [])) or '(none)'}")
    ns = r.get("namespaces")
    print(f"Namespaces:   {', '.join(ns) if ns else '(unrestricted)'}")
    print(f"Active:       {r['active']}")
    print(f"Ephemeral:    {r['is_ephemeral']}")
    print(f"Created at:   {r.get('created_at') or '?'}")
    print(f"Last used:    {r.get('last_used_at') or '(never)'}")
    print(f"Expires at:   {r.get('expires_at') or '(no expiry)'}")


@app.command()
def unseal():
    """Unseal the vault (prompts for password)."""
    client = _client(need_token=False)
    password = getpass("Master password: ")
    totp = None
    st = client.status()
    if st.get("second_factor") in ("totp", "any"):
        totp = typer.prompt("TOTP code")
    r = client.unseal(password, totp)
    print(f"Status: {r['status']}")
    if r.get("second_factor", "none") != "none":
        print(f"2FA:    {r['second_factor']}")
    if r.get("root_token"):
        kind = r.get("bootstrap_kind", "bootstrap")
        if kind == "restore-recovery":
            expires = r.get("recovery_token_expires_at", "a short TTL")
            title = (
                f"Backup restore - recovery root token issued (temporary, "
                f"expires {expires}). Rotate the stubs in Quasar > Pending "
                f"rotations to mint a permanent root token, then dismiss the "
                f"post-restore review."
            )
        else:
            title = "First-boot - root token issued."
        warning = r.get("warning", "Save this token - shown once only.")
        token = r["root_token"]
        sep = "-" * 72
        print()
        print(sep)
        print(title)
        print(warning)
        print(sep)
        print(token)
        print(sep)
        print()
        if sys.stdout.isatty():
            try:
                input(
                    "Press ENTER once you have saved the token; the screen will be cleared. "
                )
            except (KeyboardInterrupt, EOFError):
                print()
                return
            # ANSI: clear screen + scrollback (xterm \033[3J) + cursor home
            sys.stdout.write("\033[2J\033[3J\033[H")
            sys.stdout.flush()
            print("Screen cleared. Vault is unsealed.")


@app.command()
def seal():
    """Seal the vault."""
    r = _client().seal()
    print(f"Status: {r['status']}")


@app.command()
def get(
    name: str,
    namespace: str = typer.Option(None, "--namespace", "-n"),
    previous: bool = typer.Option(
        False,
        "--previous",
        help="Read the prior value if still inside its rotation grace window.",
    ),
    as_json: bool = typer.Option(False, "--json"),
):
    """Read a secret value.

    Pass --namespace/-n when the same name exists in multiple namespaces
    (the API returns 409 ambiguous otherwise). With --previous, returns the
    value from before the last non-emergency update while its grace window
    (RHORIZON_SECRET_GRACE_SECONDS) is still open, 404 once it closes.
    """
    r = _client().get_secret(name, namespace, previous=previous)
    if as_json:
        print(json.dumps(r, indent=2))
    else:
        print(r["value"])


@app.command("set")
def set_secret(
    name: str,
    value: str = typer.Argument(None),
    file: Path = typer.Option(None, "--file", "-f", help="Read value from file"),
    stdin: bool = typer.Option(False, "--stdin", help="Read value from stdin"),
    namespace: str = typer.Option("default", "--namespace", "-n"),
    update: bool = typer.Option(False, "--update", "-u", help="Update existing"),
):
    """Create or update a secret."""
    if stdin:
        value = sys.stdin.read().rstrip("\n")
    elif file:
        value = file.read_text().rstrip("\n")
    elif value is None:
        print("Error: provide VALUE, --file, or --stdin", file=sys.stderr)
        raise typer.Exit(1)

    client = _client()
    if update:
        r = client.update_secret(name, value, namespace)
    else:
        r = client.create_secret(name, value, namespace)
    version = r.get("version", 1)
    print(f"{name} (v{version})")


@app.command("update")
def update_secret_cmd(
    name: str,
    value: str = typer.Argument(None),
    file: Path = typer.Option(None, "--file", "-f", help="Read value from file"),
    stdin: bool = typer.Option(False, "--stdin", help="Read value from stdin"),
    namespace: str = typer.Option("default", "--namespace", "-n"),
    emergency: bool = typer.Option(
        False,
        "--emergency",
        help="Suppress the rotation grace window (use when rotating a leak).",
    ),
):
    """Update an existing secret's value (alias for `set --update`).

    Requires secrets:w on the secret's namespace; recorded in the audit chain.
    By default the prior value stays readable via `get --previous` for the
    configured grace window; pass --emergency to stop serving it immediately.
    """
    if stdin:
        value = sys.stdin.read().rstrip("\n")
    elif file:
        value = file.read_text().rstrip("\n")
    elif value is None:
        print("Error: provide VALUE, --file, or --stdin", file=sys.stderr)
        raise typer.Exit(1)
    r = _client().update_secret(name, value, namespace, emergency=emergency)
    print(f"{name} (v{r.get('version', 1)})")


@app.command()
def delete(
    name: str,
    namespace: str = typer.Option(None, "--namespace", "-n"),
):
    """Delete a secret.

    Pass --namespace/-n when the same name exists in multiple namespaces.
    """
    _client().delete_secret(name, namespace)
    print(f"Deleted: {name}")


@app.command("list")
def list_secrets(namespace: str = typer.Option(None, "--namespace", "-n")):
    """List secrets (names only)."""
    r = _client().list_secrets(namespace)
    for s in r.get("items", []):
        ns = f"  [{s['namespace']}]" if s["namespace"] != "default" else ""
        print(f"  {s['name']}  v{s['version']}{ns}")
    print(f"\n{len(r.get('items', []))} secret(s)")


@app.command()
def rotate(
    name: str = typer.Argument(None),
    namespace: str = typer.Option(None, "--namespace", "-n"),
    all_secrets: bool = typer.Option(False, "--all"),
):
    """Rotate DEK (re-encrypt without changing value).

    Pass --namespace/-n when the same name exists in multiple namespaces.
    """
    client = _client()
    if all_secrets:
        r = client.rotate_all()
        print(f"Rotated {r['rotated']} secret(s)")
    elif name:
        r = client.rotate_secret(name, namespace)
        print(f"{name} rotated (v{r['version']})")
    else:
        print("Error: provide NAME or --all", file=sys.stderr)
        raise typer.Exit(1)


@app.command()
def versions(
    name: str,
    namespace: str = typer.Option(None, "--namespace", "-n"),
):
    """List version history of a secret.

    Pass --namespace/-n when the same name exists in multiple namespaces.
    """
    r = _client().list_versions(name, namespace)
    for v in r.get("versions", []):
        print(f"  v{v['version']}  {v['created_at']}  by {v.get('created_by', '?')}")


@app.command()
def rollback(
    name: str,
    version: int,
    namespace: str = typer.Option(None, "--namespace", "-n"),
):
    """Restore a previous version of a secret.

    Pass --namespace/-n when the same name exists in multiple namespaces.
    """
    r = _client().rollback(name, version, namespace)
    print(f"Restored v{r['restored_from']} -> v{r['new_version']}")


@app.command()
def generate(
    length: int = typer.Argument(32, help="Key length"),
    alpha: bool = typer.Option(True, "--alpha/--no-alpha", "-a", help="Letters"),
    numeric: bool = typer.Option(True, "--numeric/--no-numeric", "-n", help="Digits"),
    special: bool = typer.Option(
        True, "--special/--no-special", "-s", help="Special chars"
    ),
    count: int = typer.Option(1, "--count", "-c", help="Number of keys"),
    store: str = typer.Option(None, "--store", help="Store in vault as this name"),
    namespace: str = typer.Option("default", "--namespace"),
):
    """Generate random keys (harlok_keygen heritage).

    Charsets: -a alpha, -n numeric, -s special (all on by default).

    Examples:
      rhorizon generate 64              # 64-char key, all charsets
      rhorizon generate 16 -c 10        # 10 keys of 16 chars
      rhorizon generate 32 --no-special # alphanumeric only
      rhorizon generate 48 --store prod/db-pass  # generate + store in vault
    """
    import secrets as _secrets
    import string

    # Build charset (same logic as harlok_keygen ASCII tables)
    charset = ""
    if alpha:
        charset += string.ascii_letters  # A-Z a-z (65-90, 97-122)
    if numeric:
        charset += string.digits  # 0-9 (48-57)
    if special:
        charset += string.punctuation  # (32-47, 58-64, 91-96, 123-126)

    if not charset:
        print("Error: at least one charset required (-a, -n, -s)", file=sys.stderr)
        raise typer.Exit(1)

    keys = []
    for _ in range(count):
        key = "".join(_secrets.choice(charset) for _ in range(length))
        keys.append(key)
        print(key)

    # Optionally store the last generated key in the vault
    if store and keys:
        client = _client()
        client.create_secret(store, keys[-1], namespace)
        print(f"\nStored as '{store}' in namespace '{namespace}'")


@app.command()
def version():
    """Show CLI version."""
    print(f"rhorizon {__version__}")


# -- Token subcommands --


def _build_permissions(
    scope: list[str] | None,
    namespace: list[str] | None,
    perms_json: str | None,
) -> dict:
    """Build a permissions dict from --scope/--namespace flags or JSON.

    Examples:
        scope=["secrets:r", "tokens:r"], namespace=["prod"]
            -> {"secrets": "r", "tokens": "r", "namespaces": ["prod"]}
        perms_json='{"admin":"rw"}'  (back-compat path)
            -> {"admin": "rw"}
    """
    if perms_json:
        try:
            return json.loads(perms_json)
        except json.JSONDecodeError as e:
            print(f"Error: invalid JSON in PERMS: {e}", file=sys.stderr)
            raise typer.Exit(1)
    if not scope:
        print(
            "Error: must provide either --scope SCOPE:MODE (repeatable) or "
            "JSON permissions as a positional arg",
            file=sys.stderr,
        )
        raise typer.Exit(1)
    perms: dict = {}
    for s in scope:
        if ":" not in s:
            print(f"Error: --scope must be SCOPE:MODE (got '{s}')", file=sys.stderr)
            raise typer.Exit(1)
        k, v = s.split(":", 1)
        if v not in ("r", "rw", "w"):
            print(
                f"Error: scope mode must be r, rw, or w (got '{v}')",
                file=sys.stderr,
            )
            raise typer.Exit(1)
        perms[k] = v
    if namespace:
        perms["namespaces"] = list(namespace)
    return perms


@token_app.command("create")
def token_create(
    name: str,
    perms: str = typer.Argument(
        None,
        help='Optional JSON permissions, e.g. \'{"secrets":"rw"}\'. '
        "Prefer --scope/--namespace flags.",
    ),
    scope: list[str] = typer.Option(
        None,
        "--scope",
        "-s",
        help="SCOPE:MODE, repeatable. e.g. -s secrets:r -s tokens:r",
    ),
    namespace: list[str] = typer.Option(
        None,
        "--namespace",
        "-n",
        help="Restrict to namespace(s), repeatable. e.g. -n prod -n staging",
    ),
):
    """Create a new long-lived token.

    Examples:
        rhorizon token create my-bot --scope secrets:r --namespace mcp/mail
        rhorizon token create deploy --scope secrets:rw --scope tokens:r \\
            --namespace prod --namespace staging
        rhorizon token create admin '{"admin":"rw"}'   # JSON fallback
    """
    permissions = _build_permissions(scope, namespace, perms)
    r = _client().create_token(name, permissions)
    print(f"Token:  {r['token']}")
    print(f"Name:   {r['name']}")
    print(f"Perms:  {json.dumps(permissions)}")
    print("(shown once - save it now)")


@token_app.command("list")
def token_list():
    """List tokens."""
    r = _client().list_tokens()
    for t in r.get("items", []):
        active = "active" if t["active"] else "REVOKED"
        print(f"  {t['id'][:8]}  {t['name']}  [{active}]  {t['permissions']}")


@token_app.command("show")
def token_show(token_id_or_name: str):
    """Show full details of a token (lookup by id prefix or by exact name)."""
    items = _client().list_tokens().get("items", [])
    matches = [
        t
        for t in items
        if t["id"].startswith(token_id_or_name) or t["name"] == token_id_or_name
    ]
    if not matches:
        print(f"No token matches '{token_id_or_name}'", file=sys.stderr)
        raise typer.Exit(1)
    if len(matches) > 1:
        print(
            f"Ambiguous '{token_id_or_name}' - {len(matches)} matches:",
            file=sys.stderr,
        )
        for t in matches:
            print(f"  {t['id']}  {t['name']}", file=sys.stderr)
        raise typer.Exit(1)
    t = matches[0]
    print(f"ID:           {t['id']}")
    print(f"Name:         {t['name']}")
    print(f"Active:       {t['active']}")
    print(f"Permissions:  {json.dumps(t['permissions'])}")
    print(f"Created by:   {t.get('created_by', '?')}")
    print(f"Created at:   {t.get('created_at', '?')}")
    print(f"Last used:    {t.get('last_used_at') or '(never)'}")
    print(f"Expires at:   {t.get('expires_at') or '(no expiry)'}")
    print(f"Revoked at:   {t.get('revoked_at') or '(not revoked)'}")


@token_app.command("revoke")
def token_revoke(token_id: str):
    """Revoke a token."""
    r = _client().revoke_token(token_id)
    print(f"Revoked: {r['name']}")


@token_app.command("rotate")
def token_rotate(
    token_id: str,
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt"),
):
    """Rotate a live token's secret in place (same id, name, scopes).

    Mints a fresh plaintext and overwrites the stored hash: the old value
    stops authenticating immediately, so re-provision every consumer with
    the new token. Shown once only.
    """
    items = _client().list_tokens().get("items", [])
    t = next((x for x in items if x["id"] == token_id or x["name"] == token_id), None)
    name = t["name"] if t else token_id
    if not yes and input(f"Type '{name}' to rotate this token: ") != name:
        print("Aborted.", file=sys.stderr)
        raise typer.Exit(1)
    r = _client().rotate_token(t["id"] if t else token_id)
    print(f"Rotated:  {r['name']}")
    print(f"Token:    {r['token']}")
    print(f"  {r.get('warning', 'Save this token - shown once only')}")


@token_app.command("set-ip")
def token_set_ip(
    token_id: str,
    allowed_ips: str = typer.Argument(
        ..., help="Comma-separated CIDRs/IPs, or '' to clear the restriction"
    ),
):
    """Change a token's IP allowlist in place (by id or name).

    An empty string clears the restriction (any IP). A namespace-restricted
    caller can only change tokens whose namespaces are a subset of its own.
    Recorded in the audit chain.
    """
    items = _client().list_tokens().get("items", [])
    t = next((x for x in items if x["id"] == token_id or x["name"] == token_id), None)
    r = _client().set_token_allowed_ips(t["id"] if t else token_id, allowed_ips or None)
    print(f"Updated:   {r['name']}")
    print(f"Allowlist: {r.get('allowed_ips') or '(any IP)'}")


@token_app.command("renew")
def token_renew(
    token_id: str,
    ttl: int = typer.Option(3600, "--ttl", help="New TTL in seconds (60..86400)"),
):
    """Extend an ephemeral token's TTL.

    Refuses long-lived tokens (no expiry to extend) - use ephemeral or
    create a fresh token instead.
    """
    if ttl < 60 or ttl > 86400:
        print("Error: --ttl must be between 60 and 86400", file=sys.stderr)
        raise typer.Exit(1)
    r = _client().renew_token(token_id, ttl)
    print(f"Renewed:  {r['name']}")
    print(f"Expires:  {r['expires_at']}")
    print(f"TTL:      {r['ttl_seconds']}s")


@token_app.command("ephemeral")
def token_ephemeral(
    ttl: int = typer.Option(3600, "--ttl", help="TTL in seconds (60 to 86400)"),
    scope: list[str] = typer.Option(
        None, "--scope", "-s", help="SCOPE:MODE, repeatable."
    ),
    namespace: list[str] = typer.Option(
        None, "--namespace", "-n", help="Restrict to namespace(s)."
    ),
    label: str = typer.Option(
        "", "--label", "-l", help="Free-text label for audit (e.g. agent name)."
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Print only the token on stdout (for: TOK=$(rhorizon ...))",
    ),
    as_json: bool = typer.Option(False, "--json"),
    perms: str = typer.Argument(None, help="Optional JSON permissions."),
):
    """Mint an ephemeral token (auto-expires after TTL).

    Examples:
        rhorizon token ephemeral --ttl 300 --scope secrets:r --namespace mcp/mail
        rhorizon token ephemeral --ttl 60 --scope secrets:r -n demo --label claude
        TOK=$(rhorizon token ephemeral -q --ttl 300 -s secrets:r -n demo)
    """
    if ttl < 60 or ttl > 86400:
        print("Error: --ttl must be between 60 and 86400", file=sys.stderr)
        raise typer.Exit(1)
    permissions = _build_permissions(scope, namespace, perms)
    r = _client().create_ephemeral_token(permissions, ttl_seconds=ttl, label=label)
    if quiet:
        print(r["token"])
        return
    if as_json:
        print(json.dumps({**r, "permissions": permissions}, indent=2))
        return
    print(f"Token:    {r['token']}")
    print(f"Name:     {r['name']}")
    print(f"Expires:  {r['expires_at']} ({r['ttl_seconds']}s)")
    print(f"Perms:    {json.dumps(permissions)}")
    if label:
        print(f"Label:    {label}")
    print("(shown once - save it now, expires automatically)")


# -- Namespace subcommands --


@ns_app.command("list")
def ns_list():
    """List namespaces."""
    r = _client().list_namespaces()
    for ns in r.get("items", []):
        print(f"  {ns['namespace']}  ({ns['secret_count']} secrets)")


@ns_app.command("delete")
def ns_delete(name: str):
    """Delete a namespace and all its secrets."""
    r = _client().delete_namespace(name)
    print(f"Deleted namespace '{name}' ({r['secrets_deleted']} secrets)")


# -- Import subcommands --


@import_app.command("dotenv")
def import_dotenv(
    file: Path,
    namespace: str = typer.Option("default", "--namespace", "-n"),
):
    """Import secrets from a .env file."""
    if not file.exists():
        print(f"Error: {file} not found", file=sys.stderr)
        raise typer.Exit(1)

    data = {}
    for line in file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip 'export ' prefix
        line = line.removeprefix("export ")
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        # Unquote (single or double)
        if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
            value = value[1:-1]
        # Unescape \n in double-quoted values
        if value and '"' not in value:
            value = value.replace("\\n", "\n")
        data[key] = value

    client = _client()
    imported = 0
    for key, val in data.items():
        client.create_secret(key, val, namespace)
        print(f"  {key}")
        imported += 1

    print(f"\n{imported} secret(s) imported into namespace '{namespace}'")


@import_app.command("json")
def import_json(
    file: Path,
    namespace: str = typer.Option(None, "--namespace", "-n"),
):
    """Import secrets from a JSON migration file."""
    if not file.exists():
        print(f"Error: {file} not found", file=sys.stderr)
        raise typer.Exit(1)

    secrets = json.loads(file.read_text())
    if isinstance(secrets, dict) and "secrets" in secrets:
        secrets = secrets["secrets"]

    client = _client()
    imported = 0
    for s in secrets:
        ns = namespace or s.get("namespace", "default")
        client.create_secret(s["name"], s["value"], ns)
        print(f"  {s['name']}")
        imported += 1

    print(f"\n{imported} secret(s) imported")


# -- Migration subcommands --


def _read_migration_config(path: Path | None) -> dict:
    if path is None:
        return {}
    if not path.exists():
        print(f"Error: {path} not found", file=sys.stderr)
        raise typer.Exit(1)
    raw = path.read_text()
    if path.suffix.lower() == ".json":
        return json.loads(raw)
    import tomlkit

    return dict(tomlkit.loads(raw))


def _cfg_get(cfg: dict, *keys: str, default=None):
    current = cfg
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def _cfg_bool(value, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _existing_secret_names(client: VaultClient, namespace: str) -> set[str]:
    try:
        body = client.list_secrets(namespace)
    except SystemExit:
        return set()
    return {str(item.get("name")) for item in body.get("items", []) if item.get("name")}


def _plan_external_items(
    items: list,
    *,
    rh_namespace: str,
    namespace_template: str | None,
    name_template: str,
    on_conflict: ConflictPolicy,
    separator: str,
):
    client = _client()
    target_namespaces = {
        render_target(
            item,
            rh_namespace=rh_namespace,
            namespace_template=namespace_template,
            name_template=name_template,
            separator=separator,
        )[0]
        for item in items
    }
    existing = {
        namespace: _existing_secret_names(client, namespace)
        for namespace in target_namespaces
    }
    return plan_migration(
        items,
        existing_by_namespace=existing,
        rh_namespace=rh_namespace,
        namespace_template=namespace_template,
        name_template=name_template,
        on_conflict=on_conflict,
        separator=separator,
    )


def _print_external_plan(
    *,
    source_label: str,
    summary_source: str,
    items: list,
    plan: list,
    do_apply: bool,
    as_json: bool,
    experimental: bool = False,
):
    summary = {
        "source": summary_source,
        "experimental": experimental,
        "found": len(items),
        "create": sum(1 for p in plan if p.action == "create"),
        "create_renamed": sum(1 for p in plan if p.action == "create-renamed"),
        "update": sum(1 for p in plan if p.action == "update"),
        "skip": sum(1 for p in plan if p.action == "skip"),
        "apply": do_apply,
    }
    if as_json:
        print(
            json.dumps(
                {
                    "summary": summary,
                    "items": [
                        {
                            "source_mount": p.source.mount,
                            "source_path": p.source.path,
                            "source_key": p.source.key,
                            "namespace": p.namespace,
                            "name": p.name,
                            "action": p.action,
                            "reason": p.reason,
                        }
                        for p in plan
                    ],
                },
                indent=2,
            )
        )
        return

    mode = "APPLY" if do_apply else "DRY-RUN"
    prefix = "EXPERIMENTAL " if experimental else ""
    print(f"{prefix}{mode}: {source_label} -> rhorizon")
    print(
        "Found {found}; create {create}; renamed {create_renamed}; "
        "update {update}; skip {skip}".format(**summary)
    )
    for p in plan[:100]:
        reason = f" ({p.reason})" if p.reason else ""
        print(
            f"  {p.action:14} {p.source.mount}/{p.source.path}#{p.source.key}"
            f" -> {p.namespace}/{p.name}{reason}"
        )
    if len(plan) > 100:
        print(f"  ... {len(plan) - 100} more")


def _confirm_and_apply(plan: list, *, yes: bool) -> None:
    if not yes and typer.prompt("Type APPLY to write these secrets") != "APPLY":
        print("Aborted.", file=sys.stderr)
        raise typer.Exit(1)
    counts = apply_plan(_client(), plan)
    print(
        "Applied: created={created} updated={updated} skipped={skipped}".format(
            **counts
        )
    )


def _validate_migration_mode(do_apply: bool, dry_run: bool) -> None:
    if do_apply and dry_run:
        print("Error: use either --apply or --dry-run, not both", file=sys.stderr)
        raise typer.Exit(1)


@migrate_app.command("vault")
def migrate_vault(
    vault_addr: str = typer.Option(
        None,
        "--vault-addr",
        envvar="VAULT_ADDR",
        help="HashiCorp Vault base URL, e.g. https://vault.example",
    ),
    vault_token: str = typer.Option(
        None,
        "--vault-token",
        envvar="VAULT_TOKEN",
        help="HashiCorp Vault token. Prompted if omitted.",
    ),
    vault_namespace: str = typer.Option(
        None,
        "--vault-namespace",
        envvar="VAULT_NAMESPACE",
        help="Vault Enterprise/HCP namespace sent as X-Vault-Namespace.",
    ),
    mount: list[str] = typer.Option(
        None,
        "--mount",
        "-m",
        help="KV mount to import. Format: path:v1 or path:v2. Repeatable.",
    ),
    rh_namespace: str = typer.Option(
        None,
        "--rh-namespace",
        "-n",
        help="Destination rhorizon namespace when --namespace-template is unset.",
    ),
    namespace_template: str = typer.Option(
        None,
        "--namespace-template",
        help="Template for destination namespace, e.g. vault-{source_namespace}.",
    ),
    name_template: str = typer.Option(
        None,
        "--name-template",
        help="Template for secret name. Default: {mount}.{path}.{key}",
    ),
    on_conflict: ConflictPolicy = typer.Option(
        ConflictPolicy.RENAME,
        "--on-conflict",
        help="rename is default and never overwrites existing rhorizon secrets.",
    ),
    separator: str = typer.Option(
        ".",
        "--separator",
        help="Replacement for source path separators in rhorizon names.",
    ),
    config: Path = typer.Option(
        None,
        "--config",
        "-c",
        help="Optional JSON/TOML migration config.",
    ),
    insecure_skip_verify: bool = typer.Option(
        False,
        "--insecure-skip-verify",
        help="Disable TLS verification for the source Vault only.",
    ),
    do_apply: bool = typer.Option(
        False,
        "--apply",
        help="Write to rhorizon. Without this, only dry-run is performed.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Only print the migration plan. This is the default.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation when --apply is set.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable plan."),
):
    """Migrate HashiCorp Vault KV v1/v2 secrets into rhorizon.

    Defaults are conservative: dry-run only, conflict policy is rename, and
    existing rhorizon secrets are never overwritten unless
    `--on-conflict update-version` is passed explicitly.
    """
    _validate_migration_mode(do_apply, dry_run)
    cfg = _read_migration_config(config)
    vault_cfg = _cfg_get(cfg, "vault", default={}) or {}
    target_cfg = _cfg_get(cfg, "target", default={}) or {}

    vault_addr = vault_addr or vault_cfg.get("addr") or vault_cfg.get("url")
    vault_token = vault_token or vault_cfg.get("token")
    vault_namespace = vault_namespace or vault_cfg.get("namespace")
    rh_namespace = rh_namespace or target_cfg.get("namespace") or "imported"
    namespace_template = namespace_template or target_cfg.get("namespace_template")
    name_template = (
        name_template or target_cfg.get("name_template") or "{mount}.{path}.{key}"
    )
    if not mount:
        mount = list(vault_cfg.get("mounts") or [])

    if not vault_addr:
        vault_addr = typer.prompt("Vault address")
    if not vault_token:
        vault_token = typer.prompt("Vault token", hide_input=True)

    try:
        source = VaultSource(
            VaultHttp(
                vault_addr,
                vault_token,
                namespace=vault_namespace,
                verify=not insecure_skip_verify,
            ),
            mounts=parse_vault_mounts(mount),
        )
        items = source.iter_secrets()
        plan = _plan_external_items(
            items,
            rh_namespace=rh_namespace,
            namespace_template=namespace_template,
            name_template=name_template,
            on_conflict=on_conflict,
            separator=separator,
        )
    except (MigrationError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise typer.Exit(1)

    _print_external_plan(
        source_label="Vault",
        summary_source="vault",
        items=items,
        plan=plan,
        do_apply=do_apply,
        as_json=as_json,
    )
    if not do_apply:
        return
    _confirm_and_apply(plan, yes=yes)


@migrate_app.command("infisical")
def migrate_infisical(
    infisical_addr: str = typer.Option(
        None,
        "--infisical-addr",
        envvar="INFISICAL_ADDR",
        help="Infisical base URL, e.g. https://us.infisical.com",
    ),
    access_token: str = typer.Option(
        None,
        "--access-token",
        envvar="INFISICAL_TOKEN",
        help="Infisical API access token. Prompted if auth vars are omitted.",
    ),
    client_id: str = typer.Option(
        None,
        "--client-id",
        envvar="INFISICAL_CLIENT_ID",
        help="Universal Auth client ID, used when --access-token is omitted.",
    ),
    client_secret: str = typer.Option(
        None,
        "--client-secret",
        envvar="INFISICAL_CLIENT_SECRET",
        help="Universal Auth client secret, prompted if omitted.",
    ),
    organization_slug: str = typer.Option(
        None,
        "--organization-slug",
        envvar="INFISICAL_ORG_SLUG",
        help="Optional Infisical organization slug for Universal Auth.",
    ),
    project_id: str = typer.Option(
        None,
        "--project-id",
        envvar="INFISICAL_PROJECT_ID",
        help="Infisical project ID to import from.",
    ),
    environment: str = typer.Option(
        None,
        "--environment",
        envvar="INFISICAL_ENVIRONMENT",
        help="Infisical environment slug to import from.",
    ),
    secret_path: str = typer.Option(
        None,
        "--secret-path",
        envvar="INFISICAL_SECRET_PATH",
        help="Infisical secret path to import recursively. Default: /",
    ),
    include_imports: bool | None = typer.Option(
        None,
        "--include-imports/--no-include-imports",
        help="Include Infisical imported secrets. Default: include.",
    ),
    expand_secret_references: bool | None = typer.Option(
        None,
        "--expand-secret-references/--no-expand-secret-references",
        help="Expand Infisical secret references. Default: expand.",
    ),
    rh_namespace: str = typer.Option(
        None,
        "--rh-namespace",
        "-n",
        help="Destination rhorizon namespace when --namespace-template is unset.",
    ),
    namespace_template: str = typer.Option(
        None,
        "--namespace-template",
        help="Template for destination namespace, e.g. infisical-{source_namespace}.",
    ),
    name_template: str = typer.Option(
        None,
        "--name-template",
        help="Template for secret name. Default: {source_namespace}.{path}.{key}",
    ),
    on_conflict: ConflictPolicy = typer.Option(
        ConflictPolicy.RENAME,
        "--on-conflict",
        help="rename is default and never overwrites existing rhorizon secrets.",
    ),
    separator: str = typer.Option(
        ".",
        "--separator",
        help="Replacement for source path separators in rhorizon names.",
    ),
    config: Path = typer.Option(
        None,
        "--config",
        "-c",
        help="Optional JSON/TOML migration config.",
    ),
    insecure_skip_verify: bool = typer.Option(
        False,
        "--insecure-skip-verify",
        help="Disable TLS verification for the source Infisical only.",
    ),
    do_apply: bool = typer.Option(
        False,
        "--apply",
        help="Write to rhorizon. Without this, only dry-run is performed.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Only print the migration plan. This is the default.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation when --apply is set.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable plan."),
):
    """EXPERIMENTAL: migrate Infisical secrets into rhorizon.

    This path is implemented from the public Infisical API docs and covered by
    local mocked tests, but it is not marked production-ready until exercised
    against a real Infisical tenant.
    """
    _validate_migration_mode(do_apply, dry_run)
    cfg = _read_migration_config(config)
    infisical_cfg = _cfg_get(cfg, "infisical", default={}) or {}
    universal_cfg = _cfg_get(infisical_cfg, "universal_auth", default={}) or {}
    target_cfg = _cfg_get(cfg, "target", default={}) or {}

    infisical_addr = (
        infisical_addr
        or infisical_cfg.get("addr")
        or infisical_cfg.get("url")
        or infisical_cfg.get("base_url")
    )
    access_token = (
        access_token or infisical_cfg.get("token") or infisical_cfg.get("access_token")
    )
    client_id = (
        client_id
        or infisical_cfg.get("client_id")
        or infisical_cfg.get("clientId")
        or universal_cfg.get("client_id")
        or universal_cfg.get("clientId")
    )
    client_secret = (
        client_secret
        or infisical_cfg.get("client_secret")
        or infisical_cfg.get("clientSecret")
        or universal_cfg.get("client_secret")
        or universal_cfg.get("clientSecret")
    )
    organization_slug = (
        organization_slug
        or infisical_cfg.get("organization_slug")
        or infisical_cfg.get("organizationSlug")
        or universal_cfg.get("organization_slug")
        or universal_cfg.get("organizationSlug")
    )
    project_id = (
        project_id or infisical_cfg.get("project_id") or infisical_cfg.get("projectId")
    )
    environment = environment or infisical_cfg.get("environment")
    secret_path = secret_path or infisical_cfg.get("secret_path") or "/"
    if include_imports is None:
        include_imports = _cfg_bool(infisical_cfg.get("include_imports"), True)
    if expand_secret_references is None:
        expand_secret_references = _cfg_bool(
            infisical_cfg.get("expand_secret_references"),
            True,
        )
    rh_namespace = rh_namespace or target_cfg.get("namespace") or "imported"
    namespace_template = namespace_template or target_cfg.get("namespace_template")
    name_template = (
        name_template
        or target_cfg.get("name_template")
        or "{source_namespace}.{path}.{key}"
    )

    if not infisical_addr:
        infisical_addr = typer.prompt(
            "Infisical URL", default="https://us.infisical.com"
        )
    if not access_token and not client_id and not client_secret:
        access_token = typer.prompt(
            "Infisical access token (blank for Universal Auth)",
            default="",
            hide_input=True,
            show_default=False,
        )
    access_token = access_token or None
    if not access_token:
        if not client_id:
            client_id = typer.prompt("Infisical Universal Auth client ID")
        if not client_secret:
            client_secret = typer.prompt(
                "Infisical Universal Auth client secret",
                hide_input=True,
            )
    if not project_id:
        project_id = typer.prompt("Infisical project ID")
    if not environment:
        environment = typer.prompt("Infisical environment slug")

    try:
        http = InfisicalHttp(
            infisical_addr,
            access_token,
            verify=not insecure_skip_verify,
        )
        if not access_token:
            http.login_universal(
                client_id=client_id,
                client_secret=client_secret,
                organization_slug=organization_slug,
            )
        source = InfisicalSource(
            http,
            project_id=project_id,
            environment=environment,
            secret_path=secret_path,
            include_imports=include_imports,
            expand_secret_references=expand_secret_references,
        )
        items = source.iter_secrets()
        plan = _plan_external_items(
            items,
            rh_namespace=rh_namespace,
            namespace_template=namespace_template,
            name_template=name_template,
            on_conflict=on_conflict,
            separator=separator,
        )
    except (MigrationError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise typer.Exit(1)

    _print_external_plan(
        source_label="Infisical",
        summary_source="infisical",
        items=items,
        plan=plan,
        do_apply=do_apply,
        as_json=as_json,
        experimental=True,
    )
    if not do_apply:
        return
    _confirm_and_apply(plan, yes=yes)


# -- Audit subcommands --


def _print_audit_entry(e: dict) -> None:
    """One-liner format for tail/follow."""
    ts = e.get("timestamp", "?")
    actor = e.get("actor", "?")
    action = e.get("action", "?")
    target = e.get("target") or ""
    verified = e.get("verified")
    if e.get("unsigned"):
        marker = "[UNSIGNED]"
    elif verified is True:
        marker = "[OK]"
    elif verified is False:
        marker = "[BROKEN]"
    else:
        marker = "?"
    line = f"  {marker}  {ts:25}  {actor:25}  {action:22}  {target}"
    print(line)


@audit_app.command("tail")
def audit_tail(
    n: int = typer.Option(20, "-n", "--limit", help="Number of entries"),
    actor: str = typer.Option(None, "--actor", help="Filter by actor"),
    action: str = typer.Option(None, "--action", help="Filter by action"),
    since: str = typer.Option(
        None, "--since", help="ISO timestamp, inclusive lower bound"
    ),
    until: str = typer.Option(
        None, "--until", help="ISO timestamp, exclusive upper bound"
    ),
    as_json: bool = typer.Option(False, "--json"),
):
    """Show the last N audit entries (with chain verification)."""
    # Use the API's built-in filtering when since/until/actor/action are set;
    # otherwise fetch a wide window and tail-slice client side for "last N".
    if since or until or actor or action:
        items = (
            _client()
            .audit_range(
                since=since, until=until, actor=actor, action=action, limit=max(n, 1000)
            )
            .get("items", [])
        )
    else:
        items = _client().list_audit(limit=max(n, 1000)).get("items", [])
    items = items[-n:]
    if as_json:
        print(json.dumps(items, indent=2))
        return
    for e in items:
        _print_audit_entry(e)


@audit_app.command("follow")
def audit_follow(
    interval: float = typer.Option(2.0, "--interval", "-i", help="Poll seconds"),
):
    """Follow the audit log in real time (tail -f style)."""
    import time

    seen: set[str] = set()
    # Prime with the most recent entries so we don't dump history on first poll
    initial = _client().list_audit(limit=1000).get("items", [])
    for e in initial[-20:]:
        _print_audit_entry(e)
    seen.update(e["id"] for e in initial)
    print(f"  --- following (poll {interval}s, Ctrl-C to stop) ---")

    try:
        while True:
            time.sleep(interval)
            try:
                items = _client().list_audit(limit=1000).get("items", [])
            except SystemExit:
                # _client() print error and exits; in follow mode we want to retry
                print("  (vault unreachable, retrying...)")
                continue
            new = [e for e in items if e["id"] not in seen]
            for e in new:
                _print_audit_entry(e)
                seen.add(e["id"])
    except KeyboardInterrupt:
        print()
        print("  --- stopped ---")


@audit_app.command("verify")
def audit_verify():
    """Verify chained mutation audit and checkpointed read audit."""
    r = _client().verify_audit()
    chain_intact = r.get("chain_intact", r.get("verified", False))
    evidence_intact = r.get("evidence_intact", chain_intact)
    lite_intact = r.get("audit_lite_intact")
    total = r.get("total_entries", r.get("total", r.get("count", "?")))
    if chain_intact:
        print(f"[OK] Chain intact ({total} entries verified)")
        if lite_intact is True:
            print(
                "[OK] Read-audit mtree intact "
                f"({r.get('audit_lite_checkpointed_rows', 0)} rows checkpointed, "
                f"{r.get('audit_lite_uncheckpointed_rows', 0)} pending)"
            )
        if evidence_intact:
            return

    if not chain_intact:
        print(f"[FAIL] CHAIN BROKEN - {total} entries, see /audit/verify")
    if lite_intact is False:
        print(
            "[FAIL] READ AUDIT MTREE BROKEN - "
            f"id={r.get('audit_lite_broken_checkpoint_id')} "
            f"reason={r.get('audit_lite_broken_reason')}"
        )
    raise typer.Exit(2)


@audit_app.command("export")
def audit_export(
    output: Path = typer.Argument(..., help="Destination .tar.gz evidence bundle."),
    since: str | None = typer.Option(
        None, "--since", help="Inclusive ISO-8601 timestamp."
    ),
    until: str | None = typer.Option(
        None, "--until", help="Exclusive ISO-8601 timestamp."
    ),
    force: bool = typer.Option(False, "--force", help="Replace an existing file."),
):
    """Export signed mutation, read, archive, and proof evidence."""
    if not output.name.endswith(".tar.gz"):
        print("Error: the audit evidence format is .tar.gz", file=sys.stderr)
        raise typer.Exit(1)
    if output.exists() and not force:
        print(f"Error: {output} already exists (use --force)", file=sys.stderr)
        raise typer.Exit(1)
    result = _client().export_audit_evidence(output, since=since, until=until)
    size_mib = result["size_bytes"] / (1024 * 1024)
    print(f"[OK] Signed audit evidence exported to {output} ({size_mib:.2f} MiB)")
    print(f"Signer: {result.get('signer_fpr') or 'unknown'}")
    print(f"Verify: rhorizon audit verify-export {output}")


@audit_app.command("verify-export")
def audit_verify_export(
    bundle: Path = typer.Argument(..., help="Signed .tar.gz evidence bundle."),
    trusted_signer: str | None = typer.Option(
        None,
        "--trusted-signer",
        help="Previously pinned Ed25519 public-key fingerprint.",
    ),
):
    """Verify an exported bundle offline without contacting the vault."""
    from .audit_bundle import AuditBundleError, verify_bundle

    try:
        result = verify_bundle(bundle, expected_signer_fpr=trusted_signer)
    except (AuditBundleError, OSError) as error:
        print(f"[FAIL] Audit evidence bundle: {error}", file=sys.stderr)
        raise typer.Exit(2) from error
    print(f"[OK] Bundle signature and {result['member_count']} member digests intact")
    print(f"Signer: {result['signer_fpr']}")
    counts = result.get("counts") or {}
    print(
        "Rows: "
        f"main={int(counts.get('main_live_rows', 0)) + int(counts.get('main_archived_rows', 0))}, "
        f"reads={int(counts.get('lite_live_rows', 0)) + int(counts.get('lite_archived_rows', 0))}"
    )
    if not result["signer_pinned"]:
        print(
            "Warning: signer authenticity is not pinned. Compare this fingerprint "
            "with a trusted record, then rerun with --trusted-signer."
        )


@audit_app.command("files")
def audit_files():
    """List the daily JSONL audit files written to /var/log/rhorizon."""
    r = _client().list_audit_files()
    files = r.get("files", [])
    if not files:
        print("(no audit files yet)")
        return
    print(f"  {'Date':12} {'Size':>10}  {'Compressed':>11}  Path")
    for f in files:
        print(
            f"  {f.get('date', ''):12} {f.get('size_bytes', 0):>10}"
            f"  {('yes' if f.get('compressed') else 'no'):>11}  {f.get('path', '')}"
        )


@audit_app.command("read")
def audit_read(date: str):
    """Read all entries from a specific day's audit file (YYYY-MM-DD)."""
    r = _client().read_audit_file(date)
    entries = r.get("entries", [])
    print(f"  {len(entries)} entries on {date}")
    for e in entries:
        _print_audit_entry(e)


# -- Master password subcommands --


@master_app.command("rotate")
def master_rotate(
    emergency: bool = typer.Option(
        False,
        "--emergency",
        help="Invalidate ALL tokens immediately (default: lazy migration "
        "via prev_hmac_key for ~15 days).",
    ),
):
    """Rotate the master password. Re-derives sub-keys, re-encrypts DEKs and
    2FA secrets. Requires the current master password."""
    current = getpass("Current master password: ")
    new_pw = getpass("New master password: ")
    confirm = getpass("Confirm new master password: ")
    if new_pw != confirm:
        print("Error: passwords don't match", file=sys.stderr)
        raise typer.Exit(1)
    if len(new_pw) < 12:
        print("Error: new password should be at least 12 chars", file=sys.stderr)
        raise typer.Exit(1)

    if emergency:
        print(
            "WARNING: emergency mode - every existing token will be "
            "invalidated immediately, INCLUDING yours."
        )
        if input("Type 'rotate-emergency' to confirm: ") != "rotate-emergency":
            print("Aborted.")
            raise typer.Exit(0)

    r = _client().rotate_master_password(current, new_pw, emergency=emergency)
    mode = "emergency" if emergency else "lazy"
    print(f"[OK] Rotated ({mode} mode)")
    print(f"  DEKs re-encrypted: {r.get('deks_rotated', '?')}")
    print(f"  Active tokens at rotation time: {r.get('active_tokens', '?')}")
    if emergency:
        print(
            "  All tokens are now invalid - re-authenticate via "
            "rhorizon login + create new tokens."
        )
    else:
        print(
            "  prev_hmac_key stored - existing tokens keep working "
            "for ~15 days, after which the reaper purges the fallback."
        )


# -- Oneshot decrypt-and-die --


@app.command()
def oneshot(
    name: str,
    namespace: str = typer.Option("default", "--namespace", "-n"),
    totp: str = typer.Option(None, "--totp", help="TOTP code if 2FA enabled"),
):
    """Decrypt-and-die: unseal -> read one secret -> re-seal in a single call.

    Vault must be SEALED at call time (otherwise use plain `get`). The
    unsealed window is bounded by Argon2id (~500ms server-side); the
    secret value is returned, the vault is automatically sealed again
    before the response.

    Example:
        rhorizon oneshot prod-api-key
        rhorizon oneshot api-token --namespace mcp/linkedin --totp 123456
    """
    password = getpass("Master password: ")
    r = _client(need_token=False).oneshot(
        password, name=name, namespace=namespace, totp_code=totp
    )
    # Output ONLY the value to stdout (script-friendly), the rest to stderr
    print(r["value"])


@backup_app.command("export")
def backup_export(
    file: Path = typer.Argument(..., help="Destination .age file."),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite if exists."),
):
    """Export an age-encrypted backup of the vault.

    Prompts twice for the passphrase. The file is written as raw age
    binary (decode the base64 returned by the API). Requires admin:w.

    Example:
        rhorizon backup export ~/backups/rhorizon-2026-05-20.age
    """
    if file.exists() and not force:
        print(
            f"Error: {file} already exists (use --force to overwrite)", file=sys.stderr
        )
        raise typer.Exit(1)

    passphrase = getpass("Backup passphrase (>= 12 chars): ")
    if len(passphrase) < 12:
        print("Error: passphrase must be at least 12 characters", file=sys.stderr)
        raise typer.Exit(1)
    confirm = getpass("Confirm passphrase: ")
    if passphrase != confirm:
        print("Error: passphrases do not match", file=sys.stderr)
        raise typer.Exit(1)

    r = _client().create_backup(passphrase)
    try:
        encrypted = base64.b64decode(r["payload"])
    except (ValueError, TypeError):
        # binascii.Error subclasses ValueError ; TypeError covers a non-str
        # payload. Anything else is a bug and should surface.
        print("Error: API returned a malformed payload", file=sys.stderr)
        raise typer.Exit(1)

    file.write_bytes(encrypted)
    file.chmod(0o600)
    print(
        f"Backup written: {file} ({r['size_bytes']} bytes) "
        f"secrets={r.get('secrets_count', 0)} "
        f"tokens={r.get('tokens_count', 0)} "
        f"groups={r.get('groups_count', 0)} "
        f"config={r.get('config_count', 0)}"
    )


@backup_app.command("restore")
def backup_restore(
    file: Path = typer.Argument(..., help="Source .age file."),
):
    """Restore the vault from an age-encrypted backup.

    Side effects (cf. docs/DISASTER-RECOVERY.md):
      - vault is automatically sealed at the end; the next unseal mints
        a fresh root-restore-<ts> root token with a short TTL.
      - tokens from the backup land in vault_pending_token_rotations
        (rotate them via Quasar > Pending rotations to get a plaintext).

    Requires admin:w on the currently unsealed vault.

    Example:
        rhorizon backup restore ~/backups/rhorizon-2026-05-20.age
    """
    if not file.exists():
        print(f"Error: {file} not found", file=sys.stderr)
        raise typer.Exit(1)

    payload_b64 = base64.b64encode(file.read_bytes()).decode()
    passphrase = getpass("Age passphrase: ")
    if len(passphrase) < 12:
        print("Error: age passphrase must be at least 12 characters", file=sys.stderr)
        raise typer.Exit(1)

    master_password_backup = getpass("Vault master password at backup time: ")
    if len(master_password_backup) < 8:
        print(
            "Error: vault master password must be at least 8 characters",
            file=sys.stderr,
        )
        raise typer.Exit(1)

    print(
        "\nThis will overwrite secrets, token metadata, namespaces, groups, "
        "and restorable config with the backup payload, then seal the vault. "
        "The current root token will be invalidated."
    )
    confirm = input('Type "RESTORE" (case-sensitive) to confirm: ')
    if confirm != "RESTORE":
        print("Error: confirmation phrase mismatch -- aborted", file=sys.stderr)
        raise typer.Exit(1)

    r = _client().restore_backup(
        payload_b64, passphrase, master_password_backup, "RESTORE"
    )
    restored = r.get("restored", {}) if isinstance(r.get("restored"), dict) else r
    print(
        f"Restored: secrets={restored.get('secrets', 0)} "
        f"tokens_pending_rotation={restored.get('tokens_pending_rotation', 0)} "
        f"namespaces={restored.get('namespaces', 0)} "
        f"groups={restored.get('groups', 0)} "
        f"group_members={restored.get('group_members', 0)} "
        f"config={restored.get('config', 0)}"
    )
    if r.get("sealed"):
        print(
            "\nVault is now sealed. Run `rhorizon unseal` with the master "
            "password of the CURRENT vault to mint a fresh recovery root token.\n"
            f"Next step: {r.get('next_step', 'unseal then review pending rotations in Quasar')}"
        )


@import_app.command("age")
def import_age(
    file: Path = typer.Argument(..., help="Source .age file."),
):
    """Alias of `rhorizon backup restore FILE`.

    Restore the vault from an age-encrypted backup. Semantically NOT a
    patch-style import (no namespace flag): replaces the whole vault
    payload, seals automatically, mints a fresh root token on the next
    unseal. See `rhorizon backup restore --help` for the full contract.
    """
    backup_restore(file)


# -- Cluster subcommands --


def _fmt_uuid_short(node_uuid: str) -> str:
    return node_uuid[:12] if len(node_uuid) > 12 else node_uuid


def _fmt_heartbeat_age(last_heartbeat: str | None) -> str:
    if not last_heartbeat:
        return "never"
    from datetime import datetime

    try:
        ts = datetime.fromisoformat(last_heartbeat)
    except ValueError:
        return last_heartbeat
    now = datetime.now(UTC)
    delta = now - ts
    secs = int(delta.total_seconds())
    if secs < 0:
        return "future"
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m"
    if secs < 86400:
        return f"{secs // 3600}h"
    return f"{secs // 86400}d"


def _fmt_cert_expiry(cert_not_after: str) -> str:
    from datetime import datetime

    try:
        ts = datetime.fromisoformat(cert_not_after)
    except ValueError:
        return cert_not_after
    now = datetime.now(UTC)
    delta = ts - now
    days = int(delta.total_seconds() // 86400)
    if days < 0:
        return f"EXPIRED ({-days}d)"
    return f"{days}d"


@cluster_app.command("health")
def cluster_health(as_json: bool = typer.Option(False, "--json")):
    """Per-component cluster health (probed live). Cluster:r."""
    r = _client().cluster_health()
    if as_json:
        print(json.dumps(r, indent=2))
        return
    fg = {"green": "green", "orange": "yellow", "red": "red", "grey": "white"}
    overall = r["overall"]
    typer.secho(
        f"cluster: {overall.upper()}  (ready={str(r['ready']).lower()})",
        fg=fg.get(overall),
        bold=True,
    )
    labels = {
        "database": "database",
        "database_ha": "database HA",
        "node": "node",
        "cluster": "application HA",
    }
    for name, c in r["components"].items():
        st = c["state"]
        dot = "○" if st == "grey" else "●"
        label = labels.get(name, name)
        typer.secho(f"  {dot} {label:<14} {st:<7} {c['reason']}", fg=fg.get(st))


@cluster_app.command("init")
def cluster_init(
    cluster_name: str = typer.Option(
        "rhorizon-cluster",
        "--cluster-name",
        help="Human-readable label embedded as CN in the cluster CA.",
    ),
    save_ha_password: Path = typer.Option(
        None,
        "--save-ha-password",
        help="Write ha_password (base64) to this file (mode 0400). "
        "Otherwise printed once to stdout.",
    ),
    as_json: bool = typer.Option(False, "--json"),
):
    """Initialise the HA cluster on this node. Cluster:w.

    Returns cluster_id + ha_password (shown once) + ca_fingerprint.
    Subsequent calls return 409 cluster_already_initialised.

    Example:
        rhorizon cluster init --cluster-name prod-eu
        rhorizon cluster init --save-ha-password /etc/rhorizon/ha_password
    """
    r = _client().cluster_init(cluster_name)
    if as_json:
        print(json.dumps(r, indent=2))
        return
    ha_password = r["ha_password"]
    print(f"cluster_id:       {r['cluster_id']}")
    print(f"primary_uuid:     {r['primary_uuid']}")
    print(f"ca_fingerprint:   {r['ca_fingerprint']}")
    print()
    if save_ha_password:
        save_ha_password.write_text(ha_password)
        save_ha_password.chmod(0o400)
        print(f"ha_password saved to {save_ha_password} (mode 0400)")
    else:
        sep = "-" * 72
        print(sep)
        print("ha_password (base64, shown ONLY once -- distribute via")
        print("RHORIZON_HA_PASSWORD_FILE to other nodes):")
        print(sep)
        print(ha_password)
        print(sep)
    if r.get("warning"):
        print(f"\nWarning: {r['warning']}")


@cluster_app.command("join")
def cluster_join(
    timeout: int = typer.Option(
        60, "--timeout", help="Max seconds to wait for ha_state != null."
    ),
    poll_interval: float = typer.Option(
        2.0, "--poll-interval", help="Seconds between /cluster/ha/self polls."
    ),
):
    """Wait until this node has joined the cluster.

    Auto-JOIN runs at API boot when HA_AUTO_JOIN=true and an
    ha_password file is provisioned. This command does NOT execute the
    JOIN itself -- it polls /cluster/ha/self until the local row appears
    (ha_state != null), and prints the resulting state.

    Returns exit 0 on success, exit 2 on timeout. Authenticates with the
    bearer token saved by `rhorizon login` (any vault scope).

    Example:
        rhorizon cluster join --timeout 120
    """
    import time

    client = _client()
    deadline = time.monotonic() + timeout
    while True:
        r = client.cluster_ha_self()
        if r.get("ha_state") is not None:
            print(f"node_uuid:        {r['node_uuid']}")
            print(f"ha_state:         {r['ha_state']}")
            if r.get("quarantine_until"):
                print(f"quarantine_until: {r['quarantine_until']}")
            if r.get("last_heartbeat"):
                print(f"last_heartbeat:   {r['last_heartbeat']}")
            return
        if time.monotonic() >= deadline:
            print(
                f"Timeout: node has no membership row after {timeout}s. "
                f"Check API logs for auto-JOIN errors "
                f"(HA_AUTO_JOIN, ha_password file, ha_primary_url).",
                file=sys.stderr,
            )
            raise typer.Exit(2)
        time.sleep(poll_interval)


@cluster_app.command("status")
def cluster_status(as_json: bool = typer.Option(False, "--json")):
    """Show cluster membership and certificate lifecycle. Cluster:r.

    Compact table by default: cluster_id header + per-node row with UUID
    (truncated), source_ip, ha_state, heartbeat age, cert expiry days.
    --json returns the full /cluster/ha payload.
    """
    r = _client().cluster_ha()
    if as_json:
        print(json.dumps(r, indent=2))
        return
    print(f"cluster_id:        {r['cluster_id']}")
    print(f"cluster_version:   {r['cluster_version']}")
    print(f"primary_uuid:      {r.get('primary_uuid') or '(none)'}")
    print(f"ha_loaded:         {r['ha_loaded']}")
    print(f"uuid_ip_conflicts: {r['uuid_ip_conflicts_total']}")
    print()
    nodes = r.get("nodes", [])
    if not nodes:
        print("(no membership rows)")
        return
    header = f"  {'UUID':14} {'IP':18} {'STATE':12} {'HEARTBEAT':>10} {'CERT':>10}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for n in nodes:
        print(
            f"  {_fmt_uuid_short(n['node_uuid']):14} "
            f"{n['source_ip']:18} "
            f"{n['ha_state']:12} "
            f"{_fmt_heartbeat_age(n.get('last_heartbeat')):>10} "
            f"{_fmt_cert_expiry(n['cert_not_after']):>10}"
        )
    print(f"\n{len(nodes)} node(s)")


@cluster_app.command("promote")
def cluster_promote(node_uuid: str):
    """Promote NODE_UUID to primary, demote previous primary. Cluster:w."""
    r = _client().cluster_promote(node_uuid)
    print(f"Promoted {r['node_uuid']} -> {r['ha_state']}")
    if r.get("primary_uuid"):
        print(f"primary_uuid: {r['primary_uuid']}")


@cluster_app.command("demote")
def cluster_demote(node_uuid: str):
    """Demote NODE_UUID (must be current primary) back to secondary. Cluster:w."""
    r = _client().cluster_demote(node_uuid)
    print(f"Demoted {r['node_uuid']} -> {r['ha_state']}")
    print(f"primary_uuid: {r.get('primary_uuid') or '(none)'}")


@cluster_app.command("drain")
def cluster_drain(node_uuid: str):
    """Mark NODE_UUID as draining; reaper evicts after deadline. Cluster:w."""
    r = _client().cluster_drain(node_uuid)
    print(f"Drain requested for {r['node_uuid']} -> {r['ha_state']}")
    if r.get("drain_deadline_at"):
        print(f"drain_deadline_at: {r['drain_deadline_at']}")


@cluster_app.command("evict")
def cluster_evict(node_uuid: str):
    """Immediately evict NODE_UUID and append to revoked_node_uuids. Cluster:w."""
    r = _client().cluster_evict(node_uuid)
    print(f"Evicted {r['node_uuid']} -> {r['ha_state']}")


@cluster_app.command("unrevoke")
def cluster_unrevoke(node_uuid: str):
    """Remove NODE_UUID from revoked_node_uuids (lift JOIN gate). Cluster:w."""
    r = _client().cluster_unrevoke(node_uuid)
    print(f"Unrevoked {r['node_uuid']} (revoked={r['revoked']})")


@cluster_app.command("rotate-cert")
def cluster_rotate_cert(
    node_uuid: str = typer.Argument(
        None, help="Target node_uuid. Omit with --all for cluster-wide broadcast."
    ),
    all_nodes: bool = typer.Option(
        False, "--all", help="Force-renew every non-evicted node."
    ),
):
    """Force a node cert renewal at the next renewal tick. Admin:w.

    Either pass NODE_UUID for a single node, or --all for cluster-wide
    broadcast (CA rotation companion).

    Examples:
        rhorizon cluster rotate-cert e8857bfd5c174a3f...
        rhorizon cluster rotate-cert --all
    """
    if all_nodes:
        if node_uuid:
            print("Error: pass NODE_UUID or --all, not both", file=sys.stderr)
            raise typer.Exit(1)
        target = "all"
    elif node_uuid:
        target = node_uuid
    else:
        print("Error: provide NODE_UUID or --all", file=sys.stderr)
        raise typer.Exit(1)
    r = _client().cluster_rotate_cert(target)
    print(f"scope={r['scope']} flipped={r['flipped']} target={r['target']}")


@cluster_app.command("rotate-ca")
def cluster_rotate_ca(
    confirm: bool = typer.Option(
        False, "--yes", help="Skip the interactive confirmation."
    ),
):
    """Mint a fresh cluster CA; keep prev for a grace window. Admin:w.

    Rare op. Once triggered, all node certs are flipped force_renew_at
    so they re-mint against the new CA. The prev CA is kept verifiable
    for cluster_ca_grace_window_secs (default 7 days) and dropped by
    the reaper once every node has rotated, or once the grace expires.
    """
    if not confirm:
        print(
            "This mints a new cluster CA and starts a grace window. "
            "All nodes will rotate their certs. Continue?"
        )
        if input('Type "rotate-ca" to confirm: ') != "rotate-ca":
            print("Aborted.")
            raise typer.Exit(0)
    r = _client().cluster_rotate_ca()
    print(f"new_fingerprint:   {r['new_fingerprint']}")
    print(f"rotated_at:        {r['rotated_at']}")
    print(f"grace_window_secs: {r['grace_window_secs']}")
    print(f"flipped:           {r['flipped']}")


@cluster_app.command("ca-bundle")
def cluster_ca_bundle(
    output: Path = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the CA PEM to this file (mode 0444). Otherwise print to stdout.",
    ),
):
    """Fetch the cluster CA cert PEM + fingerprint. Cluster:r.

    Use the PEM to install the CA on nginx (ssl_client_certificate)
    or to verify a peer cert out-of-band.
    """
    r = _client().cluster_ca_bundle()
    pem = r["ca_cert_pem"]
    if output:
        output.write_text(pem)
        output.chmod(0o444)
        print(f"CA cert written to {output} (mode 0444)")
        print(f"fingerprint: {r['fingerprint']}")
    else:
        print(pem, end="" if pem.endswith("\n") else "\n")
        print(f"# fingerprint: {r['fingerprint']}")


# -- Dynamic secrets subcommands --


@dynamic_app.command("engines")
def dynamic_engines(as_json: bool = typer.Option(False, "--json")):
    """List dynamic-secrets engines. Admin:r."""
    items = _client().list_dynamic_engines().get("items", [])
    if as_json:
        print(json.dumps(items, indent=2))
        return
    if not items:
        print("(no engines)")
        return
    for e in items:
        print(f"{e['id']}  {e['name']:<20} {e['engine_type']:<12} ns={e['namespace']}")


@dynamic_app.command("engine-add")
def dynamic_engine_add(
    name: str,
    engine_type: str = typer.Option(
        ...,
        "--type",
        "-t",
        help="postgresql | mysql | ldap | redis | cassandra",
    ),
    url: str = typer.Option(
        None,
        "--url",
        "-u",
        help="Connection URL/DSN (prompted hidden if omitted, avoids shell history).",
    ),
    namespace: str = typer.Option("default", "--namespace", "-n"),
    max_ttl: int = typer.Option(86400, "--max-ttl", help="Engine max TTL (seconds)."),
):
    """Create a dynamic-secrets engine. Admin:w.

    The connection description is the privileged DSN/JSON Horizon uses to
    create and revoke ephemeral credentials; it is stored encrypted. Omit
    --url to be prompted (hidden) so it never lands in shell history.

    Examples:
        rhorizon dynamic engine-add pg-prod -t postgresql -n prod
        rhorizon dynamic engine-add pg-prod -t postgresql \\
          -u 'postgresql://admin:pw@10.0.0.5:5432/app'
    """
    if not url:
        url = getpass("Connection URL/DSN: ")
    r = _client().create_dynamic_engine(
        name, engine_type, url, namespace=namespace, max_ttl_seconds=max_ttl
    )
    print(f"Engine created: {r['name']}  id={r['id']}")


@dynamic_app.command("engine-rm")
def dynamic_engine_rm(engine_id: str):
    """Delete an engine (cascades its roles). Admin:w."""
    _client().delete_dynamic_engine(engine_id)
    print(f"Engine {engine_id} deleted")


@dynamic_app.command("roles")
def dynamic_roles(engine_id: str, as_json: bool = typer.Option(False, "--json")):
    """List roles defined on an engine. Admin:r."""
    items = _client().list_dynamic_roles(engine_id).get("items", [])
    if as_json:
        print(json.dumps(items, indent=2))
        return
    if not items:
        print("(no roles)")
        return
    for r in items:
        print(
            f"{r['name']:<24} default_ttl={r['default_ttl_seconds']}s "
            f"max_ttl={r['max_ttl_seconds']}s"
        )


@dynamic_app.command("role-add")
def dynamic_role_add(
    engine_id: str,
    name: str,
    creation_sql: str = typer.Option(
        None, "--creation-sql", "-c", help="Creation template ({{name}}/{{password}})."
    ),
    revocation_sql: str = typer.Option(
        None, "--revocation-sql", "-r", help="Revocation template ({{name}})."
    ),
    creation_sql_file: Path = typer.Option(
        None, "--creation-sql-file", help="Read creation template from file."
    ),
    revocation_sql_file: Path = typer.Option(
        None, "--revocation-sql-file", help="Read revocation template from file."
    ),
    ttl: int = typer.Option(3600, "--ttl", help="Default lease TTL (seconds)."),
    max_ttl: int = typer.Option(
        86400, "--max-ttl", help="Absolute lease lifetime cap (seconds)."
    ),
):
    """Define a role on an engine. Admin:w.

    The reaper enforces expiry by running the revocation template at lease end,
    so revocation_sql must be idempotent (DROP ... IF EXISTS). Do not put a
    backend-native expiry (PG `VALID UNTIL`) in creation_sql if you want `renew`
    to work; the reaper is the source of truth for the lease lifetime.

    Example:
        rhorizon dynamic role-add ENGINE_ID readonly \\
          -c 'CREATE ROLE "{{name}}" LOGIN PASSWORD '"'"'{{password}}'"'"'' \\
          -r 'DROP ROLE IF EXISTS "{{name}}"' --ttl 1800 --max-ttl 7200
    """
    if creation_sql_file:
        creation_sql = creation_sql_file.read_text().strip()
    if revocation_sql_file:
        revocation_sql = revocation_sql_file.read_text().strip()
    if not creation_sql or not revocation_sql:
        print(
            "Error: both creation and revocation templates are required "
            "(--creation-sql[-file] and --revocation-sql[-file])",
            file=sys.stderr,
        )
        raise typer.Exit(1)
    r = _client().create_dynamic_role(
        engine_id,
        name,
        creation_sql,
        revocation_sql,
        default_ttl_seconds=ttl,
        max_ttl_seconds=max_ttl,
    )
    print(f"Role created: {r['name']}  id={r['id']}")


@dynamic_app.command("creds")
def dynamic_creds(
    engine_id: str,
    role_name: str,
    ttl: int = typer.Option(
        None, "--ttl", help="Override the role default TTL (capped at role max)."
    ),
    as_json: bool = typer.Option(False, "--json"),
    as_dotenv: bool = typer.Option(
        False, "--dotenv", help="Print DB_USER=/DB_PASSWORD= lines."
    ),
):
    """Mint ephemeral credentials for a role (lease tracked). Secrets:w.

    The password is shown once. Capture the lease_id if you intend to renew or
    revoke before expiry.

    Examples:
        rhorizon dynamic creds ENGINE_ID readonly --ttl 600
        eval "$(rhorizon dynamic creds ENGINE_ID readonly --dotenv)"
    """
    r = _client().generate_dynamic_creds(engine_id, role_name, ttl_seconds=ttl)
    if as_json:
        print(json.dumps(r, indent=2))
        return
    if as_dotenv:
        print(f"DB_USER={r['username']}")
        print(f"DB_PASSWORD={r['password']}")
        return
    print(f"Username: {r['username']}")
    print(f"Password: {r['password']}")
    if r.get("dn"):
        print(f"DN:       {r['dn']}")
    print(f"Lease:    {r['lease_id']}")
    print(f"Expires:  {r['expires_at']} ({r['ttl_seconds']}s)")
    print("(shown once - the reaper drops this credential at expiry)")


@dynamic_app.command("leases")
def dynamic_leases(as_json: bool = typer.Option(False, "--json")):
    """List active (un-revoked, un-expired) leases. Admin:r."""
    items = _client().list_dynamic_leases().get("items", [])
    if as_json:
        print(json.dumps(items, indent=2))
        return
    if not items:
        print("(no active leases)")
        return
    for ls in items:
        print(
            f"{ls['id']}  {ls['username']:<28} "
            f"{ls['engine']}/{ls['role']} expires={ls['expires_at']}"
        )


@dynamic_app.command("renew")
def dynamic_renew(
    lease_id: str,
    ttl: int = typer.Option(3600, "--ttl", help="Extend to NOW()+ttl (60..86400s)."),
):
    """Extend a lease (capped at the role's absolute max_ttl). Secrets:w.

    Moves the lease expiry forward; the reaper holds the credential until the
    new time. Refused with 409 once the lease is already at its max lifetime.
    """
    if ttl < 60 or ttl > 86400:
        print("Error: --ttl must be between 60 and 86400", file=sys.stderr)
        raise typer.Exit(1)
    r = _client().renew_dynamic_lease(lease_id, ttl)
    print(f"Renewed:  {r['username']}")
    print(f"Expires:  {r['expires_at']} ({r['ttl_seconds']}s)")


@dynamic_app.command("revoke")
def dynamic_revoke(lease_id: str):
    """Revoke a lease now (drops the DB user immediately). Admin:w."""
    r = _client().revoke_dynamic_lease(lease_id)
    print(f"Revoked:  {r['username']}")


@pki_app.command("init")
def pki_init(
    algorithm: str = typer.Option(
        "ed25519-mldsa65",
        "--algorithm",
        "-a",
        help="ed25519-mldsa65 (composite hybrid, default) | ml-dsa-65 | ed25519",
    ),
    common_name: str = typer.Option("rhorizon-pki", "--cn"),
    validity_days: int = typer.Option(3650, "--validity-days"),
):
    """Initialise the PKI CA (once). Admin:w."""
    r = _client().pki_init(algorithm, common_name, validity_days)
    print(f"CA initialised: {r['algorithm']}  cn={r['common_name']}")
    print(f"Fingerprint: {r['fingerprint']}")


@pki_app.command("ca")
def pki_ca(
    out: str = typer.Option(None, "--out", "-o", help="Write the CA cert PEM here."),
):
    """Print (or save) the CA certificate. Secrets:r."""
    r = _client().pki_ca()
    print(f"# {r['algorithm']}  cn={r['common_name']}  fpr={r['fingerprint']}")
    if out:
        with open(out, "w") as fh:
            fh.write(r["certificate"])
        print(f"Wrote {out}")
    else:
        print(r["certificate"], end="")


@pki_app.command("issue")
def pki_issue(
    common_name: str,
    ip: list[str] = typer.Option(None, "--ip", help="SAN IP (repeatable)."),
    dns: list[str] = typer.Option(None, "--dns", help="SAN DNS (repeatable)."),
    ttl_days: int = typer.Option(30, "--ttl-days"),
    namespace: str = typer.Option("default", "--namespace", "-n"),
    cert_out: str = typer.Option(None, "--cert-out", help="Write the leaf cert PEM."),
    key_out: str = typer.Option(None, "--key-out", help="Write the leaf key PEM."),
):
    """Issue a leaf certificate (server-side keygen). Secrets:w.

    The private key is shown ONCE; capture it with --key-out or copy it now.
    """
    r = _client().pki_issue(
        common_name, list(ip or []), list(dns or []), ttl_days, True, True, namespace
    )
    print(f"Serial:     {r['serial']}  ({r['algorithm']})")
    print(f"Not after:  {r['not_after']}")
    if cert_out:
        with open(cert_out, "w") as fh:
            fh.write(r["certificate"])
        print(f"Cert -> {cert_out}")
    else:
        print(r["certificate"], end="")
    if key_out:
        import os

        fd = os.open(key_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(r["private_key"])
        print(f"Key  -> {key_out} (mode 0600)")
    else:
        print(r["private_key"], end="")


@pki_app.command("kem-issue")
def pki_kem_issue(
    common_name: str,
    ip: list[str] = typer.Option(None, "--ip", help="SAN IP (repeatable)."),
    dns: list[str] = typer.Option(None, "--dns", help="SAN DNS (repeatable)."),
    ttl_days: int = typer.Option(30, "--ttl-days"),
    kem_algorithm: str = typer.Option("ml-kem-768", "--kem", help="ML-KEM set."),
    mode: str = typer.Option(
        "ml-kem",
        "--mode",
        help="Construction: 'ml-kem' (pure PQ) or 'x25519-ml-kem' (hybrid).",
    ),
    namespace: str = typer.Option("default", "--namespace", "-n"),
    cert_out: str = typer.Option(None, "--cert-out", help="Write the KEM cert PEM."),
    key_out: str = typer.Option(None, "--key-out", help="Write the decaps key PEM."),
):
    """Issue a KEM certificate (KEM subject key, CA-signed). Secrets:w.

    The subject key does key establishment (KeyUsage=keyEncipherment), not TLS
    auth. --mode x25519-ml-kem issues a hybrid classical+PQ subject key (ANSSI/BSI
    hybridation). The decapsulation (secret) key is shown ONCE; capture it with
    --key-out.
    """
    r = _client().pki_kem_issue(
        common_name,
        list(ip or []),
        list(dns or []),
        ttl_days,
        kem_algorithm,
        namespace,
        mode,
    )
    print(
        f"Serial:     {r['serial']}  ({r['subject_algorithm']} / sig {r['algorithm']})"
    )
    print(f"KEM mode:   {r['kem_mode']}")
    print(f"Not after:  {r['not_after']}")
    if cert_out:
        with open(cert_out, "w") as fh:
            fh.write(r["certificate"])
        print(f"Cert -> {cert_out}")
    else:
        print(r["certificate"], end="")
    if key_out:
        import os

        fd = os.open(key_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(r["private_key"])
        print(f"Key  -> {key_out} (mode 0600)")
    else:
        print(r["private_key"], end="")


@pki_app.command("certs")
def pki_certs(as_json: bool = typer.Option(False, "--json")):
    """List issued certificates (no private keys). Secrets:r."""
    items = _client().pki_list_certs().get("items", [])
    if as_json:
        print(json.dumps(items, indent=2))
        return
    if not items:
        print("(no certs issued)")
        return
    for c in items:
        state = "REVOKED" if c["revoked_at"] else "valid"
        # KEM certs: show the ML-KEM subject set (sig algo is the CA's).
        kind = c.get("subject_algorithm") or c["algorithm"]
        print(
            f"{c['serial']:<20} {c['subject_cn']:<24} {kind:<12} "
            f"ns={c['namespace']:<10} {state}  exp={c['not_after']}"
        )


@pki_app.command("revoke")
def pki_revoke(
    serial: str,
    reason: str = typer.Option("unspecified", "--reason", "-r"),
):
    """Revoke an issued certificate by serial. Admin:w."""
    _client().pki_revoke(serial, reason)
    print(f"Revoked: {serial}")


@pki_app.command("rotate")
def pki_rotate(validity_days: int = typer.Option(3650, "--validity-days")):
    """Rotate the CA (old cert kept in a grace window). Admin:w."""
    r = _client().pki_rotate(validity_days)
    print(f"CA rotated. New fingerprint: {r['fingerprint']}")


def main():
    app()
