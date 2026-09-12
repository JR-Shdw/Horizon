"""Security contract for the identity-separated AI onboarding path."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "quickstart-ai-system.sh"


def _fake_command(path: Path, name: str, body: str) -> None:
    target = path / name
    target.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    target.chmod(0o755)


def _run_preflight_as_fake_root(
    tmp_path: Path,
    target_user: str,
    *,
    groups: str = "users",
    writable_source: bool = False,
    passwordless_sudo: bool = False,
) -> subprocess.CompletedProcess[str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    _fake_command(
        fake_bin,
        "id",
        f'''case "$1" in
-u) echo 0 ;;
-nG) echo "{groups}" ;;
*) exec /usr/bin/id "$@" ;;
esac''',
    )
    _fake_command(
        fake_bin,
        "getent",
        f"""case "$2" in
root) echo "root:x:0:0:root:/root:/bin/sh" ;;
rhorizon-no-such-user) exit 2 ;;
*) echo "$2:x:1000:1000:agent:{fake_home}:/bin/sh" ;;
esac""",
    )
    if writable_source:
        runuser = 'while [ "$1" != -- ]; do shift; done; shift; exec "$@"'
    elif passwordless_sudo:
        runuser = """while [ "$1" != -- ]; do shift; done
shift
[ "$1" = sudo ] && exec "$@"
exit 1"""
    else:
        runuser = "exit 1"
    _fake_command(fake_bin, "runuser", runuser)
    _fake_command(fake_bin, "find", "exit 0")
    if passwordless_sudo:
        _fake_command(fake_bin, "sudo", "exit 0")
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    return subprocess.run(
        ["bash", str(SCRIPT), "--user", target_user],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_ai_system_script_is_executable_and_valid_bash() -> None:
    assert SCRIPT.stat().st_mode & 0o111
    subprocess.run(["bash", "-n", str(SCRIPT)], cwd=ROOT, check=True)
    result = subprocess.run(
        ["bash", str(SCRIPT), "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_ai_system_script_keeps_recovery_authority_out_of_agent_account() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "set +x" in source
    assert '--master-password-file "$PW_INPUT"' in source
    assert '--config "$AUTH_CONFIG"' in source
    assert "ROOT_TOKEN_FILE=$SECRET_DIR/root-token" in source
    assert "TARGET_TOKEN=$TARGET_CONFIG/mcp.token" in source
    assert 'rm -f -- "$ROOT_TOKEN_FILE"' not in source
    assert "Authorization: Bearer $ROOT_TOKEN" not in source
    assert "printf '%s' \"$MCP_TOKEN\" | runuser" in source
    assert "MCP_GRANT_CODE" in source
    assert "secrets/?namespace=$MCP_NAMESPACE" in source


def test_ai_system_script_rejects_root_equivalent_agent_authority() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert 'runuser -u "$TARGET_USER" -- test -w "$_path"' in source
    assert "grep -qx docker" in source
    assert "test -w /var/run/docker.sock" in source
    assert "sudo -n true" in source
    assert "doas -n true" in source
    assert 'TARGET_UID" -ne 0' in source
    assert '"$TARGET_USER" != rhorizon' in source
    assert "-type l -print -quit" in source


def test_ai_system_preflight_rejects_root_target(tmp_path: Path) -> None:
    result = _run_preflight_as_fake_root(tmp_path, "root")

    assert result.returncode != 0
    assert "must not run as root" in result.stderr


def test_ai_system_preflight_rejects_missing_target(tmp_path: Path) -> None:
    result = _run_preflight_as_fake_root(tmp_path, "rhorizon-no-such-user")

    assert result.returncode != 0
    assert "does not exist" in result.stderr


def test_ai_system_preflight_rejects_agent_writable_source(tmp_path: Path) -> None:
    result = _run_preflight_as_fake_root(tmp_path, "agent", writable_source=True)

    assert result.returncode != 0
    assert "can modify" in result.stderr


def test_ai_system_preflight_rejects_docker_group(tmp_path: Path) -> None:
    result = _run_preflight_as_fake_root(tmp_path, "agent", groups="users docker")

    assert result.returncode != 0
    assert "docker group" in result.stderr


def test_ai_system_preflight_rejects_passwordless_sudo(tmp_path: Path) -> None:
    result = _run_preflight_as_fake_root(tmp_path, "agent", passwordless_sudo=True)

    assert result.returncode != 0
    assert "passwordless sudo" in result.stderr


def test_ai_guides_enforce_transport_and_docker_boundaries() -> None:
    for relative in (
        "docs/AI-INSTALL-GUIDE.md",
        "docs/fr/AI-INSTALL-GUIDE.md",
        "docs/QUICKSTART-AI.md",
        "docs/fr/QUICKSTART-AI.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "http://127.0.0.1:8200" not in text, relative
        assert "usermod -aG docker" not in text, relative

    english = (ROOT / "docs/AI-INSTALL-GUIDE.md").read_text(encoding="utf-8")
    assert "/etc/rhorizon/secrets/root-token" in english
    assert "quickstart-ai-system.sh" in english
    assert "passwordless sudo" in english


def test_ai_system_script_contains_no_private_deployment_identifiers() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    forbidden = ("192.168.", "10.0.", "gitea.example.com", "/home/automation")
    assert not any(value in source for value in forbidden)


def test_native_vm_harness_can_validate_the_real_identity_boundary() -> None:
    source = (ROOT / "tools" / "test-vm.sh").read_text(encoding="utf-8")

    assert "RH_AI_SYSTEM:-0" in source
    assert "quickstart-ai-system.sh --user rhorizon-agent" in source
    assert "rhorizon-agent test ! -r /etc/rhorizon/secrets/root-token" in source
    assert "rhorizon test ! -r /etc/rhorizon/secrets/master-password" in source
