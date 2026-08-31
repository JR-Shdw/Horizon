"""Regression tests for native-install service identity boundaries."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "tools" / "lib" / "common.sh"


def _run_account_gate(*, fallback: bool) -> subprocess.CompletedProcess[str]:
    fallback_line = "RH_ACCOUNT_FALLBACK_ROOT=1" if fallback else ":"
    script = f"""
set -eu
RH_OS=linux
RH_SERVICE_USER='invalid/account'
RH_SERVICE_GROUP='invalid/group'
{fallback_line}
. '{COMMON}'
rh_group_exists() {{ return 1; }}
groupadd() {{ return 1; }}
rh_require_service_account
printf 'ready=%s\\n' "$RH_ACCOUNT_READY"
"""
    return subprocess.run(
        ["sh", "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_account_creation_failure_stops_without_explicit_fallback() -> None:
    result = _run_account_gate(fallback=False)

    assert result.returncode != 0
    assert "Refusing to continue silently" in result.stderr
    assert "continuing as root" not in result.stderr


def test_account_creation_failure_allows_only_logged_explicit_fallback() -> None:
    result = _run_account_gate(fallback=True)

    assert result.returncode == 0
    assert "RH_ACCOUNT_FALLBACK_ROOT=1 -- continuing as root" in result.stderr
    assert "ready=0" in result.stdout


def test_native_installer_has_no_recursive_chown() -> None:
    source = (ROOT / "tools" / "install-native.sh").read_text(encoding="utf-8")

    assert "chown -R" not in source


def test_system_recovery_material_is_explicitly_root_owned() -> None:
    source = (ROOT / "tools" / "install-native.sh").read_text(encoding="utf-8")

    assert 'run chown 0:0 "$SECRET_DIR"' in source
    assert 'run chown 0:0 "$SECRET_DIR/master-password"' in source
    assert 'run chown 0:0 "$SECRET_DIR/root-token"' in source


def test_system_drivers_restart_an_existing_service_on_reinstall() -> None:
    expected = {
        "linux.sh": "systemctl restart rhorizon.service",
        "freebsd.sh": "service rhorizon onerestart",
        "netbsd.sh": "/etc/rc.d/rhorizon restart",
        "openbsd.sh": "rcctl restart rhorizon",
    }

    for driver, command in expected.items():
        source = (ROOT / "tools" / "drivers" / driver).read_text(encoding="utf-8")
        assert command in source, driver


def test_freebsd_drops_identity_without_resetting_the_prestart_rlimit() -> None:
    source = (ROOT / "tools" / "drivers" / "freebsd.sh").read_text(encoding="utf-8")

    assert "os.setgroups([])" in source
    assert "os.setgid(account.pw_gid)" in source
    assert "os.setuid(account.pw_uid)" in source
    assert "daemon(8) -u" in source
    assert "_asuser=" not in source


def test_native_installer_uses_the_driver_resolved_python() -> None:
    installer = (ROOT / "tools" / "install-native.sh").read_text(encoding="utf-8")
    common = (ROOT / "tools" / "lib" / "common.sh").read_text(encoding="utf-8")

    assert '"$PYBIN" - "$MASTER_PW_FILE"' in installer
    assert '"${PYBIN:-python3}" -c' in common
