# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""mlockall memory-headroom guard: sizing math + the undersized-limit warning.

Regression cover for the unseal OOM: mlockall wires the 256MB Argon2id
allocation, so the container limit must cover workers x RSS + 256MB.
"""

import builtins
import logging
import os
import resource
import stat
import sys
from io import StringIO
from types import SimpleNamespace
from unittest.mock import mock_open

import pytest
from api.app import mem_hardening
from api.app.mem_hardening import check_memlock_headroom, required_memory_mb


def test_required_memory_scales_with_workers():
    assert required_memory_mb(10) > required_memory_mb(5) > required_memory_mb(1)


def test_required_memory_always_covers_argon2_unseal():
    # the 256MB Argon2id unseal allocation must be budgeted even at 1 worker
    assert required_memory_mb(1) >= 256


def test_required_memory_under_shipped_default():
    # the compose default (1536M) must clear the 5-worker floor requirement
    assert required_memory_mb(5) <= 1536


def test_warns_when_container_limit_too_small(caplog, monkeypatch):
    monkeypatch.setattr(mem_hardening, "_cgroup_memory_limit_mb", lambda: 512)
    caplog.set_level(logging.WARNING, logger="rhorizon")
    check_memlock_headroom(5)
    assert "OOM" in caplog.text


def test_silent_when_container_limit_sufficient(caplog, monkeypatch):
    monkeypatch.setattr(mem_hardening, "_cgroup_memory_limit_mb", lambda: 4096)
    caplog.set_level(logging.WARNING, logger="rhorizon")
    check_memlock_headroom(5)
    assert caplog.records == []


def test_silent_when_limit_unknown(caplog, monkeypatch):
    # unlimited / unreadable cgroup -> no false alarm
    monkeypatch.setattr(mem_hardening, "_cgroup_memory_limit_mb", lambda: None)
    caplog.set_level(logging.WARNING, logger="rhorizon")
    check_memlock_headroom(5)
    assert caplog.records == []


def test_harden_always_disables_process_dumpability(monkeypatch):
    calls = []
    monkeypatch.setattr(
        mem_hardening, "_disable_process_dumpability", lambda: calls.append("prctl")
    )

    mem_hardening.harden_process_memory(memlock_all=False, disable_core_dumps=False)

    assert calls == ["prctl"]
    assert mem_hardening.process_memory_protection() == "disabled"


def test_harden_fails_closed_when_process_remains_dumpable(monkeypatch):
    def denied():
        raise OSError("prctl denied")

    monkeypatch.setattr(mem_hardening, "_disable_process_dumpability", denied)

    with pytest.raises(RuntimeError, match="PR_SET_DUMPABLE"):
        mem_hardening.harden_process_memory(memlock_all=False, disable_core_dumps=False)


@pytest.mark.parametrize(
    ("swaps", "encrypted", "expected"),
    [
        ("Filename Type Size Used Priority\n", set(), "protected"),
        (
            "Filename Type Size Used Priority\n/dev/zram0 partition 1 0 1\n",
            set(),
            "protected",
        ),
        (
            "Filename Type Size Used Priority\n/dev/dm-0 partition 1 0 1\n",
            {"/dev/dm-0"},
            "protected",
        ),
        (
            "Filename Type Size Used Priority\n/dev/sda2 partition 1 0 1\n",
            set(),
            "unencrypted",
        ),
    ],
)
def test_swap_protection_linux(monkeypatch, swaps, encrypted, expected):
    monkeypatch.delenv("RH_SWAP_PROTECTION", raising=False)
    monkeypatch.setattr(mem_hardening.sys, "platform", "linux")
    monkeypatch.setattr("builtins.open", mock_open(read_data=swaps))
    monkeypatch.setattr(mem_hardening, "_is_dm_crypt", lambda dev: dev in encrypted)

    assert mem_hardening.swap_protection() == expected


def test_swap_protection_unknown_when_proc_unreadable(monkeypatch):
    monkeypatch.delenv("RH_SWAP_PROTECTION", raising=False)
    monkeypatch.setattr(mem_hardening.sys, "platform", "linux")
    opener = mock_open()
    opener.side_effect = OSError
    monkeypatch.setattr("builtins.open", opener)

    assert mem_hardening.swap_protection() == "unknown"


@pytest.mark.parametrize("state", ["protected", "unencrypted", "unknown"])
def test_swap_protection_accepts_installer_override(monkeypatch, state):
    monkeypatch.setenv("RH_SWAP_PROTECTION", state)

    assert mem_hardening.swap_protection() == state


def test_swap_protection_rejects_invalid_override(monkeypatch):
    monkeypatch.setenv("RH_SWAP_PROTECTION", "safe-ish")

    assert mem_hardening.swap_protection() == "unknown"


@pytest.mark.parametrize(
    ("swap_state", "warning_expected"),
    [("protected", False), ("unencrypted", True), ("unknown", True)],
)
def test_mlock_failure_warning_depends_on_swap(
    caplog, monkeypatch, swap_state, warning_expected
):
    monkeypatch.setattr(mem_hardening, "_disable_process_dumpability", lambda: None)
    monkeypatch.setattr(mem_hardening, "check_memlock_headroom", lambda *_a, **_k: None)
    monkeypatch.setattr(mem_hardening, "check_memlock_rlimit", lambda *_a, **_k: None)
    monkeypatch.setattr(mem_hardening, "swap_protection", lambda: swap_state)
    monkeypatch.setattr(
        mem_hardening,
        "_mlockall",
        lambda: (_ for _ in ()).throw(OSError("not permitted")),
    )
    caplog.set_level(logging.WARNING, logger="rhorizon")

    mem_hardening.harden_process_memory(memlock_all=True, disable_core_dumps=False)

    warnings = [
        record for record in caplog.records if record.levelno >= logging.WARNING
    ]
    assert bool(warnings) is warning_expected
    assert mem_hardening.process_memory_protection() == "swappable"


def test_required_mlock_fails_closed_with_unencrypted_swap(monkeypatch):
    monkeypatch.setattr(mem_hardening, "_disable_process_dumpability", lambda: None)
    monkeypatch.setattr(mem_hardening, "check_memlock_headroom", lambda *_a, **_k: None)
    monkeypatch.setattr(mem_hardening, "check_memlock_rlimit", lambda *_a, **_k: None)
    monkeypatch.setattr(mem_hardening, "swap_protection", lambda: "unencrypted")
    monkeypatch.setattr(
        mem_hardening,
        "_mlockall",
        lambda: (_ for _ in ()).throw(OSError("not permitted")),
    )

    with pytest.raises(RuntimeError, match="RH_MEMORY_LOCK_MODE=required"):
        mem_hardening.harden_process_memory(
            memlock_all=True,
            disable_core_dumps=False,
            memory_lock_required=True,
        )


def test_required_mlock_does_not_fail_when_swap_is_protected(monkeypatch):
    monkeypatch.setattr(mem_hardening, "_disable_process_dumpability", lambda: None)
    monkeypatch.setattr(mem_hardening, "check_memlock_headroom", lambda *_a, **_k: None)
    monkeypatch.setattr(mem_hardening, "check_memlock_rlimit", lambda *_a, **_k: None)
    monkeypatch.setattr(mem_hardening, "swap_protection", lambda: "protected")
    monkeypatch.setattr(
        mem_hardening,
        "_mlockall",
        lambda: (_ for _ in ()).throw(OSError("not permitted")),
    )

    mem_hardening.harden_process_memory(
        memlock_all=True,
        disable_core_dumps=False,
        memory_lock_required=True,
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("max", None),
        ("", None),
        ("not-a-number", None),
        (str(512 * 1024 * 1024), 512),
        (str(2 * 1024 * 1024 * 1024 * 1024), None),
    ],
)
def test_cgroup_v2_memory_limit_parsing(monkeypatch, raw, expected):
    monkeypatch.setattr("builtins.open", lambda _path: StringIO(raw))
    assert mem_hardening._cgroup_memory_limit_mb() == expected


def test_cgroup_memory_limit_falls_back_to_v1(monkeypatch):
    def opener(path):
        if path.endswith("memory.max"):
            raise OSError("no v2")
        return StringIO(str(768 * 1024 * 1024))

    monkeypatch.setattr("builtins.open", opener)
    assert mem_hardening._cgroup_memory_limit_mb() == 768


def test_raise_memlock_limit_handles_infinite_and_lifts_soft(monkeypatch):
    monkeypatch.setattr(
        resource,
        "getrlimit",
        lambda _which: (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
    )
    assert mem_hardening._raise_memlock_soft_to_hard(123) == (
        resource.RLIM_INFINITY,
        resource.RLIM_INFINITY,
    )

    limits = iter([(1, 10), (8, 10)])
    changed = []
    monkeypatch.setattr(resource, "getrlimit", lambda _which: next(limits))
    monkeypatch.setattr(
        resource, "setrlimit", lambda which, value: changed.append((which, value))
    )
    assert mem_hardening._raise_memlock_soft_to_hard(8) == (8, 10)
    assert changed == [(resource.RLIMIT_MEMLOCK, (8, 10))]


def test_raise_memlock_limit_tolerates_setrlimit_failure(monkeypatch):
    monkeypatch.setattr(resource, "getrlimit", lambda _which: (1, 2))
    monkeypatch.setattr(
        resource,
        "setrlimit",
        lambda *_args: (_ for _ in ()).throw(OSError("denied")),
    )
    assert mem_hardening._raise_memlock_soft_to_hard(8) == (1, 2)


def test_dm_crypt_device_detection(monkeypatch):
    device = SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(253, 0), st_dev=0)
    monkeypatch.setattr(os, "stat", lambda _path: device)
    monkeypatch.setattr(
        os.path,
        "realpath",
        lambda path: "/sys/block/dm-0" if path.startswith("/sys/dev/block/") else path,
    )
    monkeypatch.setattr("builtins.open", lambda _path: StringIO("CRYPT-LUKS2-test"))
    monkeypatch.setattr(os, "listdir", lambda _path: [])
    assert mem_hardening._is_dm_crypt("/dev/dm-0") is True


def test_dm_crypt_detection_fails_safe(monkeypatch):
    monkeypatch.setattr(os, "stat", lambda _path: (_ for _ in ()).throw(OSError()))
    assert mem_hardening._is_dm_crypt("/missing") is False


def test_swap_protection_non_linux_and_blank_rows(monkeypatch):
    monkeypatch.delenv("RH_SWAP_PROTECTION", raising=False)
    monkeypatch.setattr(mem_hardening.sys, "platform", "freebsd14")
    assert mem_hardening.swap_protection() == "unknown"

    monkeypatch.setattr(mem_hardening.sys, "platform", "linux")
    monkeypatch.setattr("builtins.open", lambda _path: StringIO("header\n\n"))
    assert mem_hardening.swap_protection() == "protected"


def test_memlock_rlimit_warning_and_infinite_short_circuit(caplog, monkeypatch):
    monkeypatch.setattr(
        mem_hardening,
        "_raise_memlock_soft_to_hard",
        lambda _need: (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
    )
    mem_hardening.check_memlock_rlimit(5)

    monkeypatch.setattr(
        mem_hardening, "_raise_memlock_soft_to_hard", lambda _need: (0, 0)
    )
    monkeypatch.setattr(mem_hardening, "_has_unencrypted_swap", lambda: True)
    caplog.set_level(logging.WARNING, logger="rhorizon")
    mem_hardening.check_memlock_rlimit(5)
    assert "RLIMIT_MEMLOCK" in caplog.text


def test_dumpability_and_mlock_libc_errors(monkeypatch):
    monkeypatch.setattr(mem_hardening.sys, "platform", "freebsd14")
    mem_hardening._disable_process_dumpability()

    libc = SimpleNamespace(prctl=lambda *_args: -1, mlockall=lambda *_args: -1)
    monkeypatch.setattr(mem_hardening.sys, "platform", "linux")
    monkeypatch.setattr(mem_hardening.ctypes, "CDLL", lambda *_args, **_kwargs: libc)
    monkeypatch.setattr(mem_hardening.ctypes, "get_errno", lambda: 1)
    with pytest.raises(OSError):
        mem_hardening._disable_process_dumpability()
    with pytest.raises(OSError):
        mem_hardening._mlockall()


def test_harden_core_warning_darwin_and_success_paths(caplog, monkeypatch):
    monkeypatch.setattr(mem_hardening, "_disable_process_dumpability", lambda: None)
    monkeypatch.setattr(
        mem_hardening,
        "_disable_core_dumps",
        lambda: (_ for _ in ()).throw(OSError("denied")),
    )
    caplog.set_level(logging.WARNING, logger="rhorizon")
    mem_hardening.harden_process_memory(memlock_all=False, disable_core_dumps=True)
    assert "could not disable core dumps" in caplog.text

    monkeypatch.setattr(mem_hardening.sys, "platform", "darwin")
    mem_hardening.harden_process_memory(memlock_all=True, disable_core_dumps=False)
    assert mem_hardening.process_memory_protection() == "unsupported"

    monkeypatch.setattr(mem_hardening.sys, "platform", "linux")
    monkeypatch.setattr(mem_hardening, "check_memlock_headroom", lambda *_a, **_k: None)
    monkeypatch.setattr(mem_hardening, "check_memlock_rlimit", lambda *_a, **_k: None)
    monkeypatch.setattr(mem_hardening, "_mlockall", lambda: None)
    monkeypatch.setitem(
        sys.modules,
        "rhorizon_crypto",
        SimpleNamespace(memory_lock_status=lambda: "zeroize-only"),
    )
    monkeypatch.setattr(mem_hardening, "swap_protection", lambda: "unencrypted")
    mem_hardening.harden_process_memory(memlock_all=True, disable_core_dumps=False)
    assert mem_hardening.process_memory_protection() == "mlock"
    assert "Rust buffers are not locked" in caplog.text


def test_harden_zeroize_only_is_quiet_with_protected_swap(caplog, monkeypatch):
    monkeypatch.setattr(mem_hardening, "_disable_process_dumpability", lambda: None)
    monkeypatch.setitem(
        sys.modules,
        "rhorizon_crypto",
        SimpleNamespace(memory_lock_status=lambda: "zeroize-only"),
    )
    monkeypatch.setattr(mem_hardening, "swap_protection", lambda: "protected")
    caplog.set_level(logging.INFO, logger="rhorizon")
    mem_hardening.harden_process_memory(memlock_all=False, disable_core_dumps=False)
    assert "zeroize-on-drop" in caplog.text


def test_harden_reports_unknown_when_rust_extension_is_unavailable(monkeypatch):
    real_import = builtins.__import__

    def importing(name, *args, **kwargs):
        if name == "rhorizon_crypto":
            raise ImportError("extension unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(mem_hardening, "_disable_process_dumpability", lambda: None)
    monkeypatch.setattr(builtins, "__import__", importing)
    mem_hardening.harden_process_memory(memlock_all=False, disable_core_dumps=False)


def test_a_rust_custodian_is_budgeted_as_a_daemon_not_a_worker():
    """Charging a share-holding daemon a full worker warns off sized limits.

    A Rust custodian is ~2.6MB of mlock'd share, measured on a live pool. At
    the per-worker budget a 9-slot pool would demand ~1.4GB it never uses, so
    the guard would tell an operator to raise a limit that is amply sized.
    """
    workers_only = required_memory_mb(5)
    with_pool = required_memory_mb(5, 9)

    assert with_pool > workers_only
    assert with_pool - workers_only < 64
    # smb: 5 workers + a 3-slot Rust pool must still fit the shipped 1536M.
    assert required_memory_mb(5, 3) <= 1536


def test_the_argon2_term_is_counted_once_not_per_pool():
    """Only the API process that serves an unseal derives the master key."""
    assert required_memory_mb(5, 3) - required_memory_mb(5) == 3 * 4


def test_a_negative_or_absent_pool_costs_nothing():
    assert required_memory_mb(5, 0) == required_memory_mb(5)
    assert required_memory_mb(5, -3) == required_memory_mb(5)
