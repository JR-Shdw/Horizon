# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Process-wide memory hardening, applied once per worker at startup.

  1. mlockall(MCL_CURRENT|MCL_FUTURE) - pin the whole address space into RAM
     so no page can be written to swap.
  2. RLIMIT_CORE = 0 - forbid core dumps.
  3. Linux PR_SET_DUMPABLE = 0 - deny same-UID ptrace and /proc/PID/mem reads.

Whole-process mlockall is best-effort. Rust secret buffers separately follow
RH_MEMORY_LOCK_MODE: best-effort continues and reports the state; required
fails closed. A warning is emitted only when persistent swap is unencrypted or
cannot be classified.

Footgun guard: mlockall WIRES every page, including the 256MB Argon2id
allocation at unseal. With N workers under a container memory limit that does
not cover N x per-worker + 256MB, the master OOM-dies exactly at unseal.
check_memlock_headroom() warns at boot if the cgroup limit is too small; the
docker-compose default sizes RHORIZON_API_MEM for the worker floor.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import resource
import stat
import sys

log = logging.getLogger("rhorizon")

# Linux <sys/mman.h>. Other platforms differ; we guard on the call result.
_MCL_CURRENT = 1
_MCL_FUTURE = 2
_PR_SET_DUMPABLE = 4

_PROCESS_MEMORY_PROTECTION = "unknown"

# Headroom-guard budget (all MB).
_PER_WORKER_MB = 160  # steady-state RSS/worker (Python + Rust ext + asyncpg pool)
# A standalone Rust custodian is a small mlock'd daemon holding one share, not
# an application process: measured ~2.6MB RSS per sealed slot on a live 3-slot
# pool, budgeted at 4. Charging it a full worker overstates a 9-slot pool by
# ~1.4GB and makes the guard warn on limits that are amply sized.
_PER_RUST_CUSTODIAN_MB = 4
_ARGON2_MB = 256  # crypto.ARGON2_MEMLIMIT, wired transiently at unseal
_HEADROOM_MB = 192  # PG pool, background tasks, fragmentation


def required_memory_mb(workers: int, rust_custodian_slots: int = 0) -> int:
    """Min container memory (MB) for mlockall not to OOM the master at unseal.

    ``rust_custodian_slots`` covers a separated Rust pool sharing this
    container. The Argon2id term is counted once, not per pool: only the API
    process that serves an unseal derives the master key, and a Rust custodian
    never does -- it holds a share, it does not derive keys. Under Rust custody
    that term is also rare, because a restart reopens from the persisted shares
    without a password; it stays in the budget because it is still the peak
    whenever an operator does unseal, and mlockall wires it.
    """
    return (
        max(1, workers) * _PER_WORKER_MB
        + max(0, rust_custodian_slots) * _PER_RUST_CUSTODIAN_MB
        + _ARGON2_MB
        + _HEADROOM_MB
    )


def _cgroup_memory_limit_mb() -> int | None:
    """Container memory limit MB (cgroup v2 then v1); None if unlimited/unknown.

    Linux cgroups only. On *BSD / macOS the paths are absent -> None, so the
    headroom guard no-ops (a FreeBSD jail's rctl memory cap is not detected).
    """
    for path in (
        "/sys/fs/cgroup/memory.max",  # cgroup v2
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",  # cgroup v1
    ):
        try:
            with open(path) as fh:
                raw = fh.read().strip()
        except OSError:
            continue
        if raw in ("", "max"):
            return None
        try:
            mb = int(raw) // (1024 * 1024)
        except ValueError:
            return None
        # v1 "no limit" sentinel is a huge number; treat >1TB as unlimited.
        return None if mb > 1024 * 1024 else mb
    return None


def check_memlock_headroom(workers: int, rust_custodian_slots: int = 0) -> None:
    """Warn if mlockall is on but the container memory can't cover the unseal.

    mlockall wires the 256MB Argon2id allocation; an undersized limit OOM-kills
    the master exactly at unseal. Warn with the formula so the operator raises
    the limit (docker-compose RHORIZON_API_MEM).
    """
    limit = _cgroup_memory_limit_mb()
    need = required_memory_mb(workers, rust_custodian_slots)
    if limit is not None and limit < need:
        log.warning(
            "mem-hardening: memlock_all on but container limit %dMB < ~%dMB "
            "needed (%d workers x %dMB + %dMB Argon2id + %dMB headroom); unseal "
            "may OOM-kill the master. Raise the API memory limit "
            "(RHORIZON_API_MEM).",
            limit,
            need,
            workers,
            _PER_WORKER_MB,
            _ARGON2_MB,
            _HEADROOM_MB,
        )


def _raise_memlock_soft_to_hard(need_bytes: int) -> tuple[int, int]:
    """Lift the RLIMIT_MEMLOCK soft limit toward the mlockall budget.

    mlockall honours the *soft* limit. systemd's LimitMEMLOCK sets soft==hard,
    but a login/pam or nohup launch can leave soft below hard, so raise it first
    (bounded by hard). Returns the (soft, hard) in effect afterwards.
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    if soft == resource.RLIM_INFINITY:
        return soft, hard
    target = need_bytes if hard == resource.RLIM_INFINITY else min(hard, need_bytes)
    if soft < target:
        try:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (target, hard))
        except (ValueError, OSError):
            pass  # capped by hard limit; the warning below explains the fix
        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    return soft, hard


def _is_dm_crypt(dev: str) -> bool:
    """True if a swap device or swap file is backed by dm-crypt."""
    try:
        device = os.stat(dev)
        device_id = device.st_rdev if stat.S_ISBLK(device.st_mode) else device.st_dev
        pending = [
            os.path.realpath(
                f"/sys/dev/block/{os.major(device_id)}:{os.minor(device_id)}"
            )
        ]
        seen: set[str] = set()
        while pending:
            sys_device = pending.pop()
            if sys_device in seen:
                continue
            seen.add(sys_device)
            name = os.path.basename(sys_device)
            if name.startswith("dm-"):
                try:
                    with open(f"/sys/block/{name}/dm/uuid") as fh:
                        if fh.read().startswith("CRYPT-"):
                            return True
                except OSError:
                    pass
            try:
                slaves = os.listdir(os.path.join(sys_device, "slaves"))
            except OSError:
                slaves = []
            pending.extend(
                os.path.realpath(os.path.join(sys_device, "slaves", slave))
                for slave in slaves
            )
        return False
    except OSError:
        return False


def swap_protection() -> str:
    """Return protected, unencrypted, or unknown for persistent swap.

    mlockall only matters when cleartext pages could reach disk swap. zram is
    RAM-only and dm-crypt-backed swap is protected. No configured swap is also
    protected. Unknown platforms remain unknown so callers can warn safely.
    """
    configured = os.getenv("RH_SWAP_PROTECTION", "").strip().lower()
    if configured in {"protected", "unencrypted", "unknown"}:
        return configured
    if configured:
        return "unknown"
    if not sys.platform.startswith("linux"):
        return "unknown"
    try:
        with open("/proc/swaps") as fh:
            rows = fh.read().splitlines()[1:]
    except OSError:
        return "unknown"
    for row in rows:
        parts = row.split()
        if not parts:
            continue
        dev = parts[0]
        if dev.startswith("/dev/zram") or _is_dm_crypt(dev):
            continue
        return "unencrypted"
    return "protected"


def process_memory_protection() -> str:
    """Return the effective whole-process memory-lock state for this worker."""
    return _PROCESS_MEMORY_PROTECTION


def _has_unencrypted_swap() -> bool:
    """True only when persistent swap is confirmed unencrypted."""
    return swap_protection() == "unencrypted"


def check_memlock_rlimit(workers: int, rust_custodian_slots: int = 0) -> None:
    """Raise the memlock soft limit; warn only when it matters.

    Self-raises soft up to hard (free). Warns only if the effective limit is
    below the worker budget AND there is unencrypted disk swap -- the one case
    where a failed mlockall lets cleartext secrets reach disk. Encrypted / zram
    / no swap stays quiet. Catches the worker count raised past the sized limit.
    """
    need_mb = required_memory_mb(workers, rust_custodian_slots)
    soft, _hard = _raise_memlock_soft_to_hard(need_mb * 1024 * 1024)
    if soft == resource.RLIM_INFINITY:
        return
    soft_mb = soft // (1024 * 1024)
    if soft_mb < need_mb and _has_unencrypted_swap():
        log.warning(
            "mem-hardening: unencrypted swap present and RLIMIT_MEMLOCK %dMB < "
            "~%dMB needed for %d workers; mlockall will fail and served-secret "
            "pages may reach swap. Raise LimitMEMLOCK to >=%dMB or re-run the "
            "installer to re-size it for the new worker count.",
            soft_mb,
            need_mb,
            workers,
            need_mb,
        )


def _disable_core_dumps() -> None:
    """setrlimit(RLIMIT_CORE, 0) so a crash cannot dump cleartext to disk."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _disable_process_dumpability() -> None:
    """Deny same-UID ptrace and /proc/PID/mem access on Linux.

    RLIMIT_CORE only controls crash files. ``PR_SET_DUMPABLE=0`` closes the
    separate process-memory inspection path while preserving normal service
    operation. A host root/CAP_SYS_PTRACE or kernel compromise remains outside
    this boundary.
    """
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _mlockall() -> None:
    """Pin current + future pages into RAM (no swap). Raises OSError on failure."""
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    if libc.mlockall(_MCL_CURRENT | _MCL_FUTURE) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def harden_process_memory(
    *,
    memlock_all: bool,
    disable_core_dumps: bool,
    workers: int = 1,
    rust_custodian_slots: int = 0,
    memory_lock_required: bool = False,
) -> None:
    """Apply configured memory hardening at worker startup.

    Each uvicorn worker calls this once in the lifespan; mlockall + RLIMIT are
    per-process. mlockall failures are reported in best-effort mode and fail
    closed in required mode when persistent swap is exposed or unknown. Rust
    key buffers enforce the same separately configured policy.
    """
    global _PROCESS_MEMORY_PROTECTION
    _PROCESS_MEMORY_PROTECTION = "disabled" if not memlock_all else "unknown"

    # Unlike mlockall, this has no memory/capability budget and should succeed
    # on every supported Linux deployment. Fail closed: otherwise a process
    # running as the API UID could inspect another worker's cleartext heap.
    try:
        _disable_process_dumpability()
        if sys.platform.startswith("linux"):
            log.info(
                "mem-hardening: process non-dumpable "
                "(same-UID ptrace and /proc/PID/mem denied)"
            )
    except (OSError, AttributeError) as e:
        raise RuntimeError(
            "mem-hardening: cannot set PR_SET_DUMPABLE=0; refusing to start"
        ) from e

    if disable_core_dumps:
        try:
            _disable_core_dumps()
            log.info("mem-hardening: core dumps disabled (RLIMIT_CORE=0)")
        except (ValueError, OSError) as e:
            log.warning("mem-hardening: could not disable core dumps: %s", e)

    if memlock_all:
        # macOS has no mlockall; skip cleanly rather than dlsym-fail noisily.
        if sys.platform == "darwin":
            _PROCESS_MEMORY_PROTECTION = "unsupported"
            log.info("mem-hardening: mlockall unavailable on darwin, skipped")
            return
        check_memlock_headroom(workers, rust_custodian_slots)
        check_memlock_rlimit(workers, rust_custodian_slots)
        try:
            _mlockall()
            _PROCESS_MEMORY_PROTECTION = "mlock"
            log.info("mem-hardening: address space locked into RAM (mlockall)")
        except (OSError, AttributeError) as e:
            # OSError: EPERM (no CAP_IPC_LOCK), ENOMEM (memlock ulimit too low),
            #   or libc not loadable. AttributeError: a libc without the
            #   mlockall symbol (no real target -- BSDs have it, macOS is
            #   skipped above -- but fail safe rather than crash). Warn, boot on.
            _PROCESS_MEMORY_PROTECTION = "swappable"
            swap_state = swap_protection()
            if swap_state == "protected":
                log.info(
                    "mem-hardening: mlockall unavailable (%s); swap is absent, "
                    "encrypted, or RAM-only",
                    e,
                )
            else:
                if memory_lock_required:
                    raise RuntimeError(
                        "mem-hardening: RH_MEMORY_LOCK_MODE=required but "
                        "mlockall failed while swap is unencrypted or unknown"
                    ) from e
                log.warning(
                    "mem-hardening: mlockall failed (%s); unencrypted or unknown "
                    "swap may persist secrets - grant IPC_LOCK or encrypt swap",
                    e,
                )

    try:
        import rhorizon_crypto

        rust_status = getattr(rhorizon_crypto, "memory_lock_status", lambda: "mlock")()
    except ImportError:
        rust_status = "unknown"
    if rust_status == "zeroize-only":
        if swap_protection() == "protected":
            log.info(
                "mem-hardening: Rust buffers use zeroize-on-drop; swap is absent, "
                "encrypted, or RAM-only"
            )
        else:
            log.warning(
                "mem-hardening: Rust buffers are not locked and unencrypted or "
                "unknown swap may persist secrets; grant IPC_LOCK or encrypt swap"
            )
