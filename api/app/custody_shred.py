# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Make the custody state a resolved topology change superseded unusable.

Persisted share state is named after the topology it belongs to, so a pool
relaunched under a reshare target writes beside the shape it can still revert
to. Once the transition resolves that older shape is dead -- reconciliation
demands the launched shape match the durable one, so there is no going back to
it -- but its files remain on disk and still decrypt, because a slot keeps its
transport key across a shape change by design.

The goal is NOT an empty directory. Shamir is information-theoretic below its
threshold: ``threshold - 1`` shares of a shape reveal exactly nothing about the
bundle, and no amount of further deletion improves on nothing. So the invariant
this enforces is the weakest one that is actually sufficient:

    for every superseded shape, the number of its shares that remain
    DECRYPTABLE is strictly below that shape's own threshold.

Deleting custody state has no soft landing: losing share state below quorum
does not degrade the vault, it stops the API from starting at all, and no
master password recovers it. Doing the minimum is therefore not laziness, it is
the point -- every file left alone is a file a bug in this module cannot
destroy.

A slot above the live slot count has no daemon and no future, so it goes whole:
its transport key and every share state it ever wrote. Dropping only the key is
tempting -- what remains cannot be decrypted by anyone -- but a custodian
refuses to start when a state file for its shape exists and will not open, so
that would strand the pool on any later relaunch into that shape. Surviving
slots then only need enough of each dead shape removed to cross below its
threshold.

    grow  3 -> 5   superseded 2-of-3, all 3 slots live  -> 2 states
    shrink 5 -> 3  superseded 3-of-5, slots 4-5 orphan  -> 2 keys + their
                                                           states, then 1 more
    shrink 9 -> 3  superseded 5-of-9, slots 4-9 orphan  -> 6 keys + their
                                                           states; the 3 left
                                                           are below 5
"""

import os
import re
from pathlib import Path

from .cluster_rpc import CustodianPoolController, CustodianPoolUnavailable
from .custody_reshare import _read_state, _serialized_custody_operation
from .database import async_session

# slot-<n>.<threshold>-of-<slots>.share-state, the launcher's own naming.
_SHARE_STATE = re.compile(r"^slot-(\d+)\.(\d+)-of-(\d+)\.share-state$")
_TRANSPORT_KEY = re.compile(r"^slot-(\d+)\.transport-key$")


class CustodyShredRefused(RuntimeError):
    """The pool is not in a state where deleting anything is provably safe."""


def _shred(path: Path) -> None:
    """Overwrite before unlinking, then fsync the directory.

    Best effort and nothing more: no userspace overwrite defeats a
    copy-on-write filesystem or a wear-levelling controller. It costs one write
    of a small file and removes the trivially recoverable case.
    """
    try:
        with open(path, "r+b") as handle:
            length = os.fstat(handle.fileno()).st_size
            handle.write(b"\0" * length)
            handle.flush()
            os.fsync(handle.fileno())
    except FileNotFoundError:
        return
    path.unlink(missing_ok=True)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


async def _assert_pool_is_exactly_the_live_shape(
    pool: CustodianPoolController, *, generation: int, threshold: int, slots: int
) -> None:
    """Refuse unless every live slot reports the durable shape and generation.

    This is the whole safety argument. A filename says which shape a file
    claims to belong to; only the daemons say which shape is actually running
    and which generation it holds. Anything unexpected -- a missing slot, a
    transaction in flight, a generation that is not the active one -- means the
    pool is not in a state where another shape's files are provably dead.
    """
    statuses = await pool.share_statuses()
    if sorted(statuses) != list(range(1, slots + 1)):
        raise CustodyShredRefused(
            "custodian pool does not report exactly the durable slot set"
        )
    for slot, status in statuses.items():
        if (
            status.get("slot") != slot
            or status.get("threshold") != threshold
            or status.get("slots") != slots
        ):
            raise CustodyShredRefused(
                f"custodian slot {slot} does not run the durable topology"
            )
        if status.get("generation") != generation:
            raise CustodyShredRefused(
                f"custodian slot {slot} does not hold the active generation"
            )
        if (
            status.get("prepared_generation") is not None
            or status.get("previous_generation") is not None
            or status.get("reshare_generation") is not None
        ):
            raise CustodyShredRefused(
                f"custodian slot {slot} has a custody transaction in flight"
            )


def _plan(key_dir: Path, *, threshold: int, slots: int) -> dict[str, list[Path]]:
    """Choose the fewest deletions that put every dead shape below threshold.

    An orphaned slot -- one above the live slot count -- is handled whole: its
    transport key AND every share state it ever wrote. Dropping only the key
    would look cheaper, since the state it leaves behind can no longer be
    decrypted by anyone. It is not cheaper, it is a landmine: a custodian
    refuses to start when a state file for its shape exists and does not open,
    and only tolerates one that is absent. So a later relaunch into that shape
    would find an unreadable file and the pool would not come up at all.
    Deleting it costs nothing -- its key is already gone -- and removes that.
    """
    superseded: dict[tuple[int, int], list[int]] = {}
    orphan_keys: list[Path] = []
    orphan_states: list[Path] = []
    for entry in sorted(key_dir.iterdir()):
        if not entry.is_file():
            continue
        share_state = _SHARE_STATE.match(entry.name)
        if share_state is not None:
            slot, file_threshold, file_slots = (
                int(group) for group in share_state.groups()
            )
            if slot > slots:
                orphan_states.append(entry)
            elif (file_threshold, file_slots) != (threshold, slots):
                superseded.setdefault((file_threshold, file_slots), []).append(slot)
            continue
        transport_key = _TRANSPORT_KEY.match(entry.name)
        if transport_key is not None and int(transport_key.group(1)) > slots:
            orphan_keys.append(entry)

    # An orphaned slot's shares are gone above, so they no longer count towards
    # their shape's threshold and only the surviving slots have to be reduced.
    states: list[Path] = list(orphan_states)
    residual: list[str] = []
    for (file_threshold, file_slots), members in sorted(superseded.items()):
        decryptable = sorted(members)
        excess = len(decryptable) - (file_threshold - 1)
        # Highest slot first: on a shrink those are the least likely to be
        # wanted again, and the order has to be deterministic to be reviewable.
        doomed = sorted(decryptable, reverse=True)[: max(0, excess)]
        states.extend(
            key_dir / f"slot-{slot}.{file_threshold}-of-{file_slots}.share-state"
            for slot in sorted(doomed)
        )
        residual.append(
            f"{file_threshold}-of-{file_slots}: "
            f"{len(decryptable) - len(doomed)} decryptable of {file_threshold} needed"
        )
    return {
        "superseded_share_state": sorted(states),
        "orphan_transport_keys": orphan_keys,
        "residual": residual,
    }


async def shred_superseded_custody_state(
    pool: CustodianPoolController,
    *,
    key_dir: str | Path,
    session_factory=async_session,
    dry_run: bool = False,
) -> dict[str, list[str]]:
    """Put every superseded shape below its own threshold, and no more.

    Returns what was removed (or would be, under ``dry_run``) plus the residual
    each dead shape is left at. Takes the orchestration lock, so a topology
    change cannot start while the sweep is deciding what is dead, and the sweep
    cannot run against a pool mid-ceremony.
    """
    async with _serialized_custody_operation(session_factory):
        return await shred_superseded_custody_state_locked(
            pool, key_dir=key_dir, session_factory=session_factory, dry_run=dry_run
        )


async def shred_superseded_custody_state_locked(
    pool: CustodianPoolController,
    *,
    key_dir: str | Path,
    session_factory=async_session,
    dry_run: bool = False,
) -> dict[str, list[str]]:
    """As above, for a caller that ALREADY holds the orchestration lock.

    Reconciliation sweeps from inside its own held lock. Re-taking it there
    would not merely be redundant: the try-lock runs in a second session and
    would report the caller's own lock as another operation in progress.
    """
    key_path = Path(key_dir)
    state = await _read_state(session_factory)
    if state.phase != "stable":
        # Mid-transition the older shape is not superseded at all: it is
        # the shape the operator can still return to by putting the
        # environment back.
        raise CustodyShredRefused(
            f"custody phase is {state.phase}, not stable: nothing is superseded yet"
        )
    if state.active_generation is None:
        raise CustodyShredRefused("no active custody generation to preserve")

    threshold, slots = state.threshold, state.slots
    try:
        await _assert_pool_is_exactly_the_live_shape(
            pool,
            generation=state.active_generation,
            threshold=threshold,
            slots=slots,
        )
    except CustodianPoolUnavailable as exc:
        raise CustodyShredRefused(f"custodian pool is not reachable: {exc}") from exc

    # The daemons answered, but they hold their shares in memory. Refuse if
    # the live shape is not ALSO complete on disk: deleting anything would
    # otherwise leave a pool that cannot survive its own restart, which is
    # exactly the unrecoverable state.
    missing = [
        f"slot-{slot}.{threshold}-of-{slots}.share-state"
        for slot in range(1, slots + 1)
        if not (key_path / f"slot-{slot}.{threshold}-of-{slots}.share-state").is_file()
    ]
    if missing:
        raise CustodyShredRefused(
            "live share state is incomplete on disk: " + ", ".join(missing)
        )

    plan = _plan(key_path, threshold=threshold, slots=slots)
    if not dry_run:
        # State before keys. Interrupted after a key is gone but before the
        # state it protected, a slot is left holding a file it can never open,
        # and a custodian refuses to start on exactly that. Interrupted the
        # other way round it keeps a key with no state, which is inert.
        for path in plan["superseded_share_state"]:
            _shred(path)
        for path in plan["orphan_transport_keys"]:
            _shred(path)
        # The pool answered before; make it answer after. A sweep that
        # broke something must fail here, while the operator is present,
        # not at the next restart.
        await _assert_pool_is_exactly_the_live_shape(
            pool,
            generation=state.active_generation,
            threshold=threshold,
            slots=slots,
        )

    return {
        "superseded_share_state": [
            path.name for path in plan["superseded_share_state"]
        ],
        "orphan_transport_keys": [path.name for path in plan["orphan_transport_keys"]],
        "residual": plan["residual"],
        "kept_shape": [f"{threshold}-of-{slots}"],
    }
