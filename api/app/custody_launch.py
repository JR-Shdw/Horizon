# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Decide which shape the custodian pool must be launched with.

The environment cannot be the whole answer. A topology change is prepared by a
coordinator that is still running the OLD shape -- only it can split the
runtime bundle for the new one -- so a pool whose configuration has moved ahead
of its durable state has to come up in the durable shape first, let the change
be prepared, and be relaunched. Taking the shape from the configuration alone
would skip that and land on a shape holding no shares, which does not degrade:
the API refuses to start and no master password recovers it.

The durable state does not simply win either, or a pending change could never
be abandoned. The configuration keeps one job: it says which shape is WANTED,
and that is what distinguishes rolling a prepared change forward from putting
the environment back to abort it.

    no generation yet        -> configured        (first boot, nothing to lose)
    resharding, want target  -> target            (roll forward)
    resharding, want current -> durable           (the operator reverted)
    stable                   -> durable           (drift is handled by the API,
                                                   which prepares the change
                                                   against the live quorum)

Reading this from PostgreSQL costs nothing that is not already paid: the API
does not run without it, and the shipped compose gates the container on the
database being healthy. What it must never do is guess -- an unreachable
database means refusing to start, because launching the wrong shape is the one
mistake with no way back.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LaunchTopology:
    threshold: int
    slots: int
    reason: str


def resolve_launch_topology(
    *,
    phase: str,
    active_generation: int | None,
    durable: tuple[int, int],
    configured: tuple[int, int],
    target: tuple[int, int] | None,
) -> LaunchTopology:
    """Pick the shape to launch, and say why.

    ``durable`` is the shape the recorded generation belongs to, ``target`` the
    shape a prepared-but-unresolved change would move to, and ``configured``
    what the environment asks for. The reason travels with the decision so the
    launcher can log an unexpected shape rather than silently obeying.
    """
    if active_generation is None:
        return LaunchTopology(*configured, reason="no custody generation yet")
    if phase == "resharding" and target is not None:
        if configured == target:
            return LaunchTopology(*target, reason="rolling a prepared change forward")
        # Anything other than the target -- including a configuration that has
        # been put back to the current shape -- means the change is not wanted.
        # Launching the current shape lets reconciliation drop it.
        return LaunchTopology(
            *durable, reason="prepared change is no longer configured, aborting"
        )
    return LaunchTopology(*durable, reason="running the durable shape")


async def launch_topology(session_factory, configured: tuple[int, int]):
    """Resolve the launch shape against the database."""
    from .custody_generation import (
        get_custody_generation_state,
        get_custody_topology_deliveries,
    )

    async with session_factory() as db:
        state = await get_custody_generation_state(db)
        recorded = await get_custody_topology_deliveries(db)
    target = None if recorded is None else (recorded[1], recorded[2])
    return resolve_launch_topology(
        phase=state.phase,
        active_generation=state.active_generation,
        durable=(state.threshold, state.slots),
        configured=configured,
        target=target,
    )


async def _print_launch_topology() -> int:
    """Resolve and print ``<threshold> <slots>`` for the pool launcher.

    Waits for the database rather than guessing: on a native install nothing
    orders the two, and the shipped compose already gates this container on
    PostgreSQL being healthy. A timeout is a refusal to start, which is the
    only safe way to be wrong here.
    """
    import asyncio
    import sys

    from .config import settings
    from .database import async_session

    configured = (settings.rust_custodian_threshold, settings.rust_custodian_slots)
    deadline_attempts = 30
    last: Exception | None = None
    for _ in range(deadline_attempts):
        try:
            decided = await launch_topology(async_session, configured)
        except Exception as exc:  # noqa: BLE001 - reported below, then retried
            last = exc
            await asyncio.sleep(1)
            continue
        if (decided.threshold, decided.slots) != configured:
            # Never silently disobey the operator: say which shape is coming up
            # and why the configured one is not.
            print(
                f"[rhorizon] custodian pool launching {decided.threshold}-of-"
                f"{decided.slots} rather than the configured {configured[0]}-of-"
                f"{configured[1]}: {decided.reason}",
                file=sys.stderr,
            )
        print(f"{decided.threshold} {decided.slots}")
        return 0
    print(
        f"[rhorizon] could not read the durable custody topology: {last}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":  # pragma: no cover - launcher entry point
    import asyncio
    import sys

    sys.exit(asyncio.run(_print_launch_topology()))
