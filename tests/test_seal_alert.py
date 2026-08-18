# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""record_seal: a seal must be surfaced (counter + best-effort notification).

A sealing node is the expected fail-safe under overload/attack, but it has to
be SURFACED. record_seal bumps rhorizon_seal_events_total{trigger} and, for a
deliberate unexpected seal, fires a best-effort critical notification. The
rhorizon_vault_sealed gauge is the reliable external backstop (alerts even on a
crash-seal); this is the cheap in-app ping on top.
"""

from unittest.mock import patch

import pytest
from api.app import audit
from api.app.metrics import seal_events


def _count(trigger: str) -> float:
    return sum(
        s.value
        for m in seal_events.collect()
        for s in m.samples
        if s.name.endswith("_total") and s.labels.get("trigger") == trigger
    )


def test_record_seal_increments_counter():
    before = _count("unit_a")
    audit.record_seal("unit_a", notify=False)
    assert _count("unit_a") == before + 1


@pytest.mark.asyncio
async def test_record_seal_notifies_on_unexpected():
    with patch.object(audit, "_dispatch_critical_event") as disp:
        audit.record_seal("unit_defensive", notify=True)
        # create_task scheduled the dispatch; yield so the task body runs.
        import asyncio

        await asyncio.sleep(0)
    assert disp.called, "an unexpected seal must fire a best-effort notification"
    assert "unit_defensive" in disp.call_args[0][0]


@pytest.mark.asyncio
async def test_record_seal_no_notify_for_expected():
    with patch.object(audit, "_dispatch_critical_event") as disp:
        audit.record_seal("manual", notify=False)
        import asyncio

        await asyncio.sleep(0)
    assert not disp.called, "an expected seal (operator/shutdown) must not alert"


def test_record_seal_never_raises():
    # Counter failure must not break the seal path.
    with patch.object(seal_events, "labels", side_effect=RuntimeError("boom")):
        audit.record_seal("unit_b", notify=False)  # must not raise
