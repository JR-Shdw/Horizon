"""API attachment contracts for the opt-in standalone Rust custody backend."""

import inspect
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from api.app import custody_generation as cg
from api.app import rust_custody_backend
from api.app.database import async_session
from sqlalchemy import text


class FakeVault:
    def __init__(self):
        self._rpc_client = object()
        self._sealed = False
        self.recovery = None
        self.events = []
        self.key_epoch = None
        self.master_check = "expected-master-check"

    async def hmac_sha512_hex(self, message):
        self.events.append(("hmac", message))
        return self.master_check

    @asynccontextmanager
    async def master_transition_lock(self):
        self.events.append("lock")
        yield

    def attach_rpc_client(self, client):
        self.events.append(("attach", client))
        self._rpc_client = client

    def detach_rpc_client(self):
        self.events.append("detach")
        self._rpc_client = None

    def seal(self):
        self.events.append("seal")
        self._sealed = True

    def set_rpc_recovery_hook(self, callback):
        self.recovery = callback

    def set_key_epoch(self, epoch):
        self.events.append(("epoch", epoch))
        self.key_epoch = epoch


class FakePool:
    def __init__(self, failure=None):
        self.failure = failure
        self.events = []

    async def seal_all(self):
        self.events.append("seal-all")
        if self.failure is not None:
            raise self.failure


def _patch_generation_refresh(monkeypatch, refresh):
    """Stand in for the locked activation-read + repair in custody_reshare."""
    monkeypatch.setattr(
        rust_custody_backend, "refresh_rust_custody_generation", refresh
    )


def test_pool_factory_derives_majority_and_fixed_socket_names(tmp_path):
    runtime = tmp_path / "run"
    token = runtime / "custodian-control.token"

    pool = rust_custody_backend.build_rust_custodian_pool(
        runtime_directory=runtime,
        control_token_file=token,
        slots=3,
    )

    assert pool.threshold == 2
    assert pool._socket_names == {
        1: str(runtime / "rust-custodian-1.sock"),
        2: str(runtime / "rust-custodian-2.sock"),
        3: str(runtime / "rust-custodian-3.sock"),
    }


def test_configured_pool_registry_fails_closed_until_initialized(monkeypatch):
    monkeypatch.setattr(rust_custody_backend, "_configured_pool", None)
    with pytest.raises(RuntimeError, match="not configured"):
        rust_custody_backend.configured_rust_custody_pool()
    pool = object()
    rust_custody_backend.configure_rust_custody_pool(pool)
    assert rust_custody_backend.configured_rust_custody_pool() is pool


def test_pool_factory_rejects_unsafe_or_split_runtime_paths(tmp_path):
    with pytest.raises(ValueError, match="absolute subpath"):
        rust_custody_backend.build_rust_custodian_pool(
            runtime_directory="relative",
            control_token_file="/tmp/token",
            slots=3,
        )
    with pytest.raises(ValueError, match="absolute file path"):
        rust_custody_backend.build_rust_custodian_pool(
            runtime_directory=tmp_path / "run",
            control_token_file="relative-token",
            slots=3,
        )
    with pytest.raises(ValueError, match="directly under"):
        rust_custody_backend.build_rust_custodian_pool(
            runtime_directory=tmp_path / "run",
            control_token_file=tmp_path / "other" / "token",
            slots=3,
        )
    with pytest.raises(ValueError, match="one of"):
        rust_custody_backend.build_rust_custodian_pool(
            runtime_directory=tmp_path / "run",
            control_token_file=tmp_path / "run" / "token",
            slots=4,
        )


@pytest.mark.asyncio
async def test_activation_helpers_use_durable_database_state(setup_db):
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = :key"),
                {"key": cg.CUSTODY_ACTIVATION_CONFIG_KEY},
            )
        ).fetchone()
        original = row.value if row else None
    try:
        await rust_custody_backend._persist_rust_custody_activation(
            async_session, unsealed=True
        )
        async with async_session() as db:
            assert await cg.get_rust_custody_activation(db)
    finally:
        async with async_session() as db:
            if original is None:
                await db.execute(
                    text("DELETE FROM vault_config WHERE key = :key"),
                    {"key": cg.CUSTODY_ACTIVATION_CONFIG_KEY},
                )
            else:
                await db.execute(
                    text(
                        "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
                        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
                    ),
                    {"key": cg.CUSTODY_ACTIVATION_CONFIG_KEY, "value": original},
                )
            await db.commit()


@pytest.mark.asyncio
async def test_attach_reconciles_before_exposing_selected_client(monkeypatch):
    vault = FakeVault()
    client = object()

    async def reconcile(pool, *, session_factory):
        assert pool == "pool"
        assert session_factory == "sessions"
        assert vault.events == ["lock", "detach", "seal"]
        return client

    _patch_generation_refresh(monkeypatch, reconcile)

    assert await rust_custody_backend.attach_reconciled_rust_custody(
        "pool", vault, session_factory="sessions"
    )
    assert vault._rpc_client is client
    assert not vault._sealed
    assert vault.events == [
        "lock",
        "detach",
        "seal",
        "lock",
        ("attach", client),
    ]


@pytest.mark.asyncio
async def test_attach_without_generation_leaves_worker_sealed(monkeypatch):
    vault = FakeVault()

    async def reconcile(*_args, **_kwargs):
        return None

    _patch_generation_refresh(monkeypatch, reconcile)

    assert not await rust_custody_backend.attach_reconciled_rust_custody("pool", vault)
    assert vault._rpc_client is None
    assert vault._sealed
    assert vault.events == ["lock", "detach", "seal"]


@pytest.mark.asyncio
async def test_startup_attach_waits_out_a_peer_worker_holding_the_lock(monkeypatch):
    """Every API worker runs this same reconcile when it boots.

    The orchestration lock is a non-blocking try-lock, so all but one worker
    lose it. Losing is not a failure: the winner is performing the identical
    reconcile. A loser that raised would fail its own startup, and main.py
    treats that as a fatal cluster-init error, so N-1 workers would die on
    every boot of the Rust backend.
    """
    vault = FakeVault()
    client = object()
    calls = []

    async def contended_then_reconciled(*_args, **_kwargs):
        calls.append(1)
        if len(calls) < 3:
            raise cg.CustodyOrchestrationBusy(
                "another custody generation operation is in progress"
            )
        return client

    _patch_generation_refresh(monkeypatch, contended_then_reconciled)
    monkeypatch.setattr(rust_custody_backend, "_STARTUP_ATTACH_LOCK_DELAY_SECS", 0)

    assert await rust_custody_backend.attach_reconciled_rust_custody(
        "pool", vault, session_factory="sessions"
    )
    assert len(calls) == 3
    assert vault._rpc_client is client
    assert not vault._sealed


@pytest.mark.asyncio
async def test_startup_attach_fails_closed_when_contention_never_clears(monkeypatch):
    """The wait is bounded, so a genuinely stuck holder still refuses the
    worker instead of hanging startup forever."""
    vault = FakeVault()
    calls = []

    async def always_contended(*_args, **_kwargs):
        calls.append(1)
        raise cg.CustodyOrchestrationBusy(
            "another custody generation operation is in progress"
        )

    _patch_generation_refresh(monkeypatch, always_contended)
    monkeypatch.setattr(rust_custody_backend, "_STARTUP_ATTACH_LOCK_DELAY_SECS", 0)
    monkeypatch.setattr(rust_custody_backend, "_STARTUP_ATTACH_LOCK_ATTEMPTS", 4)

    with pytest.raises(cg.CustodyOrchestrationBusy):
        await rust_custody_backend.attach_reconciled_rust_custody(
            "pool", vault, session_factory="sessions"
        )
    assert len(calls) == 4
    assert vault._sealed


class FakeDiscoveryPool:
    """Pool whose only exercised surface is read-only coordinator discovery."""

    def __init__(self, coordinator=None, generation=None, statuses=None):
        self._coordinator = coordinator
        self._generation = generation
        self._statuses = statuses
        self.events = []

    async def unsealed_coordinator(self, generation):
        self.events.append(("discover", generation))
        if self._coordinator is None or generation != self._generation:
            return None
        return self._coordinator

    async def statuses(self):
        self.events.append(("statuses",))
        if isinstance(self._statuses, Exception):
            raise self._statuses
        if self._statuses is not None:
            return self._statuses
        if self._coordinator is not None:
            return {1: {"state": "unsealed", "generation": self._generation}}
        return {1: {"state": "sealed"}, 2: {"state": "sealed"}}

    async def seal_all(self):  # pragma: no cover - must never be reached
        raise AssertionError("a follower attach must not seal the shared pool")


def _patch_durable_state(monkeypatch, *, unsealed, active_generation):
    async def activation(_db):
        return unsealed

    async def state(_db):
        return SimpleNamespace(active_generation=active_generation)

    monkeypatch.setattr(rust_custody_backend, "get_rust_custody_activation", activation)
    monkeypatch.setattr(rust_custody_backend, "get_custody_generation_state", state)

    @asynccontextmanager
    async def sessions():
        yield "db"

    return sessions


@pytest.mark.asyncio
async def test_follower_attaches_to_the_coordinator_without_orchestrating(monkeypatch):
    """A disposable worker must reach the quorum without leader-grade work.

    The design says an API worker holds no share and its replacement never
    changes the custody generation, so this path takes no orchestration lock,
    moves no share material, and never seals the pool.
    """
    vault = FakeVault()
    vault._sealed = True
    vault._rpc_client = None
    client = object()
    pool = FakeDiscoveryPool(coordinator=client, generation=7)
    sessions = _patch_durable_state(monkeypatch, unsealed=True, active_generation=7)

    assert await rust_custody_backend.attach_live_rust_coordinator(
        pool, vault, session_factory=sessions
    )
    assert pool.events == [("discover", 7)]
    assert vault._rpc_client is client
    assert not vault._sealed


@pytest.mark.asyncio
async def test_follower_stays_sealed_when_operator_intent_is_sealed(monkeypatch):
    vault = FakeVault()
    vault._sealed = True
    vault._rpc_client = None
    pool = FakeDiscoveryPool(coordinator=object(), generation=7)
    sessions = _patch_durable_state(monkeypatch, unsealed=False, active_generation=7)

    assert not await rust_custody_backend.attach_live_rust_coordinator(
        pool, vault, session_factory=sessions
    )
    # Never even probed: the durable decision settles it first.
    assert pool.events == []
    assert vault._sealed


@pytest.mark.asyncio
async def test_follower_seals_its_view_when_the_operator_seals(monkeypatch):
    """Seal must reach followers too, or they answer /status with
    sealed=false while every crypto op fails against sealed daemons."""
    vault = FakeVault()
    client = object()
    vault._rpc_client = client
    vault._sealed = False
    pool = FakeDiscoveryPool(coordinator=client, generation=7)
    sessions = _patch_durable_state(monkeypatch, unsealed=False, active_generation=7)

    assert not await rust_custody_backend.attach_live_rust_coordinator(
        pool, vault, session_factory=sessions
    )
    assert vault._sealed
    assert vault._rpc_client is None
    assert vault.events == ["lock", "detach", "seal"]
    # Sealing a follower is local: it must never touch the shared pool.
    assert pool.events == []


@pytest.mark.asyncio
async def test_follower_refuses_a_coordinator_on_a_different_generation(monkeypatch):
    """Discovery verifies rather than trusts: a coordinator serving another
    generation must not be adopted, or the worker would decrypt under keys no
    stored row matches."""
    vault = FakeVault()
    vault._sealed = True
    vault._rpc_client = None
    pool = FakeDiscoveryPool(coordinator=object(), generation=9)
    sessions = _patch_durable_state(monkeypatch, unsealed=True, active_generation=7)

    assert not await rust_custody_backend.attach_live_rust_coordinator(
        pool, vault, session_factory=sessions
    )
    # The refutation probe still runs, and it finds an unsealed daemon (on
    # the wrong generation), so the local view is left alone.
    assert pool.events == [("discover", 7), ("statuses",)]
    assert vault._sealed


@pytest.mark.asyncio
async def test_follower_seals_a_stale_latch_every_slot_refutes(monkeypatch):
    """A pool with every slot answering sealed refutes a worker's unsealed
    latch. Nothing else catches that worker: a daemon that ANSWERS "vault
    sealed" never trips the MasterUnreachable recovery hook, so without this
    the worker wedges on already_unsealed while every crypto op fails."""
    vault = FakeVault()
    stale = object()
    vault._rpc_client = stale
    vault._sealed = False
    pool = FakeDiscoveryPool(coordinator=None, generation=7)
    sessions = _patch_durable_state(monkeypatch, unsealed=True, active_generation=7)

    assert not await rust_custody_backend.attach_live_rust_coordinator(
        pool, vault, session_factory=sessions
    )
    assert pool.events == [("discover", 7), ("statuses",)]
    assert vault._sealed
    assert vault._rpc_client is None
    assert vault.events == ["lock", "detach", "seal"]


@pytest.mark.asyncio
async def test_follower_keeps_its_latch_while_a_slot_is_unreachable(monkeypatch):
    """An unreachable slot proves nothing: the coordinator might be the very
    slot that did not answer. Conservative wait, next tick retries."""
    from api.app.cluster_rpc import CustodianPoolUnavailable

    vault = FakeVault()
    stale = object()
    vault._rpc_client = stale
    vault._sealed = False
    pool = FakeDiscoveryPool(
        coordinator=None,
        generation=7,
        statuses=CustodianPoolUnavailable("slot 2 status unavailable"),
    )
    sessions = _patch_durable_state(monkeypatch, unsealed=True, active_generation=7)

    assert not await rust_custody_backend.attach_live_rust_coordinator(
        pool, vault, session_factory=sessions
    )
    assert pool.events == [("discover", 7), ("statuses",)]
    assert not vault._sealed
    assert vault._rpc_client is stale


@pytest.mark.asyncio
async def test_recovery_detaches_before_reconciling(monkeypatch):
    vault = FakeVault()
    client = object()

    async def reconcile(pool, *, session_factory):
        assert pool == "pool"
        assert session_factory == "sessions"
        assert vault._rpc_client is None
        assert vault._sealed
        return client

    _patch_generation_refresh(monkeypatch, reconcile)
    rust_custody_backend.wire_rust_custody_recovery(
        "pool", vault, session_factory="sessions"
    )

    assert await vault.recovery()
    assert vault._rpc_client is client
    assert not vault._sealed
    assert vault.events == [
        "lock",
        "detach",
        "seal",
        "lock",
        ("attach", client),
    ]


@pytest.mark.asyncio
async def test_operator_seal_decision_blocks_reconstruction(monkeypatch):
    vault = FakeVault()
    pool = FakePool()

    async def sealed_decision(candidate_pool, *, session_factory):
        assert session_factory == "sessions"
        await candidate_pool.seal_all()
        return None

    _patch_generation_refresh(monkeypatch, sealed_decision)

    assert not await rust_custody_backend.attach_reconciled_rust_custody(
        pool, vault, session_factory="sessions"
    )
    assert vault._rpc_client is None
    assert vault._sealed
    assert vault.events == ["lock", "detach", "seal"]
    assert pool.events == ["seal-all"]


@pytest.mark.asyncio
async def test_manual_deactivation_commits_before_sealing_every_view(monkeypatch):
    vault = FakeVault()
    pool = FakePool()
    events = []

    async def persist(session_factory, *, unsealed):
        events.append(("persist", session_factory, unsealed))

    monkeypatch.setattr(
        rust_custody_backend, "_persist_rust_custody_activation", persist
    )

    await rust_custody_backend.deactivate_rust_custody(
        pool, vault, session_factory="sessions"
    )
    assert events == [("persist", "sessions", False)]
    assert pool.events == ["seal-all"]
    assert vault.events == ["lock", "detach", "seal"]


@pytest.mark.asyncio
async def test_manual_deactivation_seals_api_when_a_daemon_is_unreachable(monkeypatch):
    vault = FakeVault()
    pool = FakePool(RuntimeError("slot offline"))

    async def persist(*_args, **_kwargs):
        return None

    monkeypatch.setattr(
        rust_custody_backend, "_persist_rust_custody_activation", persist
    )

    with pytest.raises(RuntimeError, match="slot offline"):
        await rust_custody_backend.deactivate_rust_custody(pool, vault)
    assert vault._rpc_client is None
    assert vault._sealed
    assert vault.events == ["lock", "detach", "seal"]


class _MasterCheckSessions:
    """Serve one ``master_check`` row without touching a database."""

    def __init__(self, stored):
        self.stored = stored

    def __call__(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def execute(self, *_args, **_kwargs):
        stored = self.stored

        class _Result:
            def fetchone(self):
                if stored is None:
                    return None
                return SimpleNamespace(value=stored)

        return _Result()


def _patch_ancillary_loaders(monkeypatch, record):
    from api.app import audit_identity, auth, ha_password

    async def load(name, db):
        record(name, db)
        return True

    monkeypatch.setattr(
        auth, "load_prev_hmac_into_ram", lambda db: load("prev-hmac", db)
    )
    monkeypatch.setattr(
        ha_password, "load_ha_password_into_ram", lambda db: load("ha-password", db)
    )
    monkeypatch.setattr(
        audit_identity,
        "load_audit_identity_into_ram",
        lambda db: load("audit-identity", db),
    )


@pytest.mark.asyncio
async def test_unseal_waits_out_a_worker_still_booting(monkeypatch):
    """/health answers as soon as the FIRST worker is ready, while the rest
    still reconcile under CUSTODY_ORCHESTRATION_LOCK. The busy window grows
    with the worker count, so at 16 workers an unseal issued the moment the
    port answers lands inside it. Losing that race is not a fault: nothing was
    attempted, and the operator's unseal must not fail because a peer worker
    happened to be mid-boot.
    """
    vault = FakeVault()
    client = object()
    calls = []

    async def busy_then_open(*_args, **_kwargs):
        calls.append(1)
        if len(calls) < 3:
            raise cg.CustodyOrchestrationBusy(
                "another custody generation operation is in progress"
            )
        return client

    monkeypatch.setattr(
        rust_custody_backend, "open_rust_custody_for_local_unseal", busy_then_open
    )
    monkeypatch.setattr(rust_custody_backend, "_UNSEAL_LOCK_DELAY_SECS", 0)
    _patch_ancillary_loaders(monkeypatch, lambda name, db: None)

    await rust_custody_backend.activate_rust_custody_from_local(
        "pool",
        vault,
        key_epoch=9,
        threshold=2,
        slots=3,
        session_factory=_MasterCheckSessions(vault.master_check),
    )

    assert len(calls) == 3
    assert vault._rpc_client is client
    assert not vault._sealed


@pytest.mark.asyncio
async def test_unseal_does_not_retry_a_durable_generation_conflict(monkeypatch):
    """A plain CustodyGenerationConflict states a fact about the generation,
    not a lost race. Retrying it would burn the whole budget re-deriving the
    same refusal and delay a real answer, so it must propagate immediately.
    """
    vault = FakeVault()
    calls = []

    async def refuse(*_args, **_kwargs):
        calls.append(1)
        raise cg.CustodyGenerationConflict(
            "local-key migration requires an empty stable Rust generation"
        )

    monkeypatch.setattr(
        rust_custody_backend, "open_rust_custody_for_local_unseal", refuse
    )
    monkeypatch.setattr(rust_custody_backend, "_UNSEAL_LOCK_DELAY_SECS", 0)

    with pytest.raises(cg.CustodyGenerationConflict):
        await rust_custody_backend.activate_rust_custody_from_local(
            "pool",
            vault,
            key_epoch=9,
            threshold=2,
            slots=3,
            session_factory=_MasterCheckSessions(vault.master_check),
        )
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_unseal_fails_closed_when_contention_never_clears(monkeypatch):
    """Bounded, like startup: a genuinely stuck holder still refuses rather
    than hanging the operator's unseal forever. The route turns this into 409,
    not 500, because it is a conflict with current state and is retryable."""
    vault = FakeVault()
    calls = []

    async def always_busy(*_args, **_kwargs):
        calls.append(1)
        raise cg.CustodyOrchestrationBusy(
            "another custody generation operation is in progress"
        )

    monkeypatch.setattr(
        rust_custody_backend, "open_rust_custody_for_local_unseal", always_busy
    )
    monkeypatch.setattr(rust_custody_backend, "_UNSEAL_LOCK_DELAY_SECS", 0)
    monkeypatch.setattr(rust_custody_backend, "_UNSEAL_LOCK_ATTEMPTS", 4)

    with pytest.raises(cg.CustodyOrchestrationBusy):
        await rust_custody_backend.activate_rust_custody_from_local(
            "pool",
            vault,
            key_epoch=9,
            threshold=2,
            slots=3,
            session_factory=_MasterCheckSessions(vault.master_check),
        )
    assert len(calls) == 4


@pytest.mark.asyncio
async def test_activation_wipes_local_view_before_loading_external_envelopes(
    monkeypatch,
):
    vault = FakeVault()
    client = object()
    observed = []

    async def open_custody(candidate_vault, pool, **kwargs):
        assert candidate_vault is vault
        observed.append(("open", pool, kwargs))
        return client

    def record(name, db):
        assert vault._rpc_client is client
        assert not vault._sealed
        observed.append((name, db is not None))

    monkeypatch.setattr(
        rust_custody_backend, "open_rust_custody_for_local_unseal", open_custody
    )
    _patch_ancillary_loaders(monkeypatch, record)

    await rust_custody_backend.activate_rust_custody_from_local(
        "pool",
        vault,
        key_epoch=9,
        threshold=2,
        slots=3,
        session_factory=_MasterCheckSessions(vault.master_check),
    )

    assert vault.events == [
        "detach",
        "seal",
        ("attach", client),
        ("epoch", 9),
        ("hmac", "master-check-value"),
    ]
    assert observed[0][0:2] == ("open", "pool")
    assert [event[0] for event in observed[1:]] == [
        "prev-hmac",
        "ha-password",
        "audit-identity",
    ]


@pytest.mark.asyncio
async def test_activation_seals_a_generation_the_password_does_not_match(monkeypatch):
    """A reopened pool must prove it holds the generation just authenticated.

    Reopen reconstructs the bundle from custodian shares instead of deriving
    it, so nothing else ties it to the password the operator supplied. A
    mismatch has to seal the daemons AND the durable decision, otherwise the
    maintenance leader reopens the divergent pool on its next tick.
    """
    vault = FakeVault()
    pool = FakePool()
    client = object()
    sealed = []

    async def open_custody(*_args, **_kwargs):
        return client

    async def persist(session_factory, *, unsealed):
        sealed.append(unsealed)

    monkeypatch.setattr(
        rust_custody_backend, "open_rust_custody_for_local_unseal", open_custody
    )
    monkeypatch.setattr(
        rust_custody_backend, "_persist_rust_custody_activation", persist
    )
    _patch_ancillary_loaders(
        monkeypatch, lambda *_args: pytest.fail("envelopes must stay unloaded")
    )

    with pytest.raises(RuntimeError, match="does not match the verified master"):
        await rust_custody_backend.activate_rust_custody_from_local(
            pool,
            vault,
            key_epoch=9,
            threshold=2,
            slots=3,
            session_factory=_MasterCheckSessions("another-generation"),
        )

    assert sealed == [False]
    assert pool.events == ["seal-all"]
    assert vault._rpc_client is None
    assert vault._sealed
    assert vault.events[-2:] == ["detach", "seal"]


@pytest.mark.asyncio
async def test_activation_refuses_a_vault_without_a_master_check(monkeypatch):
    vault = FakeVault()
    pool = FakePool()

    async def open_custody(*_args, **_kwargs):
        return object()

    async def persist(_session_factory, *, unsealed):
        assert unsealed is False

    monkeypatch.setattr(
        rust_custody_backend, "open_rust_custody_for_local_unseal", open_custody
    )
    monkeypatch.setattr(
        rust_custody_backend, "_persist_rust_custody_activation", persist
    )

    with pytest.raises(RuntimeError, match="master check is missing"):
        await rust_custody_backend.activate_rust_custody_from_local(
            pool,
            vault,
            key_epoch=9,
            threshold=2,
            slots=3,
            session_factory=_MasterCheckSessions(None),
        )
    assert vault._sealed


@pytest.mark.asyncio
async def test_aborted_key_rotation_reattaches_previous_generation(monkeypatch):
    """The restore path seals the pool, so it must reinstall the envelopes.

    A seal drops the whole locked runtime object: the audit seed, the HA
    password and the previous HMAC key are gone even though the rolled-back
    rows still match the restored generation.
    """
    from api.app import audit_identity, auth, ha_password

    vault = FakeVault()
    client = object()
    observed = []

    async def abort(pool, *, target, previous, session_factory):
        observed.append(("abort", pool, target, previous, session_factory))
        return client

    @asynccontextmanager
    async def sessions():
        yield "db"

    async def load(name, db):
        assert db == "db"
        assert vault._rpc_client is client
        assert not vault._sealed
        observed.append((name,))
        return True

    monkeypatch.setattr(rust_custody_backend, "abort_staged_rust_rotation", abort)
    monkeypatch.setattr(
        auth, "load_prev_hmac_into_ram", lambda db: load("prev-hmac", db)
    )
    monkeypatch.setattr(
        ha_password, "load_ha_password_into_ram", lambda db: load("ha-password", db)
    )
    monkeypatch.setattr(
        audit_identity,
        "load_audit_identity_into_ram",
        lambda db: load("audit-identity", db),
    )

    await rust_custody_backend.abort_rust_custody_key_rotation(
        "pool",
        vault,
        target=8,
        previous=7,
        key_epoch=12,
        session_factory=sessions,
    )

    assert observed == [
        ("abort", "pool", 8, 7, sessions),
        ("prev-hmac",),
        ("ha-password",),
        ("audit-identity",),
    ]
    assert vault.events == ["lock", ("attach", client), ("epoch", 12)]
    assert vault._rpc_client is client
    assert not vault._sealed


@pytest.mark.asyncio
async def test_staging_failure_resync_reattaches_the_restored_coordinator(monkeypatch):
    """Staging restores the previous generation but leaves the API detached."""
    from api.app import audit_identity, auth, ha_password

    vault = FakeVault()
    client = object()
    observed = []

    class Pool:
        # Must mirror CustodianPoolController.active_client, which is a
        # PROPERTY. A method here still satisfies pool.active_client() and
        # hid a production TypeError; see the shape guard below.
        @property
        def active_client(self):
            return client

    @asynccontextmanager
    async def sessions():
        yield "db"

    async def load(name, db):
        assert db == "db"
        assert vault._rpc_client is client
        observed.append(name)
        return True

    monkeypatch.setattr(
        auth, "load_prev_hmac_into_ram", lambda db: load("prev-hmac", db)
    )
    monkeypatch.setattr(
        ha_password, "load_ha_password_into_ram", lambda db: load("ha-password", db)
    )
    monkeypatch.setattr(
        audit_identity,
        "load_audit_identity_into_ram",
        lambda db: load("audit-identity", db),
    )

    await rust_custody_backend.resync_rust_custody_attachment(
        Pool(),
        vault,
        key_epoch=12,
        session_factory=sessions,
    )

    assert observed == ["prev-hmac", "ha-password", "audit-identity"]
    assert vault.events == ["lock", ("attach", client), ("epoch", 12)]


@pytest.mark.asyncio
async def test_staging_failure_resync_is_a_noop_without_a_selected_custodian():
    vault = FakeVault()
    attached = vault._rpc_client

    class Pool:
        @property
        def active_client(self):
            return None

    await rust_custody_backend.resync_rust_custody_attachment(
        Pool(), vault, key_epoch=12
    )

    assert vault.events == []
    assert vault._rpc_client is attached


def test_pool_accessor_shapes_match_what_the_backend_calls():
    """Pin the real accessor shapes so a fake cannot drift from them again.

    `resync_rust_custody_attachment` used `pool.active_client()` while the
    real controller declares a property, so production raised TypeError on
    the rotation-failure recovery path while every test passed against fakes
    that declared methods.
    """
    from api.app.cluster_rpc import CustodianPoolController

    assert isinstance(CustodianPoolController.__dict__["active_client"], property)
    assert isinstance(CustodianPoolController.__dict__["active_slot"], property)
    # Discovery is a coroutine method, not a property: it does IO.
    assert inspect.iscoroutinefunction(CustodianPoolController.unsealed_coordinator)


@pytest.mark.asyncio
async def test_finished_key_rotation_loads_new_envelopes_after_attach(monkeypatch):
    from api.app import audit_identity, auth, ha_password

    vault = FakeVault()
    client = object()
    observed = []

    async def finish(pool, *, target, session_factory):
        observed.append(("finish", pool, target, session_factory))
        return client

    @asynccontextmanager
    async def sessions():
        yield "db"

    async def load(name, db):
        assert db == "db"
        assert vault._rpc_client is client
        assert not vault._sealed
        observed.append((name,))
        return True

    monkeypatch.setattr(rust_custody_backend, "finish_staged_rust_rotation", finish)
    monkeypatch.setattr(
        auth, "load_prev_hmac_into_ram", lambda db: load("prev-hmac", db)
    )
    monkeypatch.setattr(
        ha_password, "load_ha_password_into_ram", lambda db: load("ha-password", db)
    )
    monkeypatch.setattr(
        audit_identity,
        "load_audit_identity_into_ram",
        lambda db: load("audit-identity", db),
    )

    await rust_custody_backend.finish_rust_custody_key_rotation(
        "pool",
        vault,
        target=9,
        key_epoch=13,
        session_factory=sessions,
    )

    assert observed == [
        ("finish", "pool", 9, sessions),
        ("prev-hmac",),
        ("ha-password",),
        ("audit-identity",),
    ]
    assert vault.events == ["lock", ("attach", client), ("epoch", 13)]


@pytest.mark.asyncio
async def test_refresh_switches_coordinator_without_preemptive_api_seal(monkeypatch):
    vault = FakeVault()
    client = object()

    async def repair(*_args, **_kwargs):
        assert vault.events == []
        return client

    _patch_generation_refresh(monkeypatch, repair)

    assert await rust_custody_backend.refresh_rust_custody("pool", vault)
    assert vault._rpc_client is client
    assert not vault._sealed
    assert vault.events == ["lock", ("attach", client)]


@pytest.mark.asyncio
async def test_refresh_enforces_operator_seal_on_pool_and_api(monkeypatch):
    """A sealed durable decision seals the pool inside the orchestration lock.

    The daemon seal now belongs to ``refresh_rust_custody_generation``; this
    adapter only has to seal its own API view when no client comes back.
    """
    vault = FakeVault()
    pool = FakePool()

    async def sealed_decision(candidate_pool, *, session_factory):
        await candidate_pool.seal_all()
        return None

    _patch_generation_refresh(monkeypatch, sealed_decision)

    assert not await rust_custody_backend.refresh_rust_custody(pool, vault)
    assert pool.events == ["seal-all"]
    assert vault._rpc_client is None
    assert vault._sealed
    assert vault.events == ["lock", "detach", "seal"]


@pytest.mark.asyncio
async def test_refresh_stays_sealed_when_no_generation_exists(monkeypatch):
    vault = FakeVault()

    async def repair(*_args, **_kwargs):
        return None

    _patch_generation_refresh(monkeypatch, repair)

    assert not await rust_custody_backend.refresh_rust_custody("pool", vault)
    assert vault._rpc_client is None
    assert vault._sealed
    assert vault.events == ["lock", "detach", "seal"]
