"""Where a key-lifecycle request goes, and who may reopen a pool.

Two routes are exercised here. The python one has to ADDRESS the elected
custodian instead of re-dialling until the kernel hands it over; the rust one
has to elect a leader PER NODE, because the pool it repairs is reachable only
over that host's sockets.

The per-node test is the one that matters. Separated custody exists because the
processes serving requests are what die under IO pressure -- so a node that
loses its pool in that moment must be able to bring it back itself. A single
cluster-wide leader means a stressed node waits on a machine that cannot reach
its sockets, which is the failure custody was adopted to prevent.
"""

import asyncio
import contextlib

import pytest
import pytest_asyncio
from api.app import custody_generation as cg
from api.app import custody_routing
from api.app.database import async_session
from sqlalchemy import text


class FakeVault:
    """Enough vault to survive the FOLLOWER path, deliberately.

    A follower that cannot lead falls through to attach_live_rust_coordinator,
    which seals this worker's view when no generation exists. If the fake blew
    up there, the per-node leadership test would "fail on a global lock" for
    the wrong reason -- an AttributeError, not the timeout it claims to
    measure -- and would keep passing after a real regression.
    """

    def __init__(self):
        self._rpc_client = object()
        self._sealed = False

    @property
    def sealed(self) -> bool:
        return self._sealed

    @contextlib.asynccontextmanager
    async def master_transition_lock(self):
        yield

    def detach_rpc_client(self):
        self._rpc_client = None

    def seal(self):
        self._sealed = True


@pytest_asyncio.fixture
async def clean_workers(setup_db):
    async def _wipe():
        async with async_session() as db:
            await db.execute(text("DELETE FROM vault_workers"))
            await db.commit()

    await _wipe()
    yield
    await _wipe()


# --- rust route: leadership is per node ------------------------------------


def test_maintenance_lock_names_the_node(monkeypatch):
    monkeypatch.setattr(cg, "_node_scope", lambda: "node-a")
    assert cg.custody_maintenance_lock().startswith(cg.CUSTODY_MAINTENANCE_LOCK)
    assert cg.custody_maintenance_lock("node-a") != cg.custody_maintenance_lock(
        "node-b"
    )


@pytest.mark.asyncio
async def test_rejects_a_nonpositive_interval():
    with pytest.raises(ValueError, match="positive"):
        await custody_routing.run_custody_routing(
            "pool", FakeVault(), interval_seconds=0
        )


@pytest.mark.asyncio
async def test_one_leader_per_node_and_failover(setup_db, monkeypatch):
    """Within ONE node, exactly one worker leads, and another takes over."""
    monkeypatch.setattr(cg, "_node_scope", lambda: "node-a")
    calls = []
    first_call = asyncio.Event()
    second_leader = asyncio.Event()

    async def refresh(*_args, **_kwargs):
        name = asyncio.current_task().get_name()
        calls.append(name)
        first_call.set()
        if len(set(calls)) > 1:
            second_leader.set()

    from api.app import rust_custody_backend

    monkeypatch.setattr(rust_custody_backend, "refresh_rust_custody", refresh)

    tasks = [
        asyncio.create_task(
            custody_routing.run_custody_routing(
                "pool", FakeVault(), interval_seconds=0.02
            ),
            name=f"routing-{index}",
        )
        for index in range(2)
    ]
    try:
        await asyncio.wait_for(first_call.wait(), timeout=1)
        await asyncio.sleep(0.08)
        assert len(set(calls)) == 1
        leader_name = calls[0]
        leader = next(task for task in tasks if task.get_name() == leader_name)
        leader.cancel()
        await asyncio.gather(leader, return_exceptions=True)
        await asyncio.wait_for(second_leader.wait(), timeout=1)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_two_nodes_each_elect_their_own_leader(setup_db, monkeypatch):
    """THE regression test. Fails whenever the lock goes back to being global.

    Two nodes share one database. Each must run its own maintenance leader,
    because each repairs a pool reachable only over its own sockets. With a
    single cluster-wide lock exactly one of these two ever refreshes, and the
    other node's pool can never be reopened by anyone.
    """
    from api.app import rust_custody_backend

    leaders: set[str] = set()
    both_leading = asyncio.Event()

    async def refresh(*_args, **_kwargs):
        leaders.add(asyncio.current_task().get_name())
        if len(leaders) >= 2:
            both_leading.set()

    monkeypatch.setattr(rust_custody_backend, "refresh_rust_custody", refresh)

    # Each task resolves its own node scope, exactly as two processes on two
    # machines would. Patched ONCE via monkeypatch rather than from inside the
    # tasks: two tasks each saving and restoring the global would have the
    # second restore the first's replacement, leaking a lambda that KeyErrors
    # in every later test that resolves a scope.
    scopes = {"node-a-worker": "node-a", "node-b-worker": "node-b"}

    def scope_of_current_task():
        return scopes.get(asyncio.current_task().get_name(), "node-other")

    monkeypatch.setattr(cg, "_node_scope", scope_of_current_task)

    tasks = [
        asyncio.create_task(
            custody_routing.run_custody_routing(
                "pool", FakeVault(), interval_seconds=0.02
            ),
            name=name,
        )
        for name in ("node-a-worker", "node-b-worker")
    ]
    try:
        await asyncio.wait_for(both_leading.wait(), timeout=5)
        # Both nodes lead simultaneously: that is the point.
        assert leaders == {"node-a-worker", "node-b-worker"}
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


# --- rust route: which custody routes the backend may serve ----------------


def test_rust_route_decision_partitions_every_custody_route():
    """Adding a custody route with no rust policy must fail HERE, not in prod.

    The two sets have to cover custody._CUSTODY_ROUTES exactly and not
    overlap. An uncovered route would fall through to a backend that cannot
    perform it, on the one deployment that enabled rust custody.
    """
    from api.app.custody import _CUSTODY_ROUTES

    served = custody_routing.RUST_CONTROL_ROUTES
    refused = custody_routing.RUST_BLOCKED_ROUTES
    assert served & refused == frozenset()
    assert served | refused == _CUSTODY_ROUTES


def test_rust_route_decision_answers_each_class():
    for method, path in custody_routing.RUST_CONTROL_ROUTES:
        assert custody_routing.rust_route_decision(method, path) == "serve"
    for method, path in custody_routing.RUST_BLOCKED_ROUTES:
        assert custody_routing.rust_route_decision(method, path) == "refuse"
    # A non-custody route is not the middleware's business at all.
    assert (
        custody_routing.rust_route_decision("GET", "/api/v1/vault/status")
        == "not-custody"
    )
    # Method is part of the identity: DELETE /shamir is refused, GET is not a
    # custody route at all.
    assert custody_routing.rust_route_decision("GET", "/api/v1/vault/shamir") == (
        "not-custody"
    )
    assert custody_routing.rust_route_decision("post", "/api/v1/vault/seal") == "serve"


# --- python route: the elected custodian is addressed directly -------------


@pytest.mark.asyncio
async def test_no_socket_when_no_custodian_master_is_registered(clean_workers):
    # Falling back is correct: the caller still has the slower path. Failing
    # would turn a routing hint into an outage.
    assert await custody_routing.elected_custodian_socket(async_session) is None


@pytest.mark.asyncio
async def test_the_elected_custodian_socket_is_returned(clean_workers, monkeypatch):
    from api.app.cluster import get_hostname

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_workers
                    (hostname, pid, worker_state, process_role,
                     http_socket_name, last_heartbeat)
                VALUES (:host, 4242, 'master', 'custodian', :sock, NOW())
            """),
            {"host": get_hostname(), "sock": "/run/rhorizon/custodian-h-2.sock"},
        )
        await db.commit()
    found = await custody_routing.elected_custodian_socket(async_session)
    assert found == "/run/rhorizon/custodian-h-2.sock"


@pytest.mark.asyncio
async def test_a_disposable_api_worker_is_never_routed_to(clean_workers):
    """An API worker holds no key material; addressing it would 403 forever."""
    from api.app.cluster import get_hostname

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_workers
                    (hostname, pid, worker_state, process_role,
                     http_socket_name, last_heartbeat)
                VALUES (:host, 4243, 'master', 'api', :sock, NOW())
            """),
            {"host": get_hostname(), "sock": "/run/rhorizon/should-not-be-used.sock"},
        )
        await db.commit()
    assert await custody_routing.elected_custodian_socket(async_session) is None


@pytest.mark.asyncio
async def test_a_stale_master_row_is_not_routed_to(clean_workers):
    """A custodian that stopped heartbeating is not where the keys are now."""
    from api.app.cluster import get_hostname

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_workers
                    (hostname, pid, worker_state, process_role,
                     http_socket_name, last_heartbeat)
                VALUES (:host, 4244, 'master', 'custodian', :sock,
                        NOW() - INTERVAL '1 hour')
            """),
            {"host": get_hostname(), "sock": "/run/rhorizon/stale.sock"},
        )
        await db.commit()
    assert await custody_routing.elected_custodian_socket(async_session) is None


# --- rust route: a control route must attach before it refuses -------------


class _FakeSessionFactory:
    """A session factory whose sessions do nothing; the reads are patched."""

    def __call__(self):
        return self

    async def __aenter__(self):
        return object()

    async def __aexit__(self, *_exc):
        return False


def _async_return(value):
    async def _call(*_a, **_kw):
        return value

    return _call


def _durable_state(generation):
    class _State:
        active_generation = generation

    return _State()


@pytest.mark.asyncio
async def test_an_attached_worker_proceeds_without_touching_the_pool(monkeypatch):
    from api.app import rust_custody_backend

    async def never(*_a, **_kw):
        raise AssertionError("an attached worker must not re-attach")

    monkeypatch.setattr(rust_custody_backend, "attach_live_rust_coordinator", never)
    await custody_routing.ensure_control_plane(
        "pool", FakeVault(), session_factory=_FakeSessionFactory()
    )

    # An unsealed worker with no RPC client can still serve. Requiring one here
    # made this gate report SEALED on a rotation that works -- it broke six
    # rust rotation tests, all with a false "Vault is sealed".
    unsealed_without_client = FakeVault()
    unsealed_without_client._rpc_client = None
    await custody_routing.ensure_control_plane(
        "pool", unsealed_without_client, session_factory=_FakeSessionFactory()
    )


@pytest.mark.asyncio
async def test_an_operator_seal_is_reported_as_sealed_not_as_lost_quorum(monkeypatch):
    """The distinction matters: one sends the operator to unseal, the other
    sends them to repair a quorum that is not broken."""
    from api.app.vault_state import VaultSealedError

    monkeypatch.setattr(cg, "get_rust_custody_activation", _async_return(False))
    monkeypatch.setattr(cg, "get_custody_generation_state", _async_return(None))
    vault = FakeVault()
    vault._sealed = True
    with pytest.raises(VaultSealedError):
        await custody_routing.ensure_control_plane(
            "pool", vault, session_factory=_FakeSessionFactory()
        )


@pytest.mark.asyncio
async def test_a_detached_worker_attaches_on_demand_then_proceeds(monkeypatch):
    from api.app import rust_custody_backend

    monkeypatch.setattr(cg, "get_rust_custody_activation", _async_return(True))
    monkeypatch.setattr(
        cg, "get_custody_generation_state", _async_return(_durable_state("gen-1"))
    )
    attempts = []

    async def attach(*_a, **_kw):
        attempts.append(1)
        return len(attempts) >= 2  # first tick misses, second succeeds

    monkeypatch.setattr(rust_custody_backend, "attach_live_rust_coordinator", attach)
    vault = FakeVault()
    vault._sealed = True
    await custody_routing.ensure_control_plane(
        "pool", vault, session_factory=_FakeSessionFactory(), delay_secs=0
    )
    assert len(attempts) == 2


@pytest.mark.asyncio
async def test_only_a_genuine_attach_failure_reports_lost_quorum(monkeypatch):
    from api.app import rust_custody_backend

    monkeypatch.setattr(cg, "get_rust_custody_activation", _async_return(True))
    monkeypatch.setattr(
        cg, "get_custody_generation_state", _async_return(_durable_state("gen-1"))
    )

    async def never_attaches(*_a, **_kw):
        raise RuntimeError("slot 3 refused: sealed")

    monkeypatch.setattr(
        rust_custody_backend, "attach_live_rust_coordinator", never_attaches
    )
    vault = FakeVault()
    vault._sealed = True
    with pytest.raises(custody_routing.CustodyQuorumUnavailable) as raised:
        await custody_routing.ensure_control_plane(
            "pool", vault, session_factory=_FakeSessionFactory(), delay_secs=0
        )
    # The daemon detail names slots and must stay out of the exception that
    # reaches the handler; the handler is what decides the body.
    assert "slot 3" not in str(raised.value)


@pytest.mark.asyncio
async def test_zero_attempts_is_a_programming_error():
    with pytest.raises(ValueError, match="at least one attempt"):
        await custody_routing.ensure_control_plane(
            "pool", FakeVault(), session_factory=_FakeSessionFactory(), attempts=0
        )
