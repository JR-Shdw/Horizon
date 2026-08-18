"""Fixed-slot Rust custodian pool orchestration."""

import pathlib
import re
import weakref

import pytest
from api.app import cluster_rpc, cluster_setup


class FakeCustodianClient:
    behaviors: dict[str, dict[str, object]] = {}
    instances: dict[str, "FakeCustodianClient"] = {}

    def __init__(self, socket_name: str, control_token_file: str):
        self.socket_name = socket_name
        self.control_token_file = control_token_file
        self.calls: list[tuple[str, dict]] = []
        self.instances[socket_name] = self

    async def call(self, op: str, args: dict):
        self.calls.append((op, args))
        return self._result(op)

    async def call_control(self, op: str, args: dict):
        self.calls.append((op, args))
        return self._result(op)

    def _result(self, op: str):
        result = self.behaviors.get(self.socket_name, {}).get(op)
        if isinstance(result, Exception):
            raise result
        return result


class FakeOpaqueShare:
    def __init__(
        self,
        slot: int,
        outcome: str = "installed",
        prepare_outcome: str = "prepared",
    ):
        self.x = slot
        self.outcome = outcome
        self.prepare_outcome = prepare_outcome
        self.calls: list[tuple] = []
        self.prepare_calls: list[tuple] = []

    def install_into_custodian(self, *arguments):
        self.calls.append(arguments)
        return self.outcome

    def prepare_into_custodian(self, *arguments):
        self.prepare_calls.append(arguments)
        return self.prepare_outcome


class FakeVaultBundle:
    def __init__(self):
        self.bundle = bytearray(range(160))
        self.exports = 0

    def export_subkeys_for_shamir(self):
        self.exports += 1
        return self.bundle


@pytest.fixture
def fake_clients(monkeypatch):
    FakeCustodianClient.behaviors = {}
    FakeCustodianClient.instances = {}
    monkeypatch.setattr(cluster_rpc, "CustodianRpcClient", FakeCustodianClient)
    return FakeCustodianClient


def test_pool_requires_contiguous_strong_topology(fake_clients):
    with pytest.raises(ValueError, match="contiguous"):
        cluster_rpc.CustodianPoolController({1: "one", 3: "three"}, "token", 2)
    with pytest.raises(ValueError, match="at least three"):
        cluster_rpc.CustodianPoolController({1: "one", 2: "two"}, "token", 2)
    with pytest.raises(ValueError, match="between 2"):
        cluster_rpc.CustodianPoolController(
            {1: "one", 2: "two", 3: "three"}, "token", 1
        )


@pytest.mark.asyncio
async def test_pool_installs_complete_opaque_generation_without_share_bytes(
    fake_clients,
):
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "/run/private.token", 2
    )
    shares = {1: FakeOpaqueShare(1), 2: FakeOpaqueShare(2), 3: FakeOpaqueShare(3)}

    assert await controller.install_shares(shares, generation=12) == {
        1: "installed",
        2: "installed",
        3: "installed",
    }
    for slot, share in shares.items():
        assert share.calls == [
            (
                {1: "one", 2: "two", 3: "three"}[slot],
                "/run/private.token",
                12,
                2,
                3,
            )
        ]


@pytest.mark.asyncio
async def test_pool_rejects_incomplete_or_misdirected_opaque_shares(fake_clients):
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "token", 2
    )
    with pytest.raises(ValueError, match="cover every"):
        await controller.install_shares({1: FakeOpaqueShare(1)}, generation=1)
    with pytest.raises(ValueError, match="coordinate"):
        await controller.install_shares(
            {1: FakeOpaqueShare(2), 2: FakeOpaqueShare(2), 3: FakeOpaqueShare(3)},
            generation=1,
        )


@pytest.mark.asyncio
async def test_pool_prepares_complete_opaque_generation_without_share_bytes(
    fake_clients,
):
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "/run/private.token", 2
    )
    shares = {
        1: FakeOpaqueShare(1),
        2: FakeOpaqueShare(2, prepare_outcome="already-prepared"),
        3: FakeOpaqueShare(3, prepare_outcome="already-committed"),
    }

    assert await controller.prepare_shares(shares, generation=13) == {
        1: "prepared",
        2: "already-prepared",
        3: "already-committed",
    }
    for slot, share in shares.items():
        assert share.prepare_calls == [
            (
                {1: "one", 2: "two", 3: "three"}[slot],
                "/run/private.token",
                13,
                2,
                3,
            )
        ]


@pytest.mark.asyncio
async def test_provision_wipes_bundle_before_install_and_drops_local_shares():
    vault = FakeVaultBundle()
    generated = [FakeOpaqueShare(1), FakeOpaqueShare(2), FakeOpaqueShare(3)]
    share_refs = [weakref.ref(share) for share in generated]
    events = []

    class Pool:
        async def share_statuses(self):
            return {slot: {"generation": None} for slot in range(1, 4)}

        async def install_shares(self, shares, generation):
            assert vault.bundle == bytearray(160)
            events.append(("install", sorted(shares), generation))

        async def unseal(self):
            assert all(reference() is None for reference in share_refs)
            events.append(("unseal",))
            return "active-client"

    def split_opaque(bundle, threshold, slots):
        assert bundle is vault.bundle
        assert (threshold, slots) == (2, 3)
        return generated

    assert (
        await cluster_setup.provision_rust_custodian_pool(
            vault,
            Pool(),
            generation=14,
            threshold=2,
            slots=3,
            split_opaque=split_opaque,
        )
        == "active-client"
    )
    assert generated == []
    assert events == [("install", [1, 2, 3], 14), ("unseal",)]


@pytest.mark.asyncio
async def test_provision_wipes_bundle_when_native_split_fails():
    vault = FakeVaultBundle()

    def split_failure(_bundle, _threshold, _slots):
        raise RuntimeError("split failed")

    class EmptyPool:
        async def share_statuses(self):
            return {slot: {"generation": None} for slot in range(1, 4)}

    with pytest.raises(RuntimeError, match="split failed"):
        await cluster_setup.provision_rust_custodian_pool(
            vault,
            EmptyPool(),
            generation=1,
            threshold=2,
            slots=3,
            split_opaque=split_failure,
        )
    assert vault.bundle == bytearray(160)


@pytest.mark.asyncio
async def test_provision_refuses_nonempty_pool_before_exporting_keys():
    vault = FakeVaultBundle()

    class NonemptyPool:
        async def share_statuses(self):
            return {
                1: {"generation": 4},
                2: {"generation": None},
                3: {"generation": None},
            }

    with pytest.raises(RuntimeError, match="requires every share slot empty"):
        await cluster_setup.provision_rust_custodian_pool(
            vault,
            NonemptyPool(),
            generation=5,
            threshold=2,
            slots=3,
            split_opaque=lambda *_: pytest.fail("split must not run"),
        )
    assert vault.exports == 0


@pytest.mark.asyncio
async def test_provision_rolls_back_partial_install_before_dropping_shares():
    vault = FakeVaultBundle()
    generated = [FakeOpaqueShare(1), FakeOpaqueShare(2), FakeOpaqueShare(3)]
    share_refs = [weakref.ref(share) for share in generated]
    events = []

    class FailingPool:
        async def share_statuses(self):
            return {slot: {"generation": None} for slot in range(1, 4)}

        async def install_shares(self, _shares, _generation):
            events.append("install")
            raise cluster_rpc.CustodianPoolUnavailable("slot 2 offline")

        async def clear_shares_all(self):
            assert any(reference() is not None for reference in share_refs)
            events.append("rollback")

    with pytest.raises(cluster_rpc.CustodianPoolUnavailable, match="slot 2 offline"):
        await cluster_setup.provision_rust_custodian_pool(
            vault,
            FailingPool(),
            generation=3,
            threshold=2,
            slots=3,
            split_opaque=lambda *_: generated,
        )
    assert generated == []
    assert all(reference() is None for reference in share_refs)
    assert events == ["install", "rollback"]


@pytest.mark.asyncio
async def test_pool_uses_authenticated_donor_fallback_and_selects_coordinator(
    fake_clients,
):
    fake_clients.behaviors = {
        "one": {"unseal": {"generation": 8, "state": "already-unsealed"}},
        "two": {"share_contribution": cluster_rpc.MasterUnreachable("offline")},
        "three": {"share_contribution": "encrypted-envelope"},
    }
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "/run/private.token", 2
    )

    selected = await controller.unseal(preferred_slot=1, generation=8)

    assert selected is fake_clients.instances["one"]
    assert controller.active_slot == 1
    assert controller.active_client is selected
    assert fake_clients.instances["three"].calls == [
        ("share_contribution", {"recipient_slot": 1, "generation": 8})
    ]
    assert fake_clients.instances["one"].calls == [
        ("unseal", {"contributions": ["encrypted-envelope"], "generation": 8})
    ]
    assert all(
        client.control_token_file == "/run/private.token"
        for client in fake_clients.instances.values()
    )


@pytest.mark.asyncio
async def test_pool_rejects_invalid_status_and_incomplete_quorum(fake_clients):
    fake_clients.behaviors = {
        "one": {"status": "not-an-object"},
        "two": {"share_contribution": cluster_rpc.MasterUnreachable("offline")},
        "three": {"share_contribution": cluster_rpc.RpcError("sealed")},
    }
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "token", 2
    )
    with pytest.raises(cluster_rpc.CustodianPoolUnavailable, match="invalid status"):
        await controller.statuses()
    with pytest.raises(
        cluster_rpc.CustodianPoolUnavailable, match="quorum unavailable"
    ):
        await controller.unseal(preferred_slot=1)
    assert controller.active_slot is None


@pytest.mark.asyncio
async def test_pool_availability_status_keeps_failed_slots_visible(fake_clients):
    fake_clients.behaviors = {
        "one": {"status": {"state": "unsealed", "generation": 4}},
        "two": {"status": cluster_rpc.MasterUnreachable("offline")},
        "three": {"status": "invalid"},
    }
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "token", 2
    )

    assert await controller.availability_statuses() == {
        1: {"state": "unsealed", "generation": 4},
        2: None,
        3: None,
    }


@pytest.mark.asyncio
async def test_pool_generation_transitions_attempt_every_slot(fake_clients):
    fake_clients.behaviors = {
        "one": {
            "commit_share": "committed",
            "rollback_share": "rolled-back",
            "finalize_share": "finalized",
        },
        "two": {
            "commit_share": cluster_rpc.MasterUnreachable("offline"),
            "rollback_share": "already-rolled-back",
            "finalize_share": "already-finalized",
        },
        "three": {
            "commit_share": "already-committed",
            "rollback_share": "rolled-back",
            "finalize_share": "finalized",
        },
    }
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "token", 2
    )

    with pytest.raises(cluster_rpc.CustodianPoolUnavailable, match="slot 2"):
        await controller.commit_generation_all(14)
    assert all(
        ("commit_share", {"generation": 14}) in client.calls
        for client in fake_clients.instances.values()
    )
    assert await controller.rollback_generation_all(14) == {
        1: "rolled-back",
        2: "already-rolled-back",
        3: "rolled-back",
    }
    assert await controller.finalize_generation_all(14) == {
        1: "finalized",
        2: "already-finalized",
        3: "finalized",
    }


@pytest.mark.asyncio
async def test_pool_relays_complete_native_reshare_without_plaintext(fake_clients):
    fake_clients.behaviors = {
        "one": {
            "generate_reshare": {
                "generation": 15,
                "deliveries": [
                    {"slot": 2, "envelope": "encrypted-for-two"},
                    {"slot": 3, "envelope": "encrypted-for-three"},
                ],
            }
        },
        "two": {"accept_reshare": "prepared"},
        "three": {"accept_reshare": "already-prepared"},
    }
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "token", 2
    )
    controller._active_slot = 1

    assert await controller.prepare_native_reshare(15) == {
        1: "prepared-or-cached",
        2: "prepared",
        3: "already-prepared",
    }
    assert fake_clients.instances["one"].calls == [
        ("generate_reshare", {"generation": 15})
    ]
    assert fake_clients.instances["two"].calls == [
        (
            "accept_reshare",
            {"envelope": "encrypted-for-two", "generation": 15},
        )
    ]
    assert fake_clients.instances["three"].calls == [
        (
            "accept_reshare",
            {"envelope": "encrypted-for-three", "generation": 15},
        )
    ]


@pytest.mark.asyncio
async def test_pool_native_reshare_attempts_every_recipient(fake_clients):
    fake_clients.behaviors = {
        "one": {
            "generate_reshare": {
                "generation": 16,
                "deliveries": [
                    {"slot": 2, "envelope": "two"},
                    {"slot": 3, "envelope": "three"},
                ],
            }
        },
        "two": {"accept_reshare": cluster_rpc.MasterUnreachable("offline")},
        "three": {"accept_reshare": "prepared"},
    }
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "token", 2
    )
    controller._active_slot = 1

    with pytest.raises(cluster_rpc.CustodianPoolUnavailable, match="slot 2"):
        await controller.prepare_native_reshare(16)
    assert fake_clients.instances["three"].calls == [
        ("accept_reshare", {"envelope": "three", "generation": 16})
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "deliveries",
    [
        [{"slot": 2, "envelope": "two"}],
        [
            {"slot": 2, "envelope": "two"},
            {"slot": 2, "envelope": "duplicate"},
            {"slot": 3, "envelope": "three"},
        ],
        [
            {"slot": 1, "envelope": "coordinator"},
            {"slot": 2, "envelope": "two"},
            {"slot": 3, "envelope": "three"},
        ],
    ],
)
async def test_pool_rejects_invalid_native_reshare_before_relay(
    fake_clients, deliveries
):
    fake_clients.behaviors = {
        "one": {
            "generate_reshare": {
                "generation": 17,
                "deliveries": deliveries,
            }
        }
    }
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "token", 2
    )
    controller._active_slot = 1

    with pytest.raises(cluster_rpc.CustodianPoolUnavailable, match="deliver"):
        await controller.prepare_native_reshare(17)
    assert fake_clients.instances["two"].calls == []
    assert fake_clients.instances["three"].calls == []


@pytest.mark.asyncio
async def test_pool_validates_share_coordinates_and_rolls_back_every_slot(fake_clients):
    fake_clients.behaviors = {
        "one": {"share_status": {"slot": 1, "generation": None}, "clear_share": ""},
        "two": {"share_status": {"slot": 2, "generation": 7}, "clear_share": ""},
        "three": {
            "share_status": {"slot": 3, "generation": 7},
            "clear_share": "",
        },
    }
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "token", 2
    )
    statuses = await controller.share_statuses()
    assert statuses[1]["generation"] is None
    assert statuses[2]["generation"] == 7

    await controller.clear_shares_all()

    assert all(
        ("clear_share", {}) in client.calls
        for client in fake_clients.instances.values()
    )


@pytest.mark.asyncio
async def test_pool_seal_attempts_every_slot_and_drops_active_selection(fake_clients):
    fake_clients.behaviors = {
        "one": {"seal": ""},
        "two": {"seal": cluster_rpc.MasterUnreachable("offline")},
        "three": {"seal": ""},
    }
    controller = cluster_rpc.CustodianPoolController(
        {1: "one", 2: "two", 3: "three"}, "token", 2
    )
    controller._active_slot = 1

    with pytest.raises(cluster_rpc.CustodianPoolUnavailable, match="slot 2"):
        await controller.seal_all()

    assert controller.active_slot is None
    assert all(
        ("seal", {}) in client.calls for client in fake_clients.instances.values()
    )


def _rust_gated_control_operations() -> set[str]:
    """The operations the daemon itself refuses without a control capability.

    Parsed from the Rust source rather than restated here: a hand-copied list
    would drift exactly the way the two sides already drifted once.
    """
    source = (
        pathlib.Path(__file__).resolve().parents[1]
        / "api"
        / "rust"
        / "custodian"
        / "src"
        / "main.rs"
    ).read_text(encoding="utf-8")
    start = source.index("fn dispatch_operation(")
    gate = source.index("if matches!(", start)
    end = source.index(") && !control_authorized", gate)
    return set(re.findall(r'"([a-z_]+)"', source[gate:end]))


def test_control_op_allow_list_matches_the_daemon():
    """A control op the client does not know is unreachable, not just unrouted.

    ``call_control`` rejects anything outside its own frozenset before a byte
    reaches the socket, so an operation the daemon gates but the client omits
    can never be called at all. Every pool unit test uses a fake client, which
    is precisely why this has to be asserted against the real source.
    """
    assert cluster_rpc._CUSTODIAN_CONTROL_OPS == _rust_gated_control_operations()
