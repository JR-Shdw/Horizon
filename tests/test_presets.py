"""The shipped sizing tiers have to be runnable as written.

install-container.sh sources these straight into the environment, so a preset is
not documentation: it is the configuration a fresh deployment boots with. A
tier that names an unrunnable custody shape, or budgets less memory than the
boot guard requires, fails on the operator's first unseal.
"""

import pathlib

import pytest
from api.app.mem_hardening import required_memory_mb

PRESETS = pathlib.Path(__file__).resolve().parents[1] / "tools" / "presets"
VALID_SLOTS = {3, 5, 7, 9}
# The ladder: custody quorum grows with the tier, workers hold no shares.
EXPECTED_SLOTS = {"home": None, "smb": 5, "heavy": 7, "super-heavy": 9}


def _load(tier: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (PRESETS / f"{tier}.env").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        values[key] = value
    return values


def _megabytes(value: str) -> int:
    value = value.strip().upper()
    if value.endswith("G"):
        return int(float(value[:-1]) * 1024)
    return int(value.rstrip("M"))


@pytest.mark.parametrize("tier", sorted(EXPECTED_SLOTS))
def test_every_tier_declares_the_agreed_custody_shape(tier):
    values = _load(tier)
    slots = EXPECTED_SLOTS[tier]
    if slots is None:
        # home is a single process: no follower to delegate to and no peer to
        # reconstruct from, so a custodian pool would add processes without
        # adding compartmentation -- and would put the vault behind share
        # state that no master password can recover.
        assert values.get("RHORIZON_CUSTODY_BACKEND", "python") == "python"
        assert values.get("RHORIZON_CUSTODY_MODE", "embedded") == "embedded"
        assert values["RHORIZON_WORKERS"] == "1"
        return
    assert values["RHORIZON_CUSTODY_BACKEND"] == "rust"
    # rust custody is only defined in separated mode; the settings validator
    # refuses the combination, so a preset that got this wrong would not boot.
    assert values["RHORIZON_CUSTODY_MODE"] == "separated"
    assert int(values["RHORIZON_RUST_CUSTODIAN_SLOTS"]) == slots


@pytest.mark.parametrize("tier", sorted(EXPECTED_SLOTS))
def test_every_tier_names_a_launchable_shape(tier):
    values = _load(tier)
    declared = values.get("RHORIZON_RUST_CUSTODIAN_SLOTS")
    if declared is None:
        return
    # Enforced in three places -- the launcher, the settings validator and the
    # pool controller -- so a preset outside the set is a refusal to start.
    assert int(declared) in VALID_SLOTS
    # Odd, so the majority the threshold defaults to is well defined.
    assert int(declared) % 2 == 1


@pytest.mark.parametrize("tier", ("smb", "heavy", "super-heavy"))
def test_rust_tiers_describe_default_share_recovery_honestly(tier):
    source = (PRESETS / f"{tier}.env").read_text()
    assert "Shares are RAM-only with the default state provider" in source
    assert "the master password rebuilds the pool" in source
    assert "master password does not recover it" not in source


@pytest.mark.parametrize("tier", sorted(EXPECTED_SLOTS))
def test_every_tier_budgets_the_memory_its_own_guard_demands(tier):
    values = _load(tier)
    workers = int(values["RHORIZON_WORKERS"])
    slots = int(values.get("RHORIZON_RUST_CUSTODIAN_SLOTS", 0))
    needed = required_memory_mb(workers, slots)
    limit = _megabytes(values["RHORIZON_API_MEM"])
    # Not cosmetic: mlockall wires the Argon2id allocation, so an undersized
    # limit does not run slowly, it OOM-kills the master at unseal.
    assert limit >= needed, (
        f"{tier}: RHORIZON_API_MEM={limit}MB below the {needed}MB the boot "
        f"guard computes for {workers} workers + {slots} custodian slots"
    )
