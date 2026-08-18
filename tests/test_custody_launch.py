"""Which shape the custodian pool comes up with.

Getting this wrong is not a degraded pool, it is a pool holding no shares for
the shape it launched, which stops the API from starting at all.
"""

from api.app.custody_launch import resolve_launch_topology


def _resolve(**kwargs):
    base = {
        "phase": "stable",
        "active_generation": 7,
        "durable": (2, 3),
        "configured": (2, 3),
        "target": None,
    }
    return resolve_launch_topology(**{**base, **kwargs})


def test_first_boot_obeys_the_configuration():
    # Nothing is held yet, so the operator's shape is free to take.
    decided = _resolve(active_generation=None, configured=(3, 5), durable=(2, 3))
    assert (decided.threshold, decided.slots) == (3, 5)


def test_a_stable_pool_launches_what_it_actually_holds():
    # The configuration has moved ahead. Obeying it would launch five slots
    # holding nothing; the change has to be prepared by the running quorum
    # first, which means coming up as the shape that owns the shares.
    decided = _resolve(configured=(3, 5), durable=(2, 3))
    assert (decided.threshold, decided.slots) == (2, 3)
    assert "durable" in decided.reason


def test_a_prepared_change_rolls_forward_while_it_is_still_wanted():
    decided = _resolve(
        phase="resharding", durable=(2, 3), configured=(3, 5), target=(3, 5)
    )
    assert (decided.threshold, decided.slots) == (3, 5)
    assert "forward" in decided.reason


def test_putting_the_environment_back_still_aborts_a_prepared_change():
    # The abort path is the reason the configuration keeps a say at all.
    decided = _resolve(
        phase="resharding", durable=(2, 3), configured=(2, 3), target=(3, 5)
    )
    assert (decided.threshold, decided.slots) == (2, 3)
    assert "aborting" in decided.reason


def test_a_third_shape_during_a_change_aborts_rather_than_inventing_one():
    # Neither current nor target: launching what was asked would strand the
    # pool, so drop the change and let the operator try again from stable.
    decided = _resolve(
        phase="resharding", durable=(2, 3), configured=(4, 7), target=(3, 5)
    )
    assert (decided.threshold, decided.slots) == (2, 3)


def test_a_change_recorded_without_envelopes_launches_the_durable_shape():
    # begin_ died before recording; there is nothing to roll forward into.
    decided = _resolve(
        phase="resharding", durable=(2, 3), configured=(3, 5), target=None
    )
    assert (decided.threshold, decided.slots) == (2, 3)


def test_an_unchanged_configuration_is_simply_the_durable_shape():
    decided = _resolve(configured=(3, 5), durable=(3, 5))
    assert (decided.threshold, decided.slots) == (3, 5)
