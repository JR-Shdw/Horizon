"""cluster_health: the no-false-green / no-false-red contract.

These cover the aggregation logic (the part that decides 'ready') with stubbed
probes, so they need no PG. The SQL probes themselves are exercised by the
cluster integration tests + the live /cluster/health endpoint.
"""

import pytest
from api.app import cluster_health as ch
from api.app.cluster_health import Health, probe_node


class _Vault:
    def __init__(self, sealed):
        self.sealed = sealed


def test_probe_node_states():
    assert probe_node(_Vault(sealed=True), False)[0] is Health.ORANGE  # startup
    assert probe_node(_Vault(sealed=False), False)[0] is Health.GREEN
    assert probe_node(_Vault(sealed=False), True)[0] is Health.RED  # quarantined


def _stub(monkeypatch, *, db, node, cluster, database_ha):
    async def _db(_):
        return db, "r"

    def _node(_v, _q):
        return node, "r"

    async def _cluster(_):
        return cluster, "r", {}

    async def _database_ha():
        return database_ha, "r", {}

    monkeypatch.setattr(ch, "probe_database", _db)
    monkeypatch.setattr(ch, "probe_node", _node)
    monkeypatch.setattr(ch, "probe_cluster", _cluster)
    monkeypatch.setattr(ch, "probe_database_ha", _database_ha)


@pytest.mark.asyncio
async def test_all_green_is_ready(monkeypatch):
    _stub(
        monkeypatch,
        db=Health.GREEN,
        node=Health.GREEN,
        cluster=Health.GREEN,
        database_ha=Health.GREEN,
    )
    r = await ch.cluster_health(None, _Vault(False))
    assert r["overall"] == "green" and r["ready"] is True


@pytest.mark.asyncio
async def test_red_dominates_no_false_green(monkeypatch):
    # database red, everything else green -> NOT ready (no masked failure).
    _stub(
        monkeypatch,
        db=Health.RED,
        node=Health.GREEN,
        cluster=Health.GREEN,
        database_ha=Health.GREEN,
    )
    r = await ch.cluster_health(None, _Vault(False))
    assert r["overall"] == "red" and r["ready"] is False


@pytest.mark.asyncio
async def test_orange_blocks_ready(monkeypatch):
    # a joining member (orange cluster) must not read as ready.
    _stub(
        monkeypatch,
        db=Health.GREEN,
        node=Health.GREEN,
        cluster=Health.ORANGE,
        database_ha=Health.GREEN,
    )
    r = await ch.cluster_health(None, _Vault(False))
    assert r["overall"] == "orange" and r["ready"] is False


@pytest.mark.asyncio
async def test_grey_is_never_green_but_does_not_downgrade(monkeypatch):
    # database HA grey (not configured) must not turn a healthy cluster red/orange,
    # and must not itself be reported green.
    _stub(
        monkeypatch,
        db=Health.GREEN,
        node=Health.GREEN,
        cluster=Health.GREEN,
        database_ha=Health.GREY,
    )
    r = await ch.cluster_health(None, _Vault(False))
    assert r["overall"] == "green" and r["ready"] is True
    assert r["components"]["database_ha"]["state"] == "grey"
    assert "patroni" not in r["components"]


@pytest.mark.asyncio
async def test_all_grey_is_grey_not_green(monkeypatch):
    _stub(
        monkeypatch,
        db=Health.GREY,
        node=Health.GREY,
        cluster=Health.GREY,
        database_ha=Health.GREY,
    )
    r = await ch.cluster_health(None, _Vault(False))
    assert r["overall"] == "grey" and r["ready"] is False


# --- probe bodies (the SQL / REST tiers themselves) -------------------------


class _Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Result:
    def __init__(self, one=None, many=None):
        self._one, self._many = one, many

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._many


class _DB:
    """Async DB stub: returns a canned result or raises on execute()."""

    def __init__(self, result=None, exc=None):
        self._result, self._exc = result, exc

    async def execute(self, *a, **k):
        if self._exc is not None:
            raise self._exc
        return self._result


@pytest.mark.asyncio
async def test_probe_database_states():
    assert (await ch.probe_database(_DB(_Result(one=_Row(r=False)))))[0] is Health.GREEN
    assert (await ch.probe_database(_DB(_Result(one=_Row(r=True)))))[0] is Health.ORANGE
    dead = await ch.probe_database(_DB(exc=RuntimeError("boom")))
    assert dead[0] is Health.RED and "unreachable" in dead[1]


@pytest.mark.asyncio
async def test_probe_cluster_grey_when_ha_disabled(monkeypatch):
    monkeypatch.setattr(ch.settings, "cluster_ha_enabled", False)
    h, _r, d = await ch.probe_cluster(_DB())
    assert h is Health.GREY and d == {"members": 0}


@pytest.mark.asyncio
async def test_probe_cluster_states(monkeypatch):
    monkeypatch.setattr(ch.settings, "cluster_ha_enabled", True)

    async def _grade(rows):
        return (await ch.probe_cluster(_DB(_Result(many=rows))))[0]

    assert await _grade([]) is Health.RED  # no members
    assert (
        await _grade([_Row(ha_state="primary", n=1), _Row(ha_state="secondary", n=2)])
        is Health.GREEN
    )
    assert await _grade([_Row(ha_state="primary", n=2)]) is Health.RED  # split-brain
    assert (
        await _grade([_Row(ha_state="primary", n=1), _Row(ha_state="evicted", n=1)])
        is Health.RED  # evicted member
    )
    assert (
        await _grade([_Row(ha_state="primary", n=1), _Row(ha_state="joining", n=1)])
        is Health.ORANGE  # transitional
    )


@pytest.mark.asyncio
async def test_probe_cluster_query_failure_is_red(monkeypatch):
    monkeypatch.setattr(ch.settings, "cluster_ha_enabled", True)
    h, r, _d = await ch.probe_cluster(_DB(exc=RuntimeError("pg down")))
    assert h is Health.RED and "membership query failed" in r


def _patch_httpx(monkeypatch, *, data=None, data_by_url=None, exc=None):
    class _Resp:
        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            if exc is not None:
                raise exc
            payload = data_by_url.get(url) if data_by_url is not None else data
            return _Resp(payload)

    monkeypatch.setattr(ch.httpx, "AsyncClient", lambda *a, **k: _Client())


@pytest.mark.asyncio
async def test_probe_patroni_grey_when_unconfigured(monkeypatch):
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "")
    assert (await ch.probe_patroni())[0] is Health.GREY


@pytest.mark.asyncio
async def test_probe_patroni_states(monkeypatch):
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "http://p1:8008")
    monkeypatch.setattr(ch.settings, "database_ha_max_replica_lag_bytes", 1024)

    def members(*items):
        return {"members": list(items)}

    green = members(
        {"name": "p1", "role": "leader", "state": "running", "timeline": 9},
        {
            "name": "p2",
            "role": "replica",
            "state": "streaming",
            "timeline": 9,
            "lag": 0,
        },
    )
    _patch_httpx(monkeypatch, data=green)
    h, _r, detail = await ch.probe_patroni()
    assert h is Health.GREEN
    assert detail["max_replica_lag_bytes"] == 0

    degraded = members(
        {"name": "p1", "role": "leader", "state": "running", "timeline": 9},
        {"name": "p2", "role": "replica", "state": "stopped", "lag": 0},
    )
    _patch_httpx(monkeypatch, data=degraded)
    assert (await ch.probe_patroni())[0] is Health.ORANGE  # running < members

    _patch_httpx(
        monkeypatch,
        data=members(
            {
                "name": "p2",
                "role": "replica",
                "state": "running",
                "timeline": 9,
                "lag": 0,
            }
        ),
    )
    assert (await ch.probe_patroni())[0] is Health.RED  # no single leader


@pytest.mark.asyncio
async def test_probe_patroni_running_replica_is_not_streaming(monkeypatch):
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "http://p1:8008")
    monkeypatch.setattr(ch.settings, "database_ha_max_replica_lag_bytes", 1024)
    _patch_httpx(
        monkeypatch,
        data={
            "members": [
                {
                    "name": "p1",
                    "role": "leader",
                    "state": "running",
                    "timeline": 9,
                },
                {
                    "name": "stuck",
                    "role": "replica",
                    "state": "running",
                    "timeline": 9,
                    "lag": 0,
                },
            ]
        },
    )
    h, message, detail = await ch.probe_patroni()
    assert h is Health.ORANGE
    assert "not streaming" in message
    assert detail["non_streaming_replicas"] == [{"name": "stuck", "state": "running"}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("replica", "reason"),
    [
        (
            {
                "name": "stale",
                "role": "replica",
                "state": "streaming",
                "timeline": 9,
                "lag": 2048,
            },
            "lag exceeds",
        ),
        (
            {
                "name": "unknown",
                "role": "replica",
                "state": "streaming",
                "timeline": 9,
                "lag": "unknown",
            },
            "lag unknown",
        ),
        (
            {
                "name": "old-timeline",
                "role": "replica",
                "state": "streaming",
                "timeline": 7,
                "lag": 0,
            },
            "timeline differs",
        ),
    ],
)
async def test_probe_patroni_running_replica_must_be_converged(
    monkeypatch, replica, reason
):
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "http://p1:8008")
    # This case asserts the *classification* (lag -> orange), not the
    # debounce. Pin the grace window to 0 so a single sample reports ;
    # the debounce itself is covered in test_cluster_health_lag_grace.py.
    monkeypatch.setattr(ch.settings, "database_ha_lag_grace_secs", 0)
    monkeypatch.setattr(ch.settings, "database_ha_max_replica_lag_bytes", 1024)
    _patch_httpx(
        monkeypatch,
        data={
            "members": [
                {
                    "name": "p1",
                    "role": "leader",
                    "state": "running",
                    "timeline": 9,
                },
                replica,
            ]
        },
    )
    h, message, _detail = await ch.probe_patroni()
    assert h is Health.ORANGE
    assert reason in message


@pytest.mark.asyncio
async def test_probe_patroni_unreachable_is_red(monkeypatch):
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "http://p1:8008")
    _patch_httpx(monkeypatch, exc=RuntimeError("conn refused"))
    assert (await ch.probe_patroni())[0] is Health.RED  # all endpoints failed


def _pgha_report(
    node,
    role,
    *,
    leader="a",
    quorum=True,
    vip=False,
    observed_at=1000.0,
    member_states=None,
):
    return {
        "schema_version": 1,
        "provider": "pgha",
        "node": node,
        "role": role,
        "leader": leader,
        "quorum": quorum,
        "vip_present": vip,
        "observed_at": observed_at,
        "expected_members": 3,
        "member_states": member_states or {},
    }


@pytest.mark.asyncio
async def test_probe_pgha_green(monkeypatch):
    members = {
        "a": {
            "reachable": True,
            "role": "primary",
            "replication_state": "primary",
            "lag_bytes": 0,
        },
        "b": {
            "reachable": True,
            "role": "standby",
            "replication_state": "streaming",
            "lag_bytes": 0,
        },
        "c": {
            "reachable": True,
            "role": "standby",
            "replication_state": "streaming",
            "lag_bytes": 512,
        },
    }
    monkeypatch.setattr(ch.time, "time", lambda: 1001.0)
    monkeypatch.setattr(ch.settings, "database_ha_max_replica_lag_bytes", 1024)
    monkeypatch.setattr(ch.settings, "database_ha_status_max_age_secs", 15)
    _patch_httpx(
        monkeypatch,
        data_by_url={
            "http://a/status": _pgha_report(
                "a", "primary", vip=True, member_states=members
            ),
            "http://b/status": _pgha_report("b", "standby", member_states=members),
            "http://c/status": _pgha_report("c", "standby", member_states=members),
        },
    )
    h, reason, detail = await ch.probe_pgha(["http://a", "http://b", "http://c"])
    assert h is Health.GREEN
    assert "3/3" in reason
    assert detail["provider"] == "pgha"
    assert detail["max_replica_lag_bytes"] == 512
    assert detail["vip_owners"] == ["a"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutate", "expected", "reason"),
    [
        (
            lambda reports: reports["http://b/status"].update(quorum=False),
            Health.RED,
            "quorum absent",
        ),
        (
            lambda reports: reports["http://b/status"].update(observed_at=900.0),
            Health.ORANGE,
            "stale",
        ),
        (
            lambda reports: reports["http://a/status"]["member_states"]["b"].update(
                replication_state="stopped"
            ),
            Health.ORANGE,
            "not streaming",
        ),
    ],
)
async def test_probe_pgha_degraded(monkeypatch, mutate, expected, reason):
    members = {
        "a": {
            "reachable": True,
            "role": "primary",
            "replication_state": "primary",
            "lag_bytes": 0,
        },
        "b": {
            "reachable": True,
            "role": "standby",
            "replication_state": "streaming",
            "lag_bytes": 0,
        },
        "c": {
            "reachable": True,
            "role": "standby",
            "replication_state": "streaming",
            "lag_bytes": 0,
        },
    }
    reports = {
        "http://a/status": _pgha_report(
            "a", "primary", vip=True, member_states=members
        ),
        "http://b/status": _pgha_report("b", "standby", member_states=members),
        "http://c/status": _pgha_report("c", "standby", member_states=members),
    }
    mutate(reports)
    monkeypatch.setattr(ch.time, "time", lambda: 1001.0)
    monkeypatch.setattr(ch.settings, "database_ha_max_replica_lag_bytes", 1024)
    monkeypatch.setattr(ch.settings, "database_ha_status_max_age_secs", 15)
    _patch_httpx(monkeypatch, data_by_url=reports)
    h, message, _detail = await ch.probe_pgha(["http://a", "http://b", "http://c"])
    assert h is expected
    assert reason in message


@pytest.mark.asyncio
async def test_probe_database_ha_auto_selects_provider(monkeypatch):
    monkeypatch.setattr(ch.settings, "database_ha_provider", "auto")
    monkeypatch.setattr(ch.settings, "database_ha_status_urls", "")
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "http://p1")

    async def patroni(urls):
        assert urls == ["http://p1"]
        return Health.GREEN, "patroni", {"provider": "patroni"}

    monkeypatch.setattr(ch, "probe_patroni", patroni)
    assert (await ch.probe_database_ha())[2]["provider"] == "patroni"

    monkeypatch.setattr(ch.settings, "database_ha_status_urls", "http://b1")

    async def pgha(urls):
        assert urls == ["http://b1"]
        return Health.GREEN, "pgha", {"provider": "pgha"}

    monkeypatch.setattr(ch, "probe_pgha", pgha)
    assert (await ch.probe_database_ha())[2]["provider"] == "pgha"


@pytest.mark.asyncio
async def test_pgha_unconfigured_invalid_and_duplicate_reports(monkeypatch):
    monkeypatch.setattr(ch.settings, "database_ha_status_urls", "")
    assert (await ch.probe_pgha())[0] is Health.GREY

    monkeypatch.setattr(ch.time, "time", lambda: 1001.0)
    monkeypatch.setattr(ch.settings, "database_ha_status_max_age_secs", 15)
    _patch_httpx(
        monkeypatch,
        data_by_url={
            "http://a/status": {"provider": "wrong"},
            "http://b/status": {"provider": "pgha", "node": ""},
        },
    )
    assert (await ch.probe_pgha(["http://a", "http://b"]))[0] is Health.RED

    reports = {
        "http://a/status": _pgha_report("a", "primary", observed_at=True),
        "http://b/status": _pgha_report("a", "standby"),
    }
    _patch_httpx(monkeypatch, data_by_url=reports)
    health, reason, detail = await ch.probe_pgha(["http://a", "http://b"])
    assert health is Health.RED
    assert "duplicate" in reason
    assert detail["status_age_seconds"]["a"] is None


def _healthy_pgha_reports():
    members = {
        "a": {"reachable": True, "role": "primary", "lag_bytes": 0},
        "b": {
            "reachable": True,
            "role": "standby",
            "replication_state": "streaming",
            "lag_bytes": 0,
        },
        "c": {
            "reachable": True,
            "role": "standby",
            "replication_state": "streaming",
            "lag_bytes": 0,
        },
    }
    return {
        "http://a/status": _pgha_report(
            "a", "primary", vip=True, member_states=members
        ),
        "http://b/status": _pgha_report("b", "standby", member_states=members),
        "http://c/status": _pgha_report("c", "standby", member_states=members),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutate", "expected", "fragment"),
    [
        (
            lambda r: r["http://b/status"].update(leader="other"),
            Health.RED,
            "consensus",
        ),
        (
            lambda r: r["http://a/status"].update(role="standby"),
            Health.RED,
            "primaries",
        ),
        (
            lambda r: r["http://b/status"].update(vip_present=True),
            Health.RED,
            "VIP owners",
        ),
        (
            lambda r: r["http://a/status"].update(expected_members=2),
            Health.RED,
            "at least 3",
        ),
        (
            lambda r: r["http://a/status"].update(expected_members=4),
            Health.ORANGE,
            "reporting 3/4",
        ),
        (
            lambda r: r["http://a/status"].update(expected_members=True),
            Health.GREEN,
            "3/3",
        ),
        (
            lambda r: r["http://a/status"].update(member_states=None),
            Health.ORANGE,
            "member state",
        ),
        (
            lambda r: r["http://a/status"]["member_states"]["b"].update(
                reachable=False
            ),
            Health.ORANGE,
            "2/3",
        ),
        (
            lambda r: r["http://a/status"]["member_states"]["b"].update(lag_bytes=True),
            Health.ORANGE,
            "lag unknown",
        ),
        (
            lambda r: r["http://a/status"]["member_states"]["b"].update(lag_bytes=2048),
            Health.ORANGE,
            "lag exceeds",
        ),
    ],
)
async def test_pgha_rejects_ambiguous_or_degraded_topologies(
    monkeypatch, mutate, expected, fragment
):
    reports = _healthy_pgha_reports()
    # This case asserts the *classification* (lag -> orange), not the
    # debounce. Pin the grace window to 0 so a single sample reports ;
    # the debounce itself is covered in test_cluster_health_lag_grace.py.
    monkeypatch.setattr(ch.settings, "database_ha_lag_grace_secs", 0)
    mutate(reports)
    monkeypatch.setattr(ch.time, "time", lambda: 1001.0)
    monkeypatch.setattr(ch.settings, "database_ha_status_max_age_secs", 15)
    monkeypatch.setattr(ch.settings, "database_ha_max_replica_lag_bytes", 1024)
    _patch_httpx(monkeypatch, data_by_url=reports)
    health, reason, _detail = await ch.probe_pgha(["http://a", "http://b", "http://c"])
    assert health is expected
    assert fragment in reason


@pytest.mark.asyncio
async def test_database_ha_unconfigured_and_disabled(monkeypatch):
    monkeypatch.setattr(ch.settings, "database_ha_provider", "auto")
    monkeypatch.setattr(ch.settings, "database_ha_status_urls", "")
    monkeypatch.setattr(ch.settings, "patroni_rest_urls", "")
    assert (await ch.probe_database_ha())[2] == {"provider": "unconfigured"}

    monkeypatch.setattr(ch.settings, "database_ha_provider", "none")
    assert (await ch.probe_database_ha())[2] == {"provider": "none"}


@pytest.mark.asyncio
async def test_pgha_transport_failure_is_red(monkeypatch):
    _patch_httpx(monkeypatch, exc=RuntimeError("connection refused"))
    assert (await ch.probe_pgha(["http://a"]))[0] is Health.RED
