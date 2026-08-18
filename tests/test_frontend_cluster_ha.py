"""Focused behavioral checks for the provider-neutral HA tab.

The frontend is dependency-free browser JavaScript, so these tests execute the
view in Node's built-in VM instead of adding a JS test framework to the image.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLUSTER_JS = ROOT / "frontend/js/views/cluster.js"
STYLE_CSS = ROOT / "frontend/css/style.css"


NODE_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');

const fixtures = JSON.parse(fs.readFileSync(0, 'utf8'));
const calls = [];
const timers = [];
const context = {
  console,
  Promise,
  Map,
  Set,
  Date,
  Number,
  String,
  encodeURIComponent,
  document: { getElementById: () => null },
  clearInterval: () => {},
  setInterval: (callback, delay) => {
    timers.push({ callback, delay });
    return timers.length;
  },
  api: async (method, path) => {
    calls.push([method, path]);
    if (!(path in fixtures)) throw new Error(`missing fixture: ${path}`);
    return fixtures[path];
  },
  esc: value => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;'),
  isSealed: () => false,
  sealedHtml: () => '',
  timeFromNow: value => String(value),
  timeAgo: value => String(value),
  renderPagination: () => '',
  confirmType: async () => false,
  toast: () => {},
};
context.window = context;
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);

(async () => {
  const result = await vm.runInContext(`(async () => {
    _clusterTab = 'ha';
    const html = await _renderHaTab();
    return {
      html,
      unconfiguredHtml: renderDatabaseHaSection({
        status: 'fulfilled',
        value: {
          components: {
            database_ha: {
              state: 'grey',
              reason: 'database HA supervision disabled',
              provider: 'none',
            },
          },
        },
      }),
      statusHtml: {
        green: _haStatusIndicator('green', 'ok'),
        orange: _haStatusIndicator('orange', 'recovering'),
        red: _haStatusIndicator('red', 'unsafe'),
        grey: _haStatusIndicator('grey', 'not configured'),
      },
    };
  })()`, context);
  result.calls = calls;
  result.timerDelays = timers.map(timer => timer.delay);
  process.stdout.write(JSON.stringify(result));
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
"""


def _fixtures():
    return {
        "/cluster/ha": {
            "cluster_id": "cluster-12345678",
            "cluster_version": 4,
            "cluster_min_compatible_version": 3,
            "primary_uuid": "primary-12345678",
            "ha_loaded": True,
            "uuid_ip_conflicts_total": 0,
            "nodes": [
                {
                    "node_uuid": "primary-12345678",
                    "source_ip": "192.0.2.10",
                    "ha_state": "primary",
                    "quarantine_until": None,
                    "last_heartbeat": None,
                    "cluster_version": 4,
                    "cert_not_after": None,
                    "cert_fingerprint": "abcdef1234567890",
                }
            ],
        },
        "/cluster": {
            "this_host": "app-a",
            "hosts": {
                "app-a": {
                    "master": {"pid": 101, "age_sec": 0.5},
                    "followers": [
                        {
                            "pid": 102,
                            "role": "follower",
                            "status": "ready",
                            "age_sec": 0.7,
                        }
                    ],
                }
            },
            "held_cluster_locks": [],
        },
        "/cluster/health": {
            "overall": "green",
            "ready": True,
            "components": {
                "database_ha": {
                    "state": "green",
                    "reason": "pgha leader + 3/3 healthy",
                    "provider": "pgha",
                    "leader": "db-a",
                    "leaders": 1,
                    "members": 3,
                    "running": 3,
                    "quorum": True,
                    "vip_owners": ["db-a"],
                    "agents_reporting": 3,
                    "status_max_age_seconds": 15,
                    "leader_timeline": None,
                    "max_replica_lag_bytes": 512,
                    "lag_threshold_bytes": 1024,
                    "replica_lags": {"db-b": 0, "db-c": 512},
                    "lagging_members": [],
                    "unknown_lag_members": [],
                    "non_streaming_replicas": [],
                    "timeline_mismatch_members": [],
                    "stale_agents": [],
                    "unreachable_endpoints": [],
                    "duplicate_agents": [],
                }
            },
        },
    }


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is not installed")
def test_ha_tab_fetches_and_renders_all_three_ha_layers():
    proc = subprocess.run(
        ["node", "-e", NODE_HARNESS, str(CLUSTER_JS)],
        input=json.dumps(_fixtures()),
        text=True,
        capture_output=True,
        check=True,
    )
    result = json.loads(proc.stdout)
    html = result["html"]

    assert result["calls"] == [
        ["GET", "/cluster/ha"],
        ["GET", "/cluster"],
        ["GET", "/cluster/health"],
    ]
    assert result["timerDelays"] == [5000]
    assert html.count('id="cluster-ha-section"') == 1
    assert "Application HA primary" in html
    assert "APP PRIMARY" in html
    assert "Database HA &amp; Replication" in html
    assert "Database leader" in html and "db-a" in html
    assert "Write VIP owner" in html
    assert "db-c" in html and "512 B" in html
    assert "LOCAL CRYPTO MASTER" in html
    assert "Cluster Locks Held" in html
    assert "Unknown / unconfigured (black)" in result["unconfiguredHtml"]
    assert "not reported" in result["unconfiguredHtml"]
    assert "undefined" not in result["unconfiguredHtml"]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is not installed")
def test_ha_status_dots_always_include_visible_state_text():
    proc = subprocess.run(
        ["node", "-e", NODE_HARNESS, str(CLUSTER_JS)],
        input=json.dumps(_fixtures()),
        text=True,
        capture_output=True,
        check=True,
    )
    statuses = json.loads(proc.stdout)["statusHtml"]

    assert "ha-status-dot green" in statuses["green"]
    assert "Healthy (green)" in statuses["green"]
    assert "ha-status-dot orange" in statuses["orange"]
    assert "Degraded (orange)" in statuses["orange"]
    assert "ha-status-dot red" in statuses["red"]
    assert "Unsafe (red)" in statuses["red"]
    assert "ha-status-dot black" in statuses["grey"]
    assert "Unknown / unconfigured (black)" in statuses["grey"]
    assert all('aria-hidden="true"' in html for html in statuses.values())


def test_ha_dashboard_has_distinct_non_recursive_renderers_and_dot_styles():
    source = CLUSTER_JS.read_text()
    css = STYLE_CSS.read_text()

    assert source.count("function renderHaDashboard(") == 1
    assert source.count("function renderMembershipSection(") == 1
    assert "function renderHaSection(" not in source
    for state in ("green", "orange", "red", "black"):
        assert f".ha-status-dot.{state}" in css
