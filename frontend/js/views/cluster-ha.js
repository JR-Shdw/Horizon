// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* HA data orchestration and production-readiness rendering.
 *
 * The RBAC/LDAP cluster view owns the tab state. This file owns the four HA
 * requests and their refresh lifecycle so operational logic does not grow in
 * the already large cluster.js view.
 */
'use strict';

async function _loadHaDashboard() {
  return Promise.allSettled([
    api('GET', '/cluster/ha'),
    api('GET', '/cluster'),
    api('GET', '/cluster/health'),
    api('GET', '/cluster/preflight?live=false'),
  ]);
}

async function _renderHaTab() {
  const results = await _loadHaDashboard();

  if (window._clusterTopologyTimer) clearInterval(window._clusterTopologyTimer);
  window._clusterTopologyTimer = setInterval(async () => {
    const slot = document.getElementById('cluster-ha-section');
    if (!slot || _clusterTab !== 'ha') {
      clearInterval(window._clusterTopologyTimer);
      window._clusterTopologyTimer = null;
      return;
    }
    try {
      const refreshed = await _loadHaDashboard();
      // outerHTML detaches `slot`, so re-query to restore table scroll.
      const scroll = captureTableScroll(slot);
      slot.outerHTML = renderHaDashboard(...refreshed);
      restoreTableScroll(document.getElementById('cluster-ha-section'), scroll);
    } catch (_) { /* keep the last successful render */ }
  }, 5000);

  return renderHaDashboard(...results);
}

function renderHaDashboard(haRes, topoRes, healthRes, preflightRes) {
  let h = '<div id="cluster-ha-section">';
  h += renderHaPreflightSection(preflightRes);
  h += renderMembershipSection(haRes);
  h += renderDatabaseHaSection(healthRes);
  h += renderTopologySection(topoRes);
  h += '</div>';
  return h;
}

function renderHaPreflightSection(preflightRes) {
  let h = `<section id="cluster-preflight-section">
    <div class="row-inline">
      <h4 class="section-subtitle">Production HA Readiness</h4>
      <button class="btn small secondary" data-action="_runHaLivePreflight">Run live mTLS check</button>
    </div>`;

  if (preflightRes.status === 'rejected') {
    const error = preflightRes.reason || {};
    return h + `<div class="error small">${esc(error.message || 'Failed to load HA preflight')}</div></section>`;
  }

  const result = preflightRes.value || {};
  const overall = String(result.overall || 'fail');
  const ready = result.ready === true;
  const liveVerified = result.live_mtls_requested === true;
  const tagClass = ready ? 'tag-ok good' : (overall === 'warn' ? 'tag-warn neutral' : 'tag-warn bad');
  h += `<div class="card">
    <div class="row-inline">
      <span class="tag ${tagClass}">${ready ? (liveVerified ? 'READY' : 'STATIC READY') : 'NOT READY'}</span>
      <span class="muted small">${ready
        ? (liveVerified
          ? 'All blocking HA checks, including live mTLS, passed.'
          : 'Static blocking checks passed; run the live mTLS check.')
        : `${(result.failed_checks || []).length} blocking check(s) failed.`}</span>
    </div>
  </div>`;

  const checks = result.checks || [];
  if (!checks.length) {
    return h + '<div class="empty small">No preflight checks were returned.</div></section>';
  }
  h += '<table class="table small"><thead><tr><th>Check</th><th>Status</th><th>Reason</th><th>Action</th></tr></thead><tbody>';
  for (const check of checks) {
    const status = String(check.status || 'fail');
    const statusClass = status === 'pass' ? 'tag-ok good' : (status === 'warn' ? 'tag-warn neutral' : 'tag-warn bad');
    h += `<tr class="${status === 'fail' ? 'row-warn' : ''}">
      <td><strong>${esc(check.label || check.id)}</strong><br><code>${esc(check.id)}</code></td>
      <td><span class="tag ${statusClass}">${esc(status.toUpperCase())}</span></td>
      <td>${esc(check.reason || '')}</td>
      <td>${esc(check.remediation || '-')}</td>
    </tr>`;
  }
  return h + '</tbody></table></section>';
}

window._runHaLivePreflight = async function () {
  const button = document.querySelector('[data-action="_runHaLivePreflight"]');
  if (button) button.disabled = true;
  try {
    const result = await api('GET', '/cluster/preflight?live=true');
    const slot = document.getElementById('cluster-preflight-section');
    if (slot) {
      slot.outerHTML = renderHaPreflightSection({status: 'fulfilled', value: result});
    }
    toast(result.ready ? 'HA live preflight passed' : 'HA live preflight found blocking checks', result.ready);
  } catch (error) {
    toast(error.message, false);
  } finally {
    const current = document.querySelector('[data-action="_runHaLivePreflight"]');
    if (current) current.disabled = false;
  }
};
