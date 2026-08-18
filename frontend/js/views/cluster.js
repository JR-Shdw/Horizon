// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Cluster, four tabs:
 *   - Groups: local RBAC groups (CRUD)
 *   - LDAP:   external auth via LDAP/AD (config + group → permission mappings)
 *   - SSO:    reverse-proxy auth status (env-driven, read-only display)
 *   - HA:     multi-host topology + currently-held cluster locks
 */
'use strict';

let _clusterTab = 'groups'; // 'groups' | 'ldap' | 'sso' | 'ha'
let _groupPage = 0;
let _groupSearch = '';
let _groupsCache = null;

async function renderCluster(el, opts = {}) {
  if (isSealed()) { el.innerHTML = sealedHtml(); return; }

  const tabBtn = (id, label) =>
    `<button class="btn small ${_clusterTab === id ? 'primary' : 'secondary'}" data-action="_setClusterTab" data-arg="${id}">${label}</button>`;

  let html = `<div class="toolbar toolbar-split">
    <div class="btn-group">
      ${tabBtn('groups', 'Groups')}
      ${tabBtn('ldap', 'LDAP')}
      ${tabBtn('sso', 'SSO')}
      ${tabBtn('ha', 'HA')}
    </div>
  </div>`;

  if (_clusterTab === 'ldap')      html += await _renderLdapTab();
  else if (_clusterTab === 'sso')  html += await _renderSsoTab();
  else if (_clusterTab === 'ha')   html += await _renderHaTab();
  else                             html += await _renderGroupsTab(opts);

  el.innerHTML = html;
}

window._setClusterTab = function (tab) {
  // Stop topology auto-refresh when leaving the HA tab.
  if (tab !== 'ha' && window._clusterTopologyTimer) {
    clearInterval(window._clusterTopologyTimer);
    window._clusterTopologyTimer = null;
  }
  _clusterTab = tab;
  renderCluster(document.getElementById('main'));
};

// ============================================================================
// Tab 1, Groups (local RBAC)
// ============================================================================

async function _renderGroupsTab(opts = {}) {
  try {
    if (!opts.useCache || _groupsCache === null) {
      const r = await api('GET', '/groups/');
      _groupsCache = r.items || [];
    }
    const q = _groupSearch.trim().toLowerCase();
    const items = q
      ? _groupsCache.filter(g =>
          (g.name || '').toLowerCase().includes(q) ||
          (g.source || '').toLowerCase().includes(q) ||
          JSON.stringify(g.permissions || {}).toLowerCase().includes(q))
      : _groupsCache;

    const total = items.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    const page = Math.min(_groupPage, Math.max(0, pages - 1));
    const slice = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

    let html = `<div class="toolbar toolbar-split">
      <div>
        <input type="search" id="cluster-search" class="search-input" data-action="_searchGroups"
          placeholder="Search by name, source or permissions…" value="${esc(_groupSearch)}">
        ${q ? `<span class="search-meta">${total} match${total === 1 ? '' : 'es'} of ${_groupsCache.length}</span>` : ''}
      </div>
      <button class="btn primary small" data-action="showCreateGroup">+ New Group</button>
    </div>
    <div id="group-form" class="card form-card hidden"></div>
    <table class="table"><thead><tr>
      <th>Name</th><th>Permissions</th><th>Source</th><th>Members</th><th>Actions</th>
    </tr></thead><tbody>`;
    for (const g of slice) {
      html += `<tr>
        <td><strong>${esc(g.name)}</strong></td>
        <td><code>${esc(JSON.stringify(g.permissions))}</code></td>
        <td><span class="tag">${esc(g.source)}</span></td>
        <td>${g.member_count}</td>
        <td class="actions">
          <button class="btn tiny danger" data-action="deleteGroup" data-arg="${esc(g.id)}">Del</button>
        </td>
      </tr>`;
    }
    html += '</tbody></table>';
    if (!total) html += `<div class="empty">${q ? 'No groups match your search' : 'No groups configured'}</div>`;

    html += renderPagination(page, pages, '_goGroupPage');
    return html;
  } catch (e) {
    return `<div class="error">${esc(e.message)}</div>`;
  }
}

window._goGroupPage = function(p) {
  _groupPage = parseInt(p);
  renderCluster(document.getElementById('main'), { useCache: true });
};

window._searchGroups = async function(value) {
  _groupSearch = value;
  _groupPage = 0;
  await renderCluster(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('cluster-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

function showCreateGroup() {
  const f = document.getElementById('group-form');
  f.classList.toggle('hidden');
  if (!f.classList.contains('hidden')) {
    f.innerHTML = `
      <div class="form-group"><label>Name</label><input type="text" id="cg-name" placeholder="dba-team"></div>
      <div class="form-group"><label>Permissions (JSON)</label><input type="text" id="cg-perms" value='{"secrets":"rw"}'></div>
      <button class="btn primary small" data-action="createGroup">Create</button>`;
  }
}

async function createGroup() {
  const name = document.getElementById('cg-name').value;
  const perms = document.getElementById('cg-perms').value;
  try {
    await api('POST', '/groups/', { name, permissions: JSON.parse(perms) });
    toast(`Group '${name}' created`, true);
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}

async function deleteGroup(id) {
  const g = (_groupsCache || []).find(x => x.id === id);
  const name = g ? g.name : id;
  const ok = await confirmType(name, {
    title: `Delete group '${name}'`,
    body: 'Removes the group and revokes the merged permissions of all its members. Tokens already issued via this group keep their permissions until expiry, rotate them via Quasar if needed.',
    okLabel: 'Delete',
  });
  if (!ok) return;
  try {
    await api('DELETE', `/groups/${id}`);
    toast('Group deleted', true);
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}

// ============================================================================
// Tab 2, LDAP / Active Directory
// ============================================================================

async function _renderLdapTab() {
  let cfg = null;
  let mappings = {};
  try {
    cfg = await api('GET', '/auth/ldap/config');
    const r = await api('GET', '/auth/ldap/mappings');
    mappings = r.mappings || {};
  } catch (e) {
    if (e.status === 403) {
      return '<div class="empty">LDAP configuration requires <code>admin:r</code> on your token.</div>';
    }
    return `<div class="error">${esc(e.message)}</div>`;
  }

  const v = cfg && cfg.configured ? cfg : {};
  let h = '<h4 class="section-subtitle">Connection</h4>';
  h += `<div class="card form-card">
    <div class="form-group">
      <label>LDAP URL</label>
      <input type="text" id="ldap-url" placeholder="ldaps://ad.example.local:636" value="${esc(v.url || '')}">
    </div>
    <div class="form-group">
      <label>Bind DN</label>
      <input type="text" id="ldap-bind-dn" placeholder="CN=rhorizon,OU=ServiceAccounts,DC=example,DC=local" value="${esc(v.bind_dn || '')}">
    </div>
    <div class="form-group">
      <label>Bind password ${cfg && cfg.configured ? '<span class="muted small">(leave blank to keep)</span>' : ''}</label>
      <input type="password" id="ldap-bind-password" placeholder="${cfg && cfg.configured ? '********' : 'service-account password'}">
    </div>
    <div class="form-group">
      <label>User search base</label>
      <input type="text" id="ldap-user-base" placeholder="OU=Users,DC=example,DC=local" value="${esc(v.user_base || '')}">
    </div>
    <div class="form-group">
      <label>User filter</label>
      <input type="text" id="ldap-user-filter" value="${esc(v.user_filter || '(sAMAccountName={username})')}">
    </div>
    <div class="form-group">
      <label>Group search base</label>
      <input type="text" id="ldap-group-base" placeholder="OU=Groups,DC=example,DC=local" value="${esc(v.group_base || '')}">
    </div>
    <div class="form-group">
      <label>Group filter</label>
      <input type="text" id="ldap-group-filter" value="${esc(v.group_filter || '(member={user_dn})')}">
    </div>
    <div class="form-group">
      <label>Group attribute</label>
      <input type="text" id="ldap-group-attr" value="${esc(v.group_attr || 'cn')}">
    </div>
    <div class="form-group">
      <label>Session TTL (hours)</label>
      <input type="number" id="ldap-ttl" min="1" max="168" value="${v.session_ttl_hours || 8}">
    </div>
    <div class="form-group">
      <label><input type="checkbox" id="ldap-tls-verify" ${v.tls_verify === false ? '' : 'checked'}> Verify TLS certificate (recommended)</label>
    </div>
    <button class="btn primary small" data-action="saveLdapConfig">${cfg && cfg.configured ? 'Update configuration' : 'Save configuration'}</button>
  </div>`;

  // Group mappings
  h += '<h4 class="section-subtitle">Group → Permission Mappings</h4>';
  h += '<p class="muted small">LDAP group DN (or CN) on the left, permission JSON on the right. The token issued at login receives the merged permissions of all groups the user is in.</p>';
  h += '<div id="ldap-mappings-list">';
  const keys = Object.keys(mappings);
  if (keys.length === 0) {
    h += '<div class="empty small">No mappings yet. Add one below.</div>';
  } else {
    h += `<table class="table small"><thead><tr>
      <th>LDAP group</th><th>Permissions</th><th></th>
    </tr></thead><tbody>`;
    for (const k of keys) {
      h += `<tr>
        <td><code>${esc(k)}</code></td>
        <td><code>${esc(JSON.stringify(mappings[k]))}</code></td>
        <td class="actions">
          <button class="btn tiny danger" data-action="_deleteLdapMapping" data-arg="${esc(k)}">Del</button>
        </td>
      </tr>`;
    }
    h += '</tbody></table>';
  }
  h += '</div>';

  h += `<div class="card form-card">
    <div class="form-group"><label>LDAP group</label>
      <input type="text" id="ldap-map-group" placeholder="CN=DevOps,OU=Groups,DC=example,DC=local"></div>
    <div class="form-group"><label>Permissions (JSON)</label>
      <input type="text" id="ldap-map-perms" value='{"secrets":"r"}'></div>
    <button class="btn primary small" data-action="_addLdapMapping">Add mapping</button>
  </div>`;

  // Stash mappings on window for the helper handlers
  window._ldapMappings = mappings;
  return h;
}

async function saveLdapConfig() {
  const body = {
    url: document.getElementById('ldap-url').value.trim(),
    bind_dn: document.getElementById('ldap-bind-dn').value.trim(),
    user_base: document.getElementById('ldap-user-base').value.trim(),
    user_filter: document.getElementById('ldap-user-filter').value.trim(),
    group_base: document.getElementById('ldap-group-base').value.trim(),
    group_filter: document.getElementById('ldap-group-filter').value.trim(),
    group_attr: document.getElementById('ldap-group-attr').value.trim(),
    tls_verify: document.getElementById('ldap-tls-verify').checked,
    session_ttl_hours: parseInt(document.getElementById('ldap-ttl').value, 10),
  };
  const pw = document.getElementById('ldap-bind-password').value;
  if (!pw) {
    toast('Bind password is required.', false);
    return;
  }
  body.bind_password = pw;
  try {
    await api('POST', '/auth/ldap/config', body);
    toast('LDAP configuration saved', true);
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}

window._addLdapMapping = async function () {
  const key = document.getElementById('ldap-map-group').value.trim();
  const permsRaw = document.getElementById('ldap-map-perms').value.trim();
  if (!key) { toast('Group DN required', false); return; }
  let perms;
  try { perms = JSON.parse(permsRaw); }
  catch (_) { toast('Permissions must be valid JSON', false); return; }
  const updated = { ...(window._ldapMappings || {}), [key]: perms };
  try {
    await api('PUT', '/auth/ldap/mappings', updated);
    toast(`Mapping for '${key}' added`, true);
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

window._deleteLdapMapping = async function (key) {
  const ok = await confirmType(key, {
    title: `Delete LDAP mapping for '${key}'`,
    body: 'Users in this LDAP group will lose the mapped permissions on their next login. Existing sessions keep their token permissions until expiry.',
    okLabel: 'Delete',
  });
  if (!ok) return;
  const updated = { ...(window._ldapMappings || {}) };
  delete updated[key];
  try {
    await api('PUT', '/auth/ldap/mappings', updated);
    toast(`Mapping for '${key}' removed`, true);
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

// ============================================================================
// Tab 3, SSO (reverse-proxy auth, env-driven, read-only)
// ============================================================================

async function _renderSsoTab() {
  let cfg;
  let mappings = {};
  try {
    cfg = await api('GET', '/auth/proxy/config');
    const r = await api('GET', '/auth/proxy/mappings');
    mappings = r.mappings || {};
  } catch (e) {
    if (e.status === 403) {
      return '<div class="empty">SSO configuration requires <code>admin:r</code> on your token.</div>';
    }
    return `<div class="error">${esc(e.message)}</div>`;
  }

  let h = '<h4 class="section-subtitle">Reverse-proxy SSO (Authelia / Authentik / Keycloak / oauth2-proxy)</h4>';
  h += `<p class="muted small">DB-backed config. Authentication settings apply on the next login. A trusted-IP change requires a coordinated API restart so every worker updates its X-Forwarded-For trust boundary together. Env vars <code>RHORIZON_PROXY_*</code> are fresh-install defaults.</p>`;
  h += `<div class="card form-card">
    <div class="form-group">
      <label><input type="checkbox" id="sso-enabled" ${cfg.enabled ? 'checked' : ''}> Enable proxy SSO</label>
    </div>
    <div class="form-group">
      <label>User header <span class="muted small">(env default: <code>${esc(cfg.env_defaults.user_header)}</code>)</span></label>
      <input type="text" id="sso-user-header" value="${esc(cfg.user_header)}">
    </div>
    <div class="form-group">
      <label>Groups header <span class="muted small">(env default: <code>${esc(cfg.env_defaults.groups_header)}</code>)</span></label>
      <input type="text" id="sso-groups-header" value="${esc(cfg.groups_header)}">
    </div>
    <div class="form-group">
      <label>Trusted IPs / CIDRs <span class="muted small">(comma-separated)</span></label>
      <input type="text" id="sso-trusted-ips" placeholder="172.18.0.0/16,10.0.1.5" value="${esc(cfg.trusted_ips || '')}">
      <div class="help-block">
        <span class="muted small">Quick presets:</span>
        <button class="btn tiny secondary" data-action="_ssoPresetLoopback" type="button">Loopback only</button>
        <button class="btn tiny secondary" data-action="_ssoPresetRfc1918" type="button">All RFC 1918 + IPv6 ULA</button>
        <button class="btn tiny secondary" data-action="_ssoPresetClear" type="button">Clear</button>
      </div>
      <div class="muted small help-block">
        ⚠ This list serves <strong>two</strong> purposes:
        <ol class="help-list">
          <li>SSO header trust: the immediate TCP peer must be in this list for <code>Remote-User</code>/<code>Remote-Groups</code> to be accepted (otherwise 403).</li>
          <li>Audit IP recovery: every hop in this list is skipped when walking <code>X-Forwarded-For</code>; the leftmost untrusted IP is logged as the real client. Without this, audit logs show your reverse-proxy IPs (Docker / Podman internal addresses).</li>
        </ol>
        <strong>Default = all RFC 1918 + IPv6 ULA + loopback</strong>, works out-of-the-box on any private infra (Docker / Podman / K8s / VPN). Tighten this list if you run on a shared or multi-tenant network where any internal service could forge SSO headers. Tighter alternative: list only the specific Docker / Podman / VLAN CIDRs your proxies actually use. List <strong>every</strong> hop in your chain (bundled nginx + Traefik/HAProxy/Authelia + …). Order doesn't matter.
      </div>
    </div>
    <div class="form-group">
      <label>Session TTL (hours)</label>
      <input type="number" id="sso-ttl" min="1" max="168" value="${cfg.session_ttl_hours}">
    </div>
    <button class="btn primary small" data-action="saveSsoConfig">Save SSO configuration</button>
  </div>`;

  if (cfg.enabled && !cfg.trusted_ips) {
    h += '<div class="error small">⚠ <strong>SSO is enabled but no trusted IPs are configured.</strong> Any client could forge identity headers and impersonate any user. Set Trusted IPs to the CIDR your reverse proxy connects from.</div>';
  }

  // Mappings: groupName (from Remote-Groups) → permissions
  h += '<h4 class="section-subtitle">Group → Permission Mappings (proxy)</h4>';
  h += '<p class="muted small">Group names as they appear in the <code>' + esc(cfg.groups_header) + '</code> header (typically lowercase, comma-separated by the proxy). The permissions of every matching group are merged at login time.</p>';

  const keys = Object.keys(mappings);
  if (keys.length === 0) {
    h += '<div class="empty small">No mappings yet. Add one below.</div>';
  } else {
    h += `<table class="table small"><thead><tr>
      <th>Proxy group</th><th>Permissions</th><th></th>
    </tr></thead><tbody>`;
    for (const k of keys) {
      h += `<tr>
        <td><code>${esc(k)}</code></td>
        <td><code>${esc(JSON.stringify(mappings[k]))}</code></td>
        <td class="actions">
          <button class="btn tiny danger" data-action="_deleteSsoMapping" data-arg="${esc(k)}">Del</button>
        </td>
      </tr>`;
    }
    h += '</tbody></table>';
  }

  h += `<div class="card form-card">
    <div class="form-group"><label>Proxy group</label>
      <input type="text" id="sso-map-group" placeholder="vault-admins"></div>
    <div class="form-group"><label>Permissions (JSON)</label>
      <input type="text" id="sso-map-perms" value='{"secrets":"r"}'></div>
    <button class="btn primary small" data-action="_addSsoMapping">Add mapping</button>
  </div>`;

  // Stash for the helpers
  window._proxyMappings = mappings;
  return h;
}

window._ssoPresetLoopback = function () {
  document.getElementById('sso-trusted-ips').value = '127.0.0.0/8,::1/128';
};
window._ssoPresetRfc1918 = function () {
  document.getElementById('sso-trusted-ips').value =
    '127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7';
};
window._ssoPresetClear = function () {
  document.getElementById('sso-trusted-ips').value = '';
};

async function saveSsoConfig() {
  const body = {
    enabled: document.getElementById('sso-enabled').checked,
    user_header: document.getElementById('sso-user-header').value.trim() || 'Remote-User',
    groups_header: document.getElementById('sso-groups-header').value.trim() || 'Remote-Groups',
    trusted_ips: document.getElementById('sso-trusted-ips').value.trim(),
    session_ttl_hours: parseInt(document.getElementById('sso-ttl').value, 10),
  };
  if (body.enabled && !body.trusted_ips) {
    const ok = await confirmModal({
      title: 'Save SSO without trusted IPs?',
      body: 'SSO is enabled but no trusted proxy IPs are set. Rhorizon will reject every proxy-authentication request until at least one proxy source IP is trusted.',
      okLabel: 'Save anyway',
      danger: false,
    });
    if (!ok) return;
  }
  try {
    const result = await api('POST', '/auth/proxy/config', body);
    toast(
      result.restart_required
        ? 'SSO configuration saved. Restart all API workers to apply the trusted-IP change.'
        : 'SSO configuration saved',
      true,
    );
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}

window._addSsoMapping = async function () {
  const key = document.getElementById('sso-map-group').value.trim();
  const permsRaw = document.getElementById('sso-map-perms').value.trim();
  if (!key) { toast('Group name required', false); return; }
  let perms;
  try { perms = JSON.parse(permsRaw); }
  catch (_) { toast('Permissions must be valid JSON', false); return; }
  const updated = { ...(window._proxyMappings || {}), [key]: perms };
  try {
    await api('PUT', '/auth/proxy/mappings', updated);
    toast(`Mapping for '${key}' added`, true);
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

window._deleteSsoMapping = async function (key) {
  const ok = await confirmType(key, {
    title: `Delete SSO mapping for '${key}'`,
    body: 'Users in this proxy group will lose the mapped permissions on their next login. Existing sessions keep their token permissions until expiry.',
    okLabel: 'Delete',
  });
  if (!ok) return;
  const updated = { ...(window._proxyMappings || {}) };
  delete updated[key];
  try {
    await api('PUT', '/auth/proxy/mappings', updated);
    toast(`Mapping for '${key}' removed`, true);
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

// ============================================================================
// Tab 4, HA
// ============================================================================
//
// Two parallel concerns surfaced under the same tab :
//
// - (cluster_id / primary_uuid / per-node certs), multi-host
//     membership of the cluster CA. Source : GET /cluster/ha (admin:r).
//     Operator action : POST /cluster/rotate-cert/{node_uuid|all}.
//
// - (workers grouped by host + advisory locks), intra-host
//     master/follower topology of the rhorizon API processes. Source :
//     GET /cluster (admin:r). Pre-existing.
//
// GET /cluster/health adds the provider-neutral database HA and replication
// view (Patroni on Linux, pgha on BSD). All three are admin:r ; each section
// gracefully degrades if its call fails. Auto-refresh every 5s while the HA
// tab is active.

async function _renderHaTab() {
  // Fetch all endpoints in parallel ; failures are tolerated per-section
  // so a non-initialised cluster still renders.
  const [haRes, topoRes, healthRes] = await Promise.allSettled([
    api('GET', '/cluster/ha'),
    api('GET', '/cluster'),
    api('GET', '/cluster/health'),
  ]);

  if (window._clusterTopologyTimer) clearInterval(window._clusterTopologyTimer);
  window._clusterTopologyTimer = setInterval(async () => {
    const slot = document.getElementById('cluster-ha-section');
    if (!slot || _clusterTab !== 'ha') {
      clearInterval(window._clusterTopologyTimer);
      window._clusterTopologyTimer = null;
      return;
    }
    try {
      const [ha2, topo2, health2] = await Promise.allSettled([
        api('GET', '/cluster/ha'),
        api('GET', '/cluster'),
        api('GET', '/cluster/health'),
      ]);
      // outerHTML detaches `slot`, so re-query to restore onto the new nodes.
      const scroll = captureTableScroll(slot);
      slot.outerHTML = renderHaDashboard(ha2, topo2, health2);
      restoreTableScroll(document.getElementById('cluster-ha-section'), scroll);
    } catch (_) { /* keep last successful render */ }
  }, 5000);

  return renderHaDashboard(haRes, topoRes, healthRes);
}

function renderHaDashboard(haRes, topoRes, healthRes) {
  let h = '<div id="cluster-ha-section">';
  h += renderMembershipSection(haRes);
  h += renderDatabaseHaSection(healthRes);
  h += renderTopologySection(topoRes);
  h += '</div>';
  return h;
}

// ----------------------------------------------------------------------------
// cluster identity + per-node cert lifecycle + force-rotate
// ----------------------------------------------------------------------------

function renderMembershipSection(haRes) {
  let h = '<h4 class="section-subtitle">Application HA Membership</h4>';

  if (haRes.status === 'rejected') {
    const err = haRes.reason || {};
    if (err.status === 403) {
      return h + '<div class="empty small">Cluster membership requires <code>admin:r</code> on your token.</div>';
    }
    if (err.status === 409) {
      // cluster_not_initialised, has not been bootstrapped yet.
      return h + '<div class="empty small">Cluster not initialised. Call <code>POST /cluster/init</code> on the primary to bootstrap the cluster CA and start accepting JOINs.</div>';
    }
    return h + `<div class="error small">${esc(err.message || 'Failed to load /cluster/ha')}</div>`;
  }

  const ha = haRes.value;
  const nodes = ha.nodes || [];
  const conflicts = ha.uuid_ip_conflicts_total || 0;
  const primaryShort = ha.primary_uuid ? ha.primary_uuid.slice(0, 8) : null;
  const clusterShort = ha.cluster_id ? ha.cluster_id.slice(0, 8) : '-';

  // Identity card + cluster-wide rotate-all action.
  h += `<div class="card cluster-identity-card">
    <div class="row-inline">
      <span class="muted small">cluster_id</span>
      <code title="${esc(ha.cluster_id)}">${esc(clusterShort)}</code>
      <span class="muted small">·</span>
      <span class="muted small">version</span>
      <code>${esc(ha.cluster_version)}</code>
      <span class="muted small">(min ${esc(ha.cluster_min_compatible_version)})</span>
      <span class="muted small">·</span>
      <span class="muted small">Application HA primary</span>
      ${primaryShort
        ? `<code title="${esc(ha.primary_uuid)}">${esc(primaryShort)}</code>`
        : '<span class="tag tag-warn">none</span>'}
      <span class="muted small">·</span>
      <span class="tag ${ha.ha_loaded ? 'tag-ok good' : 'tag-warn bad'}">ha_password ${ha.ha_loaded ? 'loaded' : 'NOT loaded'}</span>
      <span class="muted small">·</span>
      <span class="muted small">uuid/ip conflicts</span>
      <span class="tag ${conflicts > 0 ? 'tag-warn bad' : 'tag-muted neutral'}">${conflicts}</span>
    </div>
    <div class="row-inline mt-8">
      <button class="btn small secondary" data-action="_rotateAllCerts">Rotate ALL certs</button>
      <span class="muted small">Force-renews every non-evicted node at its next renewal tick (admin:w).</span>
    </div>
  </div>`;

  // Members table.
  if (nodes.length === 0) {
    h += '<div class="empty small">No cluster members yet. Joining nodes will appear here.</div>';
    return h;
  }

  h += `<table class="table small"><thead><tr>
    <th>Node UUID</th>
    <th>Source IP</th>
    <th>Application role</th>
    <th>Quarantine</th>
    <th>Heartbeat</th>
    <th>Version</th>
    <th>Cert expires</th>
    <th>Cert SHA-256</th>
    <th>Actions</th>
  </tr></thead><tbody>`;

  for (const n of nodes) {
    const uuidShort = n.node_uuid.slice(0, 8);
    const fprShort = n.cert_fingerprint ? n.cert_fingerprint.slice(0, 12) : '-';
    const isPrimary = n.node_uuid === ha.primary_uuid;
    const stateTag = _haStateTag(n.ha_state, isPrimary);
    const heartbeatCell = n.last_heartbeat
      ? _heartbeatCell(n.last_heartbeat)
      : '<span class="muted">never</span>';
    const quarantineCell = (n.ha_state === 'joining' || n.ha_state === 'quarantined') && n.quarantine_until
      ? `<span class="muted">${esc(timeFromNow(n.quarantine_until))}</span>`
      : '<span class="muted">-</span>';
    const certCell = _certExpiryCell(n.cert_not_after);
    h += `<tr>
      <td><code title="${esc(n.node_uuid)}">${esc(uuidShort)}</code></td>
      <td><code>${esc(n.source_ip)}</code></td>
      <td>${stateTag}</td>
      <td>${quarantineCell}</td>
      <td>${heartbeatCell}</td>
      <td><code>${esc(n.cluster_version)}</code></td>
      <td>${certCell}</td>
      <td><code title="${esc(n.cert_fingerprint || '')}">${esc(fprShort)}</code></td>
      <td class="actions">
        <button class="btn tiny secondary" data-action="_rotateNodeCert" data-arg="${esc(n.node_uuid)}">Rotate</button>
      </td>
    </tr>`;
  }
  h += '</tbody></table>';
  return h;
}

function _haStateTag(state, isPrimary) {
  if (isPrimary) return '<span class="tag tag-ok good">APP PRIMARY</span>';
  const map = {
    secondary: 'tag-info neutral',
    joining: 'tag-warn neutral',
    quarantined: 'tag-warn bad',
    draining: 'tag-warn bad',
    evicted: 'tag-warn bad',
  };
  const cls = map[state] || 'tag-muted neutral';
  return `<span class="tag ${cls}">${esc(state || 'unknown')}</span>`;
}

function _heartbeatCell(iso) {
  const ageSec = Math.floor((Date.now() - new Date(iso)) / 1000);
  const stale = ageSec > 15;
  const label = timeAgo(iso);
  return stale
    ? `<span class="tag tag-warn bad">${esc(label)}</span>`
    : `<span class="muted">${esc(label)}</span>`;
}

function _certExpiryCell(iso) {
  if (!iso) return '<span class="muted">-</span>';
  const days = Math.floor((new Date(iso) - Date.now()) / 86400000);
  const label = timeFromNow(iso);
  // Renewal threshold default is 30d (cluster_cert_renewal_threshold_days).
  // Anything <= 30d means renewal is due ; <= 7d is alarming.
  if (days <= 0) return `<span class="tag tag-warn bad">expired</span>`;
  if (days <= 7) return `<span class="tag tag-warn bad" title="${esc(iso)}">${esc(label)}</span>`;
  if (days <= 30) return `<span class="tag tag-warn neutral" title="${esc(iso)}">${esc(label)}</span>`;
  return `<span class="muted" title="${esc(iso)}">${esc(label)}</span>`;
}

window._rotateNodeCert = async function (nodeUuid) {
  const short = nodeUuid.slice(0, 8);
  const ok = await confirmType(short, {
    title: `Force-renew cert for node ${short}…`,
    body: 'Stamps force_renew_at on this node. Its per-node renewal loop picks it up at the next poll (cluster_cert_renewal_poll_secs, default 12h) and refreshes via mTLS. The current cert keeps working until the new one is installed.',
    okLabel: 'Rotate',
  });
  if (!ok) return;
  try {
    await api('POST', `/cluster/rotate-cert/${encodeURIComponent(nodeUuid)}`);
    toast(`Node ${short}: cert rotation queued`, true);
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

window._rotateAllCerts = async function () {
  const ok = await confirmType('rotate all', {
    title: 'Force-renew certs for ALL nodes',
    body: 'Stamps force_renew_at on every non-evicted node. Each per-node renewal loop picks the flip up at its next poll (default 12h). Current certs keep working until replaced. Use this after a cluster CA rotation or to manually exercise the renewal path.',
    okLabel: 'Rotate all',
  });
  if (!ok) return;
  try {
    const r = await api('POST', '/cluster/rotate-cert/all');
    toast(`Cluster: ${r.flipped} cert(s) rotation queued`, true);
    renderCluster(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

// ----------------------------------------------------------------------------
// provider-neutral database HA + replication
// ----------------------------------------------------------------------------

function renderDatabaseHaSection(healthRes) {
  let h = '<h4 class="section-subtitle">Database HA &amp; Replication</h4>';

  if (healthRes.status === 'rejected') {
    const err = healthRes.reason || {};
    if (err.status === 403) {
      return h + '<div class="empty small">Database HA health requires <code>admin:r</code> on your token.</div>';
    }
    return h + `<div class="error small">${esc(err.message || 'Failed to load /cluster/health')}</div>`;
  }

  const health = healthRes.value || {};
  const dbha = (health.components || {}).database_ha;
  if (!dbha) {
    return h + '<div class="empty small">Database HA health is not reported by this node.</div>';
  }

  const provider = dbha.provider || 'unconfigured';
  let leader = dbha.leader || 'not reported';
  if (!dbha.leader && Number.isFinite(dbha.leaders)) {
    leader = dbha.leaders === 1
      ? 'one verified (identity not reported)'
      : (dbha.leaders === 0 ? 'none' : `${dbha.leaders} reported (unsafe)`);
  }
  const members = Number.isFinite(dbha.members) ? dbha.members : null;
  const running = Number.isFinite(dbha.running) ? dbha.running : null;
  const memberSummary = members === null
    ? 'not reported'
    : `${running === null ? '?' : running}/${members} healthy`;
  const vipOwners = Array.isArray(dbha.vip_owners) ? dbha.vip_owners : [];
  const hasVipData = Array.isArray(dbha.vip_owners);
  const agentsReporting = Number.isFinite(dbha.agents_reporting)
    ? `${dbha.agents_reporting}/${members === null ? '?' : members}`
    : null;

  h += `<div class="card database-ha-card">
    <div class="database-ha-grid">
      <div class="kv"><span>Status</span>${_haStatusIndicator(dbha.state, dbha.reason)}</div>
      <div class="kv"><span>Provider</span><code>${esc(provider)}</code></div>
      <div class="kv"><span>Database leader</span><strong>${esc(leader)}</strong></div>
      <div class="kv"><span>Database members</span><span>${esc(memberSummary)}</span></div>
      <div class="kv"><span>Maximum replica lag</span><span>${_formatHaBytes(dbha.max_replica_lag_bytes)} / ${_formatHaBytes(dbha.lag_threshold_bytes)} limit</span></div>
      <div class="kv"><span>Leader timeline</span><span>${dbha.leader_timeline == null ? 'not reported' : esc(dbha.leader_timeline)}</span></div>
      ${dbha.quorum == null ? '' : `<div class="kv"><span>Quorum</span><span>${dbha.quorum ? 'present' : 'absent'}</span></div>`}
      ${hasVipData ? `<div class="kv"><span>Write VIP owner</span><span>${vipOwners.length ? esc(vipOwners.join(', ')) : 'none'}</span></div>` : ''}
      ${agentsReporting === null ? '' : `<div class="kv"><span>Supervision agents</span><span>${esc(agentsReporting)} reporting</span></div>`}
      ${Number.isFinite(dbha.status_max_age_seconds) ? `<div class="kv"><span>Maximum status age</span><span>${esc(dbha.status_max_age_seconds)}s</span></div>` : ''}
    </div>
    <div class="muted small mt-8">${esc(dbha.reason || 'No health reason reported.')}</div>
  </div>`;

  h += _renderDatabaseHaWarnings(dbha);
  h += _renderReplicaTable(dbha);
  return h;
}

function _haStatusIndicator(state, reason) {
  const normalized = String(state || 'grey').toLowerCase();
  const map = {
    green: ['green', 'Healthy (green)'],
    orange: ['orange', 'Degraded (orange)'],
    red: ['red', 'Unsafe (red)'],
    grey: ['black', 'Unknown / unconfigured (black)'],
  };
  const [dotClass, label] = map[normalized] || map.grey;
  return `<span class="ha-health-status" title="${esc(reason || '')}">
    <span class="ha-status-dot ${dotClass}" aria-hidden="true"></span>
    <span>${label}</span>
  </span>`;
}

function _formatHaBytes(value) {
  if (!Number.isFinite(value)) return 'unknown';
  const bytes = Math.max(0, Number(value));
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let scaled = bytes;
  let unit = 'B';
  for (const next of units) {
    scaled /= 1024;
    unit = next;
    if (scaled < 1024) break;
  }
  return `${scaled >= 10 ? scaled.toFixed(0) : scaled.toFixed(1)} ${unit}`;
}

function _renderDatabaseHaWarnings(dbha) {
  const warnings = [];
  const pushNames = (label, items, formatter) => {
    if (!Array.isArray(items) || !items.length) return;
    warnings.push(`<li><strong>${label}:</strong> ${items.map(formatter).map(esc).join(', ')}</li>`);
  };
  pushNames('Non-streaming replicas', dbha.non_streaming_replicas,
    item => `${item.name || 'unknown'} (${item.state || 'unknown'})`);
  pushNames('Lagging replicas', dbha.lagging_members,
    item => `${item.name || 'unknown'} (${_formatHaBytes(item.lag_bytes)})`);
  pushNames('Unknown replica lag', dbha.unknown_lag_members, item => String(item));
  pushNames('Timeline mismatch', dbha.timeline_mismatch_members,
    item => `${item.name || 'unknown'} (timeline ${item.timeline == null ? '?' : item.timeline})`);
  pushNames('Stale supervision agents', dbha.stale_agents,
    item => `${item.name || 'unknown'} (${Number.isFinite(item.age_seconds) ? `${item.age_seconds.toFixed(1)}s` : 'age unknown'})`);
  pushNames('Unreachable supervision endpoints', dbha.unreachable_endpoints, item => String(item));
  pushNames('Duplicate supervision agents', dbha.duplicate_agents, item => String(item));

  if (!warnings.length) return '';
  return `<div class="warning-box database-ha-warnings">
    <strong>Database HA attention required</strong>
    <ul class="help-list">${warnings.join('')}</ul>
  </div>`;
}

function _renderReplicaTable(dbha) {
  const lags = dbha.replica_lags || {};
  const names = Object.keys(lags).sort();
  if (!names.length) {
    return '<div class="empty small">No replica detail reported by the configured Database HA provider.</div>';
  }

  const nonStreaming = new Map((dbha.non_streaming_replicas || []).map(item => [String(item.name), item.state]));
  const lagging = new Set((dbha.lagging_members || []).map(item => String(item.name)));
  const unknownLag = new Set((dbha.unknown_lag_members || []).map(String));
  const timelineMismatch = new Set((dbha.timeline_mismatch_members || []).map(item => String(item.name)));

  let h = `<table class="table small"><thead><tr>
    <th>Replica</th><th>Replication state</th><th>Lag</th>
  </tr></thead><tbody>`;
  for (const name of names) {
    const problems = [];
    if (nonStreaming.has(name)) problems.push(`not streaming (${nonStreaming.get(name) || 'unknown'})`);
    if (unknownLag.has(name)) problems.push('lag unknown');
    if (lagging.has(name)) problems.push('lag over limit');
    if (timelineMismatch.has(name)) problems.push('timeline mismatch');
    const state = problems.length ? problems.join('; ') : 'streaming / within limit';
    h += `<tr class="${problems.length ? 'row-warn' : ''}">
      <td><code>${esc(name)}</code></td>
      <td>${problems.length
        ? `<span class="tag tag-warn bad">${esc(state)}</span>`
        : `<span class="tag tag-ok good">${esc(state)}</span>`}</td>
      <td>${_formatHaBytes(lags[name])}</td>
    </tr>`;
  }
  return h + '</tbody></table>';
}

// ----------------------------------------------------------------------------
// worker topology grouped by host + advisory locks
// ----------------------------------------------------------------------------

function renderTopologySection(topoRes) {
  let h = '<h4 class="section-subtitle">Worker Topology &amp; Local Crypto Masters</h4>';

  if (topoRes.status === 'rejected') {
    const err = topoRes.reason || {};
    if (err.status === 403) {
      return h + '<div class="empty small">Worker topology requires <code>admin:r</code> on your token.</div>';
    }
    return h + `<div class="error small">${esc(err.message || 'Failed to load /cluster')}</div>`;
  }

  const t = topoRes.value;
  const hosts = t.hosts || {};
  const hostNames = Object.keys(hosts).sort();
  h += '<div class="cluster-host-grid">';

  if (hostNames.length === 0) {
    h += '<div class="empty">No active workers</div>';
  } else {
    for (const name of hostNames) {
      const host = hosts[name];
      const isMe = name === t.this_host;
      const masterAge = host.master ? host.master.age_sec.toFixed(1) : null;
      const isMasterStale = masterAge !== null && parseFloat(masterAge) > 5;
      h += `<div class="card cluster-host-card${isMe ? ' me' : ''}">
        <div class="cluster-host-header">
          <strong>${esc(name)}</strong>
          ${isMe ? '<span class="tag tag-info">this host</span>' : ''}
        </div>
        <div class="cluster-host-master">
          ${host.master
            ? `<span class="tag ${isMasterStale ? 'tag-warn bad' : 'tag-ok good'}">LOCAL CRYPTO MASTER</span>
               <span class="muted">pid ${host.master.pid} · heartbeat ${masterAge}s ago</span>`
            : '<span class="tag tag-warn bad">NO LOCAL CRYPTO MASTER</span>'}
        </div>
        <div class="cluster-host-followers">`;
      for (const f of (host.followers || [])) {
        const ageStale = f.age_sec > 5;
        h += `<div class="cluster-follower">
          <span class="tag tag-muted">${esc(f.role)}</span>
          <span class="muted">pid ${f.pid} · ${esc(f.status)} · ${ageStale ? '<span class="warn">' : ''}${f.age_sec.toFixed(1)}s${ageStale ? '</span>' : ''}</span>
        </div>`;
      }
      if (!(host.followers || []).length) {
        h += '<div class="muted small">no followers</div>';
      }
      h += `</div></div>`;
    }
  }

  h += '</div>';

  const locks = t.held_cluster_locks || [];
  h += '<h4 class="section-subtitle">Cluster Locks Held</h4>';
  if (locks.length === 0) {
    h += '<div class="empty small">No cluster-wide locks held right now.</div>';
  } else {
    h += `<table class="table small"><thead><tr>
      <th>Lock</th><th>Holder host</th><th>Holder pid</th><th>Held for</th>
    </tr></thead><tbody>`;
    for (const lk of locks) {
      const longHeld = lk.held_for_sec > 60;
      h += `<tr class="${longHeld ? 'row-warn' : ''}">
        <td><code>${esc(lk.lock)}</code></td>
        <td>${esc(lk.holder_host)}</td>
        <td>${lk.holder_pid}</td>
        <td>${lk.held_for_sec.toFixed(1)}s</td>
      </tr>`;
    }
    h += '</tbody></table>';
  }

  return h;
}
