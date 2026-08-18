// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Dynamic secrets, rendered as the "Dynamic" sub-tab of Eclipse (Secrets).
 *
 * On-demand target credentials with a lease (short TTL, auto-revoked by the
 * reaper at expiry). Same spirit as Quasar's ephemeral tokens: a credential is
 * minted on demand, its password is shown once, and it disappears by itself.
 *
 * Layout (single panel, no own page chrome, the tab bar lives in Eclipse):
 *   - Engines  : enabled backend modules + their operator-defined roles.
 *                Selecting an engine reveals its roles, where you mint creds.
 *   - Leases   : active credentials below, with renew / revoke.
 *
 * Engine/role CRUD and lease revoke need admin:w; minting and renewing a lease
 * are consumption actions (secrets:w), same split as the API.
 */
'use strict';

let _dynSelectedEngine = null; // engine id whose roles are expanded
let _dynCache = { engines: null, leases: null, compatibility: null, modules: null };

async function renderDynamicInto(el) {
  try {
    const [engines, leases, compatibility] = await Promise.all([
      api('GET', '/dynamic/engines'),
      api('GET', '/dynamic/leases'),
      // Keep the tab usable during a mixed-version rolling upgrade where an
      // older API worker may not expose the compatibility endpoint yet.
      api('GET', '/dynamic/engines/compatibility')
        .catch(() => ({ engines: [], available_modules: [] })),
    ]);
    _dynCache.engines = engines.items || [];
    _dynCache.leases = leases.items || [];
    _dynCache.compatibility = compatibility.engines || [];
    _dynCache.modules = compatibility.available_modules || [];
    el.innerHTML = `
      <div id="dyn-reveal"></div>
      <div class="toolbar toolbar-split">
        <div>
          <div class="card-title">Modules</div>
          <div class="dim small">Fine-grained cluster state under the hard INI and image boundary.</div>
        </div>
      </div>
      <div id="dyn-modules"></div>
      <div class="toolbar toolbar-split">
        <div class="card-title">Engines</div>
        <button class="btn primary small" data-action="dynShowAddEngine">+ Add engine</button>
      </div>
      <div id="dyn-engine-form" class="card form-card hidden"></div>
      <div id="dyn-engines"></div>
      <div class="card-title mt-12">Leases</div>
      <div id="dyn-leases"></div>`;
    _dynRenderModules();
    _dynRenderEngines();
    _dynRenderLeases();
  } catch (e) {
    el.innerHTML = `<div class="error">${esc(e.message)}</div>`;
  }
}

function _dynRenderModules() {
  const wrap = document.getElementById('dyn-modules');
  if (!wrap) return;
  const modules = _dynCache.modules || [];
  if (!modules.length) {
    wrap.innerHTML = '<div class="empty">Module state is not reported by this API version.</div>';
    return;
  }
  let html = '<table class="table"><thead><tr><th>Module</th><th>Status</th><th>Driver</th><th>Boundary</th><th>Action</th></tr></thead><tbody>';
  for (const m of modules) {
    let dot = 'black';
    let status = 'Disabled';
    if (!m.configured) {
      status = 'Locked by INI';
    } else if (!m.driver_installed) {
      dot = 'red';
      status = 'Driver absent';
    } else if (m.restart_required) {
      dot = 'orange';
      status = 'Restart required';
    } else if (m.loaded) {
      dot = 'green';
      status = 'Active';
    }
    const canToggle = m.configured && m.driver_installed;
    const next = !m.enabled;
    html += `<tr>
      <td><strong>${esc(m.display_name || m.engine_type)}</strong><br><code>${esc(m.engine_type)}</code></td>
      <td><span class="ha-status-dot ${dot}" aria-hidden="true"></span> ${esc(status)}</td>
      <td><code>${esc(m.driver_module)}</code></td>
      <td>${m.configured ? 'Allowed by INI' : 'Commented / disabled in INI'}</td>
      <td><button class="btn tiny ${m.enabled ? 'danger' : 'secondary'}"
        data-action="dynSetModuleState" data-arg="${esc(m.engine_type)}"
        data-arg2="${next}" ${canToggle ? '' : 'disabled'}>
        ${m.enabled ? 'Disable' : 'Enable'}
      </button></td>
    </tr>`;
  }
  html += '</tbody></table><div class="dim small">A state change is stored for the whole cluster. Restart every API node to import or unload the module consistently.</div>';
  wrap.innerHTML = html;
}

function _dynRenderEngines() {
  const wrap = document.getElementById('dyn-engines');
  if (!wrap) return;
  const engines = _dynCache.engines || [];
  if (!engines.length) {
    wrap.innerHTML = '<div class="empty">No engines yet. Add one to start issuing dynamic credentials.</div>';
    return;
  }
  let html = '<table class="table"><thead><tr><th>Name</th><th>Type</th><th>Validated targets</th><th>Namespace</th><th>ID</th><th>Actions</th></tr></thead><tbody>';
  for (const e of engines) {
    const sel = _dynSelectedEngine === e.id;
    const capability = (_dynCache.compatibility || []).find(c => c.engine_type === e.engine_type);
    const validated = capability && capability.validated_targets.length;
    const targets = validated ? capability.validated_targets.join(', ') : 'validation pending';
    html += `<tr>
      <td><strong>${esc(e.name)}</strong></td>
      <td><code>${esc(e.engine_type)}</code></td>
      <td><span class="badge ${validated ? 'green' : 'orange'}">${esc(targets)}</span></td>
      <td><span class="tag">${esc(e.namespace)}</span></td>
      <td><code class="dim">${esc(e.id)}</code></td>
      <td class="actions">
        <button class="btn tiny secondary" data-action="dynSelectEngine" data-arg="${esc(sel ? '' : e.id)}">${sel ? 'Hide roles' : 'Roles'}</button>
        <button class="btn tiny danger" data-action="dynDeleteEngine" data-arg="${esc(e.id)}">Delete</button>
      </td>
    </tr>`;
    if (sel) {
      html += `<tr><td colspan="6" id="dyn-roles-${esc(e.id)}">Loading roles...</td></tr>`;
    }
  }
  html += '</tbody></table>';
  wrap.innerHTML = html;
  if (_dynSelectedEngine) _dynRenderRoles(_dynSelectedEngine);
}

async function _dynRenderRoles(engineId) {
  const cell = document.getElementById(`dyn-roles-${engineId}`);
  if (!cell) return;
  try {
    const roles = (await api('GET', `/dynamic/engines/${engineId}/roles`)).items || [];
    let html = `<div class="toolbar toolbar-split">
        <div class="card-title">Roles</div>
        <button class="btn primary small" data-action="dynShowAddRole" data-arg="${esc(engineId)}">+ Add role</button>
      </div>
      <div id="dyn-role-form-${esc(engineId)}" class="card form-card hidden"></div>`;
    if (!roles.length) {
      html += '<div class="empty">No roles on this engine yet.</div>';
      cell.innerHTML = html;
      return;
    }
    html += '<table class="table"><thead><tr><th>Role</th><th>Default TTL</th><th>Max TTL</th><th>Actions</th></tr></thead><tbody>';
    for (const r of roles) {
      html += `<tr>
        <td><strong>${esc(r.name)}</strong></td>
        <td>${r.default_ttl_seconds}s</td>
        <td>${r.max_ttl_seconds}s</td>
        <td class="actions"><button class="btn tiny" data-action="dynMintCreds" data-arg="${esc(engineId)}" data-arg2="${esc(r.name)}">Mint creds</button></td>
      </tr>`;
    }
    html += '</tbody></table>';
    cell.innerHTML = html;
  } catch (e) {
    cell.innerHTML = `<div class="error">${esc(e.message)}</div>`;
  }
}

function _dynRenderLeases() {
  const wrap = document.getElementById('dyn-leases');
  if (!wrap) return;
  const leases = _dynCache.leases || [];
  if (!leases.length) {
    wrap.innerHTML = '<div class="empty">No active or pending leases.</div>';
    return;
  }
  let html = '<table class="table"><thead><tr><th>Username</th><th>Engine / role</th><th>Namespace</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead><tbody>';
  for (const ls of leases) {
    const provisioning = Boolean(ls.provisioning);
    const expired = Boolean(ls.expired);
    const unverified = Boolean(ls.revoked && !ls.revocation_verified);
    let dot = 'green';
    let status = 'Active';
    if (expired || unverified) {
      dot = 'red';
      status = expired ? 'Expired - revocation pending' : 'Revocation unverified';
    } else if (provisioning) {
      dot = 'orange';
      status = 'Provisioning';
    }
    const renewDisabled = provisioning || expired || Boolean(ls.revoked);
    const revokeDisabled = provisioning && !expired;
    html += `<tr>
      <td><code>${esc(ls.username)}</code></td>
      <td>${esc(ls.engine)} / ${esc(ls.role)}</td>
      <td><span class="tag">${esc(ls.namespace)}</span></td>
      <td><span class="ha-status-dot ${dot}" aria-hidden="true"></span> ${status}</td>
      <td title="${esc(ls.expires_at)}">${esc(_dynExpiresIn(ls.expires_at))}</td>
      <td class="actions">
        <button class="btn tiny" data-action="dynRenewLease" data-arg="${esc(ls.id)}" ${renewDisabled ? 'disabled' : ''}>Renew</button>
        <button class="btn tiny danger" data-action="dynRevokeLease" data-arg="${esc(ls.id)}" ${revokeDisabled ? 'disabled' : ''}>Revoke</button>
      </td>
    </tr>`;
  }
  html += '</tbody></table>';
  wrap.innerHTML = html;
}

function _dynExpiresIn(iso) {
  const s = Math.floor((new Date(iso) - Date.now()) / 1000);
  if (s <= 0) return 'expired';
  if (s < 60) return `in ${s}s`;
  if (s < 3600) return `in ${Math.floor(s / 60)}m`;
  if (s < 86400) return `in ${Math.floor(s / 3600)}h`;
  return `in ${Math.floor(s / 86400)}d`;
}

// -- Actions --

window.dynSetModuleState = async function (engineType, enabledValue) {
  const enabled = enabledValue === 'true';
  if (!enabled) {
    const ok = await confirmType(engineType, {
      title: `Disable module '${engineType}'`,
      body: 'Every engine of this type must already be deleted. The module is fully unloaded only after every API node restarts.',
      okLabel: 'Schedule disable',
    });
    if (!ok) return;
  }
  try {
    const result = await api('PUT', `/dynamic/modules/${engineType}`, { enabled });
    toast(
      result.restart_required
        ? `Module '${engineType}' updated; restart every API node`
        : `Module '${engineType}' already matches the running state`,
      true,
    );
    renderDynamicInto(document.getElementById('eclipse-body'));
  } catch (e) { toast(e.message, false); }
};

window.dynShowAddEngine = function () {
  const f = document.getElementById('dyn-engine-form');
  f.classList.toggle('hidden');
  if (f.classList.contains('hidden')) return;
  const usableTypes = (_dynCache.modules || [])
    .filter(m => m.enabled && m.loaded)
    .map(m => (_dynCache.compatibility || [])
      .find(c => c.engine_type === m.engine_type) || m);
  const modulesReported = (_dynCache.modules || []).length > 0;
  const enabled = modulesReported
    ? usableTypes
    : [{ engine_type: 'postgresql' }, { engine_type: 'mysql' }, { engine_type: 'ldap' }];
  const options = enabled.length
    ? enabled.map(c =>
      `<option value="${esc(c.engine_type)}">${esc(c.display_name || c.engine_type)}</option>`
    ).join('')
    : '<option value="" disabled selected>No active modules</option>';
  f.innerHTML = `
    <div class="form-group"><label>Name</label><input type="text" id="dyn-eng-name" placeholder="pg-prod"></div>
    <div class="form-group"><label>Type</label>
      <span class="select-wrap"><select id="dyn-eng-type">
        ${options}
      </select></span></div>
    <div class="form-group"><label>Namespace</label><input type="text" id="dyn-eng-ns" value="default"></div>
    <div class="form-group"><label>Max TTL (seconds)</label><input type="number" id="dyn-eng-maxttl" value="86400"></div>
    <div class="form-group"><label>Connection URL / DSN</label>
      <input type="password" id="dyn-eng-url" placeholder="postgresql://admin:pw@host:5432/db">
      <div class="dim small help-block" id="dyn-eng-help"></div>
      <div class="small help-block" id="dyn-eng-probe"></div></div>
    <div class="btn-group">
      <button class="btn secondary small" data-action="dynTestEngineConnection" ${enabled.length ? '' : 'disabled'}>Test connection</button>
      <button class="btn primary small" data-action="dynCreateEngine" ${enabled.length ? '' : 'disabled'}>Create engine</button>
    </div>`;
  // Placeholder + hint follow the selected backend (CSP forbids inline onchange).
  const typeSel = f.querySelector('#dyn-eng-type');
  const urlInput = f.querySelector('#dyn-eng-url');
  const help = f.querySelector('#dyn-eng-help');
  const HINTS = {
    postgresql: { ph: 'postgresql://admin:pw@host:5432/db',
                  help: 'Admin DSN rhorizon uses to create and drop ephemeral users. Stored encrypted.' },
    mysql:      { ph: 'mysqls://admin:pw@host:3306/db',
                  help: 'Use mysqls:// for verified TLS (ssl_ca, ssl_cert and ssl_key are supported). mysql:// is explicitly unencrypted. Stored encrypted.' },
    ldap:       { ph: '{"url":"ldaps://host:636","bind_dn":"cn=admin,dc=example,dc=com","bind_pw":"pw"}',
                  help: 'JSON blob {"url","bind_dn","bind_pw"} for the bind account. Prefer ldaps://; ldap:// is explicitly unencrypted. Stored encrypted.' },
    redis:      { ph: 'rediss://admin:pw@host:6379/0',
                  help: 'Redis ACL administrator URL. Use rediss:// outside a trusted local transport. Stored encrypted.' },
    cassandra:  { ph: '{"hosts":["db1","db2"],"username":"admin","password":"pw","tls":true,"server_name":"cassandra.internal"}',
                  help: 'JSON connection description. TLS requires a server_name present in every node certificate; add ca_cert for a private CA. Stored encrypted.' },
  };
  const applyHint = () => {
    const h = HINTS[typeSel.value] || HINTS.postgresql;
    urlInput.placeholder = h.ph;
    help.textContent = h.help;
    const probe = document.getElementById('dyn-eng-probe');
    if (probe) probe.textContent = '';
  };
  typeSel.addEventListener('change', applyHint);
  applyHint();
};

window.dynTestEngineConnection = async function () {
  const engine_type = document.getElementById('dyn-eng-type').value;
  const namespace = document.getElementById('dyn-eng-ns').value.trim() || 'default';
  const connection_url = document.getElementById('dyn-eng-url').value;
  const result = document.getElementById('dyn-eng-probe');
  if (!connection_url) { toast('Connection URL is required', false); return; }
  result.innerHTML = '<span class="dim">Testing read-only connection...</span>';
  try {
    const probe = await api('POST', '/dynamic/engines/test-connection', {
      engine_type, namespace, connection_url,
    });
    const validated = probe.compatibility === 'validated';
    const version = probe.server_version || 'version not reported';
    result.innerHTML = `<span class="badge ${validated ? 'green' : 'orange'}">${validated ? 'Validated' : 'Connected, unvalidated'}</span>
      ${esc(probe.product)} ${esc(version)}`;
  } catch (e) {
    result.innerHTML = `<span class="badge red">Connection failed</span> ${esc(e.message)}`;
  }
};

window.dynCreateEngine = async function () {
  const name = document.getElementById('dyn-eng-name').value.trim();
  const engine_type = document.getElementById('dyn-eng-type').value;
  const namespace = document.getElementById('dyn-eng-ns').value.trim() || 'default';
  const max_ttl_seconds = parseInt(document.getElementById('dyn-eng-maxttl').value, 10) || 86400;
  const connection_url = document.getElementById('dyn-eng-url').value;
  if (!name || !connection_url) { toast('Name and connection URL are required', false); return; }
  try {
    await api('POST', '/dynamic/engines', { name, engine_type, namespace, connection_url, max_ttl_seconds });
    toast(`Engine '${name}' created`, true);
    renderDynamicInto(document.getElementById('eclipse-body'));
  } catch (e) { toast(e.message, false); }
};

window.dynDeleteEngine = async function (id) {
  const eng = (_dynCache.engines || []).find(e => e.id === id);
  const ok = await confirmType(eng ? eng.name : id, {
    title: `Delete engine '${eng ? eng.name : id}'`,
    body: 'Revokes every pending target credential, then removes the engine and its roles. Deletion stops if any revocation cannot be verified.',
    okLabel: 'Delete',
  });
  if (!ok) return;
  try {
    await api('DELETE', `/dynamic/engines/${id}`);
    toast('Engine deleted', true);
    if (_dynSelectedEngine === id) _dynSelectedEngine = null;
    renderDynamicInto(document.getElementById('eclipse-body'));
  } catch (e) { toast(e.message, false); }
};

window.dynSelectEngine = function (id) {
  _dynSelectedEngine = id || null;
  _dynRenderEngines();
};

window.dynShowAddRole = function (engineId) {
  const f = document.getElementById(`dyn-role-form-${engineId}`);
  f.classList.toggle('hidden');
  if (f.classList.contains('hidden')) return;
  const engine = (_dynCache.engines || []).find(e => e.id === engineId);
  const capability = engine && (_dynCache.compatibility || [])
    .find(c => c.engine_type === engine.engine_type);
  const creationExample = capability ? capability.creation_example : 'CREATE ROLE "{{name}}"';
  const revocationExample = capability ? capability.revocation_example : 'DROP ROLE IF EXISTS "{{name}}"';
  f.innerHTML = `
    <div class="form-group"><label>Name</label><input type="text" id="dyn-role-name" placeholder="readonly"></div>
    <div class="form-group"><label>Default TTL (seconds)</label><input type="number" id="dyn-role-ttl" value="3600"></div>
    <div class="form-group"><label>Max TTL (seconds)</label><input type="number" id="dyn-role-maxttl" value="86400"></div>
    <div class="form-group"><label>Creation template</label>
      <textarea id="dyn-role-create" rows="3" placeholder="${esc(creationExample)}"></textarea></div>
    <div class="form-group"><label>Revocation template</label>
      <textarea id="dyn-role-revoke" rows="2" placeholder="${esc(revocationExample)}"></textarea>
      <div class="dim small help-block">The reaper runs the revocation template at lease
        expiry, so make it idempotent (DROP ... IF EXISTS). Avoid a backend
        <code>VALID UNTIL</code> in creation if you want renew to extend the lease.</div></div>
    <div class="btn-group"><button class="btn primary small" data-action="dynCreateRole" data-arg="${esc(engineId)}">Create role</button></div>`;
};

window.dynCreateRole = async function (engineId) {
  const name = document.getElementById('dyn-role-name').value.trim();
  const creation_sql = document.getElementById('dyn-role-create').value.trim();
  const revocation_sql = document.getElementById('dyn-role-revoke').value.trim();
  const default_ttl_seconds = parseInt(document.getElementById('dyn-role-ttl').value, 10) || 3600;
  const max_ttl_seconds = parseInt(document.getElementById('dyn-role-maxttl').value, 10) || 86400;
  if (!name || !creation_sql || !revocation_sql) { toast('Name and both templates are required', false); return; }
  try {
    await api('POST', `/dynamic/engines/${engineId}/roles`, {
      name, creation_sql, revocation_sql, default_ttl_seconds, max_ttl_seconds,
    });
    toast(`Role '${name}' created`, true);
    _dynRenderRoles(engineId);
  } catch (e) { toast(e.message, false); }
};

window.dynMintCreds = async function (engineId, roleName) {
  try {
    const r = await api('POST', `/dynamic/engines/${engineId}/creds/${roleName}`, {});
    const dn = r.dn ? `<div>DN: <code>${esc(r.dn)}</code></div>` : '';
    const reveal = document.getElementById('dyn-reveal');
    if (reveal) {
      reveal.innerHTML = `
        <div class="card">
          <div class="card-title">Credential minted, shown once</div>
          <div>Username: <code>${esc(r.username)}</code></div>
          <div>Password: <span class="secret-value">${esc(r.password)}</span>
            <button class="btn tiny" data-action="copy-text" data-text="${esc(r.password)}">Copy</button></div>
          ${dn}
          <div class="dim small">Lease ${esc(r.lease_id)}, expires ${esc(r.expires_at)}.
            The reaper drops this credential at expiry.</div>
        </div>`;
    }
    _dynCache.leases = (await api('GET', '/dynamic/leases')).items || [];
    _dynRenderLeases();
  } catch (e) { toast(e.message, false); }
};

window.dynRenewLease = async function (id) {
  try {
    const r = await api('POST', `/dynamic/leases/${id}/renew`, { ttl_seconds: 3600 });
    toast(`Renewed ${r.username}, expires ${r.expires_at}`, true);
    _dynCache.leases = (await api('GET', '/dynamic/leases')).items || [];
    _dynRenderLeases();
  } catch (e) { toast(e.message, false); }
};

window.dynRevokeLease = async function (id) {
  const ls = (_dynCache.leases || []).find(l => l.id === id);
  const ok = await confirmType(ls ? ls.username : id, {
    title: `Revoke lease '${ls ? ls.username : id}'`,
    body: 'Revokes the target credential immediately. Any app still using it loses access at once.',
    okLabel: 'Revoke',
  });
  if (!ok) return;
  try {
    await api('POST', `/dynamic/leases/${id}/revoke`);
    toast('Lease revoked', true);
    _dynCache.leases = (await api('GET', '/dynamic/leases')).items || [];
    _dynRenderLeases();
  } catch (e) { toast(e.message, false); }
};
