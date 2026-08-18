// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Nebula, Namespaces (RBAC).
 *
 * First-class view for the namespace lifecycle :
 *   - list namespaces (owner group, RBAC mode, secret count)
 *   - create   : choose owner_group + initial enforce_membership
 *                (one-way ratchet, set carefully)
 *   - edit     : change owner / UPGRADE enforce_membership
 *                (downgrade impossible, DB trigger ; rename impossible, AAD)
 *   - archive  : soft-delete (refused if non-empty)
 *
 * All mutations go through the same admin + 2FA + rate-limit gate as the
 * API (a `purpose=namespace_mutation` challenge + 2FA proof). When the
 * vault has 2FA mode='none' the fields are skipped server-side.
 */
'use strict';

let _nebulaCache = null;
let _nebulaSearch = '';

async function renderNebula(el, opts = {}) {
  if (isSealed()) { el.innerHTML = sealedHtml(); return; }
  try {
    if (!opts.useCache || _nebulaCache === null) {
      const [nsResp, gResp] = await Promise.all([
        api('GET', '/namespaces/'),
        api('GET', '/groups/').catch(() => ({ items: [] })),
      ]);
      _nebulaCache = {
        namespaces: nsResp.items || [],
        groups: gResp.items || [],
      };
    }

    const groupsById = Object.fromEntries(
      (_nebulaCache.groups || []).map(g => [g.id, g.name])
    );
    const q = _nebulaSearch.trim().toLowerCase();
    const items = q
      ? _nebulaCache.namespaces.filter(n =>
          (n.name || '').toLowerCase().includes(q) ||
          (groupsById[n.owner_group_id] || '').toLowerCase().includes(q))
      : _nebulaCache.namespaces;

    let html = `<div class="toolbar toolbar-split">
      <div>
        <input type="search" id="neb-search" class="search-input" data-action="_searchNebula"
          placeholder="Search by name or owner group…" value="${esc(_nebulaSearch)}">
        ${q ? `<span class="search-meta">${items.length} match${items.length === 1 ? '' : 'es'} of ${_nebulaCache.namespaces.length}</span>` : ''}
      </div>
      <button class="btn primary small" data-action="_neb_showCreate">+ New Namespace</button>
    </div>
    <div id="neb-form" class="card form-card hidden"></div>
    <table class="table"><thead><tr>
      <th>Name</th><th>Owner group</th><th>RBAC</th><th>Delete</th><th>Secrets</th><th>State</th><th>Actions</th>
    </tr></thead><tbody>`;

    for (const n of items) {
      const ownerName = groupsById[n.owner_group_id] || `<code>${esc(n.owner_group_id.slice(0,8))}…</code>`;
      const modeBadge = n.enforce_membership
        ? '<span class="tag bad">strict</span>'
        : '<span class="tag">agnostic</span>';
      const dpBadge = (() => {
        switch (n.delete_protection) {
          case 'protected': return '<span class="tag bad">protected</span>';
          case 'soft':      return '<span class="tag">soft</span>';
          default:          return '<span class="tag good">free</span>';
        }
      })();
      const archived = n.archived_at
        ? `<span class="tag neutral">archived ${esc((n.archived_at || '').slice(0,10))}</span>`
        : '<span class="tag good">live</span>';
      html += `<tr>
        <td><strong>${esc(n.name)}</strong></td>
        <td>${esc(ownerName)}</td>
        <td>${modeBadge}</td>
        <td>${dpBadge}</td>
        <td>${n.secret_count != null ? n.secret_count : '-'}</td>
        <td>${archived}</td>
        <td class="actions">
          ${n.archived_at ? '' : `<button class="btn tiny" data-action="_neb_showEdit" data-arg="${esc(n.name)}">Edit</button>`}
          ${n.archived_at ? '' : `<button class="btn tiny danger" data-action="_neb_showArchive" data-arg="${esc(n.name)}">Archive</button>`}
        </td>
      </tr>`;
    }
    html += '</tbody></table>';
    if (!items.length) {
      html += `<div class="empty">${q ? 'No namespaces match your search' : 'No namespaces yet, create one to start'}</div>`;
    }
    html += `<div class="dim small legend-block">
      <strong>RBAC:</strong>
      <code>agnostic</code> uses claim-based access (existing behavior).
      <code>strict</code> requires live group membership for every read/write.
      <strong>Delete:</strong>
      <code>free</code> hard-deletes immediately.
      <code>soft</code> sets <code>deleted_at</code>, reaper purges after retention, restore possible.
      <code>protected</code> requires admin + 2FA, extended retention, no auto-purge.
      <br>
      Both <code>enforce_membership</code> and <code>delete_protection</code> are
      <strong>one-way ratchets</strong>, once raised, the DB trigger refuses to relax them.
      Namespace name is immutable post-creation (AAD bound to current name).
    </div>`;

    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = `<div class="error">${esc(e.message)}</div>`;
  }
}

window._searchNebula = async function (value) {
  _nebulaSearch = value;
  await renderNebula(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('neb-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

// ============================================================================
// Reusable 2FA proof block, common to create / edit / archive forms.
// Emits inputs that the submit handlers read by id (challenge / TOTP / yubikey).
// ============================================================================

function _neb2FABlock(idPrefix) {
  const s = window._vaultStatus || {};
  const showTotp = s.second_factor === 'totp' || s.second_factor === 'any';
  const showYk = s.second_factor === 'yubikey' || s.second_factor === 'any';
  if (!showTotp && !showYk) {
    return '<div class="dim small">2FA not configured, admin scope alone authorises this action.</div>';
  }
  let html = '<fieldset class="form-group fieldset-2fa">';
  html += '<legend class="dim small">2FA proof (purpose=namespace_mutation)</legend>';
  if (showTotp) {
    html += `<div class="form-group">
      <label>TOTP Code</label>
      <input type="text" id="${idPrefix}-totp" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code" maxlength="6">
    </div>`;
  }
  if (showYk) {
    html += `<div class="form-group">
      <label>YubiKey HMAC challenge</label>
      <div class="row-gap">
        <input type="text" id="${idPrefix}-yk-challenge" readonly placeholder="Click Generate" class="flex-1">
        <button type="button" class="btn tiny" data-action="_neb_genChallenge" data-arg="${idPrefix}">Generate</button>
      </div>
      <label class="spaced-top">YubiKey response (hex, 40 chars)</label>
      <input type="text" id="${idPrefix}-yk-resp" placeholder="ykchalresp -2 -x &lt;challenge&gt;">
    </div>`;
  }
  html += '</fieldset>';
  return html;
}

window._neb_genChallenge = async function (idPrefix) {
  try {
    const r = await api('POST', '/challenge?purpose=namespace_mutation');
    const inp = document.getElementById(`${idPrefix}-yk-challenge`);
    if (inp) inp.value = r.challenge;
  } catch (e) {
    toast(e.message, false);
  }
};

function _neb_collect2FA(idPrefix) {
  const out = {};
  const totp = document.getElementById(`${idPrefix}-totp`)?.value?.trim();
  if (totp) out.totp_code = totp;
  const ch = document.getElementById(`${idPrefix}-yk-challenge`)?.value?.trim();
  const yk = document.getElementById(`${idPrefix}-yk-resp`)?.value?.trim();
  if (ch && yk) {
    out.challenge = ch;
    out.yubikey_response = yk;
  }
  return out;
}

// ============================================================================
// Create
// ============================================================================

window._neb_showCreate = function () {
  const f = document.getElementById('neb-form');
  f.classList.toggle('hidden');
  if (f.classList.contains('hidden')) return;

  const groupOptions = (_nebulaCache.groups || [])
    .map(g => `<option value="${esc(g.id)}">${esc(g.name)} (${esc(g.source)})</option>`)
    .join('');

  f.innerHTML = `
    <h3>Create namespace</h3>
    <div class="form-group">
      <label>Name</label>
      <input type="text" id="nc-name" placeholder="prod-banking" maxlength="128">
    </div>
    <div class="form-group">
      <label>Owner group</label>
      <span class="select-wrap"><select id="nc-owner">${groupOptions}</select></span>
      <div class="dim small">Members of this group will have access in strict mode. Manage members under Cluster.</div>
    </div>
    <div class="form-group">
      <label><input type="checkbox" id="nc-enforce"> Enforce membership (strict RBAC)</label>
      <div class="dim small">If on, every read/write checks live group membership. <strong>One-way ratchet</strong>, cannot be relaxed afterwards.</div>
    </div>
    <div class="form-group">
      <label>Delete protection</label>
      <span class="select-wrap"><select id="nc-dp">
        <option value="free" selected>free, hard delete (default)</option>
        <option value="soft">soft, soft-delete + retention + restore</option>
        <option value="protected">protected, admin + 2FA + extended retention</option>
      </select></span>
      <div class="dim small"><strong>One-way ratchet</strong> : free → soft → protected, never backwards. Choose carefully.</div>
    </div>
    ${_neb2FABlock('nc')}
    <div class="row-gap">
      <button class="btn primary small" data-action="_neb_create">Create</button>
      <button class="btn secondary small" data-action="_neb_showCreate">Cancel</button>
    </div>`;
};

window._neb_create = async function () {
  const body = {
    name: document.getElementById('nc-name').value.trim(),
    owner_group_id: document.getElementById('nc-owner').value,
    enforce_membership: document.getElementById('nc-enforce').checked,
    delete_protection: document.getElementById('nc-dp').value,
    ..._neb_collect2FA('nc'),
  };
  if (!body.name) { toast('Name required', false); return; }
  if (!body.owner_group_id) { toast('Owner group required', false); return; }
  try {
    await api('POST', '/namespaces/', body);
    toast(`Namespace '${body.name}' created`, true);
    _nebulaCache = null;
    renderNebula(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

// ============================================================================
// Edit
// ============================================================================

window._neb_showEdit = function (name) {
  const ns = (_nebulaCache.namespaces || []).find(n => n.name === name);
  if (!ns) return;
  const f = document.getElementById('neb-form');
  f.classList.remove('hidden');
  const groupOptions = (_nebulaCache.groups || [])
    .map(g => `<option value="${esc(g.id)}" ${g.id === ns.owner_group_id ? 'selected' : ''}>${esc(g.name)}</option>`)
    .join('');
  const upgradeAvail = !ns.enforce_membership;

  f.innerHTML = `
    <h3>Edit ${esc(ns.name)}</h3>
    <div class="dim small">Namespace name is immutable. To rename, create a new namespace, transfer secrets, archive this one.</div>
    <input type="hidden" id="ne-orig-name" value="${esc(ns.name)}">
    <div class="form-group">
      <label>Owner group</label>
      <span class="select-wrap"><select id="ne-owner">${groupOptions}</select></span>
    </div>
    <div class="form-group">
      <label>
        <input type="checkbox" id="ne-enforce" ${ns.enforce_membership ? 'checked disabled' : ''}>
        Upgrade to strict RBAC (enforce_membership=true)
      </label>
      <div class="dim small">${upgradeAvail
        ? 'Once on, this cannot be reversed. All non-members will be denied at next request. Coordinate with dependent teams first.'
        : 'Already strict. Cannot relax, DB trigger refuses.'}</div>
    </div>
    <div class="form-group">
      <label>Delete protection</label>
      <span class="select-wrap"><select id="ne-dp">
        ${['free','soft','protected'].map(v => {
          const cur = ns.delete_protection || 'free';
          const rank = {free:0, soft:1, protected:2};
          const dis = rank[v] < rank[cur] ? 'disabled' : '';
          const sel = v === cur ? 'selected' : '';
          const lbl = v === 'free' ? 'free, hard delete'
                    : v === 'soft' ? 'soft, retention + restore'
                    : 'protected, admin + 2FA + extended retention';
          return `<option value="${v}" ${sel} ${dis}>${lbl}</option>`;
        }).join('')}
      </select></span>
      <div class="dim small">One-way ratchet, only upgrades (free → soft → protected) are allowed.</div>
    </div>
    ${_neb2FABlock('ne')}
    <div class="row-gap">
      <button class="btn primary small" data-action="_neb_update">Save</button>
      <button class="btn secondary small" data-action="_neb_showEdit" data-arg="${esc(ns.name)}">Cancel</button>
    </div>`;
};

window._neb_update = async function () {
  const orig = document.getElementById('ne-orig-name').value;
  const owner = document.getElementById('ne-owner').value;
  const enforceCb = document.getElementById('ne-enforce');
  const dpSel = document.getElementById('ne-dp');
  const body = { ..._neb_collect2FA('ne') };
  body.owner_group_id = owner;
  if (!enforceCb.disabled && enforceCb.checked) body.enforce_membership = true;
  if (dpSel) body.delete_protection = dpSel.value;
  try {
    await api('PUT', `/namespaces/${encodeURIComponent(orig)}`, body);
    toast('Namespace updated', true);
    _nebulaCache = null;
    renderNebula(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

// ============================================================================
// Archive
// ============================================================================

window._neb_showArchive = function (name) {
  const f = document.getElementById('neb-form');
  f.classList.remove('hidden');
  f.innerHTML = `
    <h3>Archive ${esc(name)}</h3>
    <div class="dim small">Soft-delete : sets <code>archived_at</code>. Refused if the namespace
    has any non-archived secrets, delete or migrate them first.</div>
    <input type="hidden" id="na-name" value="${esc(name)}">
    ${_neb2FABlock('na')}
    <div class="row-gap spaced-top">
      <button class="btn danger small" data-action="_neb_archive">Archive</button>
      <button class="btn secondary small" data-action="_neb_showArchive" data-arg="${esc(name)}">Cancel</button>
    </div>`;
};

window._neb_archive = async function () {
  const name = document.getElementById('na-name').value;
  const ok = await confirmType(name, {
    title: `Archive namespace '${name}'`,
    body: 'Sets `archived_at`, the namespace becomes invisible to listing but its rows persist for audit. Reversible ONLY by a manual SQL UPDATE on the vault DB. Refused if any non-archived secret still references the namespace.',
    okLabel: 'Archive',
  });
  if (!ok) return;
  const body = { ..._neb_collect2FA('na') };
  try {
    await api('DELETE', `/namespaces/${encodeURIComponent(name)}`, body);
    toast(`Namespace '${name}' archived`, true);
    _nebulaCache = null;
    renderNebula(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};
