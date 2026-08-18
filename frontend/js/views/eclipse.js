// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Eclipse, Secrets CRUD with pagination + auto-clear */
'use strict';

let _secretPage = 0;
let _secretSearch = '';
let _secretsCache = null;
let _eclipseTab = 'secrets'; // 'secrets' | 'dynamic' | 'pki'

function _eclipseTabBar() {
  const t = (id, label) =>
    `<button class="btn small ${_eclipseTab === id ? 'primary' : 'secondary'}" data-action="_setEclipseTab" data-arg="${id}">${label}</button>`;
  return `<div class="toolbar"><div class="btn-group">${t('secrets', 'Secrets')}${t('dynamic', 'Dynamic')}${t('pki', 'PKI')}</div></div>`;
}

window._setEclipseTab = function (tab) {
  _eclipseTab = tab;
  renderEclipse(document.getElementById('main'));
};

async function renderEclipse(el, opts = {}) {
  if (isSealed()) { el.innerHTML = sealedHtml(); return; }
  if (_eclipseTab === 'dynamic') {
    el.innerHTML = _eclipseTabBar() + '<div id="eclipse-body"></div>';
    renderDynamicInto(document.getElementById('eclipse-body'));
    return;
  }
  if (_eclipseTab === 'pki') {
    el.innerHTML = _eclipseTabBar() + '<div id="eclipse-body"></div>';
    renderPkiInto(document.getElementById('eclipse-body'));
    return;
  }
  try {
    if (!opts.useCache || _secretsCache === null) {
      const r = await api('GET', '/secrets/');
      _secretsCache = r.items || [];
    }
    const q = _secretSearch.trim().toLowerCase();
    const items = q
      ? _secretsCache.filter(s =>
          (s.name || '').toLowerCase().includes(q) ||
          (s.namespace || '').toLowerCase().includes(q))
      : _secretsCache;

    const total = items.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    const page = Math.min(_secretPage, Math.max(0, pages - 1));
    const slice = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

    let html = _eclipseTabBar() + `<div class="toolbar toolbar-split">
      <div>
        <input type="search" id="eclipse-search" class="search-input" data-action="_searchEclipse"
          placeholder="Search by name or namespace…" value="${esc(_secretSearch)}">
        ${q ? `<span class="search-meta">${total} match${total === 1 ? '' : 'es'} of ${_secretsCache.length}</span>` : ''}
      </div>
      <button class="btn primary small" data-action="showCreateSecret">+ New Secret</button>
    </div>
    <div id="secret-form" class="card form-card hidden"></div>
    <table class="table"><thead><tr>
      <th>Name</th><th>Namespace</th><th>Version</th><th>Updated</th><th>Actions</th>
    </tr></thead><tbody>`;
    for (const s of slice) {
      html += `<tr>
        <td><strong>${esc(s.name)}</strong></td>
        <td><span class="tag">${esc(s.namespace)}</span></td>
        <td>v${s.version}</td>
        <td>${timeAgo(s.updated_at)}</td>
        <td class="actions">
          <button class="btn tiny secondary" data-action="readSecret" data-arg="${esc(s.name)}" data-arg2="${esc(s.namespace)}">Read</button>
          <button class="btn tiny secondary" data-action="readSecretPrevious" data-arg="${esc(s.name)}" data-arg2="${esc(s.namespace)}" title="Prior value if still in its rotation grace window">Prev</button>
          <button class="btn tiny" data-action="editSecret" data-arg="${esc(s.name)}" data-arg2="${esc(s.namespace)}">Edit</button>
          <button class="btn tiny danger" data-action="deleteSecret" data-arg="${esc(s.name)}" data-arg2="${esc(s.namespace)}">Del</button>
        </td>
      </tr>`;
    }
    html += '</tbody></table>';
    if (!total) html += `<div class="empty">${q ? 'No secrets match your search' : 'No secrets stored'}</div>`;

    html += renderPagination(page, pages, '_goSecretPage');
    el.innerHTML = html;
  } catch (e) { el.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
}

window._goSecretPage = function(p) {
  _secretPage = parseInt(p);
  renderEclipse(document.getElementById('main'), { useCache: true });
};

window._searchEclipse = async function(value) {
  _secretSearch = value;
  _secretPage = 0;
  await renderEclipse(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('eclipse-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

function showCreateSecret() {
  const f = document.getElementById('secret-form');
  f.classList.toggle('hidden');
  if (!f.classList.contains('hidden')) {
    f.innerHTML = `
      <div class="form-group"><label>Name</label><input type="text" id="cs-name" placeholder="my-secret"></div>
      <div class="form-group"><label>Value</label><input type="password" id="cs-value" placeholder="secret value"></div>
      <div class="form-group"><label>Namespace</label><input type="text" id="cs-ns" value="default"></div>
      <div class="form-group">
        <label class="honey-checkbox">
          <input type="checkbox" id="cs-honey">
          <strong>Honey secret (decoy)</strong>
          <span class="dim small">- any read of this secret fires a CRITICAL alert. Pick an attractive name (prod-pgsql-master, wg-server-private) and a fake value.</span>
        </label>
      </div>
      <button class="btn primary small" data-action="createSecret">Create</button>`;
  }
}

async function createSecret() {
  const name = document.getElementById('cs-name').value;
  const value = document.getElementById('cs-value').value;
  const ns = document.getElementById('cs-ns').value || 'default';
  const isHoney = document.getElementById('cs-honey')?.checked || false;
  if (!name || !value) return toast('Name and value required', false);
  try {
    const body = { name, value, namespace: ns };
    if (isHoney) body.is_honey = true;
    await api('POST', '/secrets/', body);
    toast(`Secret '${name}' created`, true);
    renderEclipse(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}

async function readSecret(name, namespace) {
  return _revealSecret(name, namespace, false);
}

// Prior value during the rotation grace window (GET ?previous). 404 when no
// version is in grace -> a clear toast rather than an empty reveal.
window.readSecretPrevious = function (name, namespace) {
  return _revealSecret(name, namespace, true);
};

async function _revealSecret(name, namespace, previous) {
  try {
    const params = [];
    if (namespace) params.push(`namespace=${encodeURIComponent(namespace)}`);
    if (previous) params.push('previous=true');
    const qs = params.length ? `?${params.join('&')}` : '';
    const r = await api('GET', `/secrets/${name}${qs}`);
    const f = document.getElementById('secret-form');
    f.classList.remove('hidden');
    const graceTag = previous ? ' <span class="tag">previous (grace)</span>' : '';
    f.innerHTML = `<div class="card-title">${esc(name)} <span class="tag">${esc(r.namespace || namespace || '')}</span> <span class="tag">v${r.version}</span>${graceTag}</div>
      <div class="secret-value" id="sv-val">${esc(r.value)}</div>
      <button class="btn tiny" data-action="copy-el" data-src="sv-val">Copy</button>
      <span class="dim" id="sv-timer"> (auto-clear in 30s)</span>`;
    // Auto-clear after 30s
    setTimeout(() => {
      const val = document.getElementById('sv-val');
      if (val) { val.textContent = '***cleared***'; val.className = 'secret-value dim'; }
      const timer = document.getElementById('sv-timer');
      if (timer) timer.textContent = '';
    }, 30000);
  } catch (e) {
    toast(
      previous && e.status === 404
        ? 'No previous value in a grace window for this secret'
        : e.message,
      false
    );
  }
}

async function deleteSecret(name, namespace) {
  // Type-to-confirm, DELETE on a secret in a `free`-mode namespace
  // is irreversible (no soft-delete tombstone). Even in `soft` /
  // `protected` modes the operator should think twice before nuking.
  const label = namespace ? `${namespace}/${name}` : name;
  const ok = await confirmType(name, {
    title: `Delete secret '${label}'`,
    body: 'In `free` namespaces this is irreversible. In `soft` / `protected` namespaces the secret is soft-deleted with a retention window, recoverable via /restore until the reaper purges.',
    okLabel: 'Delete',
  });
  if (!ok) return;
  try {
    const qs = namespace ? `?namespace=${encodeURIComponent(namespace)}` : '';
    await api('DELETE', `/secrets/${name}${qs}`);
    toast(`Deleted '${label}'`, true);
    renderEclipse(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}

function editSecret(name, namespace) {
  // Update an existing secret's value in place (new version). Goes through
  // PUT /secrets/{name}, secrets:w + namespace check + chained audit, server
  // side. Renders an inline form card (same pattern as Nebula edit) into the
  // shared #secret-form panel instead of a native prompt; Cancel leaves the
  // secret untouched.
  // Rotation grace window. Server-reported, and 0 (the default) means an update
  // supersedes the old value at once -- nothing to say. When an operator has
  // raised it, the PREVIOUS value stays readable via GET ?previous for that
  // long, so someone rotating a LEAKED secret from here needs the emergency
  // path or they will believe the old value is already gone.
  const graceSecs = Number((window._vaultStatus || {}).secret_grace_seconds) || 0;
  const graceNotice = graceSecs > 0
    ? `<div class="info-box info-notice small">
         The previous value stays readable via <code>?previous</code> for
         <strong>${graceSecs}s</strong> after saving, so consumers can finish a
         cutover. Rotating because of a leak? Tick emergency: it clears the
         grace immediately and the old value stops resolving.
         <label class="mt-8"><input type="checkbox" id="es-emergency">
           Emergency &mdash; no grace window</label>
       </div>`
    : '';

  const f = document.getElementById('secret-form');
  f.classList.remove('hidden');
  f.innerHTML = `
    <div class="card-title">Edit secret <strong>${esc(name)}</strong> <span class="tag">${esc(namespace || 'default')}</span></div>
    <div class="dim small">Saving writes a new version. Name and namespace are immutable.</div>
    ${graceNotice}
    <input type="hidden" id="es-name" value="${esc(name)}">
    <input type="hidden" id="es-ns" value="${esc(namespace || '')}">
    <div class="form-group">
      <label>New value</label>
      <input type="password" id="es-value" placeholder="new secret value" autocomplete="off" spellcheck="false">
    </div>
    <div class="row-gap">
      <button class="btn primary small" data-action="submitEditSecret">Save new version</button>
      <button class="btn secondary small" data-action="cancelEditSecret">Cancel</button>
    </div>`;
  setTimeout(() => document.getElementById('es-value')?.focus(), 0);
}

window.submitEditSecret = async function () {
  const name = document.getElementById('es-name').value;
  const namespace = document.getElementById('es-ns').value;
  const value = document.getElementById('es-value').value;
  const label = namespace ? `${namespace}/${name}` : name;
  if (!value) return toast('Value required', false);
  try {
    const qs = namespace ? `?namespace=${encodeURIComponent(namespace)}` : '';
    // Only sent when the checkbox exists (grace window enabled); the server
    // default is false, so omitting it keeps the documented behaviour.
    const body = { value };
    if (document.getElementById('es-emergency')?.checked) body.emergency = true;
    const r = await api('PUT', `/secrets/${name}${qs}`, body);
    toast(`Updated '${label}' (v${r.version})`, true);
    renderEclipse(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

window.cancelEditSecret = function () {
  const f = document.getElementById('secret-form');
  if (f) { f.classList.add('hidden'); f.innerHTML = ''; }
};
