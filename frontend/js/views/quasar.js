// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Quasar, Token management.
 *
 * Three tabs:
 *   - Tokens: long-lived API tokens (name freeform, no expires_at
 *                  by default, the operator-issued bearers).
 *   - Ephemeral: short-TTL tokens minted by POST /tokens/ephemeral
 *                  (name = `eph-XXXX`, expires_at set, auto-purged by
 *                  the reaper). These are typically minted by rh-watch
 *                  via bootstrap → ephemeral inheritance.
 *   - Pending rotations: restored token metadata awaiting a replacement
 *                  plaintext token.
 *
 * The token response is split client-side by `is_ephemeral`; pending
 * rotations come from their dedicated endpoint and cache.
 */
'use strict';

let _quasarTab = 'tokens'; // 'tokens' | 'ephemeral' | 'pending'
let _tokensCache = null;
let _pendingCache = null;

let _tokenPage = 0;
let _tokenSearch = '';

let _ephPage = 0;
let _ephSearch = '';

let _pendingSearch = '';

async function renderQuasar(el, opts = {}) {
  if (isSealed()) { el.innerHTML = sealedHtml(); return; }
  try {
    if (!opts.useCache || _tokensCache === null) {
      const r = await api('GET', '/tokens/');
      _tokensCache = r.items || [];
    }
    if (!opts.useCache || _pendingCache === null) {
      try {
        const p = await api('GET', '/tokens/pending/');
        _pendingCache = p.items || [];
      } catch {
        // Pending endpoint is optional (admin-only). Treat absent or 403
        // as zero pending stubs so the tab badge still renders sanely.
        _pendingCache = [];
      }
    }

    const pendingBadge = _pendingCache.length
      ? ` <span class="badge revoked">${_pendingCache.length}</span>`
      : '';
    const tabBtn = (id, label, badge = '') =>
      `<button class="btn small ${_quasarTab === id ? 'primary' : 'secondary'}" data-action="_setQuasarTab" data-arg="${id}">${label}${badge}</button>`;

    let html = `<div class="toolbar toolbar-split">
      <div class="btn-group">
        ${tabBtn('tokens', 'Tokens')}
        ${tabBtn('ephemeral', 'Ephemeral')}
        ${tabBtn('pending', 'Pending rotations', pendingBadge)}
      </div>
    </div>`;

    if (_quasarTab === 'ephemeral') {
      html += _renderEphemeralTab();
    } else if (_quasarTab === 'pending') {
      html += _renderPendingTab();
    } else {
      html += _renderTokensTab();
    }
    el.innerHTML = html;
  } catch (e) { el.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
}

window._setQuasarTab = function (tab) {
  _quasarTab = tab;
  renderQuasar(document.getElementById('main'), { useCache: true });
};

// ============================================================================
// Tab : Tokens (long-lived API tokens)
// ============================================================================

function _renderTokensTab() {
  const all = (_tokensCache || []).filter(t => !t.is_ephemeral);
  const q = _tokenSearch.trim().toLowerCase();
  const items = q
    ? all.filter(t => {
        if ((t.name || '').toLowerCase().includes(q)) return true;
        if ((t.allowed_ips || '').toLowerCase().includes(q)) return true;
        const ns = (t.permissions && t.permissions.namespaces) || [];
        if (Array.isArray(ns) && ns.some(n => String(n).toLowerCase().includes(q))) return true;
        return JSON.stringify(t.permissions || {}).toLowerCase().includes(q);
      })
    : all;

  const total = items.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const page = Math.min(_tokenPage, Math.max(0, pages - 1));
  const slice = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  let html = `<div class="toolbar toolbar-split">
    <div>
      <input type="search" id="quasar-search" class="search-input" data-action="_searchTokens"
        placeholder="Search by name, namespace or IP…" value="${esc(_tokenSearch)}">
      ${q ? `<span class="search-meta">${total} match${total === 1 ? '' : 'es'} of ${all.length}</span>` : ''}
    </div>
    <button class="btn primary small" data-action="showCreateToken">+ New Token</button>
  </div>
  <div id="token-form" class="card form-card hidden"></div>
  <table class="table"><thead><tr>
    <th>Name</th><th>Permissions</th><th>IP allowlist</th><th>Status</th><th>Last Used</th><th>Actions</th>
  </tr></thead><tbody>`;
  const NEW_WINDOW_MS = 7 * 24 * 3600 * 1000;
  for (const t of slice) {
    const status = t.active ? 'active' : 'revoked';
    const ipCell = t.allowed_ips
      ? `<code>${esc(t.allowed_ips)}</code>`
      : '<span class="dim">any</span>';
    // Badge `NEW` (green) on a token that came from a pending rotation in
    // the last 7 days AND that no client has used yet. As soon as a client
    // touches it, last_used_at gets set and the badge disappears.
    const rotatedAt = t.rotated_at ? new Date(t.rotated_at).getTime() : 0;
    const isFreshRotation = rotatedAt
      && (Date.now() - rotatedAt) < NEW_WINDOW_MS
      && !t.last_used_at;
    const newBadge = isFreshRotation
      ? ' <span class="badge active" title="Rotated from a restore stub, no client has used it yet">NEW</span>'
      : '';
    html += `<tr class="${t.active ? '' : 'dimmed'}">
      <td><strong>${esc(t.name)}</strong>${newBadge}</td>
      <td><code>${esc(JSON.stringify(t.permissions))}</code></td>
      <td>${ipCell}</td>
      <td><span class="badge ${status}">${status}</span></td>
      <td>${timeAgo(t.last_used_at)}</td>
      <td class="actions">${t.active ? `<button class="btn tiny secondary" data-action="setTokenIps" data-arg="${esc(t.id)}">IPs</button> <button class="btn tiny" data-action="rotateToken" data-arg="${esc(t.id)}">Rotate</button> <button class="btn tiny danger" data-action="revokeToken" data-arg="${esc(t.id)}">Revoke</button>` : ''}</td>
    </tr>`;
  }
  html += '</tbody></table>';
  if (!total) html += `<div class="empty">${q ? 'No tokens match your search' : 'No tokens'}</div>`;
  html += renderPagination(page, pages, '_goTokenPage');
  return html;
}

window._goTokenPage = function (p) {
  _tokenPage = parseInt(p);
  _quasarTab = 'tokens';
  renderQuasar(document.getElementById('main'), { useCache: true });
};

window._searchTokens = async function (value) {
  _tokenSearch = value;
  _tokenPage = 0;
  await renderQuasar(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('quasar-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

// ============================================================================
// Tab : Ephemeral (short-TTL tokens, name = eph-XXXX)
// ============================================================================

function _renderEphemeralTab() {
  const all = (_tokensCache || []).filter(t => t.is_ephemeral);
  const q = _ephSearch.trim().toLowerCase();
  const items = q
    ? all.filter(t => {
        if ((t.name || '').toLowerCase().includes(q)) return true;
        if ((t.allowed_ips || '').toLowerCase().includes(q)) return true;
        if ((t.created_by || '').toLowerCase().includes(q)) return true;
        const ns = (t.permissions && t.permissions.namespaces) || [];
        if (Array.isArray(ns) && ns.some(n => String(n).toLowerCase().includes(q))) return true;
        return JSON.stringify(t.permissions || {}).toLowerCase().includes(q);
      })
    : all;

  const total = items.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const page = Math.min(_ephPage, Math.max(0, pages - 1));
  const slice = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  let html = `<div class="toolbar toolbar-split">
    <div>
      <input type="search" id="quasar-eph-search" class="search-input" data-action="_searchEphemerals"
        placeholder="Search by eph-name, parent or namespace…" value="${esc(_ephSearch)}">
      ${q ? `<span class="search-meta">${total} match${total === 1 ? '' : 'es'} of ${all.length}</span>` : ''}
    </div>
    <span class="dim small">Auto-minted by rh-watch / API; auto-purged by the reaper at expiry.</span>
  </div>
  <table class="table"><thead><tr>
    <th>Name</th><th>Parent</th><th>Permissions</th><th>IP allowlist</th><th>Created</th><th>Expires</th><th>Status</th><th>Actions</th>
  </tr></thead><tbody>`;
  for (const t of slice) {
    const exp = t.expires_at ? new Date(t.expires_at).getTime() : 0;
    const expired = exp && exp < Date.now();
    const expDisplay = t.expires_at
      ? (expired ? '<span class="dim">expired</span>' : timeFromNow(t.expires_at))
      : '-';
    const status = !t.active
      ? '<span class="badge revoked">revoked</span>'
      : expired
      ? '<span class="badge revoked">expired</span>'
      : '<span class="badge active">active</span>';
    const ipCell = t.allowed_ips
      ? `<code>${esc(t.allowed_ips)}</code>`
      : '<span class="dim">any</span>';
    html += `<tr class="${(t.active && !expired) ? '' : 'dimmed'}">
      <td><code>${esc(t.name)}</code></td>
      <td><span class="dim">${esc(t.created_by || '-')}</span></td>
      <td><code>${esc(JSON.stringify(t.permissions))}</code></td>
      <td>${ipCell}</td>
      <td>${timeAgo(t.created_at)}</td>
      <td>${expDisplay}</td>
      <td>${status}</td>
      <td class="actions">${t.active && !expired ? `<button class="btn tiny danger" data-action="revokeToken" data-arg="${esc(t.id)}">Revoke</button>` : ''}</td>
    </tr>`;
  }
  html += '</tbody></table>';
  if (!total) html += `<div class="empty">${q ? 'No ephemeral tokens match your search' : 'No ephemeral tokens currently active'}</div>`;
  html += renderPagination(page, pages, '_goEphPage');
  return html;
}

window._goEphPage = function (p) {
  _ephPage = parseInt(p);
  _quasarTab = 'ephemeral';
  renderQuasar(document.getElementById('main'), { useCache: true });
};

window._searchEphemerals = async function (value) {
  _ephSearch = value;
  _ephPage = 0;
  await renderQuasar(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('quasar-eph-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

// ============================================================================
// Create token (long-lived only, ephemerals are minted programmatically)
// ============================================================================

function showCreateToken() {
  const f = document.getElementById('token-form');
  f.classList.toggle('hidden');
  if (!f.classList.contains('hidden')) {
    f.innerHTML = `
      <div class="form-group"><label>Name</label><input type="text" id="ct-name" placeholder="my-token"></div>
      <div class="form-group"><label>Permissions (JSON)</label><input type="text" id="ct-perms" value='{"secrets":"r"}'>
      <div class="muted small help-block">Least privilege by default. Click "Available Permissions" below for upgrade patterns (rw, namespaces, admin, IP allowlist).</div></div>
      <div class="form-group">
        <label>IP allowlist <span class="muted small">(comma-separated CIDRs / IPs, empty = any)</span></label>
        <input type="text" id="ct-ips" placeholder="10.0.0.1, 10.0.0.1, 10.89.0.0/16">
        <div class="muted small help-block">
          Restricts where this token may be used. The vault checks the request's client IP against this list and rejects it with <code>403 Token not allowed from this IP</code> if not matched. Bare IPs are treated as <code>/32</code> (v4) / <code>/128</code> (v6).
          <br><br>
          <strong>Lists are supported</strong>, comma-separated, mix of single IPs and CIDRs, IPv4 + IPv6. Example: <code>10.0.0.1, 10.0.0.1, 2001:db8::/64</code>.
          <br><br>
          <strong>Lateral-movement attacks: narrower = safer.</strong> If a token is leaked, the allowlist limits where it can be replayed from. An explicit list of caller IPs (<code>10.0.0.1, 10.0.0.1</code>) or a tight CIDR (<code>/24</code>, <code>/27</code>) means a compromised host elsewhere on the LAN can't reuse the token. Wide ranges like <code>10.0.0.0/8</code> or full RFC 1918 effectively disable the protection.
          <br><br>
          <strong>Reference ranges</strong> (use as ceilings, not as defaults):
          <ul class="help-list">
            <li>RFC 1918 (private IPv4): <code>10.0.0.0/8</code>, <code>172.16.0.0/12</code>, <code>192.168.0.0/16</code></li>
            <li>IPv6 ULA: <code>fc00::/7</code></li>
            <li>Podman default bridge <code>podman</code>: <code>10.89.0.0/16</code></li>
            <li>Docker default bridge <code>docker0</code>: <code>172.17.0.0/16</code> (user-defined bridges allocate other /16s from <code>172.16.0.0/12</code>)</li>
            <li>VPN: whatever subnet you assigned (e.g. <code>10.0.0.1/24</code>)</li>
          </ul>
        </div>
      </div>
      <div class="form-group">
        <label class="honey-checkbox">
          <input type="checkbox" id="ct-honey">
          <strong>Honeytoken (decoy)</strong>
          <span class="dim small">- any auth using this token fires a CRITICAL alert. Pick an attractive name (prod-pgsql-master, aws-iam) so attackers want to try it.</span>
        </label>
      </div>
      <div class="btn-group">
        <button class="btn primary small" data-action="createToken">Create</button>
        <button class="btn secondary small" data-action="togglePermsHelp">Available Permissions</button>
      </div>
      <div id="perms-help" class="hidden mt-12">
        <table class="table perms-table">
          <thead><tr><th>Scope</th><th>r</th><th>w</th><th>rw</th></tr></thead>
          <tbody>
            <tr><td><code>secrets</code></td><td>read</td><td>write</td><td>read + write</td></tr>
            <tr><td><code>tokens</code></td><td>list</td><td>create / revoke</td><td>both</td></tr>
            <tr><td><code>audit</code></td><td>read logs</td><td>-</td><td>-</td></tr>
            <tr><td><code>cluster</code></td><td>HA status</td><td>node lifecycle</td><td>both</td></tr>
            <tr><td><code>admin</code></td><td colspan="3">full access (seal, unseal, 2FA, all scopes)</td></tr>
          </tbody>
        </table>
        <div class="card-title mt-12">Namespace scoping</div>
        <p class="dim">Add <code>"namespaces": ["ns1", "ns2"]</code> to restrict the token to specific namespaces. Without this key, the token sees <em>all</em> namespaces, avoid for production tokens.</p>
        <div class="card-title mt-12">Examples</div>
        <table class="table perms-table">
          <thead><tr><th>JSON value</th><th>Result</th></tr></thead>
          <tbody>
            <tr><td><code>{"secrets": "r"}</code></td><td>read-only access to all namespaces</td></tr>
            <tr><td><code>{"secrets": "r", "namespaces": ["uptime"]}</code></td><td>read-only, restricted to <code>uptime</code></td></tr>
            <tr><td><code>{"secrets": "rw", "namespaces": ["dev", "staging"]}</code></td><td>rw, restricted to 2 namespaces</td></tr>
            <tr><td><code>{"secrets": "r", "audit": "r"}</code></td><td>read secrets + view audit logs (all namespaces)</td></tr>
            <tr><td><code>{"tokens": "rw", "audit": "r"}</code></td><td>manage tokens + view audit logs</td></tr>
            <tr><td><code>{"admin": "rw"}</code></td><td>full access (admin)</td></tr>
          </tbody>
        </table>
      </div>`;
  }
}

function togglePermsHelp() {
  const h = document.getElementById('perms-help');
  if (h) h.classList.toggle('hidden');
}

let _tokenHideTimer = null;

async function createToken() {
  const name = document.getElementById('ct-name').value;
  const perms = document.getElementById('ct-perms').value;
  const ipsRaw = (document.getElementById('ct-ips').value || '').trim();
  const isHoney = document.getElementById('ct-honey')?.checked || false;
  try {
    const body = { name, permissions: JSON.parse(perms) };
    if (ipsRaw) body.allowed_ips = ipsRaw;
    if (isHoney) body.is_honey = true;
    const r = await api('POST', '/tokens/', body);
    const form = document.getElementById('token-form');
    form.innerHTML = `
      <div class="card-title">Token Created</div>
      <div id="token-reveal">
        <div class="secret-value">${esc(r.token)}</div>
        <p class="dim">Auto-hide in <span id="token-countdown">120</span>s. Copy it now.</p>
        <div class="btn-group mt-12">
          <button class="btn tiny" data-action="copy-text" data-text="${esc(r.token)}">Copy</button>
          <button class="btn tiny secondary" data-action="hideCreatedToken">Hide</button>
        </div>
      </div>
      <div id="token-hidden" class="hidden">
        <p class="dim">Token hidden.</p>
      </div>`;
    startTokenCountdown();
    _tokensCache = null;  // refetch on next render so the new token shows
  } catch (e) { toast(e.message, false); }
}

function startTokenCountdown() {
  if (_tokenHideTimer) clearInterval(_tokenHideTimer);
  let remaining = 120;
  _tokenHideTimer = setInterval(() => {
    remaining--;
    const el = document.getElementById('token-countdown');
    if (el) el.textContent = remaining;
    if (remaining <= 0) hideCreatedToken();
  }, 1000);
}

function hideCreatedToken() {
  if (_tokenHideTimer) { clearInterval(_tokenHideTimer); _tokenHideTimer = null; }
  const reveal = document.getElementById('token-reveal');
  const hidden = document.getElementById('token-hidden');
  if (reveal) reveal.classList.add('hidden');
  if (hidden) hidden.classList.remove('hidden');
}

async function revokeToken(id) {
  // Lookup the token's name so the operator types the actual identifier
  // they meant to revoke, sanity check against fat-finger row clicks.
  // Falls back to the UUID if the cache doesn't have a row (race).
  const tok = (_tokensCache || []).find(t => t.id === id);
  const expected = tok ? tok.name : id;
  const ok = await confirmType(expected, {
    title: `Revoke token '${expected}'`,
    body: 'Revocation is immediate and irreversible, every consumer of this token gets 401 at the next request. Mint a new token before revoking the only one your service holds.',
    okLabel: 'Revoke',
  });
  if (!ok) return;
  try {
    await api('POST', `/tokens/${id}/revoke`);
    toast('Token revoked', true);
    _tokensCache = null;
    renderQuasar(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}

async function rotateToken(id) {
  // Same fat-finger guard as revoke: the operator types the token's own
  // name before the secret is re-minted. Rotating invalidates the old
  // value the instant it commits, every consumer must take the new one.
  const tok = (_tokensCache || []).find(t => t.id === id);
  const expected = tok ? tok.name : id;
  const ok = await confirmType(expected, {
    title: `Rotate token '${expected}'`,
    body: 'Mints a fresh secret for this token in place, same name, scopes and IP allowlist, new value. The current value stops working immediately, so re-provision every consumer with the new token. Shown once only.',
    okLabel: 'Rotate',
  });
  if (!ok) return;
  try {
    const r = await api('POST', `/tokens/${id}/rotate`);
    // Reveal the fresh plaintext in the token-form panel, reusing the
    // same 120s auto-hide reveal as createToken.
    const form = document.getElementById('token-form');
    if (form) {
      form.classList.remove('hidden');
      form.innerHTML = `
        <div class="card-title">Token Rotated: <code>${esc(r.name)}</code></div>
        <div id="token-reveal">
          <div class="secret-value">${esc(r.token)}</div>
          <p class="dim">${esc(r.warning || 'Save this token, shown once only')}<br>
            Auto-hide in <span id="token-countdown">120</span>s. Copy it now.</p>
          <div class="btn-group mt-12">
            <button class="btn tiny" data-action="copy-text" data-text="${esc(r.token)}">Copy</button>
            <button class="btn tiny secondary" data-action="hideCreatedToken">Hide</button>
          </div>
        </div>
        <div id="token-hidden" class="hidden"><p class="dim">Token hidden.</p></div>`;
      startTokenCountdown();
    }
    _tokensCache = null;  // list refetches on next render (resets last-used)
    toast(`Rotated ${r.name}`, true);
  } catch (e) { toast(e.message, false); }
}

function setTokenIps(id) {
  // Change a token's IP allowlist in place. POST /tokens/{id}/allowed-ips -
  // tokens:w + namespace-aware POLA + chained audit, server side. Renders an
  // inline form card (same pattern as Nebula edit) into the shared #token-form
  // panel instead of a native prompt; empty clears the allowlist (any IP).
  const tok = (_tokensCache || []).find(t => t.id === id);
  const label = tok ? tok.name : id;
  const current = tok ? (tok.allowed_ips || '') : '';
  const f = document.getElementById('token-form');
  f.classList.remove('hidden');
  f.innerHTML = `
    <div class="card-title">IP allowlist <strong>${esc(label)}</strong></div>
    <div class="dim small">Comma-separated CIDRs / IPs. Leave empty to allow any IP.</div>
    <input type="hidden" id="ti-id" value="${esc(id)}">
    <div class="form-group">
      <label>Allowed IPs</label>
      <input type="text" id="ti-ips" placeholder="10.0.0.0/8, 192.168.1.5" autocomplete="off" spellcheck="false" value="${esc(current)}">
    </div>
    <div class="row-gap">
      <button class="btn primary small" data-action="submitTokenIps">Save allowlist</button>
      <button class="btn secondary small" data-action="cancelTokenIps">Cancel</button>
    </div>`;
  setTimeout(() => document.getElementById('ti-ips')?.focus(), 0);
}

window.submitTokenIps = async function () {
  const id = document.getElementById('ti-id').value;
  const next = document.getElementById('ti-ips').value;
  try {
    const r = await api('POST', `/tokens/${id}/allowed-ips`, {
      allowed_ips: next.trim() || null,
    });
    _tokensCache = null;
    toast(`Allowlist for ${r.name}: ${r.allowed_ips || '(any IP)'}`, true);
    renderQuasar(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
};

window.cancelTokenIps = function () {
  const f = document.getElementById('token-form');
  if (f) { f.classList.add('hidden'); f.innerHTML = ''; }
};

// ============================================================================
// Tab : Pending rotations (stubs from a backup restore, awaiting admin)
// ============================================================================

function _renderPendingTab() {
  const all = _pendingCache || [];
  const q = _pendingSearch.trim().toLowerCase();
  const items = q
    ? all.filter(p => {
        if ((p.name || '').toLowerCase().includes(q)) return true;
        if ((p.namespace || '').toLowerCase().includes(q)) return true;
        return JSON.stringify(p.permissions || {}).toLowerCase().includes(q);
      })
    : all;

  let html = `<div class="toolbar toolbar-split">
    <div>
      <input type="search" id="quasar-pending-search" class="search-input" data-action="_searchPending"
        placeholder="Search by name or namespace…" value="${esc(_pendingSearch)}">
      ${q ? `<span class="search-meta">${items.length} match${items.length === 1 ? '' : 'es'} of ${all.length}</span>` : ''}
    </div>
    <span class="dim small">Tokens carried over from a backup restore. Show &amp; Rotate to issue a fresh plaintext; Revoke to discard.</span>
  </div>
  <div id="pending-reveal" class="card form-card hidden"></div>
  <table class="table"><thead><tr>
    <th>Name</th><th>Namespace</th><th>Permissions</th><th>IP allowlist</th><th>Age</th><th>Actions</th>
  </tr></thead><tbody>`;
  for (const p of items) {
    const ipCell = p.allowed_ips
      ? `<code>${esc(p.allowed_ips)}</code>`
      : '<span class="dim">any</span>';
    const honeyBadge = p.is_honey
      ? ' <span class="badge orange" title="Decoy token; any use triggers honey alerts">HONEY</span>'
      : '';
    html += `<tr>
      <td><strong>${esc(p.name)}</strong>${honeyBadge}</td>
      <td><code>${esc(p.namespace || 'default')}</code></td>
      <td><code>${esc(JSON.stringify(p.permissions))}</code></td>
      <td>${ipCell}</td>
      <td>${timeAgo(p.created_at)}</td>
      <td class="actions">
        <button class="btn tiny primary" data-action="rotatePending" data-arg="${esc(p.id)}">Show &amp; Rotate</button>
        <button class="btn tiny danger" data-action="revokePending" data-arg="${esc(p.id)}">Revoke</button>
      </td>
    </tr>`;
  }
  html += '</tbody></table>';
  if (!items.length) html += `<div class="empty">${q ? 'No pending rotation matches your search' : 'No pending rotations'}</div>`;
  return html;
}

window._searchPending = async function (value) {
  _pendingSearch = value;
  await renderQuasar(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('quasar-pending-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

async function rotatePending(id) {
  const stub = (_pendingCache || []).find(p => p.id === id);
  const name = stub ? stub.name : id;
  try {
    const r = await api('POST', `/tokens/pending/${id}/rotate`);
    // Reveal the freshly minted plaintext using the same 120s pattern as
    // createToken, copy + auto-hide.
    const reveal = document.getElementById('pending-reveal');
    if (reveal) {
      reveal.classList.remove('hidden');
      reveal.innerHTML = `
        <div class="card-title">Token Rotated: <code>${esc(r.name)}</code> (${esc(r.namespace)})</div>
        <div id="token-reveal">
          <div class="secret-value">${esc(r.token)}</div>
          <p class="dim">${esc(r.warning || 'Save this token, shown once only')}<br>
            Auto-hide in <span id="token-countdown">120</span>s.</p>
          <div class="btn-group mt-12">
            <button class="btn tiny" data-action="copy-text" data-text="${esc(r.token)}">Copy</button>
            <button class="btn tiny secondary" data-action="hideCreatedToken">Hide</button>
          </div>
        </div>
        <div id="token-hidden" class="hidden"><p class="dim">Token hidden.</p></div>`;
      startTokenCountdown();
    }
    _tokensCache = null;
    _pendingCache = null;
    // Stay on the pending tab, operator may rotate multiple in a row.
    // Trigger a partial re-render without clobbering the reveal panel:
    // refresh the underlying lists, then patch the table area only.
    const p = await api('GET', '/tokens/pending/');
    _pendingCache = p.items || [];
    const tBody = document.querySelectorAll('.table tbody');
    if (tBody.length) {
      // Re-render the whole tab, the reveal panel sits above the table
      // and survives because the call below redraws `main` with the
      // current `_quasarTab` still set to 'pending'. Snapshot the reveal
      // markup, render, restore.
      const revealNode = document.getElementById('pending-reveal');
      const revealHTML = revealNode ? revealNode.outerHTML : '';
      await renderQuasar(document.getElementById('main'), { useCache: true });
      const fresh = document.getElementById('pending-reveal');
      if (fresh && revealHTML) fresh.outerHTML = revealHTML;
      startTokenCountdown();
    }
    toast(`Rotated ${r.name}`, true);
  } catch (e) { toast(e.message, false); }
}

async function revokePending(id) {
  const stub = (_pendingCache || []).find(p => p.id === id);
  const expected = stub ? stub.name : id;
  const ok = await confirmType(expected, {
    title: `Revoke pending rotation '${expected}'`,
    body: 'Discards the stub without ever emitting a token. The legacy identifier is lost for good, re-create a token manually if you change your mind.',
    okLabel: 'Revoke',
  });
  if (!ok) return;
  try {
    await api('DELETE', `/tokens/pending/${id}`);
    toast('Pending rotation revoked', true);
    _pendingCache = null;
    renderQuasar(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}
