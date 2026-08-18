// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Jets, Audit trail with pagination + file-based log browser */
'use strict';

let _auditPage = 0;
let _auditCache = null;
let _auditChainIntact = true;
let _auditTab = 'general'; // 'general' (chain+lite today), 'live' (chained today), 'reads' (lite), 'archives'
let _auditSearch = '';
let _auditFileEntries = null;
let _auditFileDate = null;
let _auditFileSearch = '';
let _auditAutoRefresh = true;
let _auditLastRefresh = null;     // ms-since-epoch of the last successful refresh
let _auditCriticalOnly = (typeof localStorage !== 'undefined' && localStorage.getItem('jets-critical-only') === '1');
let _auditExportOpen = false;
let _auditExportBusy = false;
const AUDIT_REFRESH_MS = 1000;

// Reads tab state (vault_audit_lite, no chain, append-only access log).
let _readsCache = null;
let _readsPage = 0;
let _readsSearch = '';

// General tab state (today's vault_audit + vault_audit_lite merged).
let _generalCache = null;
let _generalPage = 0;
let _generalSearch = '';

// MCP tab state (vault_audit_mcp, the OPTIONAL hub's chained per-agent tool-call
// log). Empty unless a hub is deployed and emitting.
let _mcpCache = null;
let _mcpPage = 0;
let _mcpSearch = '';
let _mcpChainIntact = true;

function _isCritical(e) {
  const d = e && e.detail;
  if (!d) return false;
  if (typeof d === 'object') return d._critical === true;
  // detail may arrive as a JSON string in archive file reads.
  if (typeof d === 'string') {
    try { return JSON.parse(d)._critical === true; } catch (_) { return false; }
  }
  return false;
}

function _matchAudit(e, q) {
  if (!q) return true;
  return [e.timestamp, e.actor, e.action, e.target, e.ip_address]
    .some(v => String(v ?? '').toLowerCase().includes(q));
}

function _critToolbarBtn() {
  // Toggle button used by Live, General and Archives (file view). The state
  // is global and persisted, flipping it on Live also affects General.
  return `<button class="btn small ${_auditCriticalOnly ? 'danger' : 'secondary'}"
    data-action="_toggleAuditCriticalOnly"
    title="Show only entries with detail._critical=true">${_auditCriticalOnly ? '● Critical only' : '○ Critical only'}</button>`;
}

async function renderJets(el, opts = {}) {
  if (isSealed()) { el.innerHTML = sealedHtml(); return; }

  // A live auto-refresh replaces the whole view innerHTML, which resets the
  // table's scroll to top-left every second -- the user can never scroll it.
  // Capture scroll positions first and restore them after the re-render so
  // the table stays where the user left it.
  let savedScroll = null;
  if (opts.fromAutoRefresh) {
    const tbl = el.querySelector('.table');
    savedScroll = {
      left: tbl ? tbl.scrollLeft : 0,
      top: tbl ? tbl.scrollTop : 0,
      mainTop: el.scrollTop,
      winY: window.scrollY,
    };
  }

  let html = `<div class="toolbar toolbar-split">
    <div class="btn-group">
      <button class="btn small ${_auditTab === 'general' ? 'primary' : 'secondary'}" data-action="_setAuditTab" data-arg="general">General</button>
      <button class="btn small ${_auditTab === 'live' ? 'primary' : 'secondary'}" data-action="_setAuditTab" data-arg="live">Writes</button>
      <button class="btn small ${_auditTab === 'reads' ? 'primary' : 'secondary'}" data-action="_setAuditTab" data-arg="reads">Reads</button>
      <button class="btn small ${_auditTab === 'mcp' ? 'primary' : 'secondary'}" data-action="_setAuditTab" data-arg="mcp">MCP</button>
      <button class="btn small ${_auditTab === 'archives' ? 'primary' : 'secondary'}" data-action="_setAuditTab" data-arg="archives">Archives</button>
    </div>
    <button class="btn small ${_auditExportOpen ? 'primary' : 'secondary'}" data-action="_toggleAuditEvidenceExport">Export evidence</button>
  </div>`;
  if (_auditExportOpen) html += _renderAuditEvidenceExport();

  if (_auditTab === 'archives') {
    _stopAuditAutoRefresh();
    html += await _renderAuditFiles();
  } else if (_auditTab === 'reads') {
    _stopAuditAutoRefresh();
    html += await _renderReadsAudit(opts);
  } else if (_auditTab === 'general') {
    html += await _renderGeneralAudit(opts);
  } else if (_auditTab === 'mcp') {
    html += await _renderMcpAudit(opts);
  } else {
    html += await _renderLiveAudit(opts);
  }
  el.innerHTML = html;
  if (savedScroll) {
    const tbl = el.querySelector('.table');
    if (tbl) { tbl.scrollLeft = savedScroll.left; tbl.scrollTop = savedScroll.top; }
    el.scrollTop = savedScroll.mainTop;
    if (savedScroll.winY) window.scrollTo(0, savedScroll.winY);
  }
  if (_auditTab === 'live' || _auditTab === 'general' || _auditTab === 'mcp') _startAuditAutoRefresh();
}

window._setAuditTab = function(tab) {
  _auditTab = tab;
  if (tab !== 'live' && tab !== 'general' && tab !== 'mcp') _stopAuditAutoRefresh();
  renderJets(document.getElementById('main'));
};

window._toggleAuditEvidenceExport = function() {
  _auditExportOpen = !_auditExportOpen;
  renderJets(document.getElementById('main'), { useCache: true });
};

function _auditDate(daysAgo = 0) {
  const value = new Date();
  value.setUTCDate(value.getUTCDate() - daysAgo);
  return value.toISOString().slice(0, 10);
}

function _renderAuditEvidenceExport() {
  return `<div class="card mb-12">
    <div class="card-title">Signed audit evidence</div>
    <div class="dim small">One portable <code>.tar.gz</code> containing writes, reads, archives, public signer keys, Merkle proofs, seals, and an Ed25519-signed manifest. Dates are UTC and inclusive.</div>
    <div class="toolbar spaced-top">
      <label class="small">From <input type="date" id="jets-export-since" value="${_auditDate(30)}"></label>
      <label class="small">To <input type="date" id="jets-export-until" value="${_auditDate(0)}"></label>
      <button class="btn primary small" data-action="downloadAuditEvidence" ${_auditExportBusy ? 'disabled' : ''}>${_auditExportBusy ? 'Preparing signed bundle…' : 'Download .tar.gz'}</button>
    </div>
  </div>`;
}

window.downloadAuditEvidence = async function() {
  if (_auditExportBusy) return;
  const sinceEl = document.getElementById('jets-export-since');
  const untilEl = document.getElementById('jets-export-until');
  const sinceDate = sinceEl ? sinceEl.value : '';
  const untilDate = untilEl ? untilEl.value : '';
  if (!sinceDate || !untilDate || sinceDate > untilDate) {
    toast('Choose a valid UTC date range', false);
    return;
  }
  const untilExclusive = new Date(`${untilDate}T00:00:00Z`);
  untilExclusive.setUTCDate(untilExclusive.getUTCDate() + 1);
  _auditExportBusy = true;
  await renderJets(document.getElementById('main'), { useCache: true });
  try {
    const result = await apiDownload('POST', '/audit/export', {
      since: `${sinceDate}T00:00:00Z`,
      until: untilExclusive.toISOString(),
    });
    const url = URL.createObjectURL(result.blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = result.filename;
    anchor.click();
    URL.revokeObjectURL(url);
    toast(`Signed evidence downloaded, signer ${result.signer || 'unknown'}`, true);
  } catch (error) {
    toast(error.message || 'Audit export failed', false);
  } finally {
    _auditExportBusy = false;
    await renderJets(document.getElementById('main'), { useCache: true });
  }
};

window._toggleAuditAutoRefresh = function() {
  _auditAutoRefresh = !_auditAutoRefresh;
  if (!_auditAutoRefresh) _stopAuditAutoRefresh();
  renderJets(document.getElementById('main'), { useCache: true });
};

window._toggleAuditCriticalOnly = function() {
  _auditCriticalOnly = !_auditCriticalOnly;
  try { localStorage.setItem('jets-critical-only', _auditCriticalOnly ? '1' : '0'); } catch (_) { /* ignore */ }
  // Reset page so the filtered slice always starts at 0.
  _auditPage = 0; _generalPage = 0;
  if (_auditTab === 'archives') {
    _renderAuditFileTable();
    return;
  }
  renderJets(document.getElementById('main'), { useCache: true });
};

function _stopAuditAutoRefresh() {
  if (window._auditRefreshTimer) {
    clearInterval(window._auditRefreshTimer);
    window._auditRefreshTimer = null;
  }
}

function _startAuditAutoRefresh() {
  _stopAuditAutoRefresh();
  if (!_auditAutoRefresh) return;
  window._auditRefreshTimer = setInterval(async () => {
    // Self-destruct if the user navigated away or switched tab. Use the
    // same hash-parsing as route() to be tolerant of `#jets`, `#jets/`,
    // `#jets/something`, and to handle the empty-hash initial load case.
    const main = document.getElementById('main');
    const view = (location.hash.slice(1).split('/')[0]) || 'horizon';
    if (!main || view !== 'jets' || (_auditTab !== 'live' && _auditTab !== 'general' && _auditTab !== 'mcp')) {
      _stopAuditAutoRefresh();
      return;
    }
    // Don't disturb the user mid-typing in the search box.
    const search = document.getElementById('jets-search')
      || document.getElementById('jets-general-search')
      || document.getElementById('jets-mcp-search');
    if (search && document.activeElement === search) return;
    // Re-fetch + re-render. Failures don't kill the loop, next tick retries.
    try {
      const scroll = captureTableScroll(main);
      await renderJets(main, { useCache: false, fromAutoRefresh: true });
      restoreTableScroll(main, scroll);
      _auditLastRefresh = Date.now();
    } catch (_) { /* keep ticking */ }
  }, AUDIT_REFRESH_MS);
}

window._goAuditPage = function(p) {
  _auditPage = parseInt(p);
  _auditTab = 'live';
  renderJets(document.getElementById('main'), { useCache: true });
};

window._searchJets = async function(value) {
  _auditSearch = value;
  _auditPage = 0;
  await renderJets(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('jets-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

window._searchJetsFile = function(value) {
  _auditFileSearch = value;
  _renderAuditFileTable();
  const inp = document.getElementById('jets-file-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

async function _renderReadsAudit(opts = {}) {
  // audit-split: `vault_audit_lite` is the append-only access
  // log populated by `log_read` (read_secret, read_secret_version, ...).
  // No chain, so no integrity badge, just a fast read of the table.
  try {
    if (!opts.useCache || _readsCache === null) {
      const r = await api('GET', '/audit/lite?limit=500');
      _readsCache = r.items || [];
    }
    const q = _readsSearch.trim().toLowerCase();
    const items = q ? _readsCache.filter(e => _matchAudit(e, q)) : _readsCache;

    const total = items.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    const page = Math.min(_readsPage, Math.max(0, pages - 1));
    const slice = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

    let html = `<div class="toolbar">
      <input type="search" id="jets-reads-search" class="search-input" data-action="_searchReads"
        placeholder="Search actor, action, target, IP, date…" value="${esc(_readsSearch)}">
      ${q ? `<span class="search-meta">${total} match${total === 1 ? '' : 'es'} of ${_readsCache.length}</span>` : ''}
    </div>
    <div class="dim small spaced-top">
      Parallel read log protected in signed Merkle checkpoints. The newest
      tail remains pending until the next checkpoint; state changes are in Writes.
    </div>
    <table class="table"><thead><tr>
      <th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th>
    </tr></thead><tbody>`;
    for (const e of slice) {
      html += `<tr>
        <td>${timeAgo(e.timestamp)}</td>
        <td>${esc(e.actor)}</td>
        <td><span class="tag">${esc(e.action)}</span></td>
        <td>${esc(e.target || '-')}</td>
        <td class="dim">${esc(e.ip_address || '-')}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    if (!total) html += `<div class="empty">${q ? 'No read events match your search' : 'No read events recorded yet'}</div>`;

    html += renderPagination(page, pages, '_goReadsPage');
    return html;
  } catch (e) { return `<div class="error">${esc(e.message)}</div>`; }
}

window._goReadsPage = function(p) {
  _readsPage = parseInt(p);
  renderJets(document.getElementById('main'), { useCache: true });
};

window._searchReads = async function(value) {
  _readsSearch = value;
  _readsPage = 0;
  await renderJets(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('jets-reads-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

async function _renderGeneralAudit(opts = {}) {
  // Union view of today (UTC): chained mutations (vault_audit) + lite reads
  // (vault_audit_lite). Merged by timestamp DESC so newest is on top, with
  // a Kind column to distinguish mutation vs read. Chain integrity badge
  // reflects the chained half only.
  try {
    if (!opts.useCache || _generalCache === null) {
      const since = new Date();
      since.setUTCHours(0, 0, 0, 0);
      const qs = `since=${encodeURIComponent(since.toISOString())}&limit=500`;
      const [chain, lite] = await Promise.all([
        api('GET', `/audit/?${qs}`),
        api('GET', `/audit/lite?${qs}`),
      ]);
      const chainItems = (chain.items || []).map(e => ({ ...e, kind: 'mutation' }));
      const liteItems = (lite.items || []).map(e => ({ ...e, kind: 'read' }));
      _generalCache = chainItems.concat(liteItems)
        .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      _auditChainIntact = !!chain.chain_intact;
      _auditLastRefresh = Date.now();
    }
    const q = _generalSearch.trim().toLowerCase();
    let items = q ? _generalCache.filter(e => _matchAudit(e, q)) : _generalCache;
    if (_auditCriticalOnly) items = items.filter(_isCritical);

    const total = items.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    const page = Math.min(_generalPage, Math.max(0, pages - 1));
    const slice = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    const sourceTotal = _generalCache.length;
    const filtered = total !== sourceTotal;

    let html = `<div class="toolbar toolbar-split">
      <div class="chain-status">
        <span class="chain-label">Chain Integrity</span>
        <span class="chain-badge ${_auditChainIntact ? 'intact' : 'broken'}">${_auditChainIntact ? 'INTACT' : 'BROKEN'}</span>
      </div>
      <div class="btn-group">
        ${_critToolbarBtn()}
        <button class="btn ${_auditAutoRefresh ? 'primary' : 'secondary'} small" data-action="_toggleAuditAutoRefresh" title="Toggle auto-refresh (${AUDIT_REFRESH_MS / 1000}s)">${_auditAutoRefresh ? `● Live ${AUDIT_REFRESH_MS / 1000}s` : '○ Paused'}</button>
        ${_auditAutoRefresh && _auditLastRefresh
          ? `<span class="dim refresh-stamp">last refresh ${new Date(_auditLastRefresh).toLocaleTimeString()}</span>`
          : ''}
      </div>
    </div>
    <div class="toolbar">
      <input type="search" id="jets-general-search" class="search-input" data-action="_searchGeneral"
        placeholder="Search actor, action, target, IP, kind, date…" value="${esc(_generalSearch)}">
      ${filtered ? `<span class="search-meta">${total} match${total === 1 ? '' : 'es'} of ${sourceTotal}</span>` : ''}
    </div>
    <div class="dim small spaced-top">
      Today's union: chained mutations + lite reads. Past days are in Archives.
    </div>
    <table class="table"><thead><tr>
      <th>Time</th><th>Kind</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th>
    </tr></thead><tbody>`;
    for (const e of slice) {
      const cls = _isCritical(e) ? 'critical' : '';
      html += `<tr${cls ? ` class="${cls}"` : ''}>
        <td>${timeAgo(e.timestamp)}</td>
        <td><span class="tag">${esc(e.kind)}</span></td>
        <td>${esc(e.actor)}</td>
        <td><span class="tag">${esc(e.action)}</span></td>
        <td>${esc(e.target || '-')}</td>
        <td class="dim">${esc(e.ip_address || '-')}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    if (!total) html += `<div class="empty">${_auditCriticalOnly ? 'No critical entries today' : (q ? 'No entries match your search' : 'No audit activity today')}</div>`;

    html += renderPagination(page, pages, '_goGeneralPage');
    return html;
  } catch (e) { return `<div class="error">${esc(e.message)}</div>`; }
}

window._goGeneralPage = function(p) {
  _generalPage = parseInt(p);
  renderJets(document.getElementById('main'), { useCache: true });
};

window._searchGeneral = async function(value) {
  _generalSearch = value;
  _generalPage = 0;
  await renderJets(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('jets-general-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

function _matchMcp(e, q) {
  if (!q) return true;
  return [e.timestamp, e.actor, e.agent_token_id, e.hub, e.backend, e.tool, e.target, e.decision, e.ip_address]
    .some(v => String(v ?? '').toLowerCase().includes(q));
}

async function _renderMcpAudit(opts = {}) {
  // vault_audit_mcp: the OPTIONAL MCP hub's chained per-agent tool-call log.
  // Each row is attributed to the calling agent (uuid = its vault token id).
  // Chain integrity comes from /audit/mcp/verify. Empty unless a hub emits here.
  try {
    if (!opts.useCache || _mcpCache === null) {
      const [list, verify] = await Promise.all([
        api('GET', '/audit/mcp?limit=500'),
        api('GET', '/audit/mcp/verify'),
      ]);
      _mcpCache = (list.items || []).slice()
        .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      _mcpChainIntact = !!verify.chain_intact;
      _auditLastRefresh = Date.now();
    }
    const q = _mcpSearch.trim().toLowerCase();
    const items = q ? _mcpCache.filter(e => _matchMcp(e, q)) : _mcpCache;

    const total = items.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    const page = Math.min(_mcpPage, Math.max(0, pages - 1));
    const slice = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

    let html = `<div class="toolbar toolbar-split">
      <div class="chain-status">
        <span class="chain-label">Chain Integrity</span>
        <span class="chain-badge ${_mcpChainIntact ? 'intact' : 'broken'}">${_mcpChainIntact ? 'INTACT' : 'BROKEN'}</span>
      </div>
      <div class="btn-group">
        <button class="btn ${_auditAutoRefresh ? 'primary' : 'secondary'} small" data-action="_toggleAuditAutoRefresh" title="Toggle auto-refresh (${AUDIT_REFRESH_MS / 1000}s)">${_auditAutoRefresh ? `● Live ${AUDIT_REFRESH_MS / 1000}s` : '○ Paused'}</button>
      </div>
    </div>
    <div class="toolbar">
      <input type="search" id="jets-mcp-search" class="search-input" data-action="_searchMcp"
        placeholder="Search agent, hub, backend, tool, target, decision…" value="${esc(_mcpSearch)}">
      ${q ? `<span class="search-meta">${total} match${total === 1 ? '' : 'es'} of ${_mcpCache.length}</span>` : ''}
    </div>
    <div class="dim small spaced-top">
      Per-agent MCP tool calls via the optional hub. Chained + tamper-evident;
      empty until a hub is deployed and emitting.
    </div>
    <table class="table"><thead><tr>
      <th>Time</th><th>Agent</th><th>Hub</th><th>Backend</th><th>Tool</th><th>Target</th><th>Decision</th>
    </tr></thead><tbody>`;
    for (const e of slice) {
      const denied = e.decision !== 'allowed';
      const uuid = e.agent_token_id ? String(e.agent_token_id).slice(0, 8) : '-';
      html += `<tr${denied ? ' class="critical"' : ''}>
        <td>${timeAgo(e.timestamp)}</td>
        <td><code>${esc(uuid)}</code> ${esc(e.actor || '')}</td>
        <td>${e.hub ? `<span class="tag">${esc(e.hub)}</span>` : '<span class="dim">-</span>'}</td>
        <td><span class="tag">${esc(e.backend)}</span></td>
        <td>${esc(e.tool)}</td>
        <td>${esc(e.target || '-')}</td>
        <td><span class="tag">${esc(e.decision)}</span></td>
      </tr>`;
    }
    html += '</tbody></table>';
    if (!total) html += `<div class="empty">${q ? 'No MCP calls match your search' : 'No MCP calls recorded (deploy the hub to populate this)'}</div>`;

    html += renderPagination(page, pages, '_goMcpPage');
    return html;
  } catch (e) { return `<div class="error">${esc(e.message)}</div>`; }
}

window._goMcpPage = function(p) {
  _mcpPage = parseInt(p);
  renderJets(document.getElementById('main'), { useCache: true });
};

window._searchMcp = async function(value) {
  _mcpSearch = value;
  _mcpPage = 0;
  await renderJets(document.getElementById('main'), { useCache: true });
  const inp = document.getElementById('jets-mcp-search');
  if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
};

async function _renderLiveAudit(opts = {}) {
  try {
    if (!opts.useCache || _auditCache === null) {
      // Live = current UTC day only. Yesterday and older live in Archives
      // (gzipped after the day rolls over, decompressed transparently).
      const since = new Date();
      since.setUTCHours(0, 0, 0, 0);
      const qs = `since=${encodeURIComponent(since.toISOString())}&limit=500`;
      const r = await api('GET', `/audit/?${qs}`);
      _auditCache = (r.items || []).reverse();
      _auditChainIntact = !!r.chain_intact;
      _auditLastRefresh = Date.now();
    }
    const q = _auditSearch.trim().toLowerCase();
    let items = q ? _auditCache.filter(e => _matchAudit(e, q)) : _auditCache;
    if (_auditCriticalOnly) items = items.filter(_isCritical);
    const total = items.length;
    const pages = Math.ceil(total / PAGE_SIZE);
    const page = Math.min(_auditPage, Math.max(0, pages - 1));
    const slice = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    const sourceTotal = _auditCache.length;
    const filtered = total !== sourceTotal;

    let html = `<div class="toolbar toolbar-split">
      <div class="chain-status">
        <span class="chain-label">Chain Integrity</span>
        <span class="chain-badge ${_auditChainIntact ? 'intact' : 'broken'}">${_auditChainIntact ? 'INTACT' : 'BROKEN'}</span>
      </div>
      <div class="btn-group">
        ${_critToolbarBtn()}
        <button class="btn ${_auditAutoRefresh ? 'primary' : 'secondary'} small" data-action="_toggleAuditAutoRefresh" title="Toggle live auto-refresh (${AUDIT_REFRESH_MS / 1000}s)">${_auditAutoRefresh ? `● Live ${AUDIT_REFRESH_MS / 1000}s` : '○ Paused'}</button>
        ${_auditAutoRefresh && _auditLastRefresh
          ? `<span class="dim refresh-stamp">last refresh ${new Date(_auditLastRefresh).toLocaleTimeString()}</span>`
          : ''}
      </div>
    </div>
    <div class="toolbar">
      <input type="search" id="jets-search" class="search-input" data-action="_searchJets"
        placeholder="Search actor, action, target, IP, date…" value="${esc(_auditSearch)}">
      ${filtered ? `<span class="search-meta">${total} match${total === 1 ? '' : 'es'} of ${sourceTotal}</span>` : ''}
    </div>
    <table class="table"><thead><tr>
      <th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th>
    </tr></thead><tbody>`;
    for (const e of slice) {
      const cls = _isCritical(e) ? 'critical' : '';
      html += `<tr${cls ? ` class="${cls}"` : ''}>
        <td>${timeAgo(e.timestamp)}</td>
        <td>${esc(e.actor)}</td>
        <td><span class="tag">${esc(e.action)}</span></td>
        <td>${esc(e.target || '-')}</td>
        <td class="dim">${esc(e.ip_address || '-')}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    if (!total) html += `<div class="empty">${_auditCriticalOnly ? 'No critical entries' : (q ? 'No audit entries match your search' : 'No audit entries')}</div>`;

    html += renderPagination(page, pages, '_goAuditPage');
    return html;
  } catch (e) { return `<div class="error">${esc(e.message)}</div>`; }
}

async function _renderAuditFiles() {
  try {
    const r = await api('GET', '/audit/files');
    const files = r.files || [];

    let html = `<div class="toolbar toolbar-split">
      <div class="kv-group">
        <div class="kv-inline"><span class="kv-label">Retention</span><span class="kv-value">${r.retention_days} days</span></div>
        <div class="kv-inline"><span class="kv-label">Files</span><span class="kv-value">${files.length}</span></div>
      </div>
    </div>`;

    if (!files.length) {
      return html + '<div class="empty">No audit log files</div>';
    }

    html += `<table class="table"><thead><tr>
      <th>Date</th><th>Size</th><th>Compressed</th><th>Actions</th>
    </tr></thead><tbody>`;

    for (const f of files) {
      const sizeKb = (f.size_bytes / 1024).toFixed(1);
      html += `<tr>
        <td><strong>${esc(f.date)}</strong></td>
        <td>${sizeKb} KB</td>
        <td><span class="badge ${f.compressed ? 'active' : 'secondary'}">${f.compressed ? 'gzip' : 'plain'}</span></td>
        <td class="actions">
          <button class="btn tiny" data-action="viewAuditFile" data-arg="${esc(f.date)}">View</button>
          <button class="btn tiny secondary" data-action="downloadAuditFile" data-arg="${esc(f.date)}">Download</button>
          <button class="btn tiny danger" data-action="deleteAuditFile" data-arg="${esc(f.date)}">Del</button>
        </td>
      </tr>`;
    }
    html += '</tbody></table>';
    html += '<div id="audit-file-view"></div>';
    return html;
  } catch (e) { return `<div class="error">${esc(e.message)}</div>`; }
}

async function viewAuditFile(date) {
  try {
    const r = await api('GET', `/audit/files/${encodeURIComponent(date)}`);
    _auditFileEntries = r.entries || [];
    _auditFileDate = date;
    _auditFileSearch = '';
    _renderAuditFileTable();
  } catch (e) { toast(e.message, false); }
}

function _renderAuditFileTable() {
  const slot = document.getElementById('audit-file-view');
  if (!slot || !_auditFileEntries) return;
  const q = _auditFileSearch.trim().toLowerCase();
  let entries = q ? _auditFileEntries.filter(e => _matchAudit(e, q)) : _auditFileEntries;
  if (_auditCriticalOnly) entries = entries.filter(_isCritical);
  const sourceTotal = _auditFileEntries.length;
  const filtered = entries.length !== sourceTotal;
  let html = `<div class="card mt-12">
    <div class="card-title">${esc(_auditFileDate)}, ${entries.length}${filtered ? ` of ${sourceTotal}` : ''} entries</div>
    <div class="toolbar toolbar-split">
      <input type="search" id="jets-file-search" class="search-input" data-action="_searchJetsFile"
        placeholder="Search actor, action, target, IP, date…" value="${esc(_auditFileSearch)}">
      <div class="btn-group">${_critToolbarBtn()}</div>
    </div>
    <table class="table"><thead><tr>
      <th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th>
    </tr></thead><tbody>`;
  for (const e of entries) {
    const cls = _isCritical(e) ? 'critical' : '';
    html += `<tr${cls ? ` class="${cls}"` : ''}>
      <td class="dim">${esc(e.timestamp || '')}</td>
      <td>${esc(e.actor || '')}</td>
      <td><span class="tag">${esc(e.action || '')}</span></td>
      <td>${esc(e.target || '-')}</td>
      <td class="dim">${esc(e.ip_address || '-')}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  slot.innerHTML = html;
}

async function downloadAuditFile(date) {
  try {
    const r = await api('GET', `/audit/files/${encodeURIComponent(date)}`);
    const content = JSON.stringify(r.entries || [], null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-${date}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast(`Downloaded audit-${date}.json`, true);
  } catch (e) { toast(e.message, false); }
}

async function deleteAuditFile(date) {
  const ok = await confirmModal({
    title: `Delete audit log ${date}`,
    body: 'Permanently removes this audit log file. Only allowed for files older than the configured retention period. This breaks the local copy of the chain for that day.',
    okLabel: 'Delete',
  });
  if (!ok) return;
  try {
    await api('DELETE', `/audit/files/${encodeURIComponent(date)}`);
    toast(`Deleted audit-${date}`, true);
    renderJets(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}
