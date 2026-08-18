// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/**
 * API helper for rhorizon frontend.
 * Token stored in localStorage (persists across tab closes; cleared via clearToken on logout).
 */
'use strict';

const API_BASE = '/api/v1/vault';

// Server-side validation : token must start with `rh_` and run ~46 chars
// (33-byte secret base64url-encoded). Anything else gets a synchronous
// 401 "Invalid token format" before the HMAC lookup ever runs. Validate
// the same way client-side at load + on every set so a corrupted
// localStorage entry (PWA cache glitch, partial paste, browser
// extension interference) auto-purges instead of letting every API call
// 401 in a confusing loop.
function _isValidTokenFormat(t) {
  return typeof t === 'string' && /^rh_[A-Za-z0-9_-]{20,128}$/.test(t);
}

function _loadTokenFromStorage() {
  const stored = localStorage.getItem('rh_token') || '';
  if (stored && !_isValidTokenFormat(stored)) {
    // Loud console line so the operator sees something happened ; the
    // PWA install can be sticky on bad cache state, this surfaces it.
    console.warn(
      '[rhorizon] purged corrupted rh_token from localStorage ' +
      `(length=${stored.length}, prefix=${JSON.stringify(stored.slice(0, 6))})`
    );
    localStorage.removeItem('rh_token');
    return '';
  }
  return stored;
}

let _token = _loadTokenFromStorage();

function setToken(t) {
  if (!_isValidTokenFormat(t)) {
    // Refuse to store a malformed value, surfaces the bug at the
    // setter rather than later at every API call.
    throw new Error('rhorizon: refusing to store malformed token');
  }
  _token = t;
  localStorage.setItem('rh_token', t);
}

function getToken() {
  return _token;
}

function clearToken() {
  _token = '';
  localStorage.removeItem('rh_token');
}

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (_token) opts.headers['Authorization'] = `Bearer ${_token}`;
  if (body) opts.body = JSON.stringify(body);

  // fetch() rejected: the request never reached the server (sleep, wifi, VPN,
  // DNS, TLS, an API restart). status 0 is the sentinel for that.
  //
  // Same consequence in every case -- the UI cannot reach the API -- and none
  // of it is the operator's problem, so do not guess a cause. This used to
  // name the rarest one ("rebuild in progress?"), so a device that slept
  // overnight came back accusing the vault of rebuilding.
  let r;
  try {
    r = await fetch(`${API_BASE}${path}`, opts);
  } catch (e) {
    throw { status: 0, message: 'Offline, trying to connect...' };
  }

  // Body parsing, backend or nginx may transiently return non-JSON during
  // a restart (HTML error page, partially-flushed buffer, "null" + garbage).
  // Show a clean message instead of letting the raw SyntaxError bubble up.
  let data;
  if (r.status === 204) {
    data = {};
  } else {
    try {
      data = await r.json();
    } catch (_) {
      throw {
        status: r.status,
        message: `Vault returned non-JSON (${r.status}), likely restarting`,
      };
    }
  }

  if (!r.ok) {
    let msg = data.error || `Error ${r.status}`;
    if (typeof data.detail === 'string') {
      msg = data.detail;
    } else if (Array.isArray(data.detail)) {
      msg = data.detail.map(d => d.msg || d.message || JSON.stringify(d)).join(', ');
    } else if (data.detail) {
      msg = JSON.stringify(data.detail);
    }
    throw { status: r.status, message: msg };
  }
  return data;
}

async function apiDownload(method, path, body) {
  const opts = { method, headers: {} };
  if (_token) opts.headers.Authorization = `Bearer ${_token}`;
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, opts);
  } catch (_) {
    // Same sentinel and wording as api() above.
    throw { status: 0, message: 'Offline, trying to connect...' };
  }
  if (!response.ok) {
    let message = `Error ${response.status}`;
    try {
      const data = await response.json();
      message = typeof data.detail === 'string' ? data.detail : (data.error || message);
    } catch (_) { /* keep bounded status message */ }
    throw { status: response.status, message };
  }
  const disposition = response.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  return {
    blob: await response.blob(),
    filename: match ? match[1] : 'rhorizon-audit-evidence.tar.gz',
    signer: response.headers.get('X-Rhorizon-Audit-Signer'),
  };
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML.replace(/'/g, '&#39;').replace(/"/g, '&quot;');
}

// One verdict from the three memory facts, because only their combination is
// actionable. Unlocked pages are harmless when swap cannot take cleartext, and
// unsafe swap is harmless when the pages are locked -- so reporting the halves
// separately made an operator correlate two rows to learn nothing, and showed
// alarming words ("swappable") for states that are perfectly safe.
//
// on      key material cannot reach the disk
// off     it can: pages may leave RAM and the swap they land on is cleartext
// unknown we could not establish either half; never render this as safe
//
// The raw states stay in the tooltip so a real exposure is still diagnosable.
function memoryProtectionState(s) {
  const swap = s.swap_protection || 'unknown';
  const buffers = s.memory_protection || 'unknown';
  const proc = s.process_memory_protection || 'unknown';

  // Encrypted, RAM-only (zram) or absent swap settles it by itself.
  if (swap === 'protected') return 'on';
  // Locked pages never reach swap, so unsafe swap is moot in turn.
  if (buffers === 'mlock' && proc === 'mlock') return 'on';
  // Confirmed both halves: pages can leave RAM, and that swap is cleartext.
  if (swap === 'unencrypted' && (buffers === 'zeroize-only' || proc === 'swappable')) {
    return 'off';
  }
  return 'unknown';
}

function memoryProtectionDetail(s) {
  return `buffers: ${s.memory_protection || 'unknown'}`
    + ` / process: ${s.process_memory_protection || 'unknown'}`
    + ` / swap: ${s.swap_protection || 'unknown'}`;
}

// Auto-refreshing views re-render by replacing their DOM wholesale, which
// throws away any scroll offset the operator had set. On a phone the tables
// scroll horizontally (.table gets overflow-x on mobile), so a table dragged
// over to read the right-hand columns snapped back to column 1 on the next
// refresh tick -- every few seconds, mid-read.
//
// Captured by position among .table elements rather than by id: an auto-
// refresh re-renders the same view, so their number and order are stable. If
// they ever are not, the entry is missing and that table simply keeps the
// default offset instead of getting a wrong one.
function captureTableScroll(root) {
  if (!root) return [];
  return Array.from(root.querySelectorAll('.table'))
    .map(el => ({ left: el.scrollLeft, top: el.scrollTop }));
}

function restoreTableScroll(root, snapshot) {
  if (!root || !snapshot || !snapshot.length) return;
  Array.from(root.querySelectorAll('.table')).forEach((el, i) => {
    const pos = snapshot[i];
    if (!pos) return;
    if (pos.left) el.scrollLeft = pos.left;
    if (pos.top) el.scrollTop = pos.top;
  });
}

function timeAgo(iso) {
  if (!iso) return '-';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function timeFromNow(iso) {
  if (!iso) return '-';
  const s = Math.floor((new Date(iso) - Date.now()) / 1000);
  if (s < 0) return 'expired';
  if (s < 60) return `in ${s}s`;
  if (s < 3600) return `in ${Math.floor(s / 60)}m`;
  if (s < 86400) return `in ${Math.floor(s / 3600)}h`;
  return `in ${Math.floor(s / 86400)}d`;
}

// confirmType, type-to-confirm modal for high-stakes destructive
// actions (secret delete, token revoke, namespace archive, master
// password rotate, Shamir disable). The user must type the exact
// `expected` string before the Confirm button enables, a single
// click on a stock browser confirm() is too easy to dismiss
// accidentally for these.
//
// Returns Promise<boolean> : true when typed correctly + clicked OK
// (or pressed Enter), false on Cancel / Escape / backdrop click.
//
// Usage :
//   if (!(await confirmType('my-secret', {
//     title: 'Delete secret',
//     body: 'This is irreversible if the namespace is in free mode.',
//   }))) return;
//
// CSP-clean : no inline event handlers, no inline styles. All visual
// state via CSS classes in style.css (.confirm-modal-backdrop etc.).
function confirmType(expected, opts = {}) {
  return new Promise((resolve) => {
    const title = opts.title || 'Confirm';
    const body = opts.body || '';
    const okLabel = opts.okLabel || 'Confirm';

    const backdrop = document.createElement('div');
    backdrop.className = 'confirm-modal-backdrop';
    backdrop.innerHTML = `
      <div class="confirm-modal" role="dialog" aria-modal="true">
        <div class="confirm-title">${esc(title)}</div>
        ${body ? `<div class="confirm-body">${esc(body)}</div>` : ''}
        <div class="confirm-prompt">Type <code>${esc(expected)}</code> to confirm:</div>
        <input type="text" class="confirm-input" autocomplete="off" spellcheck="false">
        <div class="confirm-actions">
          <button type="button" class="btn secondary small" data-cm-cancel>Cancel</button>
          <button type="button" class="btn danger small" data-cm-ok disabled>${esc(okLabel)}</button>
        </div>
      </div>`;
    document.body.appendChild(backdrop);

    const input = backdrop.querySelector('.confirm-input');
    const okBtn = backdrop.querySelector('[data-cm-ok]');
    const cancelBtn = backdrop.querySelector('[data-cm-cancel]');

    function cleanup(result) {
      document.removeEventListener('keydown', onKey, true);
      backdrop.remove();
      resolve(result);
    }
    function onKey(e) {
      if (e.key === 'Escape') { e.preventDefault(); cleanup(false); }
      if (e.key === 'Enter' && !okBtn.disabled) { e.preventDefault(); cleanup(true); }
    }

    input.addEventListener('input', () => {
      okBtn.disabled = input.value !== expected;
    });
    okBtn.addEventListener('click', () => cleanup(true));
    cancelBtn.addEventListener('click', () => cleanup(false));
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) cleanup(false);
    });
    document.addEventListener('keydown', onKey, true);

    // Focus the input on next tick so autofocus doesn't race with
    // the surrounding view's render loop.
    setTimeout(() => input.focus(), 0);
  });
}

// confirmModal, themed yes/cancel dialog for confirmations that do not
// warrant type-to-confirm : soft warnings and destructive actions with
// no short, memorable identifier to retype (cert serial, audit date,
// a plain toggle). Same visual family as confirmType, reuses the
// .confirm-modal-* CSS, so nothing here ever falls back to a native
// browser confirm() popup.
//
// Returns Promise<boolean> : true on Confirm click, false on Cancel /
// Escape / backdrop click. Cancel is focused on open so a stray Enter
// dismisses rather than confirms a destructive action.
//
// Usage :
//   if (!(await confirmModal({
//     title: 'Disable TOTP',
//     body: 'You will lose the TOTP second factor on this account.',
//     okLabel: 'Disable',
//   }))) return;
//
// opts.danger (default true) picks the OK button colour : danger (red)
// for destructive actions, primary for a neutral confirmation.
function confirmModal(opts = {}) {
  return new Promise((resolve) => {
    const title = opts.title || 'Confirm';
    const body = opts.body || '';
    const okLabel = opts.okLabel || 'Confirm';
    const okClass = opts.danger === false ? 'primary' : 'danger';

    const backdrop = document.createElement('div');
    backdrop.className = 'confirm-modal-backdrop';
    backdrop.innerHTML = `
      <div class="confirm-modal" role="dialog" aria-modal="true">
        <div class="confirm-title">${esc(title)}</div>
        ${body ? `<div class="confirm-body">${esc(body)}</div>` : ''}
        <div class="confirm-actions">
          <button type="button" class="btn secondary small" data-cm-cancel>Cancel</button>
          <button type="button" class="btn ${okClass} small" data-cm-ok>${esc(okLabel)}</button>
        </div>
      </div>`;
    document.body.appendChild(backdrop);

    const okBtn = backdrop.querySelector('[data-cm-ok]');
    const cancelBtn = backdrop.querySelector('[data-cm-cancel]');

    function cleanup(result) {
      document.removeEventListener('keydown', onKey, true);
      backdrop.remove();
      resolve(result);
    }
    function onKey(e) {
      if (e.key === 'Escape') { e.preventDefault(); cleanup(false); }
    }
    okBtn.addEventListener('click', () => cleanup(true));
    cancelBtn.addEventListener('click', () => cleanup(false));
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) cleanup(false);
    });
    document.addEventListener('keydown', onKey, true);

    // Focus Cancel, not OK : a one-click destructive confirm must not be
    // triggerable by an accidental Enter the moment it opens.
    setTimeout(() => cancelBtn.focus(), 0);
  });
}

// -- WebAuthn base64url helpers --

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const PAGE_SIZE = 25;

function isSealed() {
  const s = window._vaultStatus;
  return !s || s.sealed !== false;
}

function sealedHtml() {
  return '<div class="empty">Vault is sealed, unseal from Horizon to access this section</div>';
}

// Shared pagination renderer used by jets / quasar / eclipse / cluster / nebula.
// On mobile (≤600px) renders 3 page buttons + ±3 arrows + a full-range selector.
// On desktop renders 10 page buttons + ±10 arrows + a full-range selector.
//
// `page` is the current 0-indexed page, `totalPages` the total count, `action`
// the global handler name (e.g. '_goAuditPage') that takes a single int arg.
// Returns the inner HTML to insert at the bottom of a paginated table.
function renderPagination(page, totalPages, action) {
  if (totalPages <= 1) return '';
  const isMobile = window.matchMedia('(max-width: 600px)').matches;
  const windowSize = isMobile ? 3 : 10;
  const step = windowSize;

  // Compute the visible window centered around `page` but clamped to
  // [0, totalPages-1]. windowSize buttons unless near the edges.
  let start = Math.max(0, page - Math.floor(windowSize / 2));
  let end = Math.min(totalPages, start + windowSize);
  if (end - start < windowSize) start = Math.max(0, end - windowSize);

  const prev = Math.max(0, page - step);
  const next = Math.min(totalPages - 1, page + step);
  const prevDisabled = page <= 0;
  const nextDisabled = page >= totalPages - 1;

  let html = '<div class="pagination">';
  html += `<button class="btn tiny ${prevDisabled ? 'disabled' : 'secondary'}" data-action="${action}" data-arg="${prev}" ${prevDisabled ? 'disabled' : ''}>‹‹ ${step}</button>`;
  for (let i = start; i < end; i++) {
    html += `<button class="btn tiny ${i === page ? 'active' : 'secondary'}" data-action="${action}" data-arg="${i}">${i + 1}</button>`;
  }
  html += `<button class="btn tiny ${nextDisabled ? 'disabled' : 'secondary'}" data-action="${action}" data-arg="${next}" ${nextDisabled ? 'disabled' : ''}>${step} ››</button>`;
  // Direct-jump selector, covers the case where the user wants a page
  // outside the current window. data-action triggers when the value changes
  // (the global click handler in app.js falls through ; we attach a change
  // listener via the data-action-change attribute).
  let opts = '';
  for (let i = 0; i < totalPages; i++) {
    opts += `<option value="${i}" ${i === page ? 'selected' : ''}>Page ${i + 1} / ${totalPages}</option>`;
  }
  html += `<select class="pg-select" data-action-change="${action}">${opts}</select>`;
  html += '</div>';
  return html;
}
