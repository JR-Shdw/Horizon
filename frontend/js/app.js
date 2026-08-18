// DO NOT REMOVE: SPDX header + copyright are part of the AGPL-3.0 license terms.
// Stripping or rewriting these notices on redistribution is a license violation.
// Project: Resurgamus Horizon · Author: shdw <horizon@resurgamus.com> · License: AGPL-3.0-or-later
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/**
 * rhorizon SPA, Router + sidebar toggle.
 * Views in js/views/*.js, icons in js/icons.js
 *
 * Author: shdw <horizon@resurgamus.com>
 * Project: Resurgamus Horizon, self-hosted secrets vault.
 * License: AGPL-3.0-or-later, closed-source relicensing prohibited.
 * AI training: not authorized. TDM reservation per EU DSM directive (art. 4).
 * See: NOTICE, LICENSE-AI.md, /.well-known/tdmrep.json
 */
'use strict';

const views = {
  horizon:     { title: 'Horizon',     sub: 'Resurgamus Horizon', icon: ICONS.horizon,       fn: renderHorizon },
  eclipse:     { title: 'Eclipse',     sub: 'Secrets',         icon: ICONS.keyRound,      fn: renderEclipse },
  quasar:      { title: 'Quasar',      sub: 'Tokens',          icon: ICONS.orbits,        fn: renderQuasar },
  jets:        { title: 'Jets',        sub: 'Audit',           icon: ICONS.triangleAlert, fn: renderJets },
  cluster:     { title: 'Cluster',     sub: 'Groups / LDAP / SSO / HA', icon: ICONS.component, fn: renderCluster },
  nebula:      { title: 'Nebula',      sub: 'Namespaces',      icon: ICONS.nebula,        fn: renderNebula },
  accretion:   { title: 'Accretion',   sub: 'Migration / Backup', icon: ICONS.arrowUpDown,   fn: renderAccretion },
  pulsar:      { title: 'Pulsar',      sub: 'Notifications',   icon: ICONS.pulsar,        fn: renderPulsar },
  core:        { title: 'Core',        sub: 'Settings',        icon: ICONS.core,          fn: renderCore },
};

function navigate(view) { closeMobileMenu(); window.location.hash = view; }

let _routeId = 0;

async function route() {
  const hash = window.location.hash.slice(1) || 'horizon';
  const v = views[hash];
  if (!v) return navigate('horizon');

  const rid = ++_routeId;
  const main = document.getElementById('main');
  main.innerHTML = '<div class="loading"><span class="spinner"></span></div>';

  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.view === hash);
  });
  document.getElementById('view-title').innerHTML = `${v.icon} ${v.title} <span class="dim">- ${v.sub}</span>`;

  // Ensure vault status is loaded before rendering any view
  if (!window._vaultStatus) await pollStatus();
  if (rid !== _routeId) return;

  v.fn(main).then(() => {
    if (rid !== _routeId) main.innerHTML = '';
  }).catch(e => {
    if (rid !== _routeId) return;
    const msg = (e && e.message) ? e.message : String(e);
    main.innerHTML = `<div class="error">${esc(msg)}</div>`;
  });
}

window.addEventListener('hashchange', () => { closeMobileMenu(); route(); });

/* Global event delegation, eliminates all inline onclick handlers */
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  // Form fields use the 'input' event delegation below, a click on the
  // field would otherwise fire the action with no argument and clobber state.
  if (btn.matches('input, textarea, select')) return;
  const a = btn.dataset.action;

  // Micro-actions
  if (a === 'navigate')      { navigate(btn.dataset.view); return; }
  if (a === 'toggle')        { document.getElementById(btn.dataset.target).classList.toggle('hidden'); return; }
  if (a === 'copy-el') {
    const src = document.getElementById(btn.dataset.src);
    navigator.clipboard.writeText(src.value || src.textContent);
    toast('Copied', true);
    return;
  }
  if (a === 'copy-el-label') {
    const src = document.getElementById(btn.dataset.src);
    navigator.clipboard.writeText(src.value || src.textContent);
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    return;
  }
  if (a === 'copy-text') {
    navigator.clipboard.writeText(btn.dataset.text);
    toast('Copied', true);
    return;
  }

  // Named function dispatch
  const fn = window[a];
  if (typeof fn === 'function') {
    if (btn.dataset.arg2 !== undefined) fn(btn.dataset.arg, btn.dataset.arg2);
    else if (btn.dataset.arg !== undefined) fn(btn.dataset.arg);
    else fn();
  }
});

/* Input event delegation, for live-search fields (data-action="_searchFoo") */
document.addEventListener('input', (e) => {
  const inp = e.target;
  if (!inp.matches || !inp.matches('input[data-action], textarea[data-action], select[data-action]')) return;
  const fn = window[inp.dataset.action];
  if (typeof fn === 'function') fn(inp.value);
});

/* Change event delegation, used by paginator <select> (data-action-change). */
document.addEventListener('change', (e) => {
  const el = e.target;
  if (!el.matches || !el.matches('[data-action-change]')) return;
  const fn = window[el.dataset.actionChange];
  if (typeof fn === 'function') fn(el.value);
});

function toast(msg, ok = true) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast ${ok ? 'ok' : 'err'} show`;
  setTimeout(() => el.className = 'toast', 3500);
}

const SIDEBAR_MODES = ['expanded', 'icons'];
let sidebarMode = localStorage.getItem('sidebar-mode') || 'expanded';

function applySidebarMode() {
  const sb = document.querySelector('.sidebar');
  const ct = document.querySelector('.content');
  sb.classList.remove('collapsed');
  ct.classList.remove('sidebar-collapsed');
  if (sidebarMode === 'icons') {
    sb.classList.add('collapsed');
    ct.classList.add('sidebar-collapsed');
  }
  localStorage.setItem('sidebar-mode', sidebarMode);
}

function toggleSidebar() {
  const idx = SIDEBAR_MODES.indexOf(sidebarMode);
  sidebarMode = SIDEBAR_MODES[(idx + 1) % SIDEBAR_MODES.length];
  applySidebarMode();
}

function toggleMobileMenu() {
  document.querySelector('.sidebar').classList.toggle('mobile-open');
}

function closeMobileMenu() {
  document.querySelector('.sidebar').classList.remove('mobile-open');
}

function toggleMobileNavMode() {
  const mode = document.body.dataset.mobileNav === 'icons' ? 'dropdown' : 'icons';
  document.body.dataset.mobileNav = mode;
  localStorage.setItem('mobile-nav-mode', mode);
  closeMobileMenu();
}

function initMobileNavMode() {
  const saved = localStorage.getItem('mobile-nav-mode') || 'dropdown';
  document.body.dataset.mobileNav = saved;
}

async function pollStatus() {
  try {
    const d = await api('GET', '/status');
    document.getElementById('seal-badge').textContent = d.sealed ? 'SEALED' : 'UNSEALED';
    document.getElementById('seal-badge').className = `seal-badge ${d.sealed ? 'sealed' : 'unsealed'}`;
    if (typeof bhSetState === 'function') bhSetState(d.sealed);
    const prev = window._vaultStatus;
    const flippedToSealed   = d.sealed && prev && !prev.sealed;
    const flippedToUnsealed = !d.sealed && prev && prev.sealed;
    // Force redirect to Horizon if vault became sealed while on another view
    if (flippedToSealed) {
      navigate('horizon');
      toast('Vault sealed, session ended');
    }
    // Also redirect if sealed and not already on horizon (e.g. after rebuild)
    if (d.sealed && location.hash && location.hash !== '#horizon') {
      navigate('horizon');
    }
    window._vaultStatus = d;
    // Re-render the current view on a sealed→unsealed flip so the Horizon
    // card (and any other view holding stale `_vaultStatus`) updates without
    // requiring the operator to navigate manually.
    if (flippedToUnsealed) {
      const main = document.getElementById('main');
      const view = (location.hash.slice(1).split('/')[0]) || 'horizon';
      if (main && views[view]) views[view].fn(main).catch(() => {});
      // Proactive chain integrity check on every unseal. If the
      // chain is broken, route the operator to Jets and flag it loudly.
      // Fire-and-forget; a transient failure is silently ignored.
      api('GET', '/audit/verify').then(r => {
        if (r && r.chain_intact === false) {
          toast('Audit chain BROKEN, opening Jets');
          if (location.hash !== '#jets') navigate('jets');
        }
      }).catch(() => {});
    }
    return d;
  } catch (e) {
    document.getElementById('seal-badge').textContent = 'OFFLINE';
    document.getElementById('seal-badge').className = 'seal-badge sealed';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const nav = document.getElementById('nav-items');
  for (const [key, v] of Object.entries(views)) {
    const el = document.createElement('a');
    el.className = 'nav-item';
    el.dataset.view = key;
    el.innerHTML = `<span class="nav-icon">${v.icon}</span><span class="nav-label">${v.title}</span>`;
    el.href = `#${key}`;
    nav.appendChild(el);
  }
  // Desktop sidebar toggle (2 modes: expanded → icons)
  document.getElementById('sidebar-toggle').addEventListener('click', toggleSidebar);
  applySidebarMode();

  // Mobile sidebar (slide-in + backdrop)
  const mobileHamburger = document.getElementById('mobile-hamburger');
  const mobileNavToggle = document.getElementById('mobile-nav-toggle');
  const backdrop = document.getElementById('sidebar-backdrop');
  if (mobileHamburger) mobileHamburger.addEventListener('click', toggleMobileMenu);
  if (mobileNavToggle) mobileNavToggle.addEventListener('click', toggleMobileNavMode);
  if (backdrop) backdrop.addEventListener('click', closeMobileMenu);
  initMobileNavMode();

  // Close mobile menu on nav link click (dropdown mode only)
  document.querySelectorAll('.sidebar .nav-item, .sidebar a').forEach(a => {
    a.addEventListener('click', () => {
      if (window.innerWidth <= 768 && document.body.dataset.mobileNav !== 'icons') closeMobileMenu();
    });
  });

  if (typeof bhInit === 'function') bhInit('blackhole-canvas');
  if (typeof miniBhInit === 'function') miniBhInit('mini-bh-canvas');
  if (typeof keyInit === 'function') keyInit('key-canvas');

  // Mobile: write the real visible height to --app-height. Some mobile
  // browsers don't honor svh/dvh, so the fixed rail + .content can't rely
  // on them; window.innerHeight is the actual visible area (URL bar in).
  const setAppHeight = () => document.documentElement.style.setProperty('--app-height', window.innerHeight + 'px');
  window.addEventListener('resize', setAppHeight);
  setAppHeight();

  pollStatus();
  setInterval(pollStatus, 5000);
  route();
});
