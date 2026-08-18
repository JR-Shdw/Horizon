// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// DEMO MODE — runs the real frontend with a mocked backend so the whole
// application can be shown live (no server, no real secrets). Activated by
// `?demo` in the URL (or window.__RH_DEMO__ = true before this script).
//
// It replaces the global api() with an in-memory fake vault, seeds believable
// data, and drives an autoplay guided tour through every view. Any visitor
// interaction pauses the tour and hands them the controls.
'use strict';

(function () {
  const DEMO = /(?:[?&])demo\b/.test(location.search) || window.__RH_DEMO__;
  if (!DEMO) return;
  document.documentElement.classList.add('rh-demo');

  // ---- injected demo-bar styles -----------------------------------------
  const css = document.createElement('style');
  css.textContent = `
    #demo-bar{position:fixed;left:50%;bottom:18px;transform:translateX(-50%);
      z-index:9999;display:flex;align-items:center;gap:16px;max-width:min(760px,94vw);
      padding:12px 16px;border-radius:14px;color:#e8e6f0;
      background:rgba(16,12,28,.82);border:1px solid rgba(124,58,237,.45);
      box-shadow:0 12px 40px rgba(0,0,0,.5);backdrop-filter:blur(10px);
      font-family:system-ui,sans-serif;}
    #demo-bar .demo-badge{flex:0 0 auto;font-size:.62rem;font-weight:700;letter-spacing:1.5px;
      padding:4px 8px;border-radius:6px;color:#fff;
      background:linear-gradient(100deg,#ff0080,#7c3aed);}
    #demo-bar .demo-cap{flex:1 1 auto;min-width:0;}
    #demo-bar .demo-title{font-weight:700;font-size:.95rem;color:#fff;margin-bottom:2px;}
    #demo-bar .demo-body{font-size:.82rem;line-height:1.35;color:#c9c4dc;}
    #demo-bar .demo-ctrl{flex:0 0 auto;display:flex;gap:6px;}
    #demo-bar .demo-ctrl button{width:34px;height:34px;border-radius:9px;cursor:pointer;
      border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);
      color:#fff;font-size:1rem;line-height:1;transition:background .15s,transform .15s;}
    #demo-bar .demo-ctrl button:hover{background:rgba(124,58,237,.5);transform:translateY(-1px);}
    #demo-bar .demo-progress{position:absolute;left:16px;right:16px;bottom:6px;height:2px;
      border-radius:2px;background:rgba(255,255,255,.12);overflow:hidden;}
    #demo-bar #demo-progress-fill{display:block;height:100%;width:0;
      background:linear-gradient(90deg,#ff0080,#22d3ee);}
    @media (max-width:600px){#demo-bar{left:8px;right:8px;transform:none;max-width:none;flex-wrap:wrap;bottom:8px;padding:10px 12px;gap:10px;}
      #demo-bar .demo-cap{order:3;flex:1 0 100%;}
      #demo-bar .demo-title{font-size:.9rem;}
      #demo-bar .demo-body{font-size:.78rem;line-height:1.3;}}
    @media (prefers-reduced-motion:reduce){#demo-bar #demo-progress-fill{transition:none!important;}}

    /* injected: Grafana-style observability */
    .demo-obs{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;padding:8px 4px 96px;max-width:1040px;}
    .obs-panel{position:relative;padding:16px;border-radius:12px;background:rgba(255,255,255,.03);
      border:1px solid rgba(255,255,255,.08);}
    .obs-panel.wide{grid-column:span 2;}
    @media (max-width:640px){.obs-panel.wide{grid-column:span 1;}}
    .obs-label{font-size:.72rem;letter-spacing:.5px;text-transform:uppercase;opacity:.6;margin-bottom:8px;}
    .obs-stat{font-size:1.9rem;font-weight:800;font-variant-numeric:tabular-nums;
      background:linear-gradient(100deg,#ff0080,#22d3ee);-webkit-background-clip:text;background-clip:text;color:transparent;}
    .obs-stat.ok{background:none;color:#34d399;-webkit-text-fill-color:#34d399;}
    .obs-stat.warn{background:none;color:#9ca3af;-webkit-text-fill-color:#9ca3af;}
    .nova-spark{width:100%;height:34px;margin-top:8px;display:block;}
    .nova-spark path{fill:none;stroke:#22d3ee;stroke-width:1.6;vector-effect:non-scaling-stroke;}
  `;
  (document.head || document.documentElement).appendChild(css);

  // ---- seeded fake vault -------------------------------------------------
  let sealed = true;
  const now = Date.now();
  const ago = (min) => new Date(now - min * 60000).toISOString();
  const ahead = (min) => new Date(now + min * 60000).toISOString();

  const status = () => ({
    sealed,
    version: '1.4.0',
    uptime: sealed ? '-' : '2h 41m',
    second_factor: 'any',            // password + (TOTP or security key)
    totp_enabled: true,
    webauthn_registered: 1,
    yubikeys_registered: 1,
    shamir_enabled: true,            // M-of-N master key split
    shamir_threshold: 3,
    shamir_total: 5,
    shamir_progress: 3,
    post_quantum: true,
  });

  const channels = [
    { id: 'n1', type: 'matrix', kind: 'matrix', name: 'ops-room', target: '#ops:example.com', enabled: true },
    { id: 'n2', type: 'webhook', kind: 'webhook', name: 'siem', target: 'https://siem.internal/hook', enabled: true },
    { id: 'n3', type: 'email', kind: 'email', name: 'oncall', target: 'oncall@resurgamus.com', enabled: false },
  ];

  const secrets = [
    { name: 'stripe-secret-key', namespace: 'clients', version: 4, updated_at: ago(38), expires_at: null, value: 'sk_live_51PxxxxDEMOxxxxREDACTED' }, // pragma: allowlist secret
    { name: 'client-acme/smtp-password', namespace: 'clients', version: 2, updated_at: ago(190), expires_at: null, value: 'S3cur3-DEMO-smtp' }, // pragma: allowlist secret
    { name: 'postgres-app-dsn', namespace: 'prod', version: 7, updated_at: ago(12), expires_at: null, value: 'postgresql://app:DEMO@db/app' }, // pragma: allowlist secret
    { name: 'openai-api-key', namespace: 'mcp', version: 1, updated_at: ago(4), expires_at: ahead(60), value: 'sk-DEMO-openai-redacted' }, // pragma: allowlist secret
    { name: 'n8n-encryption-key', namespace: 'n8n', version: 3, updated_at: ago(510), expires_at: null, value: 'DEMO-n8n-enc-key' }, // pragma: allowlist secret
  ];

  const tokens = [
    { id: 'tk_ansible', name: 'ansible-deploy', permissions: { secrets: 'r', namespaces: ['prod'] }, allowed_ips: '10.0.0.1/24', created_at: ago(4300), expires_at: ahead(20000), last_used_at: ago(9), active: true },
    { id: 'tk_mcp', name: 'mcp-claude', permissions: { secrets: 'r', namespaces: ['mcp'] }, allowed_ips: '127.0.0.1/32', created_at: ago(1200), expires_at: null, last_used_at: ago(1), active: true },
    { id: 'tk_n8n', name: 'n8n-host', permissions: { secrets: 'r', namespaces: ['n8n'] }, allowed_ips: '10.89.0.0/16', created_at: ago(880), expires_at: null, last_used_at: ago(33), active: true },
    { id: 'tk_ci', name: 'ci-ephemeral', permissions: { secrets: 'r', namespaces: ['prod'] }, allowed_ips: '', created_at: ago(52), expires_at: ahead(8), last_used_at: ago(50), active: true },
    { id: 'eph_1', name: 'ci-run-8f3a', is_ephemeral: true, parent: 'ci-ephemeral', permissions: { secrets: 'r', namespaces: ['prod'] }, allowed_ips: '10.0.0.1/24', created_at: ago(4), expires_at: ahead(52), last_used_at: ago(3), active: true },
    { id: 'eph_2', name: 'mcp-agent-1c9b', is_ephemeral: true, parent: 'mcp-claude', permissions: { secrets: 'r', namespaces: ['mcp'] }, allowed_ips: '127.0.0.1/32', created_at: ago(1), expires_at: ahead(58), last_used_at: ago(1), active: true },
  ];

  const A = (min, actor, action, target) => ({
    id: 'a' + Math.round(min), timestamp: ago(min), ts: ago(min),
    actor, action, target,
  });
  const auditMut = [
    A(2, 'mcp-claude', 'read_secret', 'mcp/openai-api-key'),
    A(9, 'ansible-deploy', 'read_secret', 'prod/postgres-app-dsn'),
    A(33, 'n8n-host', 'read_secret', 'n8n/n8n-encryption-key'),
    A(38, 'root', 'update_secret', 'clients/stripe-secret-key'),
    A(52, 'root', 'create_token', 'ci-ephemeral'),
    A(190, 'root', 'unseal', 'vault'),
  ];
  const auditLite = auditMut.filter((e) => e.action === 'read_secret');

  const leases = [
    { id: 'ls_1', role: 'readonly', engine: 'pg-prod', username: 'v-demo-8f3a', expires_at: ahead(14), created_at: ago(46) },
    { id: 'ls_2', role: 'app', engine: 'pg-prod', username: 'v-demo-1c9b', expires_at: ahead(41), created_at: ago(19) },
  ];
  let pkiCa = null;

  // Mutations persist in these arrays so interactive create/delete feels real.
  const nowIso = () => new Date().toISOString();
  const rid = (pfx) => pfx + Math.random().toString(36).slice(2, 8);
  const randTok = () => 'rh_' + Array.from({ length: 30 }, () =>
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 62)]).join('');
  const auditAdd = (action, target, actor = 'root') =>
    auditMut.unshift({ id: rid('a'), timestamp: nowIso(), ts: nowIso(), actor, action, target });

  // ---- mock router -------------------------------------------------------
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  window.api = async function (method, path, body) {
    await sleep(90 + Math.random() * 120);           // network-ish latency
    const p = path.split('?')[0];

    if (p === '/status') return status();
    if (p === '/cluster/health')
      return { overall: 'healthy', components: { database: { state: 'up' }, database_ha: { state: 'up', provider: 'demo' }, cluster: { state: 'up' } } };
    if (p === '/cluster' || p === '/cluster/ha')
      return { nodes: [], workers: [], items: [] };

    if (method === 'POST' && p === '/unseal') { sealed = false; return {}; }
    if (method === 'POST' && p === '/seal') { sealed = true; return {}; }
    if (method === 'POST' && p === '/challenge') return { challenge: 'demo-challenge-0000' };

    if (method === 'GET' && p === '/secrets/') return { items: secrets.map(({ value, ...s }) => s) };
    if (method === 'GET' && p.startsWith('/secrets/')) {
      const name = decodeURIComponent(p.slice('/secrets/'.length));
      const s = secrets.find((x) => x.name === name) || {};
      return { ...s };
    }
    if (method === 'GET' && p === '/namespaces/') return { items: [
      { name: 'clients', owner_group_id: 'grp_admin_01', secret_count: 2, rbac_mode: 'free', archived_at: null },
      { name: 'prod', owner_group_id: 'grp_ops_02', secret_count: 1, rbac_mode: 'strict', archived_at: null },
      { name: 'mcp', owner_group_id: 'grp_admin_01', secret_count: 1, rbac_mode: 'free', archived_at: null },
      { name: 'n8n', owner_group_id: 'grp_ops_02', secret_count: 1, rbac_mode: 'free', archived_at: null },
    ] };
    if (method === 'GET' && p === '/groups/') return { items: [
      { id: 'grp_admin_01', name: 'admins', permissions: { admin: 'rw' }, source: 'local', member_count: 2 },
      { id: 'grp_ops_02', name: 'ops-team', permissions: { secrets: 'rw', namespaces: ['prod', 'n8n'] }, source: 'local', member_count: 3 }, // pragma: allowlist secret
    ] };

    if (method === 'GET' && p === '/tokens/') return { items: tokens };
    if (method === 'GET' && p === '/tokens/pending/') return { items: [] };

    if (p.startsWith('/audit/lite')) return { items: auditLite };
    if (p === '/audit/files') return { files: [{ date: '2026-07-01', entries: 128, size: '42 KB', compressed: false }], retention_days: 365 };
    if (p.startsWith('/audit/files/')) return { entries: auditMut };
    if (p === '/audit/verify') return { chain_intact: true, verified: auditMut.length };
    if (p.startsWith('/audit/')) return { items: auditMut, chain_intact: true };

    if (method === 'GET' && p === '/dynamic/leases') return { items: leases };
    if (method === 'GET' && p === '/dynamic/engines') return { items: [{ id: 'pg-prod', kind: 'postgresql', name: 'pg-prod' }] };

    if (method === 'GET' && p === '/notifications/') return { items: channels };

    if (method === 'GET' && p === '/pki/certs') return { items: [] };
    if (method === 'GET' && (p === '/pki/cas' || p.startsWith('/pki/ca'))) return { items: pkiCa ? [pkiCa] : [] };

    // ---- writes: persist in memory so the UI reflects them --------------
    // Secrets
    if (method === 'POST' && p === '/secrets/') {
      const b = body || {}, ns = b.namespace || 'default';
      const ex = secrets.find((s) => s.name === b.name);
      if (ex) { ex.version++; ex.value = b.value ?? ex.value; ex.updated_at = nowIso(); }
      else secrets.unshift({ name: b.name, namespace: ns, version: 1, updated_at: nowIso(), expires_at: null, value: b.value || '' });
      auditAdd('create_secret', `${ns}/${b.name}`);
      return { name: b.name, namespace: ns, version: ex ? ex.version : 1 };
    }
    if (method === 'PUT' && p.startsWith('/secrets/')) {
      const s = secrets.find((x) => x.name === decodeURIComponent(p.slice(9)));
      if (s) { s.version++; if (body && body.value != null) s.value = body.value; s.updated_at = nowIso(); auditAdd('update_secret', `${s.namespace}/${s.name}`); return { name: s.name, version: s.version }; }
      return { ok: true };
    }
    if (method === 'DELETE' && p.startsWith('/secrets/') && !p.startsWith('/secrets/namespaces')) {
      const name = decodeURIComponent(p.slice(9));
      const i = secrets.findIndex((x) => x.name === name);
      if (i >= 0) { const s = secrets.splice(i, 1)[0]; auditAdd('delete_secret', `${s.namespace}/${name}`); }
      return { ok: true };
    }
    // Tokens
    if (method === 'POST' && p === '/tokens/') {
      const b = body || {}, t = { id: rid('tk_'), name: b.name || 'new-token', permissions: b.permissions || { secrets: 'r', namespaces: [] }, allowed_ips: b.allowed_ips || '', created_at: nowIso(), expires_at: b.expires_at || null, last_used_at: null, active: true };
      tokens.unshift(t); auditAdd('create_token', t.name);
      return { ...t, token: randTok() };
    }
    if (method === 'POST' && p === '/tokens/ephemeral') { auditAdd('create_ephemeral_token', 'ephemeral'); return { token: randTok(), expires_at: ahead(60) }; }
    if (method === 'POST' && /^\/tokens\/[^/]+\/rotate$/.test(p)) { const t = tokens.find((x) => x.id === p.split('/')[2]); if (t) auditAdd('rotate_token', t.name); return { name: t ? t.name : 'token', token: randTok(), warning: 'Save this token, shown once only' }; }
    if (method === 'POST' && /^\/tokens\/[^/]+\/revoke$/.test(p)) { const t = tokens.find((x) => x.id === p.split('/')[2]); if (t) { t.active = false; auditAdd('revoke_token', t.name); } return { ok: true }; }
    if (method === 'DELETE' && /^\/tokens\/[^/]+$/.test(p)) { const i = tokens.findIndex((x) => x.id === p.split('/')[2]); if (i >= 0) { const t = tokens.splice(i, 1)[0]; auditAdd('delete_token', t.name); } return { ok: true }; }
    // Namespaces / notifications
    if (method === 'POST' && p === '/notifications/') { const c = { id: rid('n'), type: (body && body.type) || 'webhook', kind: (body && body.type) || 'webhook', name: (body && body.name) || 'channel', target: (body && body.target) || '', enabled: true }; channels.unshift(c); auditAdd('create_channel', c.name); return { ...c }; }
    if (method === 'DELETE' && /^\/notifications\/.+/.test(p)) { const i = channels.findIndex((x) => x.id === p.split('/')[2]); if (i >= 0) channels.splice(i, 1); return { ok: true }; }
    // Dynamic creds mint -> new lease
    if (method === 'POST' && /^\/dynamic\/engines\/.+\/creds\/.+$/.test(p)) {
      const u = 'v-demo-' + Math.random().toString(36).slice(2, 6);
      const l = { id: rid('ls_'), role: p.split('/')[5], engine: p.split('/')[3], username: u, expires_at: ahead(60), created_at: nowIso() };
      leases.unshift(l); auditAdd('issue_dynamic_cred', u);
      return { username: u, password: 'DEMO-' + randTok().slice(3, 15), lease_id: l.id, expires_at: l.expires_at }; // pragma: allowlist secret
    }
    if (method === 'POST' && /^\/dynamic\/leases\/.+\/revoke$/.test(p)) { const i = leases.findIndex((x) => x.id === p.split('/')[3]); if (i >= 0) leases.splice(i, 1); return { ok: true }; }
    // PKI
    if (method === 'POST' && p === '/pki/init') { pkiCa = { id: 'ca1', algorithm: (body && body.algorithm) || 'ml-dsa-65', subject: (body && body.common_name) || 'rhorizon-pki', created_at: nowIso() }; auditAdd('pki_init', pkiCa.subject); return { ...pkiCa }; }

    // Any other write: pretend it worked. Any other read: clean empty state.
    if (method !== 'GET') return { ok: true };
    return { items: [] };
  };

  // A valid-format demo token so views never nag about auth.
  try { window.setToken && window.setToken('rh_' + 'demoDEMOdemoDEMOdemoDEMO01'); } catch (e) {} // pragma: allowlist secret

  // ---- injected demo-only screens (not part of the shipped app) ----------
  const svgIcon = (paths) => `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${paths}</svg>`;
  const ICON_NOVA = svgIcon('<path d="M3 3v18h18"/><path d="M7 14l3-4 3 3 4-6"/>');

  function spark(pts) {
    const w = 132, h = 34, step = w / (pts.length - 1);
    const d = pts.map((p, i) => `${i ? 'L' : 'M'}${(i * step).toFixed(1)} ${(h - 2 - p * (h - 5)).toFixed(1)}`).join(' ');
    return `<svg class="nova-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><path d="${d}"/></svg>`;
  }
  const rnd = (n) => Array.from({ length: n }, () => Math.random());

  async function renderNova(el) {
    clearInterval(window._novaTimer);
    el.innerHTML = `<div class="demo-obs">
      <div class="obs-panel"><div class="obs-label">Vault state</div><div class="obs-stat ok">UNSEALED</div></div>
      <div class="obs-panel"><div class="obs-label">Active tokens</div><div class="obs-stat">4</div></div>
      <div class="obs-panel"><div class="obs-label">Secrets stored</div><div class="obs-stat">5</div></div>
      <div class="obs-panel"><div class="obs-label">Active connections</div><div class="obs-stat" id="obs-conn">37</div></div>
      <div class="obs-panel wide"><div class="obs-label">Secrets read/s (RPS)</div><div class="obs-stat" id="obs-rps">12.4</div>${spark(rnd(24))}</div>
      <div class="obs-panel wide"><div class="obs-label">Throughput /s</div><div class="obs-stat" id="obs-thr">1 042</div>${spark(rnd(24))}</div>
      <div class="obs-panel"><div class="obs-label">Total reads</div><div class="obs-stat" id="obs-total">184 213</div></div>
      <div class="obs-panel"><div class="obs-label">Decrypt p95</div><div class="obs-stat">0.8 ms</div></div>
      <div class="obs-panel"><div class="obs-label">Auth failures /min</div><div class="obs-stat warn">0</div></div>
    </div>`;
    const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    let total = 184213;
    const noAnim = /[?&]capture=1/.test(location.search) ||
      (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    if (noAnim) return;
    window._novaTimer = setInterval(() => {
      set('obs-rps', (11 + Math.random() * 4).toFixed(1));
      set('obs-thr', (980 + Math.floor(Math.random() * 160)).toLocaleString('fr-FR'));
      set('obs-conn', 34 + Math.floor(Math.random() * 8));
      total += Math.floor(Math.random() * 18);
      set('obs-total', total.toLocaleString('fr-FR'));
    }, 900);
  }

  // ---- guided tour -------------------------------------------------------
  const eclipseTab = (t) => () => window._setEclipseTab && window._setEclipseTab(t);
  const quasarTab = (t) => () => window._setQuasarTab && window._setQuasarTab(t);

  const steps = [
    { view: 'horizon', title: 'Sealed by default', body: 'After a reboot the vault is locked. No secret is readable until a human unseals it.' },
    { view: 'horizon', title: 'Unseal, password + 2FA', body: 'Keys derived in RAM (Argon2id). 2FA: TOTP, YubiKey or WebAuthn security key. The event horizon lights up, jets fire.', unseal: true },
    { view: 'eclipse', title: 'Secrets', body: 'Encrypted per-secret, grouped by namespace. Values auto-clear after 30s. Versioned and rollback-able.', after: eclipseTab('secrets') },
    { view: 'eclipse', title: 'Dynamic secrets', body: 'Short-lived DB credentials (PostgreSQL/MySQL/LDAP), minted on demand, auto-revoked at expiry.', after: eclipseTab('dynamic') },
    { view: 'eclipse', title: 'PKI, quantum-resistant', body: 'Built-in CA issues short X.509 certs. Signature algorithm ml-dsa-65 (FIPS 204 post-quantum) or ed25519.', after: eclipseTab('pki') },
    { view: 'quasar', title: 'Tokens', body: 'Scoped per token: read-only, one namespace, IP-locked. Give an AI agent exactly one folder.', after: quasarTab('tokens') },
    { view: 'quasar', title: 'Ephemeral tokens', body: 'Mint a token that self-destructs after minutes. Perfect for a CI job or a one-off agent run.', after: quasarTab('ephemeral') },
    { view: 'jets', title: 'Audit, chained + signed', body: 'Writes are chained; reads are Merkle-checkpointed into that signed evidence. Jets exports one offline-verifiable .tar.gz bundle.' },
    { view: 'cluster', title: 'Groups, LDAP / SSO / HA', body: 'RBAC groups, LDAP/AD mapping, SSO proxy, and high-availability cluster topology.' },
    { view: 'nebula', title: 'Namespaces', body: 'Partition secrets and tokens per client or per project. Sub-admins scoped to a single namespace.' },
    { view: 'pulsar', title: 'Notifications', body: 'Alerts to Matrix, webhook or email: seal/unseal, honeytoken hits, failed auth, rotations.' },
    { view: 'nova', title: 'Observability, Grafana', body: 'Prometheus /metrics on a dashboard: active connections, secrets, RPS, decrypt latency, throughput.' },
    { view: 'core', title: '2FA, Shamir, rotation', body: '2FA modes, Shamir M-of-N master split, master-password rotation, backup. Self-hosted, no SaaS.' },
  ];

  // Tour narration follows the page language (passed as ?lang=fr|de on the iframe).
  const DEMO_LANG = (function () {
    var l = (new URLSearchParams(location.search).get('lang') || '').slice(0, 2);
    return (l === 'fr' || l === 'de') ? l : 'en';
  })();
  const STEP_TR = {
    fr: [
      ['Scellé par défaut', "Après un redémarrage, le coffre est verrouillé. Aucun secret n'est lisible tant qu'un humain ne l'a pas déverrouillé."],
      ['Déverrouillage, mot de passe + 2FA', "Clés dérivées en RAM (Argon2id). 2FA : TOTP, YubiKey ou clé WebAuthn. L'horizon s'illumine, les jets s'allument."],
      ['Secrets', "Chiffrés un par un, groupés par namespace. Effacés de l'écran après 30 s. Versionnés et réversibles."],
      ['Secrets dynamiques', "Identifiants BDD éphémères (PostgreSQL/MySQL/LDAP), créés à la demande, révoqués automatiquement à l'expiration."],
      ['PKI, résistante au quantique', 'Une CA intégrée émet des certificats X.509 courts. Signature ml-dsa-65 (FIPS 204 post-quantique) ou ed25519.'],
      ['Jetons', 'Portée par jeton : lecture seule, un seul namespace, IP verrouillée. Donnez à un agent IA exactement un dossier.'],
      ['Jetons éphémères', "Créez un jeton qui s'autodétruit après quelques minutes. Parfait pour un job CI ou un agent ponctuel."],
      ['Audit, chaîné + signé', 'Chaque lecture et écriture est chaînée en HMAC. Infalsifiable. Exportable par client pour vos rapports.'],
      ['Groupes, LDAP / SSO / HA', 'Groupes RBAC, mapping LDAP/AD, proxy SSO et topologie de cluster haute disponibilité.'],
      ['Namespaces', 'Cloisonnez secrets et jetons par client ou par projet. Sous-admins limités à un seul namespace.'],
      ['Notifications', "Alertes vers Matrix, webhook ou email : seal/unseal, honeytokens, échecs d'authentification, rotations."],
      ['Observabilité, Grafana', 'Métriques Prometheus sur un tableau de bord : connexions, secrets, RPS, latence de déchiffrement, débit.'],
      ['2FA, Shamir, rotation', 'Modes 2FA, partage Shamir M-of-N de la clé maître, rotation du mot de passe maître, sauvegarde. Auto-hébergé, sans SaaS.'],
    ],
    de: [
      ['Standardmäßig versiegelt', 'Nach einem Neustart ist der Tresor verriegelt. Kein Secret ist lesbar, bis ein Mensch entsperrt.'],
      ['Entsperren, Passwort + 2FA', 'Schlüssel im RAM abgeleitet (Argon2id). 2FA: TOTP, YubiKey oder WebAuthn-Schlüssel. Der Horizont leuchtet auf, die Jets zünden.'],
      ['Secrets', 'Einzeln verschlüsselt, nach Namespace gruppiert. Nach 30 s vom Bildschirm gelöscht. Versioniert und zurückrollbar.'],
      ['Dynamische Secrets', 'Kurzlebige DB-Zugangsdaten (PostgreSQL/MySQL/LDAP), auf Anfrage erstellt, bei Ablauf automatisch widerrufen.'],
      ['PKI, quantenresistent', 'Eine integrierte CA stellt kurze X.509-Zertifikate aus. Signatur ml-dsa-65 (FIPS 204 post-quantum) oder ed25519.'],
      ['Tokens', 'Umfang pro Token: nur lesen, ein Namespace, IP-gebunden. Geben Sie einem KI-Agenten genau einen Ordner.'],
      ['Kurzlebige Tokens', 'Erstellen Sie ein Token, das sich nach Minuten selbst zerstört. Perfekt für einen CI-Job oder einen einmaligen Agenten.'],
      ['Audit, verkettet + signiert', 'Jeder Lese- und Schreibzugriff ist HMAC-verkettet. Manipulationssicher. Pro Kunde exportierbar.'],
      ['Gruppen, LDAP / SSO / HA', 'RBAC-Gruppen, LDAP/AD-Mapping, SSO-Proxy und Hochverfügbarkeits-Cluster-Topologie.'],
      ['Namespaces', 'Trennen Sie Secrets und Tokens pro Kunde oder Projekt. Sub-Admins auf einen Namespace beschränkt.'],
      ['Benachrichtigungen', 'Alarme an Matrix, Webhook oder E-Mail: Seal/Unseal, Honeytokens, fehlgeschlagene Auth, Rotationen.'],
      ['Observability, Grafana', 'Prometheus-Metriken auf einem Dashboard: Verbindungen, Secrets, RPS, Entschlüsselungslatenz, Durchsatz.'],
      ['2FA, Shamir, Rotation', '2FA-Modi, Shamir-M-of-N-Aufteilung des Hauptschlüssels, Rotation des Hauptpassworts, Backup. Selbst gehostet, kein SaaS.'],
    ],
  };
  function cap(i) {
    var t = STEP_TR[DEMO_LANG] && STEP_TR[DEMO_LANG][i];
    return t ? { title: t[0], body: t[1] } : { title: steps[i].title, body: steps[i].body };
  }

  let idx = 0;
  let paused = false;
  let timer = null;

  function ui() {
    const bar = document.createElement('div');
    bar.id = 'demo-bar';
    bar.innerHTML = `
      <div class="demo-badge">LIVE DEMO</div>
      <div class="demo-cap">
        <div class="demo-title"></div>
        <div class="demo-body"></div>
      </div>
      <div class="demo-ctrl">
        <button type="button" id="demo-prev" title="Previous">&#8249;</button>
        <button type="button" id="demo-play" title="Pause">&#10073;&#10073;</button>
        <button type="button" id="demo-next" title="Next">&#8250;</button>
      </div>
      <div class="demo-progress"><span id="demo-progress-fill"></span></div>`;
    document.body.appendChild(bar);
    document.getElementById('demo-prev').onclick = () => { go(idx - 1); userPause(false); };
    document.getElementById('demo-next').onclick = () => { go(idx + 1); userPause(false); };
    document.getElementById('demo-play').onclick = togglePlay;

    // Any real interaction with the app pauses autoplay.
    ['mousedown', 'keydown', 'touchstart', 'wheel'].forEach((ev) =>
      document.getElementById('main')?.addEventListener(ev, () => userPause(true), { passive: true }));
    const sb = document.querySelector('.sidebar');
    if (sb) ['mousedown', 'touchstart'].forEach((ev) => sb.addEventListener(ev, () => userPause(true), { passive: true }));
  }

  function render() {
    const c = cap(idx);
    document.querySelector('#demo-bar .demo-title').textContent = c.title;
    document.querySelector('#demo-bar .demo-body').textContent = c.body;
    const fill = document.getElementById('demo-progress-fill');
    if (fill) { fill.style.transition = 'none'; fill.style.width = '0%';
      requestAnimationFrame(() => { fill.style.transition = 'width 5.4s linear'; fill.style.width = paused ? '0%' : '100%'; }); }
  }

  async function go(n) {
    clearInterval(window._novaTimer);                     // stop obs animation when leaving
    idx = (n + steps.length) % steps.length;
    const s = steps[idx];
    sealed = (idx === 0);                                 // step 0 sealed, everything after unsealed
    // Set status directly. We deliberately do NOT call the app's pollStatus:
    // its sealed->unsealed re-render fires for the *old* view and resolves
    // late (await /cluster/health), clobbering the view we navigate to.
    window._vaultStatus = status();
    if (typeof bhSetState === 'function') bhSetState(sealed);
    const badge = document.getElementById('seal-badge');
    if (badge) { badge.textContent = sealed ? 'SEALED' : 'UNSEALED'; badge.className = `seal-badge ${sealed ? 'sealed' : 'unsealed'}`; }
    if (location.hash.slice(1) !== s.view && typeof navigate === 'function') navigate(s.view);
    else if (typeof route === 'function') route();
    render();
    if (s.after) setTimeout(() => { try { s.after(); } catch (e) {} }, 780);
  }

  function schedule() {
    clearTimeout(timer);
    if (paused) return;
    timer = setTimeout(() => go(idx + 1), 5600);
  }

  function togglePlay() {
    paused = !paused;
    document.getElementById('demo-play').innerHTML = paused ? '&#9658;' : '&#10073;&#10073;';
    if (paused) clearTimeout(timer); else { render(); schedule(); }
  }
  function userPause(showResume) {
    if (!paused) { paused = true; clearTimeout(timer);
      document.getElementById('demo-play').innerHTML = '&#9658;'; }
  }

  // advance the clock: wrap go() so each call re-arms the timer
  const _go = go;
  go = function (n) { return _go(n).then(schedule); };

  function registerInjectedViews() {
    // app.js declares `views` as a top-level const: it lives in the shared
    // global lexical scope (reachable as a bare name from this script), NOT
    // on window. route() reads the same object, so adding keys here works.
    if (typeof views === 'undefined' || !views) return;
    if (!views.nova) views.nova = { title: 'Nova', sub: 'Observability', icon: ICON_NOVA, fn: renderNova };
    const nav = document.getElementById('nav-items');
    if (!nav) return;
    [['nova', ICON_NOVA, 'Nova']].forEach(([key, icon, label]) => {
      if (nav.querySelector(`[data-view="${key}"]`)) return;
      const el = document.createElement('div');
      el.className = 'nav-item';
      el.dataset.view = key;
      el.innerHTML = `<span class="nav-icon">${icon}</span><span class="nav-label">${label}</span>`;
      el.addEventListener('click', () => { if (typeof navigate === 'function') navigate(key); });
      nav.appendChild(el);
    });
  }

  function boot() {
    registerInjectedViews();
    ui();
    // Deep-link: ?step=N starts paused on that step (deterministic, good for
    // captures and direct links); autoplay otherwise unless ?autoplay=0.
    const params = new URLSearchParams(location.search);
    let start = 0;
    if (params.has('step')) {
      start = Math.max(0, Math.min(steps.length - 1, parseInt(params.get('step'), 10) || 0));
      paused = true;
    } else if (params.get('autoplay') === '0') {
      paused = true;
    }
    if (paused) { const b = document.getElementById('demo-play'); if (b) b.innerHTML = '&#9658;'; }
    go(start);
  }

  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', () => setTimeout(boot, 400));
  else setTimeout(boot, 400);
})();
