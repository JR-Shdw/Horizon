// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Nova - live observability view. Polls GET /observability (real Prometheus
// counters + gauges, token-authed audit:r) and renders moving stats/sparklines.
// Counters are monotonic totals; we diff successive polls into per-second rates.
'use strict';

(function () {
  const POLL_MS = 2000;
  const SPARK_POINTS = 32;

  function sparkPath(pts) {
    if (!pts.length) return '';
    const w = 132, h = 34, step = w / Math.max(1, pts.length - 1);
    const max = Math.max(1e-6, ...pts);
    return pts.map((p, i) =>
      `${i ? 'L' : 'M'}${(i * step).toFixed(1)} ${(h - 2 - (p / max) * (h - 5)).toFixed(1)}`
    ).join(' ');
  }

  const nf = (n, d = 0) => Number(n).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });

  async function renderNova(el) {
    el.innerHTML = `<div class="nova-grid">
      <div class="nova-panel"><div class="nova-lbl">Vault state</div><div class="nova-val ok" id="nv-state">-</div></div>
      <div class="nova-panel"><div class="nova-lbl">Active tokens</div><div class="nova-val" id="nv-tokens">-</div></div>
      <div class="nova-panel"><div class="nova-lbl">Active connections</div><div class="nova-val" id="nv-conn">-</div></div>
      <div class="nova-panel"><div class="nova-lbl">Total reads</div><div class="nova-val" id="nv-reads">-</div></div>
      <div class="nova-panel wide"><div class="nova-lbl">Secrets read/s (RPS)</div><div class="nova-val" id="nv-rps">-</div><svg class="nova-spark" viewBox="0 0 132 34" preserveAspectRatio="none"><path id="nv-rps-spark" d=""/></svg></div>
      <div class="nova-panel wide"><div class="nova-lbl">Throughput /s (API + HTTPS)</div><div class="nova-val" id="nv-thr">-</div><svg class="nova-spark" viewBox="0 0 132 34" preserveAspectRatio="none"><path id="nv-thr-spark" d=""/></svg></div>
      <div class="nova-panel"><div class="nova-lbl">Decrypt p95</div><div class="nova-val" id="nv-p95">-</div></div>
      <div class="nova-panel"><div class="nova-lbl">Auth failures /min</div><div class="nova-val mute" id="nv-authf">-</div></div>
    </div>
    <p class="dim nova-note">Live from <code>/metrics</code>, ${POLL_MS / 1000}s refresh. Full history + alerting: import the Grafana dashboards (<code>docs/dashboards/</code>).</p>`;

    const root = el.querySelector('.nova-grid');
    const set = (id, v, cls) => { const e = document.getElementById(id); if (e) { e.textContent = v; if (cls) e.className = 'nova-val ' + cls; } };
    const rpsHist = [], thrHist = [];
    let prev = null;

    async function tick() {
      // Self-terminate when the view is navigated away (DOM node gone).
      if (!document.body.contains(root)) { clearInterval(window._novaTimer); window._novaTimer = null; return; }
      let d;
      try { d = await api('GET', '/observability'); }
      catch (e) { set('nv-state', 'no data', 'mute'); return; }

      set('nv-state', d.sealed ? 'SEALED' : 'UNSEALED', d.sealed ? 'warn' : 'ok');
      set('nv-tokens', nf(d.active_tokens));
      set('nv-conn', nf(d.active_connections));
      set('nv-reads', nf(d.reads_total));
      set('nv-p95', `${nf(d.decrypt_p95_ms, 2)} ms`, 'ok');

      const now = Date.now();
      if (prev) {
        const dt = (now - prev.t) / 1000;
        if (dt > 0) {
          const rps = Math.max(0, (d.reads_total - prev.reads_total) / dt);
          const thr = Math.max(0, (d.http_total - prev.http_total) / dt);
          const authf = Math.max(0, (d.auth_failures_total - prev.auth_failures_total) / dt) * 60;
          set('nv-rps', nf(rps, 1));
          set('nv-thr', nf(thr, thr >= 100 ? 0 : 1));
          set('nv-authf', nf(authf, 0), authf > 0 ? 'warn' : 'mute');
          rpsHist.push(rps); thrHist.push(thr);
          while (rpsHist.length > SPARK_POINTS) rpsHist.shift();
          while (thrHist.length > SPARK_POINTS) thrHist.shift();
          const rp = document.getElementById('nv-rps-spark'); if (rp) rp.setAttribute('d', sparkPath(rpsHist));
          const tp = document.getElementById('nv-thr-spark'); if (tp) tp.setAttribute('d', sparkPath(thrHist));
        }
      }
      prev = { t: now, reads_total: d.reads_total, http_total: d.http_total, auth_failures_total: d.auth_failures_total };
    }

    clearInterval(window._novaTimer);
    await tick();
    window._novaTimer = setInterval(tick, POLL_MS);
  }

  window.renderNova = renderNova;

  // Self-register as a shipped sidebar view. Skipped in demo mode, where demo.js
  // injects its own animated Nova (mocked backend). Mirrors demo.js's injection
  // and runs before app.js builds the nav, so Nova appears automatically.
  function register() {
    const demo = /[?&]demo\b/.test(location.search) || window.__RH_DEMO__;
    if (demo) return;
    if (typeof views === 'undefined' || !views || views.nova) return;
    views.nova = {
      title: 'Nova',
      sub: 'Observability',
      icon: (typeof ICONS !== 'undefined' && ICONS.nova) || '',
      fn: renderNova,
    };
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', register);
  else register();
})();
