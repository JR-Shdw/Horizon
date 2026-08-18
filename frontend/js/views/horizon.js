// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Horizon, Dashboard / Seal / Unseal */
'use strict';

async function renderHorizon(el) {
  const s = window._vaultStatus || {};
  const sealed = s.sealed !== false;
  // One verdict from buffers + process lock + swap; see memoryProtectionState.
  const memoryState = memoryProtectionState(s);
  const memoryAtRisk = memoryState !== 'on';
  const memoryTitle = memoryProtectionDetail(s);

  let ch = null;
  try { ch = await api('GET', '/cluster/health'); } catch (e) { /* non-admin or error: skip card */ }

  let html = '<div class="cards">';

  html += `<div class="card">
    <div class="card-title">Vault Status</div>
    <div class="kv"><span>State</span><span class="badge ${sealed ? 'sealed' : 'unsealed'}">${sealed ? 'SEALED' : 'UNSEALED'}</span></div>
    <div class="kv"><span>Version</span><span>${esc(s.version || '-')}</span></div>
    <div class="kv"><span>Uptime</span><span>${esc(s.uptime || '-')}</span></div>
    <div class="kv"><span>Memory protection</span><span class="badge ${memoryAtRisk ? 'sealed' : 'unsealed'}" title="${esc(memoryTitle)}">${esc(memoryState)}</span></div>
    <div class="kv"><span>Key custody</span><span>${s.custody_mode === 'separated' ? `${s.custodian_workers_live}/${s.custodian_workers_expected} min ${s.custodian_quorum_threshold}` : 'embedded workers'}</span></div>
    <div class="kv"><span>2FA</span><span>${esc(s.second_factor || 'none')}</span></div>
    ${s.shamir_enabled ? `<div class="kv"><span>Shamir</span><span>${s.shamir_progress}/${s.shamir_threshold}</span></div>` : ''}
  </div>`;

  if (ch && ch.components) {
    const componentLabels = {
      database: 'Database',
      database_ha: 'Database HA',
      node: 'Node',
      cluster: 'Application HA'
    };
    html += `<div class="card">
    <div class="card-title">Cluster Health <span class="badge ${esc(ch.overall)}">${esc((ch.overall || '').toUpperCase())}</span></div>
    ${Object.entries(ch.components).map(([n, c]) =>
      `<div class="kv"><span>${esc(componentLabels[n] || n)}</span><span class="badge ${esc(c.state)}" title="${esc(c.reason || '')}">${esc(c.state)}</span></div>`
    ).join('')}
  </div>`;
  }

  if (sealed) {
    const showTotp = s.second_factor === 'totp' || s.second_factor === 'any';
    const showYk = s.second_factor === 'yubikey' || s.second_factor === 'any';
    const showWa = showYk && (s.webauthn_registered || 0) > 0 && window.PublicKeyCredential;
    html += `<div class="card">
      <div class="card-title">Unseal</div>
      <form id="unseal-form" autocomplete="off">
      <div class="form-group">
        <label for="f-password">Master Password</label>
        <input type="password" id="f-password" name="password" autocomplete="current-password" placeholder="Enter master password">
      </div>
      <div class="form-group ${showTotp ? '' : 'hidden'}" id="f-totp-row">
        <label for="f-totp">TOTP Code</label>
        <input type="text" id="f-totp" name="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code" maxlength="6">
      </div>
      ${showWa ? `<div id="f-wa-section" class="mt-16">
        <label>Security Key (WebAuthn)</label>
        <div class="mt-4">
          <button type="button" class="btn secondary" id="f-wa-btn" data-action="doWebauthnUnseal">Touch Security Key</button>
          <span id="f-wa-status" class="dim ml-8"></span>
        </div>
      </div>` : ''}
      ${showYk ? `<div id="f-yk-section" class="${showWa ? 'mt-16' : ''}">
        <div class="form-group">
          <label>YubiKey HMAC (CLI) <button type="button" class="btn tiny secondary" data-action="toggle" data-target="f-yk-help">?</button></label>
          <div id="f-yk-help" class="hidden dim help-tip">
            Run in a terminal: <code>ykchalresp -2 -x CHALLENGE</code><br>
            Copy the challenge below, run the command, paste the response.
          </div>
          <div class="row-inline">
            <input type="text" id="f-yk-challenge" readonly placeholder="Click Generate to get a challenge" class="flex-1">
            <button type="button" class="btn secondary small" data-action="ykGetChallenge">Generate</button>
            <button type="button" class="btn tiny" data-action="copy-el" data-src="f-yk-challenge">Copy</button>
          </div>
        </div>
        <div class="form-group">
          <label for="f-yk-response">YubiKey Response</label>
          <input type="text" id="f-yk-response" placeholder="Paste ykchalresp output here">
        </div>
      </div>` : ''}
      <button type="submit" class="btn primary">Unseal Vault</button>
      </form>
    </div>`;
  } else {
    html += `<div class="card">
      <div class="card-title">Auth Token</div>
      <div class="form-group">
        <label>Set your auth token for this session</label>
        <input type="password" id="set-token" value="${esc(getToken())}" placeholder="rh_...">
      </div>
      <button class="btn primary small" data-action="_saveSessionToken">Save Token</button>
      <button class="btn secondary small" data-action="_clearSessionToken">Clear Token</button>
    </div>`;
    html += `<div class="card">
      <div class="card-title">Quick Actions</div>
      <div class="btn-group">
        <button type="button" class="btn secondary" data-action="navigate" data-view="eclipse">Secrets</button>
        <button type="button" class="btn secondary" data-action="navigate" data-view="quasar">Tokens</button>
        <button type="button" class="btn secondary" data-action="navigate" data-view="jets">Audit</button>
      </div>
      <form id="seal-form" class="mt-16" autocomplete="off">
        <label for="f-seal-token">Admin Token</label>
        <input type="password" id="f-seal-token" name="admin_token" autocomplete="current-password" placeholder="Token to seal" class="my-4">
        <button type="submit" class="btn danger small">Seal Vault</button>
      </form>
    </div>`;
  }

  html += '</div>';
  el.innerHTML = html;

  const unsealForm = document.getElementById('unseal-form');
  if (unsealForm) unsealForm.addEventListener('submit', e => { e.preventDefault(); doUnseal(); });
  const sealForm = document.getElementById('seal-form');
  if (sealForm) sealForm.addEventListener('submit', e => { e.preventDefault(); doSeal(); });
}

async function doUnseal() {
  const pw = document.getElementById('f-password')?.value;
  if (!pw) return toast('Password required', false);
  const body = { password: pw };

  const totp = document.getElementById('f-totp')?.value?.trim();
  if (totp) body.totp_code = totp;

  const challenge = document.getElementById('f-yk-challenge')?.value;
  const response = document.getElementById('f-yk-response')?.value;
  if (challenge && response) {
    body.challenge = challenge;
    body.yubikey_response = response;
  }

  try {
    const r = await api('POST', '/unseal', body);
    // First boot: root token → fullscreen overlay; pollStatus will fire on dismiss
    if (r.root_token) {
      setToken(r.root_token);
      _showTokenOverlay(r.root_token, r.bootstrap_kind, r.recovery_token_expires_at);
      return;
    }
    toast('Vault unsealed', true);
    // Await pollStatus so we re-render against fresh state (not the cached
    // sealed=true). pollStatus auto-re-renders the current view on the
    // sealed→unsealed flip, no setTimeout race.
    await pollStatus();
  } catch (e) { toast(e.message, false); }
}

async function doWebauthnUnseal() {
  const pw = document.getElementById('f-password')?.value;
  if (!pw) return toast('Password required', false);

  const statusEl = document.getElementById('f-wa-status');
  const btn = document.getElementById('f-wa-btn');
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = 'Requesting challenge...';

  try {
    // 1. Get WebAuthn auth options
    const opts = await api('POST', '/webauthn/auth/begin');

    if (statusEl) statusEl.textContent = 'Touch your security key...';

    // 2. Convert for browser
    const getOptions = {
      publicKey: {
        challenge: base64urlToBuffer(opts.publicKey.challenge),
        allowCredentials: (opts.publicKey.allowCredentials || []).map(c => ({
          ...c, id: base64urlToBuffer(c.id),
        })),
        rpId: opts.publicKey.rpId,
        timeout: opts.publicKey.timeout,
        userVerification: opts.publicKey.userVerification,
      }
    };

    // 3. Get assertion (user touches key)
    const assertion = await navigator.credentials.get(getOptions);

    if (statusEl) statusEl.textContent = 'Verifying...';

    // 4. Unseal with password + WebAuthn
    const body = {
      password: pw,
      challenge: opts.challenge_id,
      webauthn_response: {
        id: assertion.id,
        rawId: bufferToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
          authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
          signature: bufferToBase64url(assertion.response.signature),
        },
      },
    };

    const r = await api('POST', '/unseal', body);
    if (r.root_token) {
      setToken(r.root_token);
      _showTokenOverlay(r.root_token, r.bootstrap_kind, r.recovery_token_expires_at);
      return;
    }
    toast('Vault unsealed', true);
    await pollStatus();   // auto-re-renders current view on the flip
  } catch (e) {
    if (statusEl) statusEl.textContent = '';
    if (btn) btn.disabled = false;
    if (e.name === 'NotAllowedError') return toast('Authentication cancelled', false);
    toast(e.message || 'WebAuthn authentication failed', false);
  }
}

async function ykGetChallenge() {
  try {
    const r = await api('POST', '/challenge');
    document.getElementById('f-yk-challenge').value = r.challenge;
    toast('Challenge generated (60s TTL)', true);
  } catch (e) { toast(e.message, false); }
}

function _showTokenOverlay(token, bootstrapKind, recoveryExpiresAt) {
  const old = document.getElementById('token-overlay');
  if (old) old.remove();

  const isRecovery = bootstrapKind === 'restore-recovery';
  const title = isRecovery ? 'RECOVERY ROOT TOKEN' : 'VAULT UNSEALED';
  let subtitle;
  if (isRecovery) {
    const expiry = recoveryExpiresAt
      ? new Date(recoveryExpiresAt).toLocaleString()
      : 'a short TTL';
    subtitle = `Your <strong>recovery root token</strong> has been created, `
      + `<strong class="text-red">temporary</strong>, expires ${esc(expiry)}.<br>`
      + `Use it to rotate the stubs in <strong>Quasar &gt; Pending rotations</strong> `
      + `to mint a permanent root token, then dismiss the post-restore review `
      + `in <strong>Core &gt; Settings</strong>.<br>`
      + `Shown <strong class="text-red">once only</strong>. Save it now.`;
  } else {
    subtitle = `Your <strong>root token</strong> has been created.<br>`
      + `Shown <strong class="text-red">once only</strong>. Save it now.`;
  }

  const overlay = document.createElement('div');
  overlay.id = 'token-overlay';
  overlay.className = 'token-overlay';
  overlay.innerHTML = `
    <div class="token-overlay-box">
      <div class="token-overlay-title">${title}</div>
      <div class="token-overlay-subtitle">${subtitle}</div>
      <div id="overlay-token" class="token-overlay-value">${esc(token)}</div>
      <div class="token-overlay-actions">
        <button class="btn-overlay primary" data-action="copy-el-label" data-src="overlay-token">Copy Token</button>
        <button class="btn-overlay secondary" data-action="_dismissOverlay">I have saved it, Continue</button>
      </div>
    </div>`;

  document.body.appendChild(overlay);
}

window._dismissOverlay = async function() {
  document.getElementById('token-overlay').remove();
  // First-boot overlay was shown right after /unseal; the pollStatus that
  // would normally trigger the flip was skipped (we early-returned). Pull
  // a fresh status now so the post-overlay render sees sealed=false.
  await pollStatus();
  renderHorizon(document.getElementById('main'));
};

async function doSeal() {
  const token = document.getElementById('f-seal-token')?.value;
  if (!token) return toast('Token required', false);
  setToken(token);
  try {
    await api('POST', '/seal');
    toast('Vault sealed', true);
    await pollStatus();   // pollStatus auto-redirects to Horizon on the flip
  } catch (e) { toast(e.message, false); }
}
