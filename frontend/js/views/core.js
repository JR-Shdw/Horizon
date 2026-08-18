// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Core, Settings / Auth token / 2FA / Vault info */
'use strict';

window._saveSessionToken = function() {
  setToken(document.getElementById('set-token').value);
  toast('Token saved', true);
};

// Clear the saved bearer token from this browser (localStorage) -- session
// protection when leaving a shared/public machine. Re-paste to re-auth.
window._clearSessionToken = function() {
  clearToken();
  const inp = document.getElementById('set-token');
  if (inp) inp.value = '';
  toast('Token cleared', true);
};

async function renderCore(el) {
  const s = window._vaultStatus || {};
  const sealed = isSealed();
  // Server-reported, not hardcoded: token_migration_window_days is a tunable,
  // and a panel that states a fixed figure is wrong as soon as it is changed.
  // Falls back to the shipped default only when /status predates the field.
  const migrationWindow = Number(s.token_migration_window_days) || 15;

  let html = '';

  // Post-restore review banner, only when /backup/restore set the flag
  // and the operator has not dismissed it yet. Lists the tables that the
  // restore does NOT carry across (2FA, notifications, dynamic engines,
  // audit chain) so the admin can reconfigure them manually. Also shows
  // the countdown for the recovery root token.
  if (s.pending_restore_review) {
    const pendingCount = s.pending_token_rotations_count || 0;
    let expiryLine = '';
    if (s.recovery_token_expires_at) {
      const exp = new Date(s.recovery_token_expires_at).getTime();
      const days = Math.max(0, Math.round((exp - Date.now()) / 86400000));
      expiryLine = `<div class="kv"><span>Recovery token</span><span>expires in ${days} day${days === 1 ? '' : 's'}</span></div>`;
    }
    html += `<div class="card card-danger">
      <div class="card-title">Post-restore review</div>
      <p class="dim">A backup restore is in progress. The following items need your attention :</p>
      <div class="kv"><span>Tokens awaiting rotation</span><span><a href="#tokens">${pendingCount}</a></span></div>
      ${expiryLine}
      <p class="dim mt-12"><strong>Reconfigure manually</strong>, the backup does not carry these :</p>
      <ul class="dim text-left lh-relaxed">
        <li>YubiKeys (re-enroll with <code>ykman</code>)</li>
        <li>WebAuthn / FIDO2 security keys (re-register from the browser)</li>
        <li>TOTP secret (re-setup if you used it)</li>
        <li>Notification channels (Matrix, webhook, email, config was sealed under the previous dek_key)</li>
        <li>Dynamic secrets engines + roles + active leases</li>
        <li>Audit chain : a new HMAC chain started ; the pre-restore entries remain readable but are not chained to the new ones</li>
      </ul>
      <p class="dim mt-12"><strong class="text-red">Before clicking dismiss</strong>, mint a fresh root token (Quasar &gt; Tokens &gt; New Token) and switch to it. Dismissing revokes the active recovery root token.</p>
      <button class="btn danger small mt-12" data-action="dismissPostRestoreReview">Mark as reviewed</button>
    </div>`;
  }

  // Row 1: Vault Info + Auth Token
  html += `<div class="cards">
    <div class="card">
      <div class="card-title">Vault Info</div>
      <div class="kv"><span>Version</span><span>${esc(s.version || '-')}</span></div>
      <div class="kv"><span>State</span><span>${sealed ? 'SEALED' : 'UNSEALED'}</span></div>
      <div class="kv"><span>Memory protection</span><span title="${esc(memoryProtectionDetail(s))}">${esc(memoryProtectionState(s))}</span></div>
      <div class="kv"><span>Key custody</span><span>${s.custody_mode === 'separated' ? `${s.custodian_workers_live}/${s.custodian_workers_expected} min ${s.custodian_quorum_threshold}` : 'embedded in API workers'}</span></div>
      <div class="kv"><span>2FA Mode</span><span>${esc(s.second_factor || 'none')}</span></div>
      <div class="kv"><span>YubiKeys</span><span>${s.yubikeys_registered || 0}</span></div>
      <div class="kv"><span>WebAuthn</span><span>${s.webauthn_registered || 0}</span></div>
      <div class="kv"><span>TOTP</span><span>${s.totp_enabled ? 'enabled' : 'disabled'}</span></div>
      <div class="kv"><span>Shamir</span><span>${s.shamir_enabled ? s.shamir_threshold + '-of-' + s.shamir_total : 'disabled'}</span></div>
    </div>`;

  if (!sealed) {
    html += `<div class="card">
      <div class="card-title">Auth Token</div>
      <div class="form-group">
        <label>Set your auth token for this session</label>
        <input type="password" id="set-token" value="${esc(getToken())}" placeholder="rh_...">
      </div>
      <button class="btn primary small" data-action="_saveSessionToken">Save Token</button>
      <button class="btn secondary small" data-action="_clearSessionToken">Clear Token</button>
    </div>
  </div>`;

    // Row 2: 2FA + API Docs (fixed height)
    html += `<div class="cards cards-fixed">
    <div class="card">
      <div class="card-title">Two-Factor Authentication</div>
      <div class="kv"><span>Current mode</span><span>${esc(s.second_factor || 'none')}</span></div>

      <div class="mt-16">
        <label>TOTP</label>
        <div class="mt-4">
          ${!s.totp_enabled
            ? '<button class="btn secondary small" data-action="setupTotp">Setup TOTP</button>'
            : '<span class="badge active">enabled</span> <button class="btn danger small" data-action="disableTotp">Disable</button>'}
        </div>
      </div>
      <div id="2fa-result" class="mt-16"></div>

      <div class="mt-16">
        <label>YubiKeys <span class="dim">(${s.yubikeys_registered || 0} registered)</span></label>
        <div id="yk-list" class="mt-4"></div>
        <button class="btn secondary small mt-12" data-action="toggle" data-target="yk-form">+ Register YubiKey</button>
        <div id="yk-form" class="hidden mt-12">
          <div class="form-group"><label>Serial</label><input type="text" id="yk-serial" placeholder="ykman info → Serial"></div>
          <div class="form-group"><label>Name</label><input type="text" id="yk-name" placeholder="e.g. backup-key"></div>
          <div class="form-group">
            <label>HMAC Secret <button class="btn tiny secondary" data-action="toggle" data-target="yk-help">?</button></label>
            <div id="yk-help" class="hidden dim help-tip">
              <code>ykman otp chalresp --generate 2</code><br>
              Copy the 40-char hex secret displayed.
            </div>
            <input type="text" id="yk-secret" placeholder="40 hex chars from ykman">
          </div>
          <button class="btn primary small" data-action="registerYubikey">Register</button>
        </div>
      </div>

      <div class="mt-16">
        <label>Security Keys, WebAuthn <span class="dim">(${s.webauthn_registered || 0} registered)</span></label>
        <div id="wa-list" class="mt-4"></div>
        ${window.PublicKeyCredential ? `
        <button class="btn secondary small mt-12" data-action="toggle" data-target="wa-form">+ Register Security Key</button>
        <div id="wa-form" class="hidden mt-12">
          <div class="form-group"><label>Name</label><input type="text" id="wa-name" placeholder="e.g. YubiKey 5"></div>
          <button class="btn primary small" data-action="registerWebauthn">Touch to register</button>
          <div id="wa-status" class="mt-4 dim"></div>
        </div>` : '<div class="dim mt-4">WebAuthn not available (requires HTTPS or localhost)</div>'}
      </div>

      ${s.totp_enabled || s.yubikeys_registered > 0 || s.webauthn_registered > 0 ? `
      <div class="mt-16">
        <label>Set 2FA Mode</label>
        <span class="select-wrap"><select id="2fa-mode">
          <option value="none" ${s.second_factor === 'none' ? 'selected' : ''}>none</option>
          ${s.totp_enabled ? `<option value="totp" ${s.second_factor === 'totp' ? 'selected' : ''}>totp</option>` : ''}
          ${s.yubikeys_registered > 0 || s.webauthn_registered > 0 ? `<option value="yubikey" ${s.second_factor === 'yubikey' ? 'selected' : ''}>yubikey</option>` : ''}
          ${s.totp_enabled && (s.yubikeys_registered > 0 || s.webauthn_registered > 0) ? `<option value="any" ${s.second_factor === 'any' ? 'selected' : ''}>any</option>` : ''}
        </select></span>
        <button class="btn primary small mt-16" data-action="set2faMode">Apply</button>
      </div>` : ''}
    </div>

    <div class="card">
      <div class="card-title">API Documentation</div>
      <div class="warning-box">
        <strong class="warning-label">WARNING</strong><br>
        <span class="dim">API documentation exposes the full endpoint schema including request/response formats.
        Do NOT enable in production. Use only for development and integration testing.
        Disable immediately after use (<code>RHORIZON_ENABLE_DOCS=false</code> + restart).</span>
      </div>
      <p class="dim">Requires <code>RHORIZON_ENABLE_DOCS=true</code> in .env + <code>docker compose restart api</code></p>
      <div class="form-group mt-16">
        <label>Type "I understand the risks" to access the links</label>
        <input type="text" id="docs-confirm" placeholder="I understand the risks">
      </div>
      <div id="docs-links" class="btn-group mt-16 hidden">
        <a class="btn secondary small" href="/docs" target="_blank">Swagger UI</a>
        <a class="btn secondary small" href="/redoc" target="_blank">ReDoc</a>
        <a class="btn secondary small" href="/openapi.json" target="_blank">OpenAPI JSON</a>
      </div>
    </div>
    </div>`;

    // Row 3: Shamir + Master Password Rotation
    html += `<div class="cards">
    <div class="card">
      <div class="card-title">Shamir Secret Sharing</div>
      ${s.shamir_enabled
        ? `<div class="kv"><span>Status</span><span>${s.shamir_threshold}-of-${s.shamir_total}</span></div>
           <button class="btn danger small mt-16" data-action="disableShamir">Disable Shamir</button>`
        : `<div class="form-group"><label>Threshold (M)</label><input type="number" id="shamir-t" value="3" min="2"></div>
           <div class="form-group"><label>Total shares (N)</label><input type="number" id="shamir-n" value="5" min="3"></div>
           <button class="btn primary small" data-action="initShamir">Initialize Shamir</button>`}
      <div id="shamir-result" class="mt-16"></div>
    </div>

    <div class="card">
      <div class="card-title">Master Password Rotation</div>
      <div class="info-box info-notice">
        <strong class="text-cyan">Token migration</strong><br>
        Tokens are stored as one-way HMAC hashes. After a standard rotation the old key is kept encrypted for <strong>${migrationWindow} days</strong>. Each token is re-hashed with the new key on first use, no manual action required.<br>
        <span class="dim">Tokens not used within ${migrationWindow} days stop working. A second standard rotation inside that window is <strong>refused</strong> (409) because only one previous key is kept &mdash; wait out the window or re-mint long-lived tokens first. Forcing it anyway invalidates every token minted before the first rotation.</span><br>
        <span class="dim">An <strong>emergency</strong> rotation is different: no previous key is kept, so every existing token &mdash; including the one you are using now &mdash; stops working immediately and must be re-minted.</span>
      </div>
      <div class="form-group mt-16">
        <label>Current password</label>
        <input type="password" id="rotate-current-pw" placeholder="Current master password">
      </div>
      <div class="form-group">
        <label>New password</label>
        <input type="password" id="rotate-new-pw" placeholder="New master password">
      </div>
      <div class="form-group">
        <label>Confirm new password</label>
        <input type="password" id="rotate-confirm-pw" placeholder="Confirm new password">
      </div>
      <button class="btn danger small" data-action="rotateMasterPassword">Rotate Password</button>
      <div id="rotate-pw-result" class="mt-16"></div>
    </div>
  </div>`;
  } else {
    html += '</div>';
  }
  el.innerHTML = html;

  // Load YubiKey + WebAuthn lists
  loadYubikeys();
  loadWebauthn();

  // Docs confirmation gate
  const docsInput = document.getElementById('docs-confirm');
  if (docsInput) {
    docsInput.addEventListener('input', function () {
      const links = document.getElementById('docs-links');
      if (this.value.trim().toLowerCase() === 'i understand the risks') {
        links.classList.remove('hidden');
      } else {
        links.classList.add('hidden');
      }
    });
  }
}

// --- 2FA ---

async function setupTotp() {
  try {
    const r = await api('POST', '/totp/setup');
    document.getElementById('2fa-result').innerHTML = `
      <div class="card-title">Scan with your auth app</div>
      <canvas id="totp-qr" class="totp-qr-canvas"></canvas>
      <div class="form-group mt-16">
        <label>Or enter manually</label>
        <div class="secret-value">${esc(r.secret)}</div>
      </div>
      <div class="form-group mt-16">
        <label>Enter code from app to confirm</label>
        <input type="text" id="totp-confirm" placeholder="6-digit code" maxlength="6">
      </div>
      <button class="btn primary small" data-action="enableTotp">Confirm TOTP</button>`;
    if (typeof drawQR === 'function') drawQR('totp-qr', r.uri, { scale: 4 });
  } catch (e) { toast(e.message, false); }
}

async function enableTotp() {
  const code = document.getElementById('totp-confirm')?.value;
  if (!code) return toast('Enter the 6-digit code', false);
  try {
    await api('POST', '/totp/enable', { code });
    toast('TOTP enabled', true);
    pollStatus();
    setTimeout(() => renderCore(document.getElementById('main')), 500);
  } catch (e) { toast(e.message, false); }
}

async function disableTotp() {
  const ok = await confirmModal({
    title: 'Disable TOTP',
    body: 'Removes the TOTP second factor from this account. Anyone with the master password alone will be able to unseal until you re-enable a second factor.',
    okLabel: 'Disable',
  });
  if (!ok) return;
  try {
    await api('DELETE', '/totp');
    toast('TOTP disabled', true);
    pollStatus();
    setTimeout(() => renderCore(document.getElementById('main')), 500);
  } catch (e) { toast(e.message, false); }
}

async function registerYubikey() {
  const serial = document.getElementById('yk-serial')?.value?.trim();
  const name = document.getElementById('yk-name')?.value?.trim() || serial;
  const secret = document.getElementById('yk-secret')?.value?.trim();
  if (!serial || !secret) return toast('Serial and HMAC secret required', false);
  if (!/^[0-9a-fA-F]{40}$/.test(secret)) return toast('HMAC secret must be 40 hex chars', false);
  try {
    await api('POST', '/yubikey', { serial, name, hmac_secret: secret });
    toast(`YubiKey ${serial} registered`, true);
    pollStatus();
    setTimeout(() => renderCore(document.getElementById('main')), 500);
  } catch (e) { toast(e.message, false); }
}

async function loadYubikeys() {
  const el = document.getElementById('yk-list');
  if (!el) return;
  try {
    const r = await api('GET', '/yubikey');
    const keys = r.keys || r.items || [];
    if (!keys.length) {
      el.innerHTML = '<span class="dim">No YubiKeys registered</span>';
      return;
    }
    let html = '<table class="table"><thead><tr><th>Serial</th><th>Name</th><th>Registered</th><th></th></tr></thead><tbody>';
    for (const k of keys) {
      html += `<tr>
        <td><code>${esc(k.serial)}</code></td>
        <td>${esc(k.name || '-')}</td>
        <td class="dim">${timeAgo(k.registered_at)}</td>
        <td><button class="btn tiny danger" data-action="deleteYubikey" data-arg="${esc(k.serial)}">Del</button></td>
      </tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch (e) { el.innerHTML = '<span class="dim">Failed to load YubiKeys</span>'; }
}

async function deleteYubikey(serial) {
  const ok = await confirmModal({
    title: `Delete YubiKey ${serial}`,
    body: 'Unregisters this YubiKey. If it is your only second factor you will fall back to the master password alone until you register another.',
    okLabel: 'Delete',
  });
  if (!ok) return;
  try {
    await api('DELETE', `/yubikey/${encodeURIComponent(serial)}`);
    toast(`YubiKey ${serial} deleted`, true);
    pollStatus();
    setTimeout(() => renderCore(document.getElementById('main')), 500);
  } catch (e) { toast(e.message, false); }
}

async function set2faMode() {
  const mode = document.getElementById('2fa-mode')?.value;
  try {
    await api('PUT', `/2fa?mode=${mode}`);
    toast(`2FA mode: ${mode}`, true);
    pollStatus();
    setTimeout(() => renderCore(document.getElementById('main')), 500);
  } catch (e) { toast(e.message, false); }
}

// --- Master Password Rotation ---

async function rotateMasterPassword() {
  const current = document.getElementById('rotate-current-pw')?.value;
  const newPw = document.getElementById('rotate-new-pw')?.value;
  const confirm = document.getElementById('rotate-confirm-pw')?.value;
  const resultEl = document.getElementById('rotate-pw-result');

  if (!current || !newPw || !confirm) return toast('Fill all fields', false);
  if (newPw !== confirm) return toast('New passwords do not match', false);
  if (newPw.length < 12) return toast('New password must be at least 12 characters', false);
  const ok = await confirmType('ROTATE', {
    title: 'Rotate master password',
    body: 'Re-derives the master key, re-wraps every DEK, and re-encrypts the 2FA secrets. Existing tokens are lazy-migrated on next use (15-day window). If you need immediate token invalidation, use the API directly with `emergency: true`.',
    okLabel: 'Rotate',
  });
  if (!ok) return;

  try {
    const r = await api('POST', '/rotate-password', {
      current_password: current,
      new_password: newPw,
    });
    document.getElementById('rotate-current-pw').value = '';
    document.getElementById('rotate-new-pw').value = '';
    document.getElementById('rotate-confirm-pw').value = '';
    resultEl.innerHTML = `<div class="badge unsealed badge-lg">${esc(r.status || 'Password rotated')}</div>`;
    toast('Master password rotated', true);
  } catch (e) { toast(e.message, false); }
}

// --- WebAuthn / FIDO2 ---

async function loadWebauthn() {
  const el = document.getElementById('wa-list');
  if (!el) return;
  try {
    const r = await api('GET', '/webauthn');
    const keys = r.items || [];
    if (!keys.length) {
      el.innerHTML = '<span class="dim">No security keys registered</span>';
      return;
    }
    let html = '<table class="table"><thead><tr><th>Name</th><th>Registered</th><th>Uses</th><th></th></tr></thead><tbody>';
    for (const k of keys) {
      html += `<tr>
        <td>${esc(k.name || '-')}</td>
        <td class="dim">${timeAgo(k.registered_at)}</td>
        <td class="dim">${k.sign_count}</td>
        <td><button class="btn tiny danger" data-action="deleteWebauthn" data-arg="${esc(k.id)}" data-arg2="${esc(k.name)}">Del</button></td>
      </tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch (e) { el.innerHTML = '<span class="dim">Failed to load security keys</span>'; }
}

async function registerWebauthn() {
  const name = document.getElementById('wa-name')?.value?.trim() || 'Security Key';
  const statusEl = document.getElementById('wa-status');
  if (statusEl) statusEl.textContent = 'Starting registration...';
  try {
    // 1. Get options from server
    const opts = await api('POST', '/webauthn/register/begin', { name });

    if (statusEl) statusEl.textContent = 'Touch your security key now...';

    // 2. Convert for browser
    const createOptions = {
      publicKey: {
        rp: opts.publicKey.rp,
        user: {
          ...opts.publicKey.user,
          id: base64urlToBuffer(opts.publicKey.user.id),
        },
        challenge: base64urlToBuffer(opts.publicKey.challenge),
        pubKeyCredParams: opts.publicKey.pubKeyCredParams,
        excludeCredentials: (opts.publicKey.excludeCredentials || []).map(c => ({
          ...c, id: base64urlToBuffer(c.id),
        })),
        authenticatorSelection: opts.publicKey.authenticatorSelection,
        timeout: opts.publicKey.timeout,
        attestation: opts.publicKey.attestation,
      }
    };

    // 3. Create credential (user touches key)
    const credential = await navigator.credentials.create(createOptions);

    if (statusEl) statusEl.textContent = 'Verifying...';

    // 4. Send to server
    await api('POST', '/webauthn/register/complete', {
      challenge_id: opts.challenge_id,
      name: name,
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        attestationObject: bufferToBase64url(credential.response.attestationObject),
      },
    });

    toast('Security key registered', true);
    pollStatus();
    setTimeout(() => renderCore(document.getElementById('main')), 500);
  } catch (e) {
    if (statusEl) statusEl.textContent = '';
    if (e.name === 'NotAllowedError') return toast('Registration cancelled', false);
    toast(e.message || 'Registration failed', false);
  }
}

async function deleteWebauthn(id, name) {
  const ok = await confirmType(name, {
    title: `Delete security key '${name}'`,
    body: 'Unregisters this WebAuthn/passkey authenticator. If it is your only second factor you will fall back to the master password alone until you register another.',
    okLabel: 'Delete',
  });
  if (!ok) return;
  try {
    await api('DELETE', `/webauthn/${encodeURIComponent(id)}`);
    toast(`Security key "${name}" deleted`, true);
    pollStatus();
    setTimeout(() => renderCore(document.getElementById('main')), 500);
  } catch (e) { toast(e.message, false); }
}

// --- Shamir ---

async function initShamir() {
  const threshold = parseInt(document.getElementById('shamir-t')?.value);
  const total = parseInt(document.getElementById('shamir-n')?.value);
  try {
    const r = await api('POST', '/shamir/init', { threshold, total });
    let html = `<div class="card-title">Shares (${r.threshold}-of-${r.total}), shown ONCE</div>`;
    r.shares.forEach((s, i) => {
      html += `<div class="secret-value secret-share">${i + 1}: ${esc(s)}</div>`;
    });
    html += '<p class="dim">Distribute to key holders. These are not stored.</p>';
    document.getElementById('shamir-result').innerHTML = html;
    toast('Shamir initialized', true);
    pollStatus();
  } catch (e) { toast(e.message, false); }
}

async function disableShamir() {
  const ok = await confirmType('DISABLE', {
    title: 'Disable Shamir',
    body: 'Password unseal becomes the ONLY recovery path. If you forget the master password, every secret is lost, Shamir was your independent backup. Make sure your master passphrase is stored safely (paper safe, second password manager) before disabling.',
    okLabel: 'Disable Shamir',
  });
  if (!ok) return;
  try {
    await api('DELETE', '/shamir');
    toast('Shamir disabled', true);
    pollStatus();
    setTimeout(() => renderCore(document.getElementById('main')), 500);
  } catch (e) { toast(e.message, false); }
}

async function dismissPostRestoreReview() {
  const ok = await confirmType('DISMISS', {
    title: 'Mark post-restore review as completed',
    body: 'This will revoke the active recovery root token. If your browser is currently using it, you will need to re-authenticate with a root token immediately.',
    okLabel: 'Mark reviewed',
  });
  if (!ok) return;
  try {
    const r = await api('POST', '/post-restore-review/dismiss');
    if (r.warning) {
      toast(r.warning, false);
    } else {
      toast(`Reviewed (${r.revoked_recovery_tokens || 0} recovery root token(s) revoked)`, true);
    }
    pollStatus();
    setTimeout(() => renderCore(document.getElementById('main')), 500);
  } catch (e) { toast(e.message, false); }
}
