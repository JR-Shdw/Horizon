// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Accretion, Migration Import / Backup / Restore */
'use strict';

async function renderAccretion(el) {
  if (isSealed()) { el.innerHTML = sealedHtml(); return; }
  el.innerHTML = `<div class="cards">
    <div class="card">
      <div class="card-title">Backup Vault (encrypted)</div>
      <p class="dim mb-12">Creates an age-encrypted logical backup of secrets, namespaces, groups, config, and token metadata.<br>
        Encryption: <code>age</code> format (scrypt + ChaCha20-Poly1305).</p>
      <p class="mb-12 text-red"><strong>Important:</strong> keep the
        <strong>vault master password</strong> in addition to the
        <strong>age passphrase</strong> below, both are required to
        restore this backup. Losing either makes the backup
        unreadable.</p>
      <div class="form-group"><label>Age passphrase (min 12 chars)</label>
        <input type="password" id="bk-pass" placeholder="age passphrase (encrypts the .age file)"></div>
      <button class="btn primary small" data-action="doBackup">Create Backup</button>
      <div id="backup-result"></div>
      <div class="mt-12">
        <button class="btn secondary small" data-action="toggleBackupHelp">How does it work?</button>
        <div id="backup-help" class="hidden mt-12">
          <div class="card-title">Encryption</div>
          <p class="dim mt-12">Backups use the <a href="https://age-encryption.org" target="_blank" class="link-accent">age</a> standard format.<br>
            Key derivation: scrypt. Cipher: ChaCha20-Poly1305.<br>
            The passphrase opens the backup envelope; the vault master password from backup time is still required to unwrap secret DEKs during restore.</p>
          <div class="card-title mt-12">Standalone decrypt (without rhorizon)</div>
          <p class="dim mt-12">Decrypt the downloaded <code>.age</code> file with the <code>age</code> CLI to inspect the backup envelope JSON; secret values remain wrapped by vault DEKs:</p>
          <div class="code-block mt-12">age -d -o backup.json backup.age</div>
          <p class="dim mt-12"><strong>GDPR</strong>: this backup contains encrypted data.
            Losing either the age passphrase or the backup-time master password makes the secret values unrecoverable.</p>
        </div>
      </div>
    </div>
  </div>

  <div class="cards mt-12">
    <div class="card">
      <div class="card-title">Migration Import (JSON)</div>
      <p class="dim mb-12">Upload a JSON file <strong>or</strong> paste JSON below.<br>
        Accepted: a raw array <code>[{"name":"k","value":"v"}, ...]</code> or a wrapper <code>{"secrets":[...], "count":N}</code>.<br>
        Optional per-entry: <code>namespace</code> (default below), <code>metadata</code> (object).</p>
      <div class="form-group"><label>Namespace</label>
        <input type="text" id="imp-ns" value="default" placeholder="default"></div>
      <div class="form-group"><label>JSON file (optional, takes precedence over paste)</label>
        <input type="file" id="imp-file" accept=".json,application/json"></div>
      <div class="form-group"><label>Secrets JSON (paste)</label>
        <textarea id="imp-data" rows="5" placeholder='[{"name": "db-pass", "value": "s3cret"}]'></textarea></div>
      <button class="btn primary small" data-action="doImport">Import</button>
      <div id="import-result" class="mt-12"></div>
    </div>
    <div class="card">
      <div class="card-title">Restore Vault (from encrypted backup)</div>
      <p class="dim mb-12">Restore a logical vault backup from a <code>.age</code> file.<br>
        You need <strong>two</strong> credentials from the time the backup was taken:
        the <strong>age passphrase</strong> (decrypts the <code>.age</code> envelope)
        and the <strong>vault master password</strong> (unwraps the backup DEKs).
        Both are required and independent.</p>
      <div class="form-group"><label>Age passphrase</label>
        <input type="password" id="rst-pass" placeholder="age passphrase (decrypts the .age file)"></div>
      <div class="form-group"><label>Vault master password (at backup time)</label>
        <input type="password" id="rst-master-pass" placeholder="master password used when the backup was created"></div>
      <div class="form-group"><label>Backup file (.age)</label>
        <input type="file" id="rst-file" accept="*/*"></div>
      <button class="btn primary small" data-action="doRestore">Restore</button>
      <div id="restore-result" class="mt-12"></div>
    </div>
  </div>`;
}

function toggleBackupHelp() {
  const h = document.getElementById('backup-help');
  if (h) h.classList.toggle('hidden');
}

async function doBackup() {
  const pass = document.getElementById('bk-pass').value;
  if (!pass || pass.length < 12) return toast('Passphrase must be 12+ chars', false);
  try {
    const r = await api('POST', '/backup/create', { passphrase: pass });
    // Decode base64 → binary for direct .age download
    const raw = atob(r.payload);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const ts = new Date().toISOString().slice(0, 10);
    const fname = `rhorizon-backup-${ts}.age`;
    document.getElementById('backup-result').innerHTML = `
      <div class="kv"><span>Secrets</span><span>${r.secrets_count}</span></div>
      <div class="kv"><span>Tokens</span><span>${r.tokens_count}</span></div>
      <div class="kv"><span>Namespaces</span><span>${r.namespaces_count ?? 0}</span></div>
      <div class="kv"><span>Groups</span><span>${r.groups_count}</span></div>
      <div class="kv"><span>Group members</span><span>${r.group_members_count ?? 0}</span></div>
      <div class="kv"><span>Config</span><span>${r.config_count}</span></div>
      <div class="kv"><span>Size</span><span>${r.size_bytes} bytes</span></div>
      <div class="kv"><span>Checksum</span><span class="dim">${esc(r.checksum?.slice(0, 16))}...</span></div>
      <a class="btn primary download" href="${url}" download="${fname}">Download ${fname}</a>`;
    toast('Backup created', true);
  } catch (e) { toast(e.message, false); }
}

async function doImport() {
  const ns = document.getElementById('imp-ns').value || 'default';
  const fileInput = document.getElementById('imp-file');
  let raw;
  if (fileInput && fileInput.files.length) {
    raw = await fileInput.files[0].text();
  } else {
    raw = document.getElementById('imp-data').value;
  }
  if (!raw || !raw.trim()) return toast('Pick a JSON file or paste JSON first', false);

  let parsed;
  try { parsed = JSON.parse(raw); } catch { return toast('Invalid JSON', false); }
  const secrets = Array.isArray(parsed) ? parsed : (parsed && Array.isArray(parsed.secrets) ? parsed.secrets : null);
  if (!secrets) return toast('Expected a JSON array or {secrets:[...]} object', false);

  let ok = 0, fail = 0;
  for (const s of secrets) {
    if (!s.name || !s.value) { fail++; continue; }
    try {
      await api('POST', '/secrets/', {
        name: s.name,
        value: s.value,
        namespace: s.namespace || ns,
        metadata: s.metadata || {},
      });
      ok++;
    } catch { fail++; }
  }

  document.getElementById('import-result').innerHTML = `
    <div class="kv"><span>Imported</span><span class="badge active">${ok}</span></div>
    ${fail ? `<div class="kv"><span>Failed</span><span class="badge revoked">${fail}</span></div>` : ''}`;
  toast(`Imported ${ok}/${secrets.length} secret(s)`, ok > 0);
}

function _showRestoreConfirmOverlay() {
  return new Promise((resolve) => {
    const old = document.getElementById('restore-confirm-overlay');
    if (old) old.remove();
    const overlay = document.createElement('div');
    overlay.id = 'restore-confirm-overlay';
    overlay.className = 'token-overlay';
    overlay.innerHTML = `
      <div class="token-overlay-box">
        <div class="token-overlay-title">CONFIRM RESTORE</div>
        <div class="token-overlay-subtitle">
          This is a <strong class="text-red">breaking operation</strong>.
          Restoring a backup will:
        </div>
        <ul class="dim mt-12 text-left lh-relaxed">
          <li>overwrite <strong>secrets, token metadata, namespaces, groups, and restorable config</strong> with the backup payload;</li>
          <li>keep the current vault identity; backup <code>argon2_salt</code> and <code>master_check</code> are used only to unwrap backup-side DEKs;</li>
          <li>seal the vault automatically and make every existing token, including the one in your browser, unusable;</li>
          <li>mint a <strong>fresh root token</strong> on the very next unseal, shown once only.</li>
        </ul>
        <div class="form-group mt-12 text-left">
          <label>Type <code>RESTORE</code> to confirm</label>
          <input type="text" id="restore-confirm-input" autocomplete="off" placeholder="RESTORE">
        </div>
        <div class="token-overlay-actions">
          <button class="btn-overlay secondary" id="restore-confirm-cancel">Cancel</button>
          <button class="btn-overlay primary" id="restore-confirm-ok" disabled>Confirm Restore</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    const input = document.getElementById('restore-confirm-input');
    const ok = document.getElementById('restore-confirm-ok');
    const cancel = document.getElementById('restore-confirm-cancel');
    input.focus();
    input.addEventListener('input', () => {
      ok.disabled = input.value !== 'RESTORE';
    });
    const done = (result) => {
      overlay.remove();
      resolve(result);
    };
    ok.addEventListener('click', () => done(true));
    cancel.addEventListener('click', () => done(false));
  });
}

async function doRestore() {
  const pass = document.getElementById('rst-pass').value;
  const masterPass = document.getElementById('rst-master-pass').value;
  const fileInput = document.getElementById('rst-file');
  if (!pass) return toast('Age passphrase required', false);
  if (!masterPass) return toast('Vault master password (at backup time) required', false);
  if (masterPass.length < 8) return toast('Vault master password must be at least 8 characters', false);
  if (!fileInput.files.length) return toast('Select a .age backup file', false);

  if (!await _showRestoreConfirmOverlay()) return;

  try {
    const buf = await fileInput.files[0].arrayBuffer();
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    const payload = btoa(bin);

    const r = await api('POST', '/backup/restore', {
      passphrase: pass,
      master_password_backup: masterPass,
      confirm_phrase: 'RESTORE',
      payload: payload,
    });
    const nextStep = r.sealed
      ? `<p class="dim mt-12"><strong class="text-red">Vault sealed.</strong>
           ${esc(r.next_step || 'Unseal with the current master password to mint the recovery root token.')}</p>`
      : '';
    document.getElementById('restore-result').innerHTML = `
      <div class="kv"><span>Secrets</span><span class="badge active">${r.secrets}</span></div>
      <div class="kv"><span>Tokens pending rotation</span><span class="badge active">${r.tokens_pending_rotation ?? 0}</span></div>
      <div class="kv"><span>Namespaces</span><span class="badge active">${r.namespaces ?? 0}</span></div>
      <div class="kv"><span>Groups</span><span class="badge active">${r.groups}</span></div>
      <div class="kv"><span>Group members</span><span class="badge active">${r.group_members ?? 0}</span></div>
      <div class="kv"><span>Config</span><span class="badge active">${r.config}</span></div>
      ${nextStep}`;
    toast(r.sealed ? 'Restore complete, vault sealed, unseal now' : 'Restore complete', true);
  } catch (e) { toast(e.message, false); }
}
