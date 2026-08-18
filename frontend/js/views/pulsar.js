// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* Pulsar, Notification channels (typed forms per channel type) */
'use strict';

// Known events the operator can subscribe a channel to. The backend dispatches
// these via routes.notifications.dispatch_event(...). Empty events list on a
// channel = subscribe to all events.
const PULSAR_EVENTS = [
  { name: 'honey_access',           label: 'Honey access (CRITICAL, decoy used)' },
  { name: 'unseal',                 label: 'Vault unseal' },
  { name: 'seal',                   label: 'Vault seal' },
  { name: 'master_password_rotated', label: 'Master password rotated' },
  { name: 'token_created',          label: 'Token created' },
  { name: 'token_revoked',          label: 'Token revoked' },
  { name: 'secret_created',         label: 'Secret created' },
  { name: 'secret_deleted',         label: 'Secret deleted' },
  { name: 'chain_broken',           label: 'Audit chain integrity broken' },
];

async function renderPulsar(el) {
  if (isSealed()) { el.innerHTML = sealedHtml(); return; }
  try {
    const r = await api('GET', '/notifications/');
    let html = `<div class="toolbar">
      <button class="btn primary small" data-action="showCreateChannel">+ New Channel</button>
    </div>
    <div id="channel-form" class="card form-card hidden"></div>
    <table class="table"><thead><tr>
      <th>Name</th><th>Type</th><th>Events</th><th>Enabled</th><th>Actions</th>
    </tr></thead><tbody>`;
    for (const c of r.items || []) {
      const evs = Array.isArray(c.events) && c.events.length
        ? c.events.map(e => `<span class="tag tiny">${esc(e)}</span>`).join(' ')
        : '<span class="dim">all</span>';
      html += `<tr>
        <td><strong>${esc(c.name)}</strong></td>
        <td><span class="tag">${esc(c.channel_type)}</span></td>
        <td>${evs}</td>
        <td><span class="badge ${c.enabled ? 'unsealed' : 'sealed'}">${c.enabled ? 'on' : 'off'}</span></td>
        <td class="actions">
          <button class="btn tiny" data-action="testChannel" data-arg="${esc(c.id)}">Test</button>
          <button class="btn tiny danger" data-action="deleteChannel" data-arg="${esc(c.id)}" data-arg2="${esc(c.name)}">Del</button>
        </td>
      </tr>`;
    }
    html += '</tbody></table>';
    if (!(r.items || []).length) html += '<div class="empty">No notification channels</div>';
    el.innerHTML = html;
  } catch (e) { el.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
}

function _eventsCheckboxes() {
  return PULSAR_EVENTS.map(ev => `
    <label class="event-checkbox">
      <input type="checkbox" name="cc-event" value="${esc(ev.name)}">
      <code>${esc(ev.name)}</code> <span class="dim">${esc(ev.label)}</span>
    </label>`).join('');
}

function _formMatrix() {
  return `
    <div class="form-group"><label>Homeserver URL</label>
      <input type="url" id="cc-mx-homeserver" placeholder="https://matrix.example.com"></div>
    <div class="form-group"><label>Room ID</label>
      <input type="text" id="cc-mx-room" placeholder="!XXXXXXXX:matrix.example.com"></div>
    <div class="form-group"><label>Bot access token</label>
      <input type="password" id="cc-mx-token" placeholder="syt_..."></div>`;
}

function _formSmtp() {
  return `
    <div class="form-group"><label>SMTP host</label>
      <input type="text" id="cc-sm-host" placeholder="mail.example.com"></div>
    <div class="form-group"><label>Port</label>
      <input type="number" id="cc-sm-port" value="587"></div>
    <div class="form-group">
      <label><input type="checkbox" id="cc-sm-starttls" checked> STARTTLS</label>
      <label><input type="checkbox" id="cc-sm-ssl"> SSL/TLS (port 465)</label>
    </div>
    <div class="form-group"><label>Username (optional)</label>
      <input type="text" id="cc-sm-user" placeholder="alerts@example.com"></div>
    <div class="form-group"><label>Password (optional)</label>
      <input type="password" id="cc-sm-pass"></div>
    <div class="form-group"><label>From</label>
      <input type="text" id="cc-sm-from" placeholder="rhorizon-alerts <alerts@example.com>"></div>
    <div class="form-group"><label>To (comma-separated)</label>
      <input type="text" id="cc-sm-to" placeholder="ops@example.com, security@example.com"></div>`;
}

function _formWebhook() {
  return `
    <div class="form-group"><label>Webhook URL</label>
      <input type="url" id="cc-wh-url" placeholder="https://hooks.example.com/services/...">
      <div class="dim text-xs">Generic JSON payload. Compatible with Mattermost, Slack, Discord, Rocket.Chat, ntfy.sh.</div></div>`;
}

function showCreateChannel() {
  const f = document.getElementById('channel-form');
  f.classList.toggle('hidden');
  if (f.classList.contains('hidden')) return;
  f.innerHTML = `
    <div class="form-group"><label>Channel name</label>
      <input type="text" id="cc-name" placeholder="ops-alerts"></div>
    <div class="form-group"><label>Type</label>
      <span class="select-wrap"><select id="cc-type" data-action="onPulsarTypeChange">
        <option value="matrix">Matrix</option>
        <option value="email">Email (SMTP)</option>
        <option value="webhook">Webhook (Mattermost / Slack / Discord / ntfy)</option>
      </select></span></div>
    <div id="cc-type-fields"></div>
    <div class="form-group">
      <label>Subscribe to events <span class="dim">(none = all events)</span></label>
      <div class="event-list">${_eventsCheckboxes()}</div>
    </div>
    <button class="btn primary small" data-action="createChannel">Create</button>`;
  onPulsarTypeChange();
}

function onPulsarTypeChange(value) {
  const t = value || document.getElementById('cc-type').value;
  const target = document.getElementById('cc-type-fields');
  if (t === 'matrix')        target.innerHTML = _formMatrix();
  else if (t === 'email')    target.innerHTML = _formSmtp();
  else if (t === 'webhook')  target.innerHTML = _formWebhook();
}

function _readMatrix() {
  return {
    homeserver: document.getElementById('cc-mx-homeserver').value.trim(),
    room_id:    document.getElementById('cc-mx-room').value.trim(),
    token:      document.getElementById('cc-mx-token').value.trim(),
  };
}

function _readSmtp() {
  const ssl      = document.getElementById('cc-sm-ssl').checked;
  const starttls = document.getElementById('cc-sm-starttls').checked && !ssl;
  return {
    smtp_host:         document.getElementById('cc-sm-host').value.trim(),
    smtp_port:         parseInt(document.getElementById('cc-sm-port').value, 10) || 587,
    smtp_use_ssl:      ssl,
    smtp_use_starttls: starttls,
    smtp_user:         document.getElementById('cc-sm-user').value.trim(),
    smtp_password:     document.getElementById('cc-sm-pass').value,
    from:              document.getElementById('cc-sm-from').value.trim(),
    to:                document.getElementById('cc-sm-to').value.trim(),
  };
}

function _readWebhook() {
  return { url: document.getElementById('cc-wh-url').value.trim() };
}

async function createChannel() {
  const name = document.getElementById('cc-name').value.trim();
  const type = document.getElementById('cc-type').value;
  if (!name) { toast('Name required', false); return; }

  let config;
  try {
    if (type === 'matrix')       config = _readMatrix();
    else if (type === 'email')   config = _readSmtp();
    else if (type === 'webhook') config = _readWebhook();
  } catch (e) { toast(e.message, false); return; }

  const events = Array.from(document.querySelectorAll('input[name="cc-event"]:checked'))
    .map(i => i.value);

  try {
    await api('POST', '/notifications/', { name, channel_type: type, config, events });
    toast(`Channel '${name}' created`, true);
    renderPulsar(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}

async function testChannel(id) {
  try { await api('POST', `/notifications/${id}/test`); toast('Test sent', true); }
  catch (e) { toast(e.message, false); }
}

async function deleteChannel(id, name) {
  const label = name || id;
  const ok = await confirmType(label, {
    title: `Delete channel '${label}'`,
    body: 'Removes this notification channel. Events routed only to it stop being delivered until you add a replacement.',
    okLabel: 'Delete',
  });
  if (!ok) return;
  try {
    await api('DELETE', `/notifications/${id}`);
    toast('Channel deleted', true);
    renderPulsar(document.getElementById('main'));
  } catch (e) { toast(e.message, false); }
}
