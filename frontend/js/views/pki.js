// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/* PKI engine, rendered as the "PKI" sub-tab of Eclipse (Secrets).
 *
 * One issuing CA per namespace. Pick the algorithm (ml-dsa-65 or ed25519)
 * once per namespace at init. Init/revoke/rotate need admin:w; issuing is a
 * consumption action (secrets:w). The leaf private key is shown ONCE on issue.
 */
'use strict';

let _pkiCertsCache = null;
let _pkiNs = 'default'; // selected namespace (which CA to view/manage)

async function renderPkiInto(el) {
  try {
    const r = await api('GET', '/pki/cas');
    const namespaces = r.namespaces || [];
    if (!namespaces.length) {
      _pkiRenderInit(el, []);
      return;
    }
    if (!namespaces.includes(_pkiNs)) _pkiNs = namespaces[0];
    const ca = await api('GET', '/pki/ca?namespace=' + encodeURIComponent(_pkiNs));
    _pkiRenderManage(el, ca, namespaces);
  } catch (e) {
    el.innerHTML = `<div class="error">${esc((e && e.message) || 'error')}</div>`;
  }
}

function _nsBar(namespaces) {
  if (!namespaces.length) return '';
  const opts = namespaces
    .map(n => `<button class="btn tiny ${n === _pkiNs ? 'primary' : 'secondary'}" data-action="pkiSelectNs" data-arg="${esc(n)}">${esc(n)}</button>`)
    .join('');
  return `<div class="toolbar"><span class="muted">CA namespace:</span>
    <div class="btn-group">${opts}</div>
    <button class="btn tiny" data-action="pkiShowNewCa">+ New CA</button></div>`;
}

window.pkiSelectNs = function (ns) {
  _pkiNs = ns;
  renderPkiInto(document.getElementById('eclipse-body'));
};

window.pkiShowNewCa = function () {
  _pkiRenderInit(document.getElementById('eclipse-body'), null);
};

function _pkiRenderInit(el, namespaces) {
  // namespaces === null means "add another CA" (came from + New CA).
  const back = namespaces === null
    ? '<button class="btn tiny secondary" data-action="pkiBackToCas">Back</button>'
    : '';
  el.innerHTML = `
    <div class="card form-card">
      <div class="card-title">Initialise a PKI CA ${back}</div>
      <p class="muted">One CA per namespace; the algorithm is fixed once. Default
        is the ANSSI/BSI composite hybrid (classical + PQ, both must verify).</p>
      <label>Namespace <input id="pki-ns" value="default" maxlength="64"></label>
      <label>Algorithm
        <span class="select-wrap">
          <select id="pki-alg">
            <option value="ed25519-mldsa65" selected>ed25519-mldsa65 (hybrid, ANSSI/BSI)</option>
            <option value="ml-dsa-65">ml-dsa-65 (PQ only)</option>
            <option value="ed25519">ed25519 (classical)</option>
          </select>
        </span>
      </label>
      <label>Common name <input id="pki-cn" value="rhorizon-pki" maxlength="64"></label>
      <label>Validity (days) <input id="pki-validity" type="number" value="3650" min="1"></label>
      <div class="btn-group">
        <button class="btn primary small" data-action="pkiInit">Initialise CA</button>
      </div>
    </div>`;
}

window.pkiBackToCas = function () {
  renderPkiInto(document.getElementById('eclipse-body'));
};

window.pkiInit = async function () {
  const namespace = document.getElementById('pki-ns').value.trim() || 'default';
  const algorithm = document.getElementById('pki-alg').value;
  const common_name = document.getElementById('pki-cn').value.trim() || 'rhorizon-pki';
  const validity_days = parseInt(document.getElementById('pki-validity').value, 10) || 3650;
  try {
    await api('POST', '/pki/init', { namespace, algorithm, common_name, validity_days });
    _pkiNs = namespace;
    renderPkiInto(document.getElementById('eclipse-body'));
  } catch (e) {
    toast((e && e.message) || 'init failed', false);
  }
};

function _pkiRenderManage(el, ca, namespaces) {
  const prev = ca.previous_certificate
    ? '<span class="badge">grace: previous CA active</span>'
    : '';
  el.innerHTML = _nsBar(namespaces) + `
    <div class="card">
      <div class="card-title">CA &mdash; ${esc(ca.namespace)} / ${esc(ca.algorithm)} ${prev}</div>
      <div class="kv"><span>Common name</span><code>${esc(ca.common_name)}</code></div>
      <div class="kv stack"><span>Fingerprint</span><code class="break">${esc(ca.fingerprint)}</code></div>
      <div class="btn-group">
        <button class="btn tiny secondary" data-action="pkiDownloadCa">Download CA PEM</button>
        <button class="btn tiny danger" data-action="pkiRotate">Rotate CA</button>
      </div>
    </div>
    <div class="card form-card">
      <div class="card-title">Issue a certificate (namespace ${esc(ca.namespace)})</div>
      <label>Common name <input id="pki-issue-cn" placeholder="svc.internal" maxlength="253"></label>
      <label>SAN DNS (comma-separated) <input id="pki-issue-dns" placeholder="svc.internal,svc"></label>
      <label>SAN IPs (comma-separated) <input id="pki-issue-ips" placeholder="10.0.0.1"></label>
      <label>TTL (days) <input id="pki-issue-ttl" type="number" value="30" min="1"></label>
      <div class="btn-group">
        <button class="btn primary small" data-action="pkiIssue">Issue</button>
      </div>
    </div>
    <div class="card form-card">
      <div class="card-title">Issue a KEM certificate (namespace ${esc(ca.namespace)})</div>
      <label>Common name <input id="pki-kem-cn" placeholder="kem.internal" maxlength="253"></label>
      <label>SAN DNS <input id="pki-kem-dns" placeholder="comma-separated"></label>
      <label>SAN IPs <input id="pki-kem-ips" placeholder="comma-separated"></label>
      <label>TTL (days) <input id="pki-kem-ttl" type="number" value="30" min="1"></label>
      <label>Mode
        <span class="select-wrap">
          <select id="pki-kem-mode">
            <option value="x25519-ml-kem" selected>x25519-ml-kem (hybrid, ANSSI/BSI)</option>
            <option value="ml-kem">ml-kem (PQ only)</option>
          </select>
        </span>
      </label>
      <div class="btn-group">
        <button class="btn primary small" data-action="pkiKemIssue">Issue KEM cert</button>
      </div>
    </div>
    <div id="pki-reveal"></div>
    <div class="card-title mt-12">Issued certificates</div>
    <div id="pki-certs"></div>
    <p class="form-foot">Leaf/KEM certs are signed by this CA; their private key is
      shown once on issue, never stored. KEM certs do key establishment
      (KeyUsage keyEncipherment), not TLS auth. Hybrid modes (ed25519-mldsa65,
      x25519-ml-kem) pair a classical + a post-quantum algorithm &mdash; the ANSSI/BSI
      requirement; &ldquo;PQ only&rdquo; drops the classical leg.</p>`;
  _pkiRenderCerts();
}

window.pkiDownloadCa = async function () {
  try {
    const ca = await api('GET', '/pki/ca?namespace=' + encodeURIComponent(_pkiNs));
    _pkiDownload(`rhorizon-ca-${_pkiNs}.pem`, ca.certificate);
  } catch (e) {
    toast((e && e.message) || 'error', false);
  }
};

window.pkiRotate = async function () {
  const ok = await confirmModal({
    title: `Rotate ${_pkiNs} CA`,
    body: 'Issues a new CA for this namespace. The previous CA stays valid during a grace window so existing certs keep verifying, but new certs chain to the new CA. Distribute the new CA to relying parties.',
    okLabel: 'Rotate',
  });
  if (!ok) return;
  try {
    await api('POST', '/pki/rotate', { namespace: _pkiNs });
    toast('CA rotated', true);
    renderPkiInto(document.getElementById('eclipse-body'));
  } catch (e) {
    toast((e && e.message) || 'rotate failed', false);
  }
};

const _split = (s) => (s || '').split(',').map(x => x.trim()).filter(Boolean);

// An IP literal does not belong in SAN DNS (it goes in SAN IPs). IPv4 = four
// dotted octets; IPv6 = contains a colon. The backend rejects it too.
const _looksLikeIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(':');

window.pkiIssue = async function () {
  const body = {
    common_name: document.getElementById('pki-issue-cn').value.trim(),
    san_dns: _split(document.getElementById('pki-issue-dns').value),
    san_ips: _split(document.getElementById('pki-issue-ips').value),
    ttl_days: parseInt(document.getElementById('pki-issue-ttl').value, 10) || 30,
    namespace: _pkiNs,
  };
  if (!body.common_name) { toast('common name is required', false); return; }
  const badDns = body.san_dns.find(_looksLikeIp);
  if (badDns) {
    toast(`"${badDns}" is an IP -- put it in SAN IPs, not SAN DNS`, false);
    return;
  }
  try {
    const r = await api('POST', '/pki/issue', body);
    _pkiShowIssued(r);
    await _pkiRenderCerts();
  } catch (e) {
    toast((e && e.message) || 'issue failed', false);
  }
};

window.pkiKemIssue = async function () {
  const body = {
    common_name: document.getElementById('pki-kem-cn').value.trim(),
    san_dns: _split(document.getElementById('pki-kem-dns').value),
    san_ips: _split(document.getElementById('pki-kem-ips').value),
    ttl_days: parseInt(document.getElementById('pki-kem-ttl').value, 10) || 30,
    kem_algorithm: 'ml-kem-768',
    kem_mode: document.getElementById('pki-kem-mode').value,
    namespace: _pkiNs,
  };
  if (!body.common_name) { toast('common name is required', false); return; }
  const badDns = body.san_dns.find(_looksLikeIp);
  if (badDns) {
    toast(`"${badDns}" is an IP -- put it in SAN IPs, not SAN DNS`, false);
    return;
  }
  try {
    const r = await api('POST', '/pki/kem/issue', body);
    _pkiShowIssued(r);
    await _pkiRenderCerts();
  } catch (e) {
    toast((e && e.message) || 'KEM issue failed', false);
  }
};

function _pkiShowIssued(r) {
  const box = document.getElementById('pki-reveal');
  const isKem = !!r.kem_mode;
  // KEM certs: subject key algorithm != the CA signature algorithm, and hybrid
  // certs return TWO PKCS8 blocks (X25519 + ML-KEM), so label them accordingly.
  // The serial is a long unbreakable hex string -> keep it out of the uppercase
  // card-title (which does not wrap) and put it in a .break line below.
  const algLine = isKem
    ? `<span><b>Subject</b>${esc(r.subject_algorithm)}</span>
       <span><b>Mode</b>${esc(r.kem_mode)}</span>
       <span><b>CA sig</b>${esc(r.algorithm)}</span>`
    : `<span><b>Alg</b>${esc(r.algorithm)}</span>`;
  const keyLabel = isKem ? 'Decapsulation key(s)' : 'Private key';
  const keyWarn = isKem
    ? 'The decapsulation key(s) are shown ONCE. Copy them now; never stored.'
    : 'The private key is shown ONCE. Copy it now; it is never stored.';
  box.innerHTML = `
    <div class="card reveal-card">
      <div class="card-title">Issued ${isKem ? 'KEM ' : ''}certificate</div>
      <div class="kv stack"><span>Serial</span><code class="break">${esc(r.serial)}</code></div>
      <div class="cert-meta mb-12">${algLine}</div>
      <p class="warn">${keyWarn}</p>
      <label>Certificate
        <textarea id="pki-out-cert" readonly rows="6">${esc(r.certificate)}</textarea></label>
      <button class="btn tiny" data-action="copy-el" data-src="pki-out-cert">Copy cert</button>
      <label>${keyLabel}
        <textarea id="pki-out-key" readonly rows="6">${esc(r.private_key)}</textarea></label>
      <button class="btn tiny" data-action="copy-el" data-src="pki-out-key">Copy key</button>
      <button class="btn tiny secondary" data-action="pkiDismissReveal">Dismiss</button>
    </div>`;
}

window.pkiDismissReveal = function () {
  const box = document.getElementById('pki-reveal');
  if (box) box.innerHTML = '';
};

async function _pkiRenderCerts() {
  const wrap = document.getElementById('pki-certs');
  try {
    const r = await api('GET', '/pki/certs');
    _pkiCertsCache = r.items || [];
    if (!_pkiCertsCache.length) {
      wrap.innerHTML = '<div class="empty">No certificates issued yet.</div>';
      return;
    }
    // Card list (not a wide table) so long serials wrap on mobile instead
    // of overflowing the viewport.
    let html = '<div class="cert-list">';
    for (const c of _pkiCertsCache) {
      const revoked = !!c.revoked_at;
      html += `<div class="cert-card${revoked ? ' row-muted' : ''}">
        <code class="break cert-serial">${esc(c.serial)}</code>
        <div class="cert-meta">
          <span><b>CN</b>${esc(c.subject_cn)}</span>
          <span><b>Alg</b>${esc(c.algorithm)}</span>
          ${c.kem_mode ? `<span><b>KEM</b>${esc(c.subject_algorithm || c.kem_mode)}</span>` : ''}
          <span><b>NS</b>${esc(c.namespace)}</span>
          <span><b>Expires</b>${esc((c.not_after || '').slice(0, 10))}</span>
          <span>${revoked ? '<span class="badge danger">revoked</span>' : '<span class="badge">valid</span>'}</span>
        </div>
        ${revoked ? '' :
          `<div class="cert-actions"><button class="btn tiny danger" data-action="pkiRevoke" data-arg="${esc(c.serial)}">Revoke</button></div>`}
      </div>`;
    }
    wrap.innerHTML = html + '</div>';
  } catch (e) {
    wrap.innerHTML = `<div class="error">${esc((e && e.message) || 'error')}</div>`;
  }
}

window.pkiRevoke = async function (serial) {
  const ok = await confirmModal({
    title: `Revoke certificate ${serial}`,
    body: 'Marks this certificate as revoked and publishes it on the CRL. Revocation is immediate and irreversible; any peer honouring the CRL will reject it.',
    okLabel: 'Revoke',
  });
  if (!ok) return;
  try {
    await api('POST', '/pki/revoke', { serial, reason: 'revoked via UI' });
    await _pkiRenderCerts();
  } catch (e) {
    toast((e && e.message) || 'revoke failed', false);
  }
};

function _pkiDownload(filename, text) {
  const blob = new Blob([text], { type: 'application/x-pem-file' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
