# 2FA setup

rhorizon supports three second factors, used at the unseal step
(and at the unlock-protected-secret step). The 2FA modes are :

| Mode | Allowed factors |
|------|-----------------|
| `none` | password only - default at first install |
| `totp` | password + RFC 6238 6-digit code |
| `yubikey` | password + YubiKey HMAC-SHA1 challenge-response, **OR** WebAuthn / FIDO2 |
| `any` | password + (TOTP **or** YubiKey **or** WebAuthn) |

All 2FA configuration happens in the **Core** view of the UI, behind
the admin-only auth gate. Below is the same flow via API, for
scripted bootstraps.

## TOTP (any RFC 6238 authenticator)

```bash
# 1. Generate a fresh secret + provisioning URI
curl -X POST http://127.0.0.1:8200/api/v1/vault/totp/setup \
  -H "Authorization: Bearer $ADMIN"

# {
#   "secret_base32": "JBSWY3DPEHPK3PXP",
#   "uri": "otpauth://totp/rhorizon:admin?secret=...&issuer=rhorizon"
# }
```

Scan the URI in your authenticator (Aegis, FreeOTP, Google
Authenticator, 1Password). Then enable it by submitting a code :

```bash
curl -X POST http://127.0.0.1:8200/api/v1/vault/totp/enable \
  -H "Authorization: Bearer $ADMIN" \
  -d '{"code": "123456"}'
```

After this, `/unseal` requires either `totp_code` or another factor
depending on the configured mode.

An accepted TOTP time-step is recorded in PostgreSQL in the same transaction
that authorizes the operation. Reusing that code is rejected across API
workers and HA nodes, including during the allowed clock-skew window. Keep
system clocks synchronized; a counter older than the last accepted counter is
also rejected.

## YubiKey HMAC-SHA1 (CLI, scripts, `ykchalresp`)

For automation that can't use WebAuthn (no browser) :

```bash
# 1. Generate a YubiKey HMAC secret (CLI : ykman or yubikey-personalization-gui)
#    Then register it with the vault.
curl -X POST http://127.0.0.1:8200/api/v1/vault/yubikey \
  -H "Authorization: Bearer $ADMIN" \
  -d '{
    "serial": "12345678",
    "hmac_secret": "0011223344556677889900112233445566778899"
  }'
```

The HMAC secret is encrypted with the `dek_key` before storage. At unseal time,
use the Core view in the UI. It requests the challenge, computes the response
after the YubiKey touch, and submits the password without placing it in shell
history. Custom clients must send `password`, `yubikey_response`, and
`challenge` in the HTTPS request body, not as command arguments.

## WebAuthn / FIDO2 (browser-native)

The cleanest for operator-driven unseal. Goes through the **Core** view
of the UI :

1. Plug in a security key (YubiKey, SoloKey, Nitrokey, Titan, etc.).
2. Click **Register WebAuthn credential**.
3. Touch the key when prompted.

The credential's public key is stored in `vault_webauthn`. At unseal,
the UI calls `navigator.credentials.get()` with a fresh challenge -
the operator touches the key, the browser signs, the vault verifies.

WebAuthn is only available over HTTPS or localhost. Anti-clone
protection : the sign counter is tracked across uses, a cloned key
that returns a stale counter is rejected with `webauthn_cloned_key`
in the audit log.

## Choose the mode

```bash
curl -X PUT 'http://127.0.0.1:8200/api/v1/vault/2fa?mode=any' \
  -H "Authorization: Bearer $ADMIN"
```

Modes : `none`, `totp`, `yubikey`, `any`.

`any` is the operator-friendly default once you have >= 2 second
factors registered - covers the case where one of them is unavailable
(forgot the YubiKey, phone TOTP app crashed). If you go down to one
remaining factor of a given type, the vault auto-falls-back to a
weaker mode rather than locking you out - the audit log records the
fallback for inspection.

## Recovery - what if I lose all 2FA factors

Same answer as the master password : if you lose every registered
factor and the vault is in `totp` or `yubikey` mode, you cannot
unseal. There is no admin-recoverable bypass by design.

Mitigations :

- Always register **at least two** factors (one TOTP + one WebAuthn,
  or two security keys).
- Print the TOTP secret URI as a QR code and store it in a safe.
- Use Shamir M-of-N for the master key so you have an independent
  recovery path.
