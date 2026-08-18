# Honeytokens - runtime intrusion detection

## Concept

A honeytoken is a vault entry (token or secret) that **no legitimate
client ever uses**. Any access is therefore strong evidence of an
active intrusion or insider misuse.

When an attacker dumps the vault, lists tokens, or steals a config
file, the honey entries look like the most attractive targets
(production database master password, AWS IAM key, VPN server
private key...). The attacker uses them. **rhorizon emits an alert event
as part of the access path** - but the auth response itself is unchanged,
so it does not disclose that the credential is a decoy.

## Detection paths

When a honey token is used to authenticate, or a honey secret is
read, three things happen out of band:

1. **CRITICAL log line** in the `rhorizon.honey` logger
2. **Tamper-evident audit entry** with `action='honey_access'` -
   signed in the audit chain so later alteration or removal is detectable
3. **Notification dispatch** on event `honey_access` to every
   enabled channel subscribed to it (Matrix, SMTP, webhook)

The auth/read response itself is **identical** to a legitimate one.
Operator triages from the audit log + Matrix ping.

## Seeding

Two ways: **API** (programmatic) and **UI** (interactive).

### API - POST `/api/v1/vault/tokens/`

```json
{
  "name": "prod-pgsql-master",
  "permissions": {"secrets": "rw"},
  "is_honey": true
}
```

Returns the plaintext token once. Don't ship this token to any
legitimate consumer - store it nowhere except, deliberately, where
an intruder might look (a bait config file, an internal "old
backup" share).

### API - POST `/api/v1/vault/secrets/`

```json
{
  "name": "wg-server-private-key",
  "value": "tG3I9qF...truncated...fake==",
  "namespace": "infra",
  "is_honey": true
}
```

The stored value should be **plausible but fake** - random bytes of
the right shape. Attackers may attempt to use it before realising
it's a decoy, which is exactly the window we want.

### UI

- **Quasar** (Tokens) - the create-token form has a yellow "Honeytoken
  (decoy)" checkbox. Tick it before submitting.
- **Eclipse** (Secrets) - same pattern in the create-secret form.

The visual styling is intentionally distinctive (orange tint) so
operators don't accidentally mark a real token/secret as honey.

## Picking attractive names

Honeytokens are only useful if attackers want to use them. Names
should mirror your real ops naming scheme. Examples:

**Tokens**
- `prod-pgsql-master`
- `aws-infra-iam`
- `backup-restic-key`
- `monitoring-collect-admin`

**Secrets**
- `wg-server-private`
- `prod-db-superuser`
- `harbor-registry-pull`
- `ssh-bastion-deploy`

**Bad names** (obviously fake - attackers skip):
- `decoy-1`
- `honey-test`
- `do-not-use`

## Configuring the alert channel

The honey alert is dispatched on event `honey_access`. To actually
receive it on Matrix, SMTP or webhook, configure a channel in
**Pulsar** subscribed to that event.

### Recommended setup

- **Dedicated bot account** (`@rhorizon-alerts:matrix.example.com`) -
  not your personal account. Token leak then doesn't compromise you.
- **Dedicated Matrix room** for honey/intrusion alerts, separated
  from operational alerts. You don't want a CRITICAL signal lost
  in the noise of nightly CVE reports.
- **Backup channel** (SMTP to a non-rhorizon-hosted address, or
  webhook to ntfy.sh) - if rhorizon itself is down you still get
  the alert.

### Pulsar UI (preferred)

1. Sidebar -> **Pulsar**
2. **+ New Channel**
3. Type: Matrix / Email (SMTP) / Webhook
4. Fill in the typed form (no raw JSON)
5. Tick `honey_access` in the events checklist
6. Create -> **Test** to verify it fires

### Direct SQL (one-shot bootstrap)

```sql
INSERT INTO vault_notification_channels
    (name, channel_type, config, events, enabled)
VALUES (
    'matrix-honey',
    'matrix',
    jsonb_build_object(
        'homeserver', 'https://matrix.example.com',
        'room_id',    '!XXXXXXXX:matrix.example.com',
        'token',      'syt_BOT_TOKEN'
    ),
    jsonb_build_array('honey_access'),
    true
);
```

## Threat model

**What honeytokens catch**
- Compromise of an operator host with vault token / config files
- Insider browsing the vault out of curiosity
- Backup/dump of the vault DB exfiltrated and parsed
- LLM-assisted reconnaissance reading "interesting-looking" tokens

**What they don't catch**
- Compromise of vault internals at rest (master key extraction) -
  mitigated by sealed-by-default + Rust mlock memory protection
- Read of audit log itself (the alert is reactive, not preventive)
- Replay attacks against legitimate tokens

**Threshold for alert review** - investigate every honey access promptly.
A hit may indicate:
- A genuine intrusion -> isolate, rotate all real tokens, audit
- An honest mistake (operator picked a honey name and then forgot)
  -> rename or delete the honey, document
- A pentest -> confirm with the team

Treat honey access as a P1 incident by default.

## Rotation

Honeytokens **don't need rotation** in the way real tokens do. They're
not used; they don't leak. Replace one only if:
- It was triggered (incident closed, want a fresh decoy)
- The attractive name no longer fits real naming evolution
- You realise the name is too obviously fake

To rotate: delete the row, create a new one with a different name.
