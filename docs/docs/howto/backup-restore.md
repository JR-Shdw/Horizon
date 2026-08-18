# Backup & restore

rhorizon has two recovery paths:

- `pg_dump | age -p` is the full-fidelity disaster-recovery path. It preserves every table, token hash, 2FA credential, dynamic engine, and audit row because the database is restored as-is.
- `/api/v1/vault/backup/create` + `/backup/restore` is an age-encrypted logical migration path. It restores current secrets, namespaces, groups, group members, restorable config, and token metadata stubs. It intentionally does not restore token hashes or plaintexts, 2FA credentials, notification channels, dynamic engines and leases, or the audit chain.

Use `pg_dump` for cold DR. Use the API backup when you want to move vault content into a fresh installation and accept the post-restore reconfiguration checklist.

## Create an API backup

```bash
curl -sS -X POST http://127.0.0.1:8200/api/v1/vault/backup/create \
  -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"use-a-long-age-passphrase"}' \
  | tee backup-response.json

jq -r .payload backup-response.json | base64 -d > rhorizon-backup.age
```

CLI equivalent, which avoids shell-specific `base64` flags:

```bash
rhorizon backup export ./rhorizon-backup.age
```

Keep both credentials:

- the age passphrase, which opens the backup envelope;
- the vault master password that was current when the backup was taken, which unwraps the backup-side DEKs during restore.

Losing either one makes the secret values unrecoverable.

## Restore an API backup

The target vault must be unsealed and the caller needs `admin:w`.

```bash
PAYLOAD="$(base64 < rhorizon-backup.age | tr -d '\n')"

curl -sS -X POST http://127.0.0.1:8200/api/v1/vault/backup/restore \
  -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" \
  -d "{
    \"passphrase\":\"use-a-long-age-passphrase\",
    \"master_password_backup\":\"master-password-at-backup-time\",
    \"confirm_phrase\":\"RESTORE\",
    \"payload\":\"$PAYLOAD\"
  }"
```

Restore is destructive for the logical tables it manages. It rebuilds secrets, DEKs, pending token rotations, namespaces, groups, and group members from the backup. It also clears dynamic tables and notification channels: dynamic engine connection material is DEK-bound, and notification delivery config is external integration state that the API backup does not carry.

The restore response returns `sealed: true`. Unseal with the **current vault master password**, not the backup password. The unseal response includes a fresh temporary recovery root token shown once.

CLI equivalent:

```bash
rhorizon backup restore ./rhorizon-backup.age
```

The API backup does not import 2FA registrations or audit history. A fresh target has none; an in-place target may keep existing YubiKey/WebAuthn rows and audit-chain state, but those rows are target-side state, not restored backup content.

Backup format v4 records each secret's AAD version. Restore accepts legacy
backups without that field as v1, decrypts them with the legacy encoding, and
rewrites them with the current v2 length-prefixed encoding.

## Post-restore checklist

- [ ] Save the recovery root token shown by the next `/unseal`.
- [ ] Rotate or revoke every row in Quasar -> Pending rotations.
- [ ] Re-enroll 2FA devices and TOTP if needed.
- [ ] Recreate notification channels.
- [ ] Recreate dynamic secret engines and roles.
- [ ] Run `/audit/verify`; a fresh target starts its own chain, while an in-place target continues the current target chain.
- [ ] Create the long-lived admin/service tokens you actually need.
- [ ] Dismiss the post-restore review panel only after the checks above.

## Full DR with pg_dump

For full-fidelity recovery, stop the API and dump PostgreSQL under age:

```bash
docker compose stop api
docker compose exec postgres \
  pg_dump -U rhorizon -d rhorizon --no-owner --no-privileges \
  | age -p > rhorizon-$(date +%Y%m%d-%H%M).sql.age
docker compose start api
```

Restore onto a fresh PostgreSQL volume:

```bash
docker compose down -v
docker compose up -d postgres
age -d rhorizon-YYYYMMDD-HHMM.sql.age \
  | docker compose exec -T postgres psql -U rhorizon -d rhorizon
docker compose up -d api
```

This keeps the same vault cryptographic identity and preserves tokens, 2FA, dynamic engines, and audit history exactly as they were at dump time.
