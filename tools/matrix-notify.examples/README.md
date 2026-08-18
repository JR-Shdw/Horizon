# matrix-notify - adoption guide

End-to-end recipe to post Matrix messages without ever embedding a Matrix
access token in your scripts, env files, or container layers. The token
lives in rhorizon; `matrix-notify` pulls it on demand at every send.

Same dogfood pattern as `git-credential-rhorizon` - same bootstrap token
on the workstation, same audit trail on the vault side.

## What you get

Before:

```bash
# alerts.sh
curl -X PUT "https://matrix.example.com/_matrix/client/v3/rooms/.../send/..." \
     -H "Authorization: Bearer syt_LEAKABLE_TOKEN" \
     -d '{"msgtype":"m.text","body":"deploy ok"}'
```

After:

```bash
# alerts.sh
matrix-notify "deploy ok"
```

No token in the script, no token in env, no token in `journalctl` history.

## When to use it

| Use case | Pattern |
|---|---|
| Backup post-script | `restic backup ... && matrix-notify "backup ok" \|\| matrix-notify "backup FAILED"` |
| Cron health-check | `0 * * * * /usr/local/bin/healthcheck \|\| matrix-notify --stdin < /tmp/error.log` |
| Ansible handler | `notify: matrix-notify "deploy {{ inventory_hostname }} done"` |
| Woodpecker step | `notify: { commands: ['matrix-notify "build ${CI_COMMIT_SHA:0:7} ok"'] }` |
| Webhook receiver | Run `webhook-relay.py` (next section) and point Grafana / GitHub / Restic at it |

## 1. Store Matrix credentials in the vault

Mint or pick an existing Matrix access token (Element -> Settings ->
Help & About -> Advanced -> Access Token; or `/login` via Synapse admin
API). Store it + the target room ID in rhorizon:

```bash
# 1.a - Matrix bot access token
curl -X POST "$VAULT_URL/api/v1/vault/secrets/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"matrix-bot-token",
    "namespace":"alerts",
    "value":"syt_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }'

# 1.b - Target room ID (starts with "!")
curl -X POST "$VAULT_URL/api/v1/vault/secrets/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"matrix-alerts-room",
    "namespace":"alerts",
    "value":"!aBcDeFgH:matrix.example.com"
  }'
```

Why two secrets and not one combined value? Operationally the room
might change (you re-shape your channels) without rotating the token,
and vice-versa. Decoupled secrets means each rotation touches one
record.

## 2. Mint a bootstrap token

`secrets:r` on the `alerts` namespace, with an IP allowlist tying it
to the host doing the alerting:

```bash
curl -X POST "$VAULT_URL/api/v1/vault/tokens/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"alert-host-bootstrap",
    "permissions":{"secrets":"r","namespaces":["alerts"]},
    "allowed_ips":"10.0.0.1/32"
  }'
```

## 3. Configure the helper

```bash
mkdir -p ~/.config/rhorizon
chmod 700 ~/.config/rhorizon
umask 077

read -rsp 'Bootstrap token: ' RH_TOKEN; echo
printf '%s\n' "$RH_TOKEN" > ~/.config/rhorizon/token
unset RH_TOKEN
echo 'https://vault.example.com'                    > ~/.config/rhorizon/url

cp tools/matrix-notify.examples/matrix.conf.example ~/.config/rhorizon/matrix.conf
$EDITOR ~/.config/rhorizon/matrix.conf
# Adjust homeserver / token_secret / room_secret to match step 1
```

## 4. Install + smoke-test

```bash
sudo install -m 0755 tools/matrix-notify /usr/local/bin/

matrix-notify "smoke test from $(hostname) at $(date -Iseconds)"
# Prints the event_id on success, or fails with non-zero exit code.
```

Exit codes (useful for shell trapping):

| Code | Meaning |
|---|---|
| 0  | Sent. event_id printed on stdout (unless --quiet). |
| 1  | Bad CLI input (no message, etc.). |
| 2  | Helper config problem (no token file, mode too open). |
| 3  | Vault unreachable or returned an error. |
| 4  | Matrix unreachable or returned an error. |

## 5. Reading the room (matrix-read)

`matrix-notify` is one-way: it posts. The companion `tools/matrix-read`
is the read side - pulls new `m.room.message` events from the same
room, prints them, and persists a sync cursor so the next call resumes
where this one left off. Same vault-backed credential lookup, same
config file (`~/.config/rhorizon/matrix.conf`).

```bash
# One-shot - print every message that landed since the last invocation
matrix-read

# Stream mode - long-poll, prints events as they arrive
matrix-read --watch

# JSON output, one event per line, jq-friendly
matrix-read --format json | jq -r '.content.body'

# Backfill the last 50 messages from history (independent of the cursor)
matrix-read --backfill 50

# First run on a new host: discard any leftover cursor and start "from now"
matrix-read --reset
```

Output (text mode):

```
[2026-04-30T14:25:40+00:00] @alice:matrix.example.com: deploy ok
[2026-04-30T14:26:01+00:00] @bob:matrix.example.com: thanks
```

The sync cursor lives at `~/.config/rhorizon/matrix.state` (mode 0600).
Each call captures the next-batch token from `/sync` and saves it; the
next call passes it back in `?since=` so you get pure deltas, no
duplication, no missed events.

### When to use it

| Use case | Pattern |
|---|---|
| Cron poller for a chatops command room | `*/1 * * * * matrix-read \| grep -F '!deploy ' \| my-command-handler` |
| Bot watching for a keyword | `matrix-read --watch --format json \| ./reaction-bot.py` |
| Audit dump of recent activity | `matrix-read --backfill 200 > /var/log/room-snapshot-$(date +%F).log` |
| Operator catch-up on a host that was offline | `matrix-read` - prints everything missed since last run |

## 6. Webhook receiver - generic entry point for tooling that doesn't speak Matrix

`tools/matrix-notify.examples/webhook-relay.py` is a stdlib HTTP server
you run as a service. It accepts JSON or form payloads on three routes
(`/webhook`, `/grafana`, `/woodpecker`) and forwards them to Matrix
using the same vault-backed credentials. Replace the `*_format()`
functions to match your senders.

```bash
# Run as a service
./tools/matrix-notify.examples/webhook-relay.py --host 127.0.0.1 --port 8765

# In another shell:
curl -X POST http://127.0.0.1:8765/webhook \
     -H 'Content-Type: application/json' \
     -d '{"text":"hello from curl"}'
```

For shared-secret auth (defense-in-depth - even on a private network,
you don't want any local process posting to your alerts room):

```bash
# Store the shared secret in the vault first
openssl rand -hex 32 | rhorizon set webhook-shared-secret \
  --namespace alerts --stdin

# Run the relay with it
./webhook-relay.py --shared-secret-secret webhook-shared-secret

# Senders include it in the X-Webhook-Token header
curl -X POST http://127.0.0.1:8765/webhook \
     -H @<( { printf 'X-Webhook-Token: '; \
              rhorizon get webhook-shared-secret --namespace alerts; } ) \
     -d '{"text":"..."}'
```

The process-substitution form keeps the header value out of shell history,
process arguments, and temporary files. It requires Bash.

### Adapting to specific senders

Two pre-baked formatters ship with the relay:

- `/grafana` - Grafana alertmanager v4 payload -> compact `[FIRING] title - rule: foo` summary.
- `/woodpecker` - Woodpecker pipeline notification -> `[OK|FAIL] repo (branch) - url`.

Add your own by writing a `myservice_format(payload) -> (text, html_or_None)`
and wiring a route - diff is ~10 lines. The relay stays single-file.

### Systemd unit

```ini
# /etc/systemd/system/matrix-webhook-relay.service
[Unit]
Description=Matrix webhook relay (rhorizon-backed)
After=network-online.target
Wants=network-online.target

[Service]
User=relay
ExecStart=/usr/local/bin/webhook-relay.py --host 127.0.0.1 --port 8765
Restart=on-failure
RestartSec=5s
ProtectSystem=strict
ProtectHome=read-only
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

The vault token (`~relay/.config/rhorizon/token`) is the only thing the
service user needs. If that file leaks, rotating the bootstrap token
in the vault revokes access immediately.

## 7. Mock stack - try the helpers without a real vault or Matrix server

`tools/matrix-notify.examples/mock-stack.py` is a runnable, single-file
demo: starts a fake rhorizon vault and a fake Matrix homeserver in two
threads, writes a temp `~/.config/rhorizon/` look-alike, prints a
banner with copy-paste instructions, and logs every interaction.

```bash
# Terminal 1 - start the mock
./tools/matrix-notify.examples/mock-stack.py
# (banner prints two URLs, the temp config dir, and example commands)

# Terminal 2 - paste the export from the banner, then:
matrix-notify "first demo message"
matrix-notify --format html "<strong>second</strong>"
matrix-read --backfill 10
matrix-read --watch                 # blocks until you send another from
                                    # a third terminal - long-poll demo
```

Watch terminal 1: every helper invocation prints a `[VAULT]` line
(secret fetch) and/or a `[MATRIX]` line (PUT `m.room.message`,
GET `/sync`, GET `/messages`) with timestamps and payload excerpts.

### When to use it

- **Onboarding a new operator** - show them the helpers working before
  asking them to provision a real vault token.
- **Testing your own helper modifications** without spamming a real
  room or risking a production token.
- **Building a sender that targets the same APIs** - point it at the
  mock to verify your wire format, then flip to the real homeserver.

## 8. Mocker for tests - fixture pattern

`tests/test_matrix_notify.py` shows the end-to-end test pattern: a fake
vault and a fake Matrix homeserver are stood up on ephemeral ports, and
the helper is invoked as a subprocess. Steal the `_FakeMatrixHandler`
class for your own test suite if you want to verify your alerting code
without spamming a real room:

```python
# my_alerter_test.py
from tests.test_matrix_notify import _FakeMatrixHandler  # reusable

# Run a fake homeserver in the test, point your code at it via
# MATRIX_HOMESERVER, assert on FakeMatrixHandler.captured.
```

The mocker captures every PUT including the room, transaction id,
auth header and body - enough to assert that your code formats
messages correctly and uses the right room.

## Operational notes

- **Audit volume**: every send = 2 vault reads (token + room) +
  1 Matrix PUT. If your alerter fires 1000x/day, you'll see 2000
  `read_secret` events on the vault. Use a per-host bootstrap token
  so you can identify the noisy alerter without grepping IPs.
- **Token rotation**: rotate the Matrix access token, update the secret
  in the vault, every running service picks it up on next call.
  Workers don't need restart - `matrix-notify` is stateless.
- **Sealing**: while the vault is sealed, all sends fail with exit 3.
  Health-check your alerters; not great if your alerter is what would
  page you about a sealed vault. Use a different channel (email,
  systemd-cat) for that one specific case.
- **Federation**: if your homeserver is federated and the bot account
  isn't in the target room yet, the PUT will return 403. Join first.
