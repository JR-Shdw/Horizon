<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# fail2ban (or similar) integration

Ready-to-use configs for banning brute-force sources at the firewall, fed by
the auth-failure log (`api/app/authfail.py`). Full guide: `docs/FAIL2BAN.md`.

## Files

| File | Install to |
|------|------------|
| `filter.d/rhorizon.conf` | `/etc/fail2ban/filter.d/rhorizon.conf` |
| `jail.d/rhorizon.conf.example` | `/etc/fail2ban/jail.d/rhorizon.conf` (edit `logpath`) |
| `../logrotate/rhorizon-authfail` | `/etc/logrotate.d/rhorizon-authfail` |

## Quick install

```bash
sudo cp filter.d/rhorizon.conf /etc/fail2ban/filter.d/rhorizon.conf
sudo cp jail.d/rhorizon.conf.example /etc/fail2ban/jail.d/rhorizon.conf
# point logpath at the authfail.log on the host, then:
sudo systemctl restart fail2ban
fail2ban-client status rhorizon
# test the filter against the live log:
fail2ban-regex <logpath> /etc/fail2ban/filter.d/rhorizon.conf
```

## Or a similar tool

The log is plain UTF-8, one event per line, append-only with an ISO-8601
timestamp:

```
2026-04-13T14:23:45+0000 rhorizon AUTH_FAIL ip=192.168.1.42 type=invalid_token
```

This format is a stability contract. Any log shipper / IPS (CrowdSec, a SIEM,
Promtail) can tail the same file, `ip=` and `type=` are sanitized to
`[A-Za-z0-9._:/-]` at the source, so a single line can never be forged from
request input. `type` values are listed in `docs/FAIL2BAN.md`.
