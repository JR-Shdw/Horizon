# fail2ban - Firewall-level brute force protection

Resurgamus Horizon writes every authentication failure to a dedicated log file,
compatible with fail2ban. fail2ban reads this log and bans IPs at the
iptables/nftables level - before the request even reaches the application.

## Log file

**Path**: `/var/log/rhorizon/authfail.log` (configurable via `RH_AUTHFAIL_LOG`)

The file lives in the Docker volume `audit_logs`, readable from the host.

### Format

```
2026-04-13T14:23:45+0000 rhorizon AUTH_FAIL ip=192.168.1.42 type=invalid_token
2026-04-13T14:23:46+0000 rhorizon AUTH_FAIL ip=192.168.1.42 type=invalid_password
2026-04-13T14:23:47+0000 rhorizon AUTH_FAIL ip=192.168.1.42 type=rate_limited
```

One line per failure, append-only, atomic (POSIX, multi-worker safe).

### Failure types

| type | Source | Description |
|------|--------|-------------|
| `invalid_header` | Token API | Malformed Authorization header |
| `invalid_token_format` | Token API | Token does not start with `rh_` |
| `invalid_token` | Token API | Unknown or revoked token |
| `token_expired` | Token API | Expired token |
| `invalid_password` | Unseal | Incorrect master password |
| `2fa_failed` | Unseal | 2FA failure (TOTP, YubiKey, WebAuthn) |
| `shamir_reconstruction_failed` | Unseal | Shamir reconstruction failed |
| `shamir_invalid_data` | Unseal | Invalid Shamir share data |
| `shamir_master_check_failed` | Unseal | Valid shares but master check fails |
| `shamir_master_check_missing` | Unseal | Reconstruction produced no master check to compare |
| `shamir_stale_generation` | Unseal | Shares belong to a superseded key generation |
| `oneshot_invalid_password` | Oneshot | Incorrect master password on `POST /oneshot` |
| `oneshot_2fa_failed` | Oneshot | 2FA failure on `POST /oneshot` |
| `ldap_invalid_credentials` | LDAP login | Invalid LDAP credentials |
| `proxy_untrusted_ip` | SSO proxy | Proxy-auth attempt from an IP outside `proxy_trusted_ips` |
| `token_ip_not_allowed` | Token API | Valid token presented from outside its `allowed_ips` |
| `bootstrap_blocked` | Cluster JOIN | Rejected HA bootstrap attempt |
| `rate_limited` | All | IP blocked by rate limiter (429) |

Two of these deserve a jail even though the request was already refused:
`token_ip_not_allowed` means a **valid** token was replayed from the wrong
host - the token leaked, and the source IP is worth banning while you rotate
it. `proxy_untrusted_ip` means something tried to assert an identity header
from outside the trusted-proxy set, which is an auth-bypass attempt against
the SSO path.

## fail2ban setup

> Ready-to-use configs ship in `contrib/fail2ban/` and `contrib/logrotate/` -
> copy those instead of pasting the blocks below; they stay versioned with the
> log format. See `contrib/fail2ban/README.md`.
>
> The filter is `contrib/fail2ban/filter.d/rhorizon.conf` (drop in as-is). The
> jail ships as `jail.d/rhorizon.conf.example` and **must be renamed** to
> `rhorizon.conf` after you set `logpath` for your deployment - fail2ban does
> not read `.example` files.

### 1. Find the volume on the host

```bash
docker volume inspect rhorizon_audit_logs | grep Mountpoint
# /var/lib/docker/volumes/rhorizon_audit_logs/_data
```

The authfail.log file is in this directory.

### 2. fail2ban filter

```ini
# /etc/fail2ban/filter.d/rhorizon.conf
[Definition]
failregex = ^.*rhorizon AUTH_FAIL ip=<HOST> type=\S+\s*$
ignoreregex =
datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S%%z
```

### 3. fail2ban jail

```ini
# /etc/fail2ban/jail.d/rhorizon.conf
[rhorizon]
enabled  = true
filter   = rhorizon
logpath  = /var/lib/docker/volumes/rhorizon_audit_logs/_data/authfail.log
maxretry = 5
findtime = 300
bantime  = 3600
action   = iptables-multiport[name=rhorizon, port="8200,8443", protocol=tcp]
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| `maxretry` | 5 | Attempts before ban |
| `findtime` | 300 | Counting window (5 min) |
| `bantime` | 3600 | Ban duration (1h) |
| `port` | 8200,8443 | Blocked ports (HTTP + HTTPS) |

### 4. Enable and test

```bash
# Restart fail2ban
systemctl restart fail2ban

# Verify the jail is active
fail2ban-client status rhorizon

# Test the filter against the existing log
fail2ban-regex /var/lib/docker/volumes/rhorizon_audit_logs/_data/authfail.log \
    /etc/fail2ban/filter.d/rhorizon.conf
```

### 5. Check a ban

```bash
# List banned IPs
fail2ban-client status rhorizon

# Manually unban
fail2ban-client set rhorizon unbanip 192.168.1.42
```

## nftables (iptables alternative)

If the server uses nftables:

```ini
# /etc/fail2ban/jail.d/rhorizon.conf
[rhorizon]
enabled  = true
filter   = rhorizon
logpath  = /var/lib/docker/volumes/rhorizon_audit_logs/_data/authfail.log
maxretry = 5
findtime = 300
bantime  = 3600
banaction = nftables-multiport
```

## Logrotate

The file grows over time. Add rotation:

```
# /etc/logrotate.d/rhorizon-authfail
/var/lib/docker/volumes/rhorizon_audit_logs/_data/authfail.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

`copytruncate`: copies then truncates the file without closing the fd
held by the application (no signal or restart needed).

## Defense in depth

Resurgamus Horizon has two layers of brute force protection:

```
Incoming request
    |
    +-- fail2ban (firewall) --- blocks the IP BEFORE the TCP connection
    |                           (iptables/nftables DROP)
    |
    +-- rate_limit (application) --- 429 after 5/10/20 failures
    |                                (DB-backed, multi-worker)
    |
    +-- authfail.log --- continuously feeds fail2ban
```

fail2ban acts at the network level (more efficient, less load),
the application rate limiter is a safety net if fail2ban is not installed.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RH_AUTHFAIL_LOG` | `/var/log/rhorizon/authfail.log` | Log path inside the container |
