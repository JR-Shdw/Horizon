# fail2ban - protection anti-brute force au niveau firewall

rhorizon écrit chaque échec d'authentification dans un fichier log dédié,
compatible fail2ban. fail2ban lit ce log et bannit les IPs au niveau
iptables/nftables - avant que la requête n'atteigne l'application.

## Fichier de log

**Chemin** : `/var/log/rhorizon/authfail.log` (configurable via `RH_AUTHFAIL_LOG`)

Le fichier est dans le volume Docker `audit_logs`, accessible en lecture sur l'hôte.

### Format

```
2026-04-13T14:23:45+0000 rhorizon AUTH_FAIL ip=192.168.1.42 type=invalid_token
2026-04-13T14:23:46+0000 rhorizon AUTH_FAIL ip=192.168.1.42 type=invalid_password
2026-04-13T14:23:47+0000 rhorizon AUTH_FAIL ip=192.168.1.42 type=rate_limited
```

Une ligne par échec, append-only, atomique (POSIX, multi-worker safe).

### Types d'échecs

| type | Source | Description |
|------|--------|-------------|
| `invalid_header` | Token API | Header Authorization malformé |
| `invalid_token_format` | Token API | Token ne commence pas par `rh_` |
| `invalid_token` | Token API | Token inconnu ou révoqué |
| `token_expired` | Token API | Token expiré |
| `invalid_password` | Unseal | Master password incorrect |
| `2fa_failed` | Unseal | Échec 2FA (TOTP, YubiKey, WebAuthn) |
| `shamir_reconstruction_failed` | Unseal | Reconstruction Shamir échouée |
| `shamir_invalid_data` | Unseal | Données Shamir invalides |
| `shamir_master_check_failed` | Unseal | Shares valides mais master check échoue |
| `shamir_master_check_missing` | Unseal | La reconstruction n'a produit aucun master check à comparer |
| `shamir_stale_generation` | Unseal | Les shares appartiennent à une génération de clé périmée |
| `oneshot_invalid_password` | Oneshot | Master password incorrect sur `POST /oneshot` |
| `oneshot_2fa_failed` | Oneshot | Échec 2FA sur `POST /oneshot` |
| `ldap_invalid_credentials` | LDAP login | Identifiants LDAP invalides |
| `proxy_untrusted_ip` | SSO proxy | Tentative d'auth proxy depuis une IP hors `proxy_trusted_ips` |
| `token_ip_not_allowed` | Token API | Token **valide** présenté depuis une IP hors de son `allowed_ips` |
| `bootstrap_blocked` | Cluster JOIN | Tentative de bootstrap HA rejetée |
| `rate_limited` | Tous | IP bloquée par le rate limiter (429) |

Deux d'entre eux méritent une jail alors même que la requête a déjà été
refusée : `token_ip_not_allowed` signifie qu'un token **valide** a été rejoué
depuis le mauvais hôte — le token a fuité, et l'IP source vaut la peine d'être
bannie pendant que vous le faites tourner. `proxy_untrusted_ip` signifie que
quelque chose a essayé d'affirmer un en-tête d'identité depuis l'extérieur de
l'ensemble des proxies de confiance, ce qui est une tentative de contournement
d'authentification sur le chemin SSO.

## Installation fail2ban

> Des configs prêtes à l'emploi sont livrées dans `contrib/fail2ban/` (filtre +
> jail) et `contrib/logrotate/` - copiez-les plutôt que de coller les blocs
> ci-dessous ; elles suivent le format de log. Voir `contrib/fail2ban/README.md`.

### 1. Trouver le volume sur l'hôte

```bash
docker volume inspect rhorizon_audit_logs | grep Mountpoint
# /var/lib/docker/volumes/rhorizon_audit_logs/_data
```

Le fichier authfail.log est dans ce répertoire.

### 2. Filtre fail2ban

```ini
# /etc/fail2ban/filter.d/rhorizon.conf
[Definition]
failregex = ^.*rhorizon AUTH_FAIL ip=<HOST> type=.*$
ignoreregex =
datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S%%z
```

### 3. Jail fail2ban

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

| Paramètre | Valeur | Description |
|-----------|--------|-------------|
| `maxretry` | 5 | Tentatives avant ban |
| `findtime` | 300 | Fenêtre de comptage (5 min) |
| `bantime` | 3600 | Durée du ban (1h) |
| `port` | 8200,8443 | Ports bloqués (HTTP + HTTPS) |

### 4. Activer et tester

```bash
# Redémarrer fail2ban
systemctl restart fail2ban

# Vérifier que la jail est active
fail2ban-client status rhorizon

# Tester le filtre sur le log existant
fail2ban-regex /var/lib/docker/volumes/rhorizon_audit_logs/_data/authfail.log \
    /etc/fail2ban/filter.d/rhorizon.conf
```

### 5. Vérifier un ban

```bash
# Lister les IPs bannies
fail2ban-client status rhorizon

# Débannir manuellement
fail2ban-client set rhorizon unbanip 192.168.1.42
```

## Nftables (alternative à iptables)

Si le serveur utilise nftables :

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

Le fichier grossit avec le temps. Ajouter une rotation :

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

`copytruncate` : copie puis tronque le fichier sans fermer le fd ouvert
par l'application (pas besoin de signal ou restart).

## Double protection

rhorizon a deux niveaux de protection contre le brute force :

Pour une requête entrante, trois couches interviennent en série :

- **fail2ban (firewall)** : bloque l'IP avant la connexion TCP (iptables/nftables DROP).
- **rate_limit (applicatif)** : 429 après 5/10/20 échecs (DB-backed, multi-worker).
- **authfail.log** : nourrit fail2ban en continu.

fail2ban agit au niveau réseau (plus efficace, moins de charge),
le rate limiter applicatif est un filet de sécurité si fail2ban n'est pas installé.

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `RH_AUTHFAIL_LOG` | `/var/log/rhorizon/authfail.log` | Chemin du log dans le container |
