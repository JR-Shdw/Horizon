<!--
-----------------------------------------------------------------------------
Resurgamus Horizon - (c) 2024-2026 shdw <horizon@resurgamus.com> - AGPL-3.0
Self-hosted secrets vault
-----------------------------------------------------------------------------
-->

# Installation native (sans Docker)

> Statut par OS
>
> | OS | Statut | Note |
> |----|--------|------|
> | ArchLinux + linux-hardened | **validée** | Compatible linux-hardened |
> | Debian 12+ | validée | Même base que l'image Docker officielle |
> | Ubuntu 22.04+ | validée | Dérivée Debian |
> | Fedora 39+ | validée | `dnf` ; voir notes SELinux |
> | RHEL 9 / Rocky 9 / AlmaLinux 9 | validée | EPEL pour `python3.12` si absent |
> | openSUSE Leap 15.5+ / Tumbleweed | validée | `zypper` ; AppArmor au lieu de SELinux |
> | FreeBSD 14+ | validée | Toutes les primitives IPC shimmées 2026-05 |
> | OpenBSD 7.4+ | validée | Même chemin shim que FreeBSD |
> | macOS 13+ | squelette / non testée | `tools/install-macos.sh --mode user` |
> | stack Linux aarch64 | validée | Raspberry Pi 4 |
> | AIX / Solaris | non supporté | POWER/SPARC + IBM/Oracle proprio, hors scope |
>
> Chaque OS validé ci-dessus a été déroulé bout-en-bout via son script
> `tools/install-<os>.sh` (lanes BSD aussi gatées en CI, `.cirrus.yml`).

### Portabilité

Les bloqueurs historiquement Linux-only sont désormais portables ou supprimés :

| Primitive | Linux | macOS | BSD | Usage | Statut |
|-----------|:-----:|:-----:|:---:|-------|--------|
| Sockets AF_UNIX filesystem-path | yes | yes | yes | RPC crypto-ops + share-back Shamir | portable depuis 2026-05 (remplace abstract `\0name`) |
| Check peer-UID (shim `peer_cred`) | `SO_PEERCRED` | `LOCAL_PEERCRED` | `getpeereid()` | auth UID, fail-closed | shimmé 2026-05 ; Linux validé, macOS/BSD via mocks |
| `mlock(2)` | yes | yes | yes | Rust SecureBuffer | POSIX, validé |

Deux bloqueurs antérieurs ont été éliminés :

- `/dev/shm` (flow legacy key_share): retiré 2026-05. La RPC
  est le seul chemin multi-worker.
- Unix abstract sockets (`\0name`) : remplacés 2026-05 par des sockets
  filesystem-path sous `socket_paths.runtime_dir()` (défaut système Linux
  `/run/rhorizon/` ; BSD et macOS système utilisent `/var/run/rhorizon` ;
  override via `RH_RUNTIME_DIR`, `XDG_RUNTIME_DIR/rhorizon`, ou le
  défaut macOS `$TMPDIR/rhorizon`).

La propriété architecturale qui définit rhorizon - le master tient les
sub-keys, les followers délèguent toute opération crypto via IPC
authentifié - est préservée sur les 3 familles d'OS. Aucune primitive
de sécurité (check peer-UID, Shamir, buffers Rust mlock'd) n'a été
touchée par le travail de portabilité.

WSL2 et Docker Desktop sur macOS exécutent un noyau Linux sous le capot
et fonctionnent donc comme sur Linux - c'est le chemin recommandé pour
les utilisateurs sur hôte macOS / Windows qui ne veulent pas faire
tourner rhorizon nativement.

Le déploiement Docker Compose (`docker-compose.yml`) reste recommandé.
Ce document s'adresse aux opérateurs qui ne peuvent pas (ou ne veulent
pas) faire tourner de conteneurs sur l'hôte vault : environnements
régulés, nœuds air-gapped, ou infra où le vault est l'unique service
sur la machine.

L'install native **perd deux durcissements compose** : système de
fichiers `read_only` et `cap_drop: ALL`. Vous pouvez reconstruire des
contraintes équivalentes via les directives systemd - voir la section
[Durcissement](#9-durcissement).

---

## 1. Pré-requis système

| Composant | Version | Pourquoi |
|-----------|---------|----------|
| Noyau Linux | 5.10+ | abstract sockets, `mlock`, namespaces |
| Python | **3.12** exactement | extension Rust `pyo3` buildée avec `abi3-py312` |
| Toolchain Rust | 1.79+ stable | build `rhorizon_crypto` via maturin |
| PostgreSQL | **18** | `pg_advisory_xact_lock`, `gen_random_uuid()`, `hashtext()` |
| `libsodium` | 1.0.18+ | dépendance runtime de `pynacl` (Argon2id, XChaCha20-Poly1305) |
| `libldap` + `libsasl2` | récent | `bonsai` (auth LDAP/AD) |
| `git` | quelconque | clone du dépôt |
| `age` (optionnel) | 1.1+ | nécessaire seulement si vous lancez le CLI backup sur l'hôte |

`mlock` exige `CAP_IPC_LOCK` ou `RLIMIT_MEMLOCK` suffisant. Les distros
modernes ont une limite assez haute par défaut ; sur noyaux durcis aux
réglages plus stricts, voir [Durcissement](#9-durcissement).

---

## 2. Installation des dépendances

### 2.1 ArchLinux (validée)

```bash
sudo pacman -S --needed \
    python python-pip python-virtualenv \
    rustup base-devel \
    libsodium libldap libsasl \
    postgresql git
rustup default stable
```

> **linux-hardened** : le projet est régulièrement éprouvé sur Arch
> avec `linux-hardened` (politique infra du projet : tous les serveurs
> Arch tournent ce noyau). Aucun réglage particulier en pratique -
> `mlock` fonctionne avec le `RLIMIT_MEMLOCK` par défaut, les abstract
> sockets sont disponibles, et les directives systemd ci-dessous se
> superposent proprement au durcissement noyau.

### 2.2 Debian 12+ / Ubuntu 22.04+

```bash
sudo apt update
sudo apt install -y \
    python3.12 python3.12-venv python3.12-dev python3-pip \
    build-essential pkg-config curl \
    libsodium-dev libldap2-dev libsasl2-dev \
    postgresql-18 postgresql-client-18 \
    git
# Toolchain Rust via rustup (rustc Debian/Ubuntu trop ancien au 2026-05)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
```

Si la distro ne fournit pas encore Python 3.12 (Debian 12 a 3.11),
utiliser le PPA [deadsnakes](https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa)
sur Ubuntu, ou builder depuis `python3.12.tar.xz` sur Debian. **Ne pas
utiliser 3.11** : la wheel `rhorizon_crypto` est `abi3-py312`.

Si PostgreSQL 18 n'est pas dans les dépôts par défaut, utiliser le
[dépôt PostgreSQL Apt](https://wiki.postgresql.org/wiki/Apt).

### 2.3 Fedora 39+

```bash
sudo dnf install -y \
    python3.12 python3.12-devel python3-pip \
    gcc make pkgconf-pkg-config curl \
    libsodium-devel openldap-devel cyrus-sasl-devel \
    postgresql18-server postgresql18 \
    git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
```

> **SELinux** : si `pg_hba.conf` est édité et Postgres ne démarre pas,
> lancer `sudo restorecon -Rv /var/lib/pgsql`. Pour l'unité systemd
> ci-dessous, si les logs montrent des blocages `audit2allow`, générer
> une politique locale avec
> `audit2allow -M rhorizon < /var/log/audit/audit.log` et la charger
> via `semodule -i rhorizon.pp`.

### 2.4 RHEL 9 / Rocky 9 / AlmaLinux 9

```bash
sudo dnf install -y epel-release
sudo dnf install -y \
    python3.12 python3.12-devel python3-pip \
    gcc make pkgconf-pkg-config curl \
    libsodium-devel openldap-devel cyrus-sasl-devel \
    git
# PostgreSQL 18 via PGDG officiel (RHEL 9 fournit 13 par défaut)
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
sudo dnf -qy module disable postgresql
sudo dnf install -y postgresql18-server postgresql18
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
```

### 2.5 openSUSE Leap 15.5+ / Tumbleweed

```bash
sudo zypper install -y \
    python312 python312-devel python312-pip \
    gcc make pkg-config curl \
    libsodium-devel openldap2-devel cyrus-sasl-devel \
    postgresql18-server postgresql18 \
    git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
```

### 2.6 FreeBSD 14+

```sh
# pkg fait partie du base system depuis FreeBSD 10.
sudo pkg install -y \
    python312 py312-pip py312-virtualenv \
    rust \
    libsodium openldap-client cyrus-sasl \
    postgresql18-server postgresql18-client \
    git curl ca_root_nss

# Active + démarre postgres (rc.conf)
sudo sysrc postgresql_enable=YES
sudo service postgresql initdb
sudo service postgresql start
```

> **maturin via pip** : `pkg` ne fournit pas `maturin`. L'installer
> dans le venv rhorizon (section 4.2). Le toolchain Rust de
> `pkg install rust` est suffisamment récent (>= 1.79 depuis FreeBSD 14.1).
>
> **`/run` n'est pas tmpfs par défaut sur FreeBSD**. Le répertoire
> runtime des sockets doit être tmpfs pour éviter de persister des
> fichiers de socket entre les redémarrages. Soit monter un tmpfs
> (`tmpfs /run/rhorizon tmpfs rw,mode=0700,uid=rhorizon 0 0` dans
> `/etc/fstab`), soit régler `RH_RUNTIME_DIR=/var/run/rhorizon`
> (qui est tmpfs par défaut).
>
> **service rc.d** : FreeBSD n'utilise pas systemd. Un script rc.d de
> référence est dans `tools/rc.d/rhorizon` (non testé). Adapter
> l'unité systemd de la section 6 aux idiomes rc.d :
> `daemon -P /var/run/rhorizon.pid` pour le background, `procname` pour
> le check de statut. Le durcissement systemd a des équivalents dans
> `jail(8)` (lancer rhorizon dans un vnet jail avec
> `allow.raw_sockets=0` etc.).

### 2.7 OpenBSD 7.4+

```sh
# pkg_add demande le miroir au premier lancement; le miroir FAQ marche.
doas pkg_add -v \
    python-3.12 \
    rust \
    libsodium openldap-client cyrus-sasl \
    postgresql-server-18.x \
    git curl

# Postgres
doas /etc/rc.d/postgresql configtest
doas su - _postgresql -c "initdb -D /var/postgresql/data --locale=en_US.UTF-8"
doas rcctl enable postgresql
doas rcctl start postgresql
```

> **Spécificités OpenBSD** :
>
> - **`pledge(2)` / `unveil(2)`** : primitives OpenBSD pour restreindre
>   syscalls et accès filesystem. rhorizon ne les utilise pas
>   actuellement ; un déploiement durci devrait les ajouter autour du
>   point d'entrée du worker uvicorn (hors scope de ce guide - ouvrir
>   un ticket).
> - **`mlock(2)`** fonctionne sans configuration sur OpenBSD >= 7.0.
> - **`getpeereid(3)`** est fourni par libc.so.96.x ; le shim
>   `peer_cred` utilise `ctypes.util.find_library("c")` donc la
>   version n'a pas besoin d'être en dur.
> - **`/var/run` EST tmpfs (mfs)** par défaut -
>   `RH_RUNTIME_DIR=/var/run/rhorizon` est le réglage recommandé.
> - **service rc.d** : idem FreeBSD, voir `tools/rc.d/rhorizon`.

---

## 3. PostgreSQL

```bash
# Arch / RHEL / openSUSE - initdb manuel
sudo -u postgres initdb -D /var/lib/postgres/data    # Arch
sudo postgresql-setup --initdb                       # RHEL family
sudo systemctl enable --now postgresql

# Debian/Ubuntu - postgresql-common s'en charge à l'install
sudo systemctl enable --now postgresql
```

Création du rôle et de la base :

```bash
sudo -u postgres psql <<SQL
CREATE ROLE rhorizon WITH LOGIN PASSWORD 'CHANGE_ME_LONG_RANDOM';
CREATE DATABASE rhorizon OWNER rhorizon;
SQL
```

> **TLS vers Postgres** : la config par défaut a `RH_DATABASE_SSL=true`.
> Si votre cluster a TLS activé (recommandé), rien à faire. Pour une
> install locale sans TLS (mono-host, loopback), passer
> `RH_DATABASE_SSL=false` dans le fichier d'env (section 5.2).

---

## 4. Build et installation

### 4.1 Clone et venv

```bash
sudo useradd --system --home-dir /opt/rhorizon --shell /usr/sbin/nologin rhorizon
sudo mkdir -p /opt/rhorizon
sudo chown rhorizon:rhorizon /opt/rhorizon

sudo -u rhorizon -H bash <<'EOF'
cd /opt/rhorizon
git clone https://github.com/JR-Shdw/Horizon.git src
cd src
python3.12 -m venv /opt/rhorizon/venv
source /opt/rhorizon/venv/bin/activate
pip install --upgrade pip wheel
pip install --require-hashes -r api/requirements.txt
EOF
```

### 4.2 Build de l'extension Rust

À builder **en tant que `rhorizon`** pour que le venv reçoive le bon tag ABI :

```bash
sudo -u rhorizon -H bash <<'EOF'
source /opt/rhorizon/venv/bin/activate
pip install maturin
cd /opt/rhorizon/src/api/rust
RUSTFLAGS="--remap-path-prefix=$PWD=." maturin build --release --locked --strip
pip install target/wheels/*.whl
EOF
```

Vérification :

```bash
sudo -u rhorizon /opt/rhorizon/venv/bin/python -c \
    "from rhorizon_crypto import secure_zero; print('rhorizon_crypto OK')"
```

#### Chemin dev rapide : sauter la toolchain Rust (contributeurs uniquement)

Pour itérer côté Python en tant que contributeur - pas une install de
production - un wheel pré-buildé est livré sous `api/rust/wheel-out/`.
Installe-le directement dans un venv local au projet, sans `rustup` +
`maturin` :

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r api/requirements.txt
make rust-wheel-install        # choisit le wheel abi3 qui matche ce Python
```

Tags supportés : linux x86_64, glibc >= 2.34, cpython 3.12+ via abi3 (et
cpython 3.13 exact). musllinux, arm64, BSD, glibc plus ancien ne sont pas
couverts par les wheels livrés - repli sur le flux `maturin build`
ci-dessus.

### 4.3 Application du schéma

```bash
sudo -u postgres psql -d rhorizon -f /opt/rhorizon/src/schema.sql
```

Le schéma est idempotent (`IF NOT EXISTS` / `CREATE OR REPLACE`) - sans
risque de re-jouer à chaque mise à jour.

---

## 5. Configuration

### 5.1 Répertoire d'audit

```bash
sudo install -d -o rhorizon -g rhorizon -m 0750 /var/log/rhorizon
```

### 5.2 Fichier d'environnement

Installer la config native documentée (`examples/rhorizon.env.example`,
root, mode 0600 - elle contient le DSN avec le mot de passe DB) et l'éditer :

```bash
sudo install -d -o root -g root -m 0755 /etc/rhorizon
sudo install -m 0600 examples/rhorizon.env.example /etc/rhorizon/rhorizon.env
sudoedit /etc/rhorizon/rhorizon.env        # poser le mot de passe RH_DATABASE_URL
```

L'exemple livré est sectionné et commenté par option (défauts affichés).
Set minimal single-host :

```ini
# Base de données
RH_DATABASE_URL=postgresql+asyncpg://rhorizon:CHANGE_ME_LONG_RANDOM@127.0.0.1:5432/rhorizon
RH_DATABASE_SSL=false

# Audit
RH_AUDIT_DIR=/var/log/rhorizon
RH_AUDIT_RETENTION_DAYS=365
RH_AUDIT_COMPRESS_DAYS=1

# Log fail2ban-ready
RH_AUTHFAIL_LOG=/var/log/rhorizon/authfail.log

# Vault
RH_AUTO_SEAL_MINUTES=0
RH_DEK_KEY_MAX_AGE_DAYS=30

# Limites de body
RH_MAX_BODY_BYTES=1048576
RH_MAX_BODY_BACKUP=104857600

# Reverse proxies de confiance (utile seulement derrière un reverse proxy)
RH_PROXY_TRUSTED_IPS=127.0.0.0/8,::1/128

# Métriques (Prometheus) - restreindre au host monitoring
RH_METRICS_ENABLED=true
RH_METRICS_ALLOWED_CIDRS=127.0.0.1/32

# Cluster laisser false en mono-host
RH_CLUSTER_HA_ENABLED=false
```

> **Ne jamais** exposer rhorizon sur une IP publique. Bind sur localhost
> + VPN ou reverse proxy sur VLAN privé (cf. `SECURITY.md`).

---

## 6. Unité systemd

`/etc/systemd/system/rhorizon.service` :

```ini
[Unit]
Description=Resurgamus Horizon - vault de secrets self-hosted
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=exec
User=rhorizon
Group=rhorizon
WorkingDirectory=/opt/rhorizon/src
EnvironmentFile=/etc/rhorizon/rhorizon.env
ExecStart=/opt/rhorizon/venv/bin/uvicorn api.app.main:app \
    --host 127.0.0.1 --port 8200 \
    --workers 4 --no-access-log

Restart=on-failure
RestartSec=5s

#, Durcissement (équivalent compose) --
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/log/rhorizon /opt/rhorizon
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @reboot @swap @debug

# Mémoire : autoriser mlock pour l'extension Rust
LimitMEMLOCK=infinity
CapabilityBoundingSet=CAP_IPC_LOCK
AmbientCapabilities=CAP_IPC_LOCK

# Limites
TasksMax=50
MemoryMax=512M
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rhorizon
sudo systemctl status rhorizon
sudo journalctl -u rhorizon -f
```

---

## 7. Vérification

> **Ces commandes valent pour l'unit écrite à la main ci-dessus**, qui sert du
> HTTP en clair et compte sur nginx (section 8) pour terminer TLS devant.
> `tools/install-native.sh` ne fonctionne pas comme ça : il génère un certificat
> auto-signé sous `<config-dir>/certs`, le passe à uvicorn via
> `--ssl-certfile/--ssl-keyfile`, et le vault ne répond qu'en **https**. Dans ce
> cas, ajouter `--cacert <config-dir>/certs/cert.pem` à chaque curl, ou exporter
> `RH_CA_FILE` pour la CLI.
>
> Dans les deux cas, l'API logge un avertissement `PLAINTEXT TRANSPORT` pour
> chaque appel authentifié qui arrive en clair - loopback compris. Si vous
> terminez TLS à nginx, c'est l'en-tête `X-Forwarded-Proto` de la section 8 qui
> indique au vault que le saut client était bien chiffré.

```bash
# Healthcheck (sans auth)
curl http://127.0.0.1:8200/health

# Status (vault sealed au premier boot - attendu)
curl http://127.0.0.1:8200/api/v1/vault/status
```

Vous devez voir `"sealed": true`. Premier unseal :

```bash
sudo -u rhorizon /opt/rhorizon/venv/bin/python -m rhorizon.main \
    --url http://127.0.0.1:8200 unseal
```

---

## 8. Frontend (optionnel)

Pour servir la SPA UI sur le même hôte, pointer un vhost nginx sur
`frontend/` et proxifier `/api/` vers l'API :

```nginx
server {
    listen 127.0.0.1:8443 ssl http2;
    ssl_certificate     /etc/rhorizon/tls/fullchain.pem;
    ssl_certificate_key /etc/rhorizon/tls/privkey.pem;

    root /opt/rhorizon/src/frontend;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
    location /api/ {
        proxy_pass http://127.0.0.1:8200;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        # Nécessaire, pas cosmétique : sans ça le vault voit un saut en clair
        # et logge un avertissement PLAINTEXT TRANSPORT à chaque appel authentifié.
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Les headers et CSP sont déjà dans `frontend/nginx.conf` - piocher au besoin.

---

## 9. Durcissement

L'unité systemd reproduit la majorité du durcissement compose
(`no-new-privileges`, drop de capabilities, restrictions namespaces,
filtre syscalls). Pour s'approcher de la parité :

- **fs read-only** : `ProtectSystem=strict` met déjà `/usr`, `/boot`,
  `/etc` en lecture seule. Les chemins applicatifs sont sous
  `ReadWritePaths` uniquement.
- **cap_drop: ALL** : `CapabilityBoundingSet=CAP_IPC_LOCK` ne laisse
  que la seule capability réellement nécessaire.
- **mlock** : `LimitMEMLOCK=infinity` + `AmbientCapabilities=CAP_IPC_LOCK`
  permettent à l'extension Rust de verrouiller ses buffers de clés.
- **noexec /tmp** : `PrivateTmp=true` donne déjà au process un `/tmp`
  privé namespacé ; ajoutez un mount `tmpfs` `noexec,nosuid` côté hôte
  si vous gérez aussi le mount.

### Particularités linux-hardened (Arch)

- `kernel.unprivileged_userns_clone=0` : par défaut sur hardened -
  sans impact pour rhorizon (pas de fork de user namespaces).
- `kernel.kptr_restrict=2` : sans impact.
- `mlock` fonctionne sans réglage supplémentaire grâce aux directives
  systemd qui accordent `CAP_IPC_LOCK`. Si `journalctl` montre
  `Cannot allocate memory`, augmenter `LimitMEMLOCK` ou vérifier une
  limite per-user concurrente dans `/etc/security/limits.d/`.
- La couche RPC multiworker utilise des sockets filesystem sous
  `/run/rhorizon/` (pas le namespace abstract), donc ces réglages ne
  l'affectent pas.

### SELinux / AppArmor

- **SELinux** (Fedora/RHEL) : la politique par défaut ne couvre pas
  un service Python custom bindant le port 8200. Si `journalctl`
  montre `permission denied`, soit basculer en mode permissif le temps
  de rédiger une politique (`setenforce 0`), soit générer une
  politique locale depuis l'audit log :

  ```bash
  sudo audit2allow -M rhorizon -l < /var/log/audit/audit.log
  sudo semodule -i rhorizon.pp
  ```

- **AppArmor** (Ubuntu/SUSE) : aucun profil n'est livré avec le projet.
  Le profil unconfined par défaut convient ; si la politique du site
  exige un profil, le baser sur `/etc/apparmor.d/abstractions/python`
  et ajouter `/var/log/rhorizon/** rw,` plus
  `/opt/rhorizon/venv/** mr,`.

---

## 10. Procédure de mise à jour

```bash
sudo systemctl stop rhorizon
sudo -u rhorizon -H bash <<'EOF'
cd /opt/rhorizon/src
git fetch --tags
git checkout vX.Y.Z          # ou 'main' pour la dernière
source /opt/rhorizon/venv/bin/activate
pip install --require-hashes -r api/requirements.txt
cd api/rust
maturin build --release --locked --strip
pip install --force-reinstall target/wheels/*.whl
EOF
sudo -u postgres psql -d rhorizon -f /opt/rhorizon/src/schema.sql
sudo systemctl start rhorizon
```

Le vault se re-scelle au stop. L'opérateur doit unseal après chaque
redémarrage (comportement documenté, pas un bug - voir SECURITY.md).

---

## 11. Backup

Quel que soit le process choisi pour `/var/lib/pgsql` (ou l'équivalent
distro), inclure `/var/log/rhorizon/audit-*.jsonl*` pour préserver la
chaîne d'audit. Restic / rsync / `pg_dump` fonctionnent - l'outil
préféré du projet est Restic vers un datacenter séparé.

---

## 12. Dépannage

| Symptôme | Cause probable | Correctif |
|----------|----------------|-----------|
| Import `rhorizon_crypto` échoue | mauvais ABI Python | rebuilder la wheel contre le `python3.12` du venv |
| `mlock failed` dans les logs | `RLIMIT_MEMLOCK` trop bas | augmenter `LimitMEMLOCK` dans l'unité systemd |
| 503 sur tout appel API | vault sealed | lancer `unseal` |
| 401 avec un token valide après restart | vault sealed puis re-unseal avec un autre password | rotation de token, corriger le flow d'unseal |
| `connection refused` sur Postgres | mismatch TLS | passer `RH_DATABASE_SSL=false` ou corriger `pg_hba.conf` |
| `address already in use` sur 8200 | un worker précédent vit encore | `systemctl restart rhorizon` puis `ss -tlnp \| grep 8200` |
| Chaîne d'audit `intact: false` | une row a été éditée à la main, ou un write a crashé | `GET /api/v1/vault/audit/verify` montre le point de rupture ; restaurer depuis backup |

Issues à ouvrir sur le Gitea du projet ; mentionner distro + noyau +
sortie de `systemctl status rhorizon` et
`journalctl -u rhorizon --since '5 min ago'`.
