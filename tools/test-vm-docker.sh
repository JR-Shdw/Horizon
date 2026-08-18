#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# docker validation: boot a Debian/Ubuntu cloud VM, install
# docker.io + compose plugin, load the locally-built rhorizon-agent
# image, run the four-pattern step 2 compose against the production
# vault (vault.example.com / 10.0.0.1:8200 over VPN NAT), and
# assert each backend authenticates with its vault-fetched secret.
#
# Usage :
#   tools/test-vm-docker.sh {debian|ubuntu}     [default: debian]
#
# Required env :
#   RHORIZON_BOOTSTRAP_TOKEN      - bearer token (tokens:w + secrets:r,
#                                   namespace claude). Mounted into the
#                                   VM as a file ; compose treats it as
#                                   a docker file-secret.
#   RHORIZON_VAULT_ADDR           - default http://10.0.0.1:8200
#
# This script does *not* run pytest ; it only validates that the agent
# binaries and compose patterns work under a real `docker compose` -
# distinct from the podman-compose validation already in /tmp.

set -euo pipefail

OS="${1:-debian}"
case "$OS" in
    debian|ubuntu) ;;
    *) echo "usage: $0 {debian|ubuntu}" >&2; exit 1 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE_DIR="${HOME}/.cache/rhorizon-vms"
WORK_DIR="/tmp/rhorizon-vmtest-${OS}-docker"
SSH_PORT="${SSH_PORT:-2298}"
mkdir -p "${WORK_DIR}" "${CACHE_DIR}"

case "$OS" in
    debian)
        IMG_FILENAME="debian-12-genericcloud-amd64.qcow2"
        IMG_URL="https://cloud.debian.org/images/cloud/bookworm/latest/${IMG_FILENAME}"
        SSH_USER="debian"
        ;;
    ubuntu)
        IMG_FILENAME="ubuntu-24.04-noble-server-cloudimg-amd64.qcow2"
        IMG_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
        SSH_USER="ubuntu"
        ;;
esac

if [[ -z "${RHORIZON_BOOTSTRAP_TOKEN:-}" ]]; then
    echo "Set RHORIZON_BOOTSTRAP_TOKEN (a token with tokens:w + secrets:r in namespace claude)" >&2
    exit 1
fi
VAULT_ADDR="${RHORIZON_VAULT_ADDR:-http://10.0.0.1:8200}"

DISK="${WORK_DIR}/disk.qcow2"
SEED="${WORK_DIR}/seed.iso"

# ---------------------------------------------------------------------------
# 1. Acquire image (use cache if present)
# ---------------------------------------------------------------------------
if [[ ! -f "${CACHE_DIR}/${IMG_FILENAME}" ]]; then
    echo ">> downloading ${IMG_URL}"
    curl -fsSL --proto '=https' "${IMG_URL}" -o "${CACHE_DIR}/${IMG_FILENAME}.tmp"
    mv "${CACHE_DIR}/${IMG_FILENAME}.tmp" "${CACHE_DIR}/${IMG_FILENAME}"
fi

cp "${CACHE_DIR}/${IMG_FILENAME}" "${DISK}"
qemu-img resize "${DISK}" 30G >/dev/null

# ---------------------------------------------------------------------------
# 2. Cloud-init seed
# ---------------------------------------------------------------------------
rm -f "${WORK_DIR}/id_ed25519" "${WORK_DIR}/id_ed25519.pub"
ssh-keygen -t ed25519 -N '' -f "${WORK_DIR}/id_ed25519" -q
SSH_PUBKEY="$(cat "${WORK_DIR}/id_ed25519.pub")"

cat > "${WORK_DIR}/user-data" <<EOF
#cloud-config
hostname: rhorizon-${OS}-docker
ssh_pwauth: false
users:
  - name: ${SSH_USER}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/sh
    ssh_authorized_keys:
      - ${SSH_PUBKEY}
disable_root: false
package_update: true
packages:
  - sudo
  - rsync
  - docker.io
  - docker-compose
  - curl
  - jq
runcmd:
  - systemctl enable --now docker
  - usermod -aG docker ${SSH_USER}
EOF
cat > "${WORK_DIR}/meta-data" <<EOF
instance-id: rhorizon-${OS}-docker
local-hostname: rhorizon-${OS}-docker
EOF
if command -v cloud-localds >/dev/null 2>&1; then
    cloud-localds "${SEED}" "${WORK_DIR}/user-data" "${WORK_DIR}/meta-data"
else
    genisoimage -output "${SEED}" -volid cidata -joliet -rock \
        "${WORK_DIR}/user-data" "${WORK_DIR}/meta-data" >/dev/null
fi

# ---------------------------------------------------------------------------
# 3. Boot
# ---------------------------------------------------------------------------
PIDFILE="${WORK_DIR}/qemu.pid"
LOGFILE="${WORK_DIR}/qemu.log"
cleanup() { [[ -z "${KEEP_VM:-}" && -f "${PIDFILE}" ]] && kill "$(cat "${PIDFILE}")" 2>/dev/null || true; }
trap cleanup EXIT

VM_CPUS="${VM_CPUS:-8}"
VM_RAM="${VM_RAM:-8G}"

echo ">> booting ${OS} VM (ssh 127.0.0.1:${SSH_PORT}, ${VM_CPUS} vCPU / ${VM_RAM})"
qemu-system-x86_64 \
    -name "rhorizon-${OS}-docker" \
    -machine type=q35,accel=kvm:tcg -cpu host \
    -smp "${VM_CPUS}" -m "${VM_RAM}" \
    -drive "file=${DISK},if=virtio" \
    -drive "file=${SEED},if=virtio,format=raw,readonly=on" \
    -nic "user,model=virtio,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -display none -serial "file:${LOGFILE}" -monitor none \
    -daemonize -pidfile "${PIDFILE}"

echo ">> waiting for sshd (up to 5 min)"
for _ in $(seq 1 60); do
    if ssh -p ${SSH_PORT} -i "${WORK_DIR}/id_ed25519" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 "${SSH_USER}@127.0.0.1" 'true' 2>/dev/null; then
        echo ">> sshd up"
        break
    fi
    sleep 5
done

SSH="ssh -p ${SSH_PORT} -i ${WORK_DIR}/id_ed25519 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    ${SSH_USER}@127.0.0.1"

echo ">> waiting for cloud-init (docker install)"
timeout 240 ${SSH} "cloud-init status --wait" || true

# ---------------------------------------------------------------------------
# 4. Push the agent image into the VM
# ---------------------------------------------------------------------------
echo ">> exporting + uploading rhorizon-agent image"
podman save -o "${WORK_DIR}/rhorizon-agent.tar" localhost/rhorizon-agent:dev-ephemeral
scp -P ${SSH_PORT} -i "${WORK_DIR}/id_ed25519" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${WORK_DIR}/rhorizon-agent.tar" "${SSH_USER}@127.0.0.1:/tmp/"
${SSH} "sudo docker load -i /tmp/rhorizon-agent.tar"
${SSH} "sudo docker tag localhost/rhorizon-agent:dev-ephemeral rhorizon-agent:dev-ephemeral"
${SSH} "sudo docker images | grep rhorizon-agent"

# ---------------------------------------------------------------------------
# 5. Push the bootstrap token + a step 2 compose
# ---------------------------------------------------------------------------
${SSH} "mkdir -p step2 && chmod 0700 step2"
# Bootstrap file mode 0444 : the agent image runs as USER 65534 ; under
# docker (rootful) the file-secret is bind-mounted with the source
# permissions, so we make it world-readable. The directory above is
# 0700 owned by the user, so external readers can't enumerate it.
${SSH} "umask 022 && printf '%s' '${RHORIZON_BOOTSTRAP_TOKEN}' > step2/rh-bootstrap && chmod 0444 step2/rh-bootstrap"

cat > "${WORK_DIR}/compose.yml" <<COMPOSE_EOF
# v2 - docker validation. Distinguishing features vs the
# podman-compose run :
#   - bootstrap token comes via docker file-secret (file: ./rh-bootstrap)
#     which docker compose maps to /run/secrets/rh-bootstrap mode 0400
#   - postgres + mariadb + rh-watch ephemeral, all hitting the prod vault
services:
  # Init / sidecar containers override user to root so they can write to
  # the named volume (docker rootful creates these owned by root). The
  # actual app containers (postgres, mariadb) keep their own user model.
  rh-fetch-pg:
    image: rhorizon-agent:dev-ephemeral
    user: "0"
    entrypoint: /usr/local/bin/rh-fetch
    environment:
      RHORIZON_ADDR: ${VAULT_ADDR}
      RHORIZON_TOKEN_FILE: /run/secrets/rh-bootstrap
      RHORIZON_SECRETS: test-pg-pw:/run/secrets/POSTGRES_PASSWORD
    secrets:
      - rh-bootstrap
    volumes:
      - secrets-pg:/run/secrets

  postgres:
    image: postgres:18-trixie
    depends_on:
      rh-fetch-pg:
        condition: service_completed_successfully
    environment:
      POSTGRES_USER: rhorizon_test
      POSTGRES_DB: rhorizon_test
      POSTGRES_PASSWORD_FILE: /run/secrets/POSTGRES_PASSWORD
    volumes:
      - secrets-pg:/run/secrets:ro
    ports:
      - "127.0.0.1:55432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U rhorizon_test"]

  rh-fetch-mariadb:
    image: rhorizon-agent:dev-ephemeral
    user: "0"
    entrypoint: /usr/local/bin/rh-fetch
    environment:
      RHORIZON_ADDR: ${VAULT_ADDR}
      RHORIZON_TOKEN_FILE: /run/secrets/rh-bootstrap
      RHORIZON_SECRETS: mariadb-root-pw:/run/secrets/MARIADB_ROOT_PASSWORD
    secrets:
      - rh-bootstrap
    volumes:
      - secrets-mariadb:/run/secrets

  mariadb:
    image: mariadb:11
    depends_on:
      rh-fetch-mariadb:
        condition: service_completed_successfully
    environment:
      MARIADB_DATABASE: rhorizon_demo
      MARIADB_ROOT_PASSWORD_FILE: /run/secrets/MARIADB_ROOT_PASSWORD
    volumes:
      - secrets-mariadb:/run/secrets:ro
    healthcheck:
      test: ["CMD", "mariadb-admin", "ping", "-h", "localhost"]

  rh-watch-demo:
    image: rhorizon-agent:dev-ephemeral
    user: "0"
    entrypoint: /usr/local/bin/rh-watch
    environment:
      RHORIZON_ADDR: ${VAULT_ADDR}
      RHORIZON_TOKEN_FILE: /run/secrets/rh-bootstrap
      RHORIZON_SECRETS: test-pg-pw:/run/secrets/POSTGRES_PASSWORD
      RHORIZON_POLL_SECS: "10"
      RHORIZON_EPHEMERAL: "true"
      RHORIZON_EPHEMERAL_TTL: "60"
    secrets:
      - rh-bootstrap
    volumes:
      - secrets-watch:/run/secrets

secrets:
  rh-bootstrap:
    file: ./rh-bootstrap

volumes:
  secrets-pg:
  secrets-mariadb:
  secrets-watch:
COMPOSE_EOF
scp -P ${SSH_PORT} -i "${WORK_DIR}/id_ed25519" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${WORK_DIR}/compose.yml" "${SSH_USER}@127.0.0.1:step2/compose.yml"

# ---------------------------------------------------------------------------
# 6. Bring up the stack and wait for healthy
# ---------------------------------------------------------------------------
${SSH} "cd step2 && sudo docker-compose up -d 2>&1 | tail -20"

echo ">> waiting for backends healthy (up to 3 min)"
# docker-compose v1 doesn't support --format json. We poll docker inspect
# directly on the named containers (compose v1 uses underscore separator).
PG_CT="step2_postgres_1"
MDB_CT="step2_mariadb_1"
for _ in $(seq 1 36); do
    PG_HEALTH=$(${SSH} "sudo docker inspect --format '{{.State.Health.Status}}' ${PG_CT} 2>/dev/null" || true)
    MDB_HEALTH=$(${SSH} "sudo docker inspect --format '{{.State.Health.Status}}' ${MDB_CT} 2>/dev/null" || true)
    if [[ "${PG_HEALTH}" == "healthy" && "${MDB_HEALTH}" == "healthy" ]]; then
        echo ">> postgres + mariadb healthy"
        break
    fi
    sleep 5
done

# ---------------------------------------------------------------------------
# 7. Validate
# ---------------------------------------------------------------------------
echo
echo "================ DOCKER STEP 2 VALIDATION ================"
echo
echo "--- A1) postgres auth via _FILE ---"
${SSH} "sudo docker exec ${PG_CT} psql -U rhorizon_test -d rhorizon_test -c \"SELECT 'pg_auth_ok' AS r;\" 2>&1 | tail -3"

echo
echo "--- A2) mariadb auth via _FILE ---"
MDB_PW=$(curl -sS -H "Authorization: Bearer ${RHORIZON_BOOTSTRAP_TOKEN}" \
    "${VAULT_ADDR}/api/v1/vault/secrets/mariadb-root-pw?namespace=claude" \
    | jq -r .value)
${SSH} "sudo docker exec ${MDB_CT} mariadb -uroot -p'${MDB_PW}' -e \"SELECT 'mdb_auth_ok' AS r;\" 2>&1 | tail -3"

echo
echo "--- B) rh-watch ephemeral rotation (15s observation) ---"
sleep 15
${SSH} "sudo docker logs step2_rh-watch-demo_1 2>&1 | grep -E 'enabled|refreshed' | head -5 || true"

echo
echo "--- token hygiene : bootstrap value NOT in docker inspect Env ---"
${SSH} "sudo docker inspect step2_rh-watch-demo_1 2>/dev/null | jq '.[0].Config.Env[]? | select(test(\"TOKEN|BOOTSTRAP\"))'"

echo
echo ">> validation done - VM logs in ${WORK_DIR}/qemu.log (KEEP_VM=1 to retain VM)"
