#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Spin up a VM (FreeBSD / OpenBSD / Debian / Ubuntu / Rocky / openSUSE /
# Arch + linux-hardened) via qemu, provision rhorizon's deps, run the
# pytest suite. Each OS has its own install-${OS}.sh that lands the deps
# and bootstraps PostgreSQL.
#
# Usage:
#   tools/test-vm.sh {freebsd|openbsd|debian|ubuntu|rocky|opensuse|arch}
#
# Resources:
#   VM_CPUS=16 VM_RAM=16G  (defaults - override on the env if needed)
#
# Native installer validation (instead of legacy install-${OS}.sh + pytest):
#   RH_NATIVE=1 [RH_INSTALL_MODE=system|user] tools/test-vm.sh {freebsd|netbsd|...}
#   -> runs tools/install.sh and asserts the vault unseals end-to-end.
#
# Prerequisites:
#   tools/qemu.yml ansible playbook installs qemu-base + cloud-utils +
#   cdrtools + signify (signify only needed for OpenBSD bootstrap).
#
# Workflow:
#   1. Acquire boot media : download official cloud image + verify SHA256
#      (or clone the OpenBSD golden built by openbsd-bootstrap.sh).
#   2. Build a cloud-init seed (skipped for OpenBSD - golden has it baked).
#   3. Boot qemu, wait for sshd, push checkout, run install-${OS}.sh +
#      pytest.
#   4. On exit: kill qemu, save logs to /tmp/rhorizon-vmtest-${OS}/.

set -euo pipefail

OS="${1:-}"
case "$OS" in
    freebsd|openbsd|netbsd|debian|ubuntu|rocky|opensuse|arch|fedora) ;;
    *)
        cat >&2 <<EOF
usage: $0 {freebsd|openbsd|netbsd|debian|ubuntu|rocky|opensuse|arch|fedora}

Tested matrix (status table in docs/INSTALL-NATIVE.md):
    freebsd    FreeBSD 14.4 (cloud image)
    openbsd    OpenBSD 7.8  (golden image - see openbsd-bootstrap.sh)
    netbsd     NetBSD 10.1  (golden image - see netbsd-bootstrap.sh)
    debian     Debian 12 bookworm
    ubuntu     Ubuntu 24.04 LTS noble
    rocky      Rocky Linux 10 (GenericCloud; ROCKY_VERSION=9 for old stream)
    opensuse   openSUSE Leap 16.0 (SUSE_VERSION=15.6 is EOL)
    fedora     Fedora 43 Cloud (FEDORA_VERSION to override)
    arch       Arch Linux + linux-hardened kernel
EOF
        exit 2
        ;;
esac

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "qemu-system-x86_64 missing. Run ansible-playbook ansible/qemu.yml ..." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE_DIR="${HOME}/.cache/rhorizon-vms"
WORK_DIR="/tmp/rhorizon-vmtest-${OS}"
mkdir -p "${CACHE_DIR}" "${WORK_DIR}"

# Override via env for parallel multi-OS runs.
SSH_PORT="${SSH_PORT:-2222}"
PG_PORT="${PG_PORT:-5433}"
SSH_USER=""
IMG_URL=""
IMG_FILENAME=""
CHECKSUM_URL=""
CHECKSUM_PATTERN=""   # how to grep checksum from CHECKSUM file ; default = filename
DEFAULT_PASSWD_USER=""  # cloud-init user; "" means use root

# ---------------------------------------------------------------------------
# Per-OS variables : cloud image URL, SSH user, install script.
# ---------------------------------------------------------------------------

case "$OS" in
    freebsd)
        FREEBSD_VERSION="14.4"
        FREEBSD_BASE="https://download.freebsd.org/releases/VM-IMAGES/${FREEBSD_VERSION}-RELEASE/amd64/Latest"
        IMG_URL="${FREEBSD_BASE}/FreeBSD-${FREEBSD_VERSION}-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
        CHECKSUM_URL="${FREEBSD_BASE}/CHECKSUM.SHA256"
        IMG_FILENAME="$(basename "${IMG_URL%.xz}")"
        SSH_USER="freebsd"
        ;;
    openbsd)
        # Pre-built golden image - no download here. operator runs
        # tools/openbsd-bootstrap.sh once (~25 min) before this script.
        OPENBSD_VERSION="7.8"
        IMG_FILENAME="openbsd-${OPENBSD_VERSION}-golden.qcow2"
        SSH_USER="root"
        ;;
    netbsd)
        # Pre-built golden image - no download here. operator runs
        # tools/netbsd-bootstrap.sh once (~25 min) before this script.
        NBSD_VERSION="10.1"
        IMG_FILENAME="netbsd-${NBSD_VERSION}-golden.qcow2"
        SSH_USER="root"
        ;;
    debian)
        # Debian 12 (bookworm) genericcloud - daily builds with cloud-init.
        DEBIAN_VERSION="${DEBIAN_VERSION:-13}"
        DEBIAN_CODENAME="${DEBIAN_CODENAME:-trixie}"
        IMG_URL="https://cloud.debian.org/images/cloud/${DEBIAN_CODENAME}/latest/debian-${DEBIAN_VERSION}-genericcloud-amd64.qcow2"
        IMG_FILENAME="debian-${DEBIAN_VERSION}-genericcloud-amd64.qcow2"
        CHECKSUM_URL="https://cloud.debian.org/images/cloud/${DEBIAN_CODENAME}/latest/SHA512SUMS"
        SSH_USER="debian"
        ;;
    ubuntu)
        # Ubuntu LTS server cloud image. Defaults to the current LTS (26.04
        # resolute); override for an older LTS, e.g. UBUNTU_VERSION=24.04
        # UBUNTU_CODENAME=noble. Only LTS releases are validated - interim
        # releases (25.10, ...) get 9 months of support and are not prod targets.
        UBUNTU_VERSION="${UBUNTU_VERSION:-26.04}"
        UBUNTU_CODENAME="${UBUNTU_CODENAME:-resolute}"
        IMG_URL="https://cloud-images.ubuntu.com/${UBUNTU_CODENAME}/current/${UBUNTU_CODENAME}-server-cloudimg-amd64.img"
        IMG_FILENAME="ubuntu-${UBUNTU_VERSION}-${UBUNTU_CODENAME}-server-cloudimg-amd64.qcow2"
        CHECKSUM_URL="https://cloud-images.ubuntu.com/${UBUNTU_CODENAME}/current/SHA256SUMS"
        SSH_USER="ubuntu"
        ;;
    rocky)
        # Rocky Linux GenericCloud. Defaults to current major (10); override
        # with ROCKY_VERSION=9 for the older stream.
        ROCKY_VERSION="${ROCKY_VERSION:-10}"
        IMG_URL="https://download.rockylinux.org/pub/rocky/${ROCKY_VERSION}/images/x86_64/Rocky-${ROCKY_VERSION}-GenericCloud-Base.latest.x86_64.qcow2"
        IMG_FILENAME="rocky-${ROCKY_VERSION}-genericcloud.qcow2"
        CHECKSUM_URL="https://download.rockylinux.org/pub/rocky/${ROCKY_VERSION}/images/x86_64/CHECKSUM"
        SSH_USER="rocky"
        ;;
    opensuse)
        # openSUSE Leap Minimal VM cloud image. Default 16.0 (matrix target);
        # override SUSE_VERSION=15.6 for the older stream. Leap 16.0 dropped the
        # "openSUSE-" filename prefix that 15.x carried.
        SUSE_VERSION="${SUSE_VERSION:-16.0}"
        case "$SUSE_VERSION" in
            16.*|16) _SUSE_IMG="Leap-${SUSE_VERSION}-Minimal-VM.x86_64-Cloud.qcow2" ;;
            *)       _SUSE_IMG="openSUSE-Leap-${SUSE_VERSION}-Minimal-VM.x86_64-Cloud.qcow2" ;;
        esac
        IMG_URL="https://download.opensuse.org/distribution/leap/${SUSE_VERSION}/appliances/${_SUSE_IMG}"
        IMG_FILENAME="opensuse-leap-${SUSE_VERSION}-minimal-cloud.qcow2"
        CHECKSUM_URL="${IMG_URL}.sha256"
        # cloud-init creates a `root` account directly when ssh_authorized_keys
        # is set at the top level. We use root for parity with our other paths.
        SSH_USER="root"
        ;;
    fedora)
        # Fedora Cloud Base Generic qcow2. Default current release (43);
        # override FEDORA_VERSION. The compose build suffix (e.g. -1.6) varies,
        # so discover the exact image + CHECKSUM filenames from the mirror.
        FEDORA_VERSION="${FEDORA_VERSION:-43}"
        _FED_DIR="https://download.fedoraproject.org/pub/fedora/linux/releases/${FEDORA_VERSION}/Cloud/x86_64/images"
        _FED_LS=$(curl -fsSL "${_FED_DIR}/")
        _FED_IMG=$(printf '%s' "$_FED_LS" | grep -oE "Fedora-Cloud-Base-Generic-${FEDORA_VERSION}-[0-9.]+\.x86_64\.qcow2" | sort -u | head -1 || true)
        _FED_CK=$(printf '%s' "$_FED_LS" | grep -oE "Fedora-Cloud-${FEDORA_VERSION}-[0-9.]+-x86_64-CHECKSUM" | sort -u | head -1 || true)
        [ -n "$_FED_IMG" ] || { echo "fedora: no Cloud image under ${_FED_DIR}" >&2; exit 1; }
        IMG_URL="${_FED_DIR}/${_FED_IMG}"
        IMG_FILENAME="fedora-${FEDORA_VERSION}-cloud.qcow2"
        CHECKSUM_URL="${_FED_DIR}/${_FED_CK}"
        SSH_USER="fedora"
        ;;
    arch)
        # Arch Linux official cloud image. install-arch.sh adds the
        # linux-hardened kernel + flips the GRUB default after first boot.
        IMG_URL="https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2"
        IMG_FILENAME="arch-cloudimg-amd64.qcow2"
        CHECKSUM_URL="https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2.SHA256"
        SSH_USER="arch"
        ;;
esac

DISK="${WORK_DIR}/disk.qcow2"
SEED="${WORK_DIR}/seed.iso"

# ---------------------------------------------------------------------------
# 1. Acquire boot media + prepare disk
# ---------------------------------------------------------------------------

if [[ "$OS" == "openbsd" || "$OS" == "netbsd" ]]; then
    if [[ ! -f "${CACHE_DIR}/${IMG_FILENAME}" ]]; then
        cat >&2 <<EOF
${CACHE_DIR}/${IMG_FILENAME} missing.

Build the ${OS} golden image once (~25 min) :

  tools/${OS}-bootstrap.sh

EOF
        exit 1
    fi
    qemu-img create -f qcow2 -F qcow2 -b "${CACHE_DIR}/${IMG_FILENAME}" "${DISK}" >/dev/null
    # NetBSD build scratch. Its golden has a 13G root and the source builds
    # (pydantic-core, watchfiles, rhorizon_crypto) exhaust it -- the overlay hit
    # 12G and watchfiles died with ENOSPC. The driver points TMPDIR at /var/tmp,
    # so give /var/tmp its own disk rather than rebuild the golden.
    if [[ "$OS" == "netbsd" ]]; then
        SCRATCH="${WORK_DIR}/scratch.qcow2"
        qemu-img create -f qcow2 "${SCRATCH}" 24G >/dev/null
    fi
else
    if [[ ! -f "${CACHE_DIR}/${IMG_FILENAME}" ]]; then
        echo ">> downloading ${IMG_URL}"
        TMP_DL="${CACHE_DIR}/${IMG_FILENAME}.tmp"
        if [[ "${IMG_URL}" == *.xz ]]; then
            # For .xz : keep the .xz suffix so xz -d recognizes it.
            curl -fsSL --proto '=https' "${IMG_URL}" -o "${CACHE_DIR}/${IMG_FILENAME}.xz.tmp"
            mv "${CACHE_DIR}/${IMG_FILENAME}.xz.tmp" "${CACHE_DIR}/${IMG_FILENAME}.xz"
            if [[ -n "${CHECKSUM_URL}" ]]; then
                echo ">> verifying SHA256 (against .xz archive)"
                EXPECTED=$(curl -fsSL "${CHECKSUM_URL}" | grep "$(basename "${IMG_FILENAME}").xz" | awk '{print $4}')
                ACTUAL=$(sha256sum "${CACHE_DIR}/${IMG_FILENAME}.xz" | awk '{print $1}')
                if [[ "${EXPECTED}" != "${ACTUAL}" ]]; then
                    echo "SHA256 mismatch: expected ${EXPECTED}, got ${ACTUAL}" >&2
                    rm -f "${CACHE_DIR}/${IMG_FILENAME}.xz"
                    exit 1
                fi
            fi
            xz -d "${CACHE_DIR}/${IMG_FILENAME}.xz"
        else
            curl -fsSL --proto '=https' "${IMG_URL}" -o "${TMP_DL}"
            mv "${TMP_DL}" "${CACHE_DIR}/${IMG_FILENAME}"
            if [[ -n "${CHECKSUM_URL}" ]]; then
                echo ">> verifying checksum from ${CHECKSUM_URL}"
                # CHECKSUM file formats vary :
                #   FreeBSD : "SHA256 (foo) = abc"   awk $4
                #   Debian/Ubuntu : "abc  foo"      awk $1
                #   Rocky : "SHA256 (foo) = abc"     awk $4
                #   openSUSE : sha256 file is one-line "abc *foo"  awk $1
                #   Arch : "abc  foo"               awk $1
                # Rocky's CHECKSUM has comment + checksum lines for each
                # filename ; skip lines starting with `#` to grab the
                # checksum row only. Then take the rightmost long hex
                # token as the checksum (works for "SHA256 (foo) = abc"
                # and for "abc  foo" alike).
                CKLINE=$(curl -fsSL "${CHECKSUM_URL}" \
                    | grep -F "$(basename "${IMG_URL}")" \
                    | grep -v '^#' \
                    | head -1)
                EXPECTED=$(printf '%s\n' "${CKLINE}" | awk '{
                    for (i=NF; i>0; i--)
                        if (length($i) >= 32 && $i ~ /^[0-9a-fA-F]+$/) { print $i; exit }
                }')
                ACTUAL=$(sha256sum "${CACHE_DIR}/${IMG_FILENAME}" | awk '{print $1}')
                # Some manifests still ship SHA512 ; if our SHA256 doesn't
                # match, also try sha512 (Debian SHA512SUMS).
                if [[ "${EXPECTED}" != "${ACTUAL}" ]]; then
                    ACTUAL_512=$(sha512sum "${CACHE_DIR}/${IMG_FILENAME}" | awk '{print $1}')
                    if [[ "${EXPECTED}" == "${ACTUAL_512}" ]]; then
                        echo ">> matched SHA512 (manifest is SHA512SUMS)"
                    else
                        echo "checksum mismatch: expected ${EXPECTED}, got SHA256 ${ACTUAL}" >&2
                        rm -f "${CACHE_DIR}/${IMG_FILENAME}"
                        exit 1
                    fi
                fi
            fi
        fi
    fi

    cp "${CACHE_DIR}/${IMG_FILENAME}" "${DISK}"
    qemu-img resize "${DISK}" 30G
fi

# ---------------------------------------------------------------------------
# 2. SSH key + cloud-init seed (Linux/FreeBSD) - OpenBSD reuses golden key.
# ---------------------------------------------------------------------------

if [[ "$OS" == "openbsd" || "$OS" == "netbsd" ]]; then
    # Key name derives from the golden image (openbsd-7.8-... / netbsd-10.1-...).
    GOLDEN_KEY="${CACHE_DIR}/${IMG_FILENAME%-golden.qcow2}-id_ed25519"
    if [[ ! -f "${GOLDEN_KEY}" ]]; then
        echo "${OS} VM key missing: ${GOLDEN_KEY}" >&2
        echo "Run tools/${OS}-bootstrap.sh first." >&2
        exit 1
    fi
    cp -f "${GOLDEN_KEY}" "${WORK_DIR}/id_ed25519"
    cp -f "${GOLDEN_KEY}.pub" "${WORK_DIR}/id_ed25519.pub"
    chmod 0600 "${WORK_DIR}/id_ed25519"
else
    rm -f "${WORK_DIR}/id_ed25519" "${WORK_DIR}/id_ed25519.pub"
    ssh-keygen -t ed25519 -N '' -f "${WORK_DIR}/id_ed25519" -q
fi

# Generate the cloud-init seed for any non-OpenBSD OS. Same shape for all
# Linux distros and FreeBSD ; package list varies (FreeBSD needs sudo +
# rsync, Linux distros usually have sudo + rsync prebuilt but we ask
# explicitly to be defensive).
build_cloudinit_seed() {
    local hostname="$1"
    local ssh_pubkey
    ssh_pubkey="$(cat "${WORK_DIR}/id_ed25519.pub")"

    cat > "${WORK_DIR}/user-data" <<EOF
#cloud-config
hostname: ${hostname}
ssh_pwauth: false
users:
  - name: ${SSH_USER}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/sh
    ssh_authorized_keys:
      - ${ssh_pubkey}
ssh_authorized_keys:
  - ${ssh_pubkey}
disable_root: false
package_update: true
packages:
  - sudo
  - rsync
EOF
    cat > "${WORK_DIR}/meta-data" <<EOF
instance-id: rhorizon-${OS}-test
local-hostname: ${hostname}
EOF
    if command -v cloud-localds >/dev/null 2>&1; then
        cloud-localds "${SEED}" "${WORK_DIR}/user-data" "${WORK_DIR}/meta-data"
    else
        genisoimage -output "${SEED}" -volid cidata -joliet -rock \
            "${WORK_DIR}/user-data" "${WORK_DIR}/meta-data"
    fi
}

case "$OS" in
    freebsd)  build_cloudinit_seed "rhorizon-fbsd" ;;
    debian)   build_cloudinit_seed "rhorizon-deb" ;;
    ubuntu)   build_cloudinit_seed "rhorizon-ubuntu" ;;
    rocky)    build_cloudinit_seed "rhorizon-rocky" ;;
    opensuse) build_cloudinit_seed "rhorizon-suse" ;;
    fedora)   build_cloudinit_seed "rhorizon-fedora" ;;
    arch)     build_cloudinit_seed "rhorizon-arch" ;;
    openbsd|netbsd) : ;;  # golden has it baked
esac

# ---------------------------------------------------------------------------
# 3. Boot qemu (KVM, 16 vCPU / 16 GB by default - host has ~32/62)
# ---------------------------------------------------------------------------

PIDFILE="${WORK_DIR}/qemu.pid"
LOGFILE="${WORK_DIR}/qemu.log"

cleanup() {
    if [[ -z "${KEEP_VM:-}" && -f "${PIDFILE}" ]]; then
        kill "$(cat "${PIDFILE}")" 2>/dev/null || true
    fi
}
trap cleanup EXIT

VM_CPUS="${VM_CPUS:-16}"
VM_RAM="${VM_RAM:-16G}"

QEMU_DRIVES=( -drive "file=${DISK},if=virtio" )
if [[ "$OS" != "openbsd" && "$OS" != "netbsd" ]]; then
    QEMU_DRIVES+=( -drive "file=${SEED},if=virtio,format=raw,readonly=on" )
fi
if [[ -n "${SCRATCH:-}" ]]; then
    QEMU_DRIVES+=( -drive "file=${SCRATCH},if=virtio" )   # becomes ld1
fi

echo ">> booting ${OS} VM (ssh on localhost:${SSH_PORT}, ${VM_CPUS} vCPU / ${VM_RAM})"
qemu-system-x86_64 \
    -name "rhorizon-${OS}" \
    -machine type=q35,accel=kvm:tcg \
    -cpu host \
    -smp "${VM_CPUS}" -m "${VM_RAM}" \
    "${QEMU_DRIVES[@]}" \
    -nic user,model=virtio,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22,hostfwd=tcp:127.0.0.1:${PG_PORT}-:5432 \
    -display none \
    -serial "file:${LOGFILE}" \
    -monitor none \
    -daemonize \
    -pidfile "${PIDFILE}"

# ---------------------------------------------------------------------------
# 4. Wait for sshd
# ---------------------------------------------------------------------------

echo ">> waiting for sshd (up to 5 min)"
for _ in $(seq 1 60); do
    if ssh -p ${SSH_PORT} -i "${WORK_DIR}/id_ed25519" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        "${SSH_USER}@127.0.0.1" 'true' 2>/dev/null; then
        echo ">> sshd up"
        break
    fi
    sleep 5
done

SSH="ssh -p ${SSH_PORT} -i ${WORK_DIR}/id_ed25519 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    ${SSH_USER}@127.0.0.1"

# ---------------------------------------------------------------------------
# 5. Post-boot setup (cloud-init wait, install rsync if missing, etc.)
# ---------------------------------------------------------------------------

case "$OS" in
    openbsd)
        echo ">> bootstrapping rsync (autoinstall didn't deploy it)"
        ${SSH} "pkg_add -I 'rsync--'" || true
        ;;
    netbsd)
        # newfs needs -I: the raw whole-disk partition is not typed 4.2BSD,
        # and labelling it buys nothing for scratch space. /sbin is not on
        # the ssh PATH here, hence the explicit one.
        echo ">> mounting 24G build scratch on /var/tmp"
        ${SSH} "export PATH=/sbin:/usr/sbin:/bin:/usr/bin
                newfs -O2 -I /dev/rld1d >/dev/null 2>&1
                mount /dev/ld1d /var/tmp && df -h /var/tmp | tail -1" \
            || echo ">> WARNING: scratch mount failed; build may hit ENOSPC"
        ;;
    freebsd)
        # FreeBSD's nuageinit has no `cloud-init` CLI, and it is NOT synchronous
        # wrt sshd: sshd starts accepting before nuageinit finishes installing
        # packages, and nuageinit restarts sshd mid-handshake -> rsync dies with
        # `kex_exchange_identification: Connection reset by peer`. Poll for rsync
        # to actually exist (seed `packages:` install complete), retrying through
        # the resets, before we sync.
        echo ">> waiting for FreeBSD nuageinit to finish (rsync present, up to 5 min)"
        for _ in $(seq 1 60); do
            if timeout 10 ${SSH} 'command -v rsync >/dev/null 2>&1' 2>/dev/null; then
                echo ">> nuageinit done (rsync present)"
                break
            fi
            sleep 5
        done
        ;;
    debian|ubuntu|rocky|opensuse|arch)
        echo ">> waiting for cloud-init to finalize (cap 2 min)"
        # Cap the wait : Rocky 9 cloud-init occasionally hangs in --wait
        # due to a python traceback, but the rest of bootstrap (users,
        # ssh, packages) is already done when sshd is accepting.
        timeout 120 ${SSH} "cloud-init status --wait" || true
        ;;
esac

# Arch runs pacman-init (keyring) in the background on first boot ; it holds
# /var/lib/pacman/db.lck. cloud-init --wait returning does NOT mean it is done,
# so a `pacman -Sy` in the installer can race it -> "could not lock database".
# The linux-hardened path below happened to warm pacman past this ; the stock
# path skips it and exposes the race. Wait for the lock to clear either way.
if [[ "$OS" == "arch" ]]; then
    echo ">> waiting for pacman db lock to clear (pacman-init, up to 2 min)"
    for _ in $(seq 1 24); do
        ${SSH} "test ! -f /var/lib/pacman/db.lck" 2>/dev/null && { echo ">> pacman ready"; break; }
        sleep 5
    done
fi

# Arch Linux only ships `linux` (vanilla) in its cloud image. The user's
# production servers run linux-hardened, so install it + flip GRUB and
# reboot before any tests run, to validate the actual prod kernel path.
if [[ "$OS" == "arch" && -z "${RH_STOCK_KERNEL:-}" ]]; then
    echo ">> installing linux-hardened + reboot to it"
    ${SSH} "sudo pacman -Sy --noconfirm linux-hardened linux-hardened-headers >/dev/null"
    # GRUB picks the kernel via /etc/default/grub GRUB_DEFAULT.
    # On Arch cloud image grub-mkconfig auto-detects all kernels ; we
    # set GRUB_DEFAULT to the linux-hardened entry name (saved for
    # next boot only).
    ${SSH} "sudo sed -i 's|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"Advanced options for Arch Linux>Arch Linux, with Linux linux-hardened\"|' /etc/default/grub"
    ${SSH} "sudo grub-mkconfig -o /boot/grub/grub.cfg"
    ${SSH} "sudo reboot" || true
    sleep 5
    echo ">> waiting for sshd after reboot to linux-hardened (up to 5 min)"
    for _ in $(seq 1 60); do
        if ssh -p ${SSH_PORT} -i "${WORK_DIR}/id_ed25519" \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 \
            "${SSH_USER}@127.0.0.1" 'true' 2>/dev/null; then
            echo ">> sshd up post-reboot - running on $(${SSH} 'uname -r')"
            break
        fi
        sleep 5
    done
fi

# ---------------------------------------------------------------------------
# 6. Push checkout + run install-${OS}.sh + pytest
# ---------------------------------------------------------------------------

# Honour .gitignore as well as the explicit list below. The list is hand
# maintained and had already drifted: tools/chaos/results is gitignored, was
# not in it, and at 8.4G filled the guest disk mid-transfer -- rsync died with
# ENOSPC and the run never reached the installer. Anything git ignores is by
# definition not part of what the installer needs.
echo ">> pushing rhorizon checkout"
if [ "${OS}" = "netbsd" ]; then
    # The NetBSD golden has no rsync (pkgsrc install is unreliable), so push
    # via tar over ssh -- needs only base-system tar on both ends. Excludes
    # are applied by the host's GNU tar; NetBSD just extracts.
    tar czf - -C "${REPO_ROOT}" \
        --exclude-vcs-ignores \
        --exclude=.venv --exclude=__pycache__ --exclude=target \
        --exclude=node_modules --exclude=.cache --exclude=htmlcov \
        --exclude='*.qcow2' . \
        | ${SSH} "rm -rf rhorizon && mkdir rhorizon && cd rhorizon && tar xzf -"
else
    rsync -az --delete --filter=':- .gitignore' \
        --exclude='.venv' --exclude='__pycache__' \
        --exclude='target' --exclude='node_modules' --exclude='.cache' \
        --exclude='htmlcov' --exclude='*.qcow2' \
        -e "ssh -p ${SSH_PORT} -i ${WORK_DIR}/id_ed25519 \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
        "${REPO_ROOT}/" "${SSH_USER}@127.0.0.1:rhorizon/"
fi

# RH_NATIVE=1 : validate the UNIVERSAL native installer (tools/install.sh ->
# tools/drivers/${OS}.sh) instead of the legacy per-OS install-${OS}.sh + pytest.
# Success criterion = the installer's own unseal step confirms "vault unsealed"
# (pkg -> ssl-capable python -> venv -> rust ext -> PG -> boot service -> unseal).
# RH_INSTALL_MODE overrides the mode (default system).
if [[ -n "${RH_NATIVE:-}" ]]; then
    RH_MODE_ARG="${RH_INSTALL_MODE:-system}"
    echo ">> running native installer (tools/install.sh --mode ${RH_MODE_ARG}) on ${OS}"
    # system mode needs root: prefix sudo only when we ssh in as a non-root user
    # (BSD goldens log in as root). user mode always runs AS the login user -- the
    # driver self-elevates with sudo for the pkg/PG steps only (laptop model).
    if [ "$RH_MODE_ARG" = system ] && [ "$SSH_USER" != root ]; then
        RUN="cd rhorizon && sudo sh tools/install.sh --mode system"
    else
        RUN="cd rhorizon && sh tools/install.sh --mode ${RH_MODE_ARG}"
    fi
    # Capture to the file, THEN grep it -- do not `... | grep -q` mid-pipe: under
    # `set -o pipefail` grep -q's early exit SIGPIPEs tee+ssh, which both
    # false-fails the assertion AND kills the remote install before it writes the
    # secrets file and prints "done".
    ${SSH} "${RUN}" 2>&1 | tee "${WORK_DIR}/install.log" || true
    if grep -q 'vault unsealed' "${WORK_DIR}/install.log"; then
        echo ">> PASS: native install + vault unseal on ${OS}"
    else
        echo ">> FAIL: native install did not confirm vault unseal on ${OS}" >&2
        echo ">>       see ${WORK_DIR}/install.log" >&2
        exit 1
    fi
    # Independent confirmation the API is live inside the VM. The vault is https
    # only (uvicorn terminates TLS), so this needs the CA the installer minted --
    # read its path back out of the install log rather than re-deriving the
    # per-OS config dir here. In system mode that file is root-only.
    RH_CA=$(sed -n 's/^>>[[:space:]]*export RH_CA_FILE=//p' "${WORK_DIR}/install.log" | tail -1)
    if [ -n "${RH_CA}" ]; then
        HEALTH_CURL="curl -s -m5 --cacert '${RH_CA}' https://127.0.0.1:8200/health"
        if [ "$RH_MODE_ARG" = system ] && [ "$SSH_USER" != root ]; then
            HEALTH_CURL="sudo ${HEALTH_CURL}"
        fi
        echo ">> /health:"; ${SSH} "${HEALTH_CURL}" || true; echo

        # Record the TLS posture ON THE WIRE, not from the installer's own
        # decision line. Which group nginx was configured with and which one a
        # client actually negotiates are different claims, and the VM is
        # destroyed seconds from now -- capture it while the vault is live.
        # Every lane then self-documents its HTTP version and key exchange.
        echo ">> TLS posture:"
        # shellcheck disable=SC2016
        # No blanket sudo: the BSD goldens log in AS root and may not even have
        # sudo installed, in which case every probe silently returns empty and
        # is reported as "no h2 / classical" -- a false negative indistinguishable
        # from a real result.
        PRIV=""
        if [ "$SSH_USER" != root ]; then PRIV="sudo"; fi
        ${SSH} "CA='${RH_CA}'; PORT=8200; PRIV='${PRIV}'
            SSL=\$(command -v openssl 2>/dev/null || echo /usr/local/bin/openssl)
            [ -x \"\$SSL\" ] || { echo '   (no openssl on guest)'; exit 0; }
            ALPN=\$(echo | \$PRIV \"\$SSL\" s_client -connect 127.0.0.1:\$PORT -alpn h2 \\
                -CAfile \"\$CA\" 2>/dev/null | sed -n 's/^ALPN protocol: //p')
            GRP=\$(echo | \$PRIV \"\$SSL\" s_client -connect 127.0.0.1:\$PORT -tls1_3 \\
                -groups X25519MLKEM768 -CAfile \"\$CA\" 2>/dev/null \\
                | sed -n 's/^Negotiated TLS1.3 group: //p')
            printf '   ALPN            : %s\n' \"\${ALPN:-none (HTTP/1.1)}\"
            printf '   TLS1.3 group    : %s\n' \"\${GRP:-not X25519MLKEM768 (classical)}\"
        " || true
    else
        echo ">> /health: skipped (installer printed no RH_CA_FILE path)"
    fi
    echo ">> done - VM logs in ${WORK_DIR}/qemu.log, install log ${WORK_DIR}/install.log"
    exit 0
fi

INSTALL_SCRIPT="tools/install-${OS}.sh"

case "$OS" in
    openbsd|netbsd)
        # Already root.
        ${SSH} "cd rhorizon && sh ${INSTALL_SCRIPT}"
        ;;
    *)
        # All others SSH as a non-root user with NOPASSWD sudo.
        ${SSH} "cd rhorizon && sudo sh ${INSTALL_SCRIPT}"
        ;;
esac

echo ">> running pytest"
${SSH} "cd rhorizon && . .venv/bin/activate && \
    ulimit -l unlimited 2>/dev/null || true; \
    export RHORIZON_RUNTIME_DIR=/tmp/rhorizon-vm-runtime && \
    mkdir -p \$RHORIZON_RUNTIME_DIR && chmod 0700 \$RHORIZON_RUNTIME_DIR && \
    export RHORIZON_DATABASE_URL=postgresql+asyncpg://rhorizon_test:rhorizon_test@127.0.0.1:5432/rhorizon_test && \
    export RHORIZON_DATABASE_SSL=false && \
    python -m pytest tests/ --no-header --no-cov -q"

echo ">> done - VM logs in ${WORK_DIR}/qemu.log"
