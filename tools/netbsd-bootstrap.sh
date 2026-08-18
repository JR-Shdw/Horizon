#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# One-shot NetBSD/amd64 install into a cached "golden" qcow2 image, used as
# the base disk for `tools/test-vm.sh netbsd` (exactly like OpenBSD's golden
# built by openbsd-bootstrap.sh). NetBSD has no cloud-init image, so we drive
# the installer with anita(1) (the NetBSD project's own automated-install tool,
# fetched checksum-pinned from gson.org), then provision sshd + dhcpcd + a
# dedicated ssh key + rsync over the serial console, and convert to qcow2.
#
# Usage:
#   tools/netbsd-bootstrap.sh
#
# Outputs:
#   ~/.cache/rhorizon-vms/netbsd-${NBSD_VERSION}-golden.qcow2
#   ~/.cache/rhorizon-vms/netbsd-${NBSD_VERSION}-id_ed25519{,.pub}
#
# Requires: qemu-system-x86_64 (+ KVM), qemu-img, python3 (venv), ssh-keygen.
# Idempotent: exits 0 immediately if the golden already exists.

set -eu

NBSD_VERSION="${NBSD_VERSION:-10.1}"
ARCH=amd64
CACHE_DIR="${HOME}/.cache/rhorizon-vms"
GOLDEN="${CACHE_DIR}/netbsd-${NBSD_VERSION}-golden.qcow2"
SSH_KEY="${CACHE_DIR}/netbsd-${NBSD_VERSION}-id_ed25519"
# anita writes a DENSE (non-sparse) ~16G wd0.img into the workdir, so it must
# sit on a roomy filesystem -- a small TMPDIR (e.g. a tmpfs) fills instantly.
mkdir -p "${CACHE_DIR}"
WORK_DIR="$(mktemp -d "${CACHE_DIR}/bootstrap.XXXXXX")"
ANITA_VERSION="2.18"
ANITA_SHA256="fa5ac3a8b3e30a3a35df9254bbee213b28210a396544592c3e604a1e53a294ce"
ANITA_URL="https://www.gson.org/netbsd/anita/download/anita-${ANITA_VERSION}.tar.gz"
NBSD_DIST="https://cdn.netbsd.org/pub/NetBSD/NetBSD-${NBSD_VERSION}/${ARCH}/"

mkdir -p "${CACHE_DIR}"
trap 'rm -rf "${WORK_DIR}"' EXIT

if [ -e "${GOLDEN}" ]; then
    printf '%s already exists - golden up to date, nothing to do.\n' "${GOLDEN}"
    printf 'Delete it (and the id_ed25519 pair) to rebuild from scratch.\n'
    exit 0
fi

echo ">> generating a dedicated VM ssh key"
[ -f "${SSH_KEY}" ] || ssh-keygen -t ed25519 -N '' -C "netbsd-golden" -f "${SSH_KEY}" >/dev/null
PUBKEY="$(cat "${SSH_KEY}.pub")"

echo ">> installing anita ${ANITA_VERSION} (checksum-pinned) into a venv"
ANITA_TGZ="${CACHE_DIR}/anita-${ANITA_VERSION}.tar.gz"
if [ ! -f "${ANITA_TGZ}" ]; then
    curl -fsSL -o "${ANITA_TGZ}" "${ANITA_URL}"
fi
echo "${ANITA_SHA256}  ${ANITA_TGZ}" | sha256sum -c -
ANITA_VENV="${CACHE_DIR}/anita-venv"
[ -d "${ANITA_VENV}" ] || python3 -m venv "${ANITA_VENV}"
"${ANITA_VENV}/bin/pip" install --quiet pexpect "${ANITA_TGZ}"
ANITA="${ANITA_VENV}/bin/anita"

echo ">> installing NetBSD ${NBSD_VERSION}/${ARCH} via anita (KVM, ~10-20 min)"
"${ANITA}" --workdir "${WORK_DIR}" --memory-size 3G --disk-size 16G \
    --vmm qemu --vmm-args="-accel kvm" \
    install "${NBSD_DIST}"

echo ">> provisioning the image (sshd + dhcpcd + root login + key + rsync)"
# The provisioning runs over the serial console; --persist keeps the changes.
# rsync is needed because test-vm.sh pushes the checkout with it.
PROV="set -e
echo sshd=YES >> /etc/rc.conf
echo dhcpcd=YES >> /etc/rc.conf
echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
mkdir -p /root/.ssh; chmod 700 /root/.ssh
echo '${PUBKEY}' > /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
export PKG_PATH=http://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/${ARCH}/${NBSD_VERSION}/All/
/usr/sbin/pkg_add rsync-3.4.3 || true
sync; echo PROVISION_DONE"
"${ANITA}" --workdir "${WORK_DIR}" --persist --no-install \
    --vmm-args="-accel kvm" --run "${PROV}" \
    boot "${NBSD_DIST}"

echo ">> converting to golden qcow2"
qemu-img convert -O qcow2 "${WORK_DIR}/wd0.img" "${GOLDEN}"

echo ">> NetBSD golden ready : ${GOLDEN}"
echo "   key : ${SSH_KEY}"
echo "   run : SSH_PORT=2241 tools/test-vm.sh netbsd"
