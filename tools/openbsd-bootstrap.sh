#!/bin/sh
# SPDX-License-Identifier: ISC
# Copyright (c) 2020 Stefan Kreutz <mail@skreutz.com> (original recipe)
# Copyright (c) 2024 0xJJ (LD_PRELOAD port-80 shim)
# Copyright (c) 2026 shdw <horizon@resurgamus.com> (rhorizon adaptation)
#
# One-shot OpenBSD/amd64 install into a cached "golden" qcow2 image, used
# as the base disk for tools/test-vm-bsd.sh openbsd. Skips the install ISO
# entirely - we netboot bsd.rd over qemu's built-in TFTP server, drive
# autoinstall(8) by serving install.conf over HTTP from the host (with
# the LD_PRELOAD port-80 shim to avoid root), and end up with a fully
# unattended OpenBSD VM in roughly 30 minutes.
#
# Usage:
#   tools/openbsd-bootstrap.sh
#
# Outputs:
#   ~/.cache/rhorizon-vms/openbsd-${OBSD_VERSION}-golden.qcow2
#   ~/.cache/rhorizon-vms/openbsd-${OBSD_VERSION}-id_ed25519{,.pub}
#
# Requires:
#   curl, qemu-img, qemu-system-x86_64, rsync, signify, ssh, gcc, python3
#
# Default OBSD_VERSION is 7.8 (matching tools/test-vm-bsd.sh).
#
# This is fast on re-runs: if the golden image already exists, the
# script exits 0 immediately. Delete it manually to rebuild.

set -o errexit
set -o nounset

OSREV="${OBSD_VERSION-7.8}"
OSrev="$(printf '%s' "$OSREV" | tr -d .)"

CACHE_DIR="${HOME}/.cache/rhorizon-vms"
GOLDEN="${CACHE_DIR}/openbsd-${OSREV}-golden.qcow2"
SSH_KEY="${CACHE_DIR}/openbsd-${OSREV}-id_ed25519"

if [ -e "${GOLDEN}" ]; then
    printf "%s already exists - golden image up to date, nothing to do.\n" "${GOLDEN}"
    printf "Delete it manually if you want to rebuild from scratch.\n"
    exit 0
fi

# OpenBSD mirror. We use cdn.openbsd.org for everything (~700 MB) since
# mirror sync lag between the trusted public key + SHA256.sig and the
# bulk .tgz files caused signify(1) FAILs on the rsync mirror leaseweb.
# cdn.openbsd.org is the same one pkg_add uses by default - backed by
# Cloudflare, fast, single source of truth, signify still verifies the
# whole chain so an MITM cannot substitute corrupt bytes.
HTTPS_MIRROR="${HTTPS_MIRROR-https://cdn.openbsd.org/pub/OpenBSD/}"

DISK_SIZE="${DISK_SIZE-30G}"
CPU_COUNT="${CPU_COUNT-8}"
MEMORY_SIZE="${MEMORY_SIZE-8G}"
CC="${CC-gcc}"

for cmd in curl qemu-img qemu-system-x86_64 signify ssh-keygen "${CC}" python3 mktemp awk; do
    if ! command -v "${cmd}" >/dev/null; then
        printf "command not found: %s\n" "${cmd}" >&2
        printf "Install via: ansible-playbook ansible/qemu.yml -i 'localhost ansible_connection=local,' -l localhost --ask-become-pass\n" >&2
        exit 1
    fi
done

mkdir -p "${CACHE_DIR}"

# SSH key dedicated to the OpenBSD VM (separate from the operator's keys).
if [ ! -e "${SSH_KEY}" ]; then
    ssh-keygen -t ed25519 -N '' -f "${SSH_KEY}" -C "rhorizon-openbsd-vm" -q
    printf "Generated SSH keypair at %s\n" "${SSH_KEY}"
fi

# Build the bootstrap working tree under a session tmpdir so re-runs
# don't leave stale state in the cache.
WORK_DIR="$(mktemp -d -t rhorizon-openbsd-bootstrap.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT
cd "${WORK_DIR}"

printf ">> fetching kernel + sets from %s (~700 MB, all over HTTPS)\n" "${HTTPS_MIRROR}"
mkdir -p "mirror/pub/OpenBSD/${OSREV}" tmp
curl --silent --fail \
    --output "mirror/pub/OpenBSD/${OSREV}/openbsd-${OSrev}-base.pub" \
    "${HTTPS_MIRROR}${OSREV}/openbsd-${OSrev}-base.pub"
# Note : include game + X sets even though we don't need them - the
# installer pre-selects all sets in the catalogue and aborts on 404 if
# any are missing. install.conf can de-select them with "-x*" but the
# response only matches the first prompt iteration, not the auto-skip
# logic. Cheaper to just fetch and ignore them post-install.
for f in SHA256.sig BUILDINFO bsd bsd.mp bsd.rd pxeboot \
         "base${OSrev}.tgz" "comp${OSrev}.tgz" "man${OSrev}.tgz" \
         "game${OSrev}.tgz" \
         "xbase${OSrev}.tgz" "xfont${OSrev}.tgz" \
         "xserv${OSrev}.tgz" "xshare${OSrev}.tgz"
do
    if [ ! -e "tmp/${f}" ]; then
        curl --silent --fail --show-error \
            --output "tmp/${f}" \
            "${HTTPS_MIRROR}${OSREV}/amd64/${f}"
    fi
done

printf ">> verifying signatures with signify(1)\n"
# Note : do NOT prefix the .tgz glob with ./ - signify(1) string-matches
# the argument against the entry name in SHA256.sig (e.g. "base78.tgz"),
# so "./base78.tgz" reports FAIL even when the bytes are correct.
( cd tmp && signify -C -q \
    -p "../mirror/pub/OpenBSD/${OSREV}/openbsd-${OSrev}-base.pub" \
    -x SHA256.sig \
    -- bsd bsd.* pxeboot *"${OSrev}".tgz )
mv tmp "mirror/pub/OpenBSD/${OSREV}/amd64"

# Site-specific tarball with first-boot config: doas for wheel,
# CDN mirror for pkg_add. install-openbsd.sh handles the rest later.
mkdir site
cat >site/install.site <<'EOF'
#!/bin/ksh
set -o errexit
echo "https://cdn.openbsd.org/pub/OpenBSD" > /etc/installurl
echo "permit nopass keepenv :wheel" > /etc/doas.conf
EOF
chmod +x site/install.site
( cd site && tar -czf "../mirror/pub/OpenBSD/${OSREV}/amd64/site${OSrev}.tgz" . )
( cd "mirror/pub/OpenBSD/${OSREV}/amd64" && ls -l > index.txt )

# autoinstall(8) response file. Forces console=com0 in the installed
# system (so subsequent boots stay on serial without our intervention)
# and enables root SSH key-only login - test-vm-bsd.sh ssh's as root to
# skip doas wiring during test runs. We also create a `puffy` user so
# operators can ssh in interactively for debugging via the same key.
SSH_PUBKEY="$(cat "${SSH_KEY}.pub")"
cat >mirror/install.conf <<EOF
Change the default console to com0 = yes
Which speed should com0 use = 115200
System hostname = rhorizon-obsd
Password for root = *************
Public ssh key for root = ${SSH_PUBKEY}
Allow root ssh login = prohibit-password
Setup a user = puffy
Password for user = *************
Public ssh key for user = ${SSH_PUBKEY}
What timezone are you in = UTC
Which disk is the root disk = sd0
Use (W)hole disk MBR, whole disk (G)PT or (E)dit = whole
URL to autopartitioning template for disklabel = http://10.0.2.2/disklabel
Location of sets = http
HTTP Server = 10.0.2.2
Unable to connect using https. Use http instead = yes
Set name(s) = site${OSrev}.tgz
Checksum test for site${OSrev}.tgz failed. Continue anyway = yes
Unverified sets: site${OSrev}.tgz. Continue without verification = yes
EOF

# Custom disklabel: OpenBSD's auto layout splits 30 GB across nine
# partitions assuming a build host (/usr/src, /usr/obj, /home...). For a
# headless test VM that just runs python+cargo+pytest under /root we
# want most of the disk on / so pip caches, venvs and cargo registries
# fit. We drop /usr/src, /usr/obj, /usr/X11R6 entirely.
cat >mirror/disklabel <<'EOF'
/            6G
swap         1G
/tmp         1G
/var         2G
/usr         4G
/usr/local   12G
/home        1G-*
EOF

# TFTP root: pxeboot under the auto_install name, plus a boot.conf
# that switches the console to com0 *before* the kernel is loaded -
# this is the trick that makes the OpenBSD kernel itself emit on serial
# under qemu, where neither -vga none nor `set tty com0` typed at the
# boot> prompt was sufficient.
mkdir -p tftp/etc
ln -s "../mirror/pub/OpenBSD/${OSREV}/amd64/pxeboot" tftp/auto_install
ln -s "../mirror/pub/OpenBSD/${OSREV}/amd64/bsd.rd" tftp/bsd.rd
cat >tftp/etc/boot.conf <<'EOF'
stty com0 115200
set tty com0
boot tftp:/bsd.rd
EOF

# Build the golden disk image fresh.
qemu-img create -q -f qcow2 "${WORK_DIR}/disk.qcow2" -o nocow=on "${DISK_SIZE}"

# Serve mirror over HTTP on a random unprivileged port. autoinstall
# expects port 80 on the host - the LD_PRELOAD shim below rewrites
# qemu's connect() to port 80 to point at this port instead. (Without
# the shim we'd need root to bind 80, or a setcap dance; this avoids
# both.)
TMPDIR="$(mktemp -d -t rhorizon-openbsd-runtime.XXXXXX)"
PYTHONUNBUFFERED=1 python3 -m http.server \
    --directory mirror \
    --bind 127.0.0.1 0 \
    >  "${TMPDIR}/httpd.port" \
    2> "${TMPDIR}/httpd.log" &
HTTPD_PID=$!
sleep 1
SERVER_PORT="$(awk '{ print $6 }' "${TMPDIR}/httpd.port")"
SERVER_PORT="$((SERVER_PORT))"
printf ">> mirror http server pid=%s port=%s\n" "${HTTPD_PID}" "${SERVER_PORT}"

# Compose the LD_PRELOAD shim. dlsym RTLD_NEXT for the original connect(),
# rewrite AF_INET 127.0.0.1:80 to 127.0.0.1:${SERVER_PORT}, leave anything
# else alone.
PATCH="${TMPDIR}/qemu_patch.so"
"${CC}" -Wall -fPIC -shared -ldl -o "${PATCH}" -xc - <<EOF
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int (*original_connect)(int, const struct sockaddr *, socklen_t) = NULL;

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!original_connect) {
        original_connect = dlsym(RTLD_NEXT, "connect");
    }
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        if (ntohs(addr_in->sin_port) == 80 &&
            addr_in->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            fprintf(stderr,
                    "[ld_preload] redirecting host port 80 -> ${SERVER_PORT}\n");
            addr_in->sin_port = htons(${SERVER_PORT});
        }
    }
    return original_connect(sockfd, addr, addrlen);
}
EOF

# Cleanup chain: kill httpd subprocess + drop ld_preload shim dir.
trap '
    kill "${HTTPD_PID}" 2>/dev/null || true
    rm -rf "${TMPDIR}"
    rm -rf "${WORK_DIR}"
' EXIT

# Net-boot install. -nographic routes serial to stdio; the kernel will
# stream installer prompts to it. The whole run takes ~25-35 min on a
# decent host (downloads ~250 MB of sets again over HTTP, sigh, but
# that's autoinstall's design).
printf ">> launching qemu (auto-install, ~25-35 min)\n"
LD_PRELOAD="${PATCH}" qemu-system-x86_64 \
    -enable-kvm \
    -no-reboot \
    -smp "cpus=${CPU_COUNT}" \
    -m "${MEMORY_SIZE}" \
    -drive "file=${WORK_DIR}/disk.qcow2,media=disk,if=virtio" \
    -device virtio-net-pci,netdev=n1 \
    -netdev "user,id=n1,hostname=rhorizon-obsd,tftp=tftp,bootfile=auto_install,hostfwd=tcp::${SSH_PORT:-2222}-:22" \
    -nographic

# After autoinstall halts, qemu exits. Promote the disk to the cache.
mv "${WORK_DIR}/disk.qcow2" "${GOLDEN}"
printf ">> golden image ready: %s\n" "${GOLDEN}"
printf "   tools/test-vm-bsd.sh openbsd will copy this on each test run.\n"
