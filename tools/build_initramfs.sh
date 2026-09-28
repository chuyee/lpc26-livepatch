#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# build_initramfs.sh - Build the QEMU test initramfs for the standalone
# LPC 2026 Livepatch & Ftrace Coexistence Suite (lpc26-livepatch).
#
# Usage:
#   ./tools/build_initramfs.sh                        # build everything, default paths
#   ./tools/build_initramfs.sh -k /path/to/linux      # specify kernel build tree
#   ./tools/build_initramfs.sh -o /tmp/my.cpio.gz     # custom output
#   ./tools/build_initramfs.sh --no-vim               # skip the 17M vim runtime
#   ./tools/build_initramfs.sh --no-build             # use already-built .ko files
#   ./tools/build_initramfs.sh --run                  # build, then boot QEMU

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_KDIR="$(cd "${REPO_DIR}/../linux" 2>/dev/null && pwd || echo "/lib/modules/$(uname -r)/build")"
KDIR="${KDIR:-${DEFAULT_KDIR}}"

OUT="/tmp/initramfs-lpc26-livepatch.cpio.gz"
STAGE="/tmp/test_initramfs_livepatch"
WITH_VIM=1
DO_BUILD=1
DO_RUN=0
BANNER=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)   OUT="$2"; shift 2 ;;
        -s|--stage)    STAGE="$2"; shift 2 ;;
        -k|--kdir)     KDIR="$2"; shift 2 ;;
        --no-vim)      WITH_VIM=0; shift ;;
        --no-build)    DO_BUILD=0; shift ;;
        --no-banner)   BANNER=0; shift ;;
        --run)         DO_RUN=1; shift ;;
        -h|--help)     sed -n '3,14p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)             echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

say() { printf '\n\033[1;32m[*] %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31m[!] %s\033[0m\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------------
# 0. Host prerequisites
# ------------------------------------------------------------------
say "Checking host prerequisites"
for t in cpio gzip ldd; do
    command -v "$t" >/dev/null || die "missing required tool: $t"
done
[[ -x /bin/busybox ]] || die "/bin/busybox not found. Install with: sudo apt-get install busybox-static"
file /bin/busybox | grep -q "statically linked" || \
    die "/bin/busybox is dynamically linked; install the busybox-static package"
[[ -f "${KDIR}/arch/x86/boot/bzImage" ]] || \
    echo "    warning: ${KDIR}/arch/x86/boot/bzImage not found (build the kernel before --run)"

# ------------------------------------------------------------------
# 1. Build the coexistence modules & BPF binary
# ------------------------------------------------------------------
if [[ "${DO_BUILD}" == "1" ]]; then
    say "Building lpc26-livepatch modules & BPF tools against KDIR=${KDIR}"
    make -C "${REPO_DIR}" KDIR="${KDIR}" all
fi

# ------------------------------------------------------------------
# 2. Rootfs skeleton
# ------------------------------------------------------------------
say "Creating rootfs skeleton at ${STAGE}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}"/{bin,dev,etc/udhcpc,lib,lib64,mnt,proc,root,sbin,sys,tmp,var/run,usr/bin,usr/lib,usr/share}
chmod 1777 "${STAGE}/tmp"

# ------------------------------------------------------------------
# 3. busybox + applet symlinks
# ------------------------------------------------------------------
say "Installing busybox and applet symlinks"
cp /bin/busybox "${STAGE}/bin/busybox"
for applet in $(/bin/busybox --list); do
    [[ "${applet}" == "busybox" ]] && continue
    ln -sf busybox "${STAGE}/bin/${applet}"
done
echo "    $(/bin/busybox --list | wc -l) applets"

# ------------------------------------------------------------------
# 4. Dynamic host binaries + their shared libraries
# ------------------------------------------------------------------
VIM_BIN=""
if [[ "${WITH_VIM}" == "1" ]]; then
    for cand in /usr/bin/vim.basic /usr/bin/vim.nox /usr/bin/vim.tiny /usr/bin/vim; do
        [[ -x "${cand}" ]] || continue
        VIM_BIN="${cand}"
        break
    done
    [[ -n "${VIM_BIN}" ]] || echo "    warning: no vim binary found, continuing without it"
fi

say "Installing host binaries and resolving shared libraries"
copy_lib() {
    local lib="$1" dest
    dest="${STAGE}${lib}"
    [[ -e "${dest}" ]] && return 0
    mkdir -p "$(dirname "${dest}")"
    cp -L "${lib}" "${dest}"
}

BINSPECS=(/usr/bin/bash /usr/bin/env)
if [[ -n "${VIM_BIN}" ]]; then
    BINSPECS+=("${VIM_BIN}:vim")
fi

for spec in "${BINSPECS[@]}"; do
    bin="${spec%%:*}"
    name="${spec#*:}"
    if [[ "${name}" == "${bin}" ]]; then
        name="$(basename "${bin}")"
    fi
    [[ -x "${bin}" ]] || { echo "    skipping missing ${bin}"; continue; }
    cp -L "${bin}" "${STAGE}/usr/bin/${name}"
    echo "    ${bin} -> /usr/bin/${name}"
    while read -r lib; do
        if [[ -n "${lib}" ]]; then
            copy_lib "${lib}"
        fi
    done < <(ldd "${bin}" 2>/dev/null | awk '
        /=>/   { if ($3 ~ /^\//) print $3; next }
        /^\s*\// { print $1 }
    ')
done

if [[ -x "${STAGE}/usr/bin/vim" ]]; then
    ln -sf vim "${STAGE}/usr/bin/vi"
fi

if [[ -e /lib64/ld-linux-x86-64.so.2 ]]; then
    cp -L /lib64/ld-linux-x86-64.so.2 "${STAGE}/lib64/"
fi

# ------------------------------------------------------------------
# 5. terminfo + vim runtime
# ------------------------------------------------------------------
say "Installing terminfo"
mkdir -p "${STAGE}/usr/share/terminfo"
for t in x/xterm-256color x/xterm l/linux; do
    src="/usr/share/terminfo/${t}"
    [[ -f "${src}" ]] || continue
    mkdir -p "${STAGE}/usr/share/terminfo/$(dirname "${t}")"
    cp "${src}" "${STAGE}/usr/share/terminfo/${t}"
done

if [[ "${WITH_VIM}" == "1" && -n "${VIM_BIN}" ]]; then
    VIMRT="$(ls -d /usr/share/vim/vim* 2>/dev/null | head -1 || true)"
    if [[ -n "${VIMRT}" ]]; then
        say "Installing vim runtime from ${VIMRT}"
        mkdir -p "${STAGE}/usr/share/vim"
        tar -C "$(dirname "${VIMRT}")" -cf - \
            --exclude="$(basename "${VIMRT}")/doc" \
            --exclude="$(basename "${VIMRT}")/lang" \
            --exclude="$(basename "${VIMRT}")/spell" \
            --exclude="$(basename "${VIMRT}")/tutor" \
            --exclude="$(basename "${VIMRT}")/print" \
            --exclude="$(basename "${VIMRT}")/macros" \
            "$(basename "${VIMRT}")" \
            | tar -C "${STAGE}/usr/share/vim" -xf -
    fi
fi

# ------------------------------------------------------------------
# 6. Configuration files & sudo shim
# ------------------------------------------------------------------
say "Writing configuration files"
cat > "${STAGE}/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
EOF

cat > "${STAGE}/etc/group" <<'EOF'
root:x:0:
nogroup:x:65534:
EOF

echo "lpc26" > "${STAGE}/etc/hostname"
cat > "${STAGE}/etc/hosts" <<'EOF'
127.0.0.1	localhost lpc26
::1		localhost ip6-localhost ip6-loopback
EOF

cat > "${STAGE}/etc/profile" <<'EOF'
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export TERM=xterm-256color
resize >/dev/null 2>&1 || true
EOF

cat > "${STAGE}/root/.bashrc" <<'EOF'
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export TERM=xterm-256color
export PS1='\[\e[1;32m\]lpc26\[\e[0m\]:\w# '
resize >/dev/null 2>&1 || true
EOF
cp "${STAGE}/root/.bashrc" "${STAGE}/root/.profile"

cat > "${STAGE}/etc/udhcpc/default.script" <<'EOF'
#!/bin/sh
case "$1" in
  deconfig)
    ip addr flush dev "$interface"
    ;;
  renew|bound)
    ip addr add "$ip/${mask:-24}" dev "$interface" 2>/dev/null || ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}"
    if [ -n "$router" ]; then
      ip route add default via "${router%% *}" dev "$interface" 2>/dev/null || route add default gw "${router%% *}"
    fi
    if [ -n "$dns" ]; then
      echo -n > /etc/resolv.conf
      for d in $dns; do
        echo "nameserver $d" >> /etc/resolv.conf
      done
    fi
    ;;
esac
EOF
chmod +x "${STAGE}/etc/udhcpc/default.script"

cat > "${STAGE}/usr/bin/sudo" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do
    case "$1" in
        -n|-E|-H|-P|-S|-b|-i|-s) shift ;;
        -u|-g|-p|-C|-U|-c)       shift 2 ;;
        --)                      shift; break ;;
        -*)                      shift ;;
        *)                       break ;;
    esac
done
[ $# -eq 0 ] && exec /bin/sh
exec "$@"
EOF
chmod +x "${STAGE}/usr/bin/sudo"

if [[ "${WITH_VIM}" == "1" ]]; then
    mkdir -p "${STAGE}/etc/vim"
    cat > "${STAGE}/etc/vim/vimrc" <<'EOF'
runtime! debian.vim
syntax on
set backspace=indent,eol,start
set ruler
set number
EOF
fi

# ------------------------------------------------------------------
# 7. /init
# ------------------------------------------------------------------
cat > "${STAGE}/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export TERM=xterm-256color

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug 2>/dev/null
mount -t tracefs none /sys/kernel/tracing 2>/dev/null

resize >/dev/null 2>&1 || true

ip link set lo up 2>/dev/null || ifconfig lo up
if [ -d /sys/class/net/eth0 ]; then
  ip link set eth0 up 2>/dev/null || ifconfig eth0 up
  echo "[*] Configuring eth0 via DHCP..."
  udhcpc -i eth0 -n -q -t 3 -s /etc/udhcpc/default.script >/dev/null 2>&1
fi

echo "=========================================================="
echo "    WELCOME TO LPC26-LIVEPATCH KERNEL GUEST VM (KVM)      "
echo "=========================================================="
echo "Kernel: $(uname -a)"
echo "Cmdline: $(cat /proc/cmdline)"
echo ""
echo "Coexistence Suite (/lpc26-livepatch):"
echo "  /lpc26-livepatch/run_coexistence_experiment.sh  (28 klp Contender & Incumbent scenarios)"
echo "=========================================================="
echo ""

resize >/dev/null 2>&1 || true

LPC26_AUTORUN=""
for lpc26_arg in $(cat /proc/cmdline); do
  case "${lpc26_arg}" in
  lpc26.autorun=*) LPC26_AUTORUN="${lpc26_arg#lpc26.autorun=}" ;;
  esac
done

if [ -n "${LPC26_AUTORUN}" ]; then
  echo ""
  echo "[*] autorun: ${LPC26_AUTORUN}"
  echo ""
  if [ -x "${LPC26_AUTORUN}" ]; then
    "${LPC26_AUTORUN}"
  else
    sh "${LPC26_AUTORUN}"
  fi
  lpc26_rc=$?
  echo ""
  echo "LPC26_AUTORUN_EXIT:${lpc26_rc}"
  sync
  poweroff -f
  sleep 30
fi

cd /lpc26-livepatch 2>/dev/null || true
exec /bin/sh
EOF
chmod +x "${STAGE}/init"

# ------------------------------------------------------------------
# 8. Install lpc26-livepatch payload
# ------------------------------------------------------------------
say "Installing lpc26-livepatch payload into /lpc26-livepatch"
DEST="${STAGE}/lpc26-livepatch"
mkdir -p "${DEST}"

( cd "${REPO_DIR}" && tar -cf - \
    --exclude='.git' --exclude='*.o' --exclude='*.mod' --exclude='*.mod.c' \
    --exclude='.*.cmd' --exclude='Module.symvers' --exclude='modules.order' \
    --exclude='vmlinux.h' --exclude='.gitignore' \
    . ) | ( cd "${DEST}" && tar -xf - )

if [[ -f "${REPO_DIR}/bpf_coexist_users.bpf.o" ]]; then
    cp "${REPO_DIR}/bpf_coexist_users.bpf.o" "${DEST}/bpf_coexist_users.bpf.o"
    echo "    bpf obj: bpf_coexist_users.bpf.o"
fi

chmod +x "${DEST}"/*.sh "${DEST}"/tools/*.sh 2>/dev/null || true
mkdir -p "${STAGE}/samples/lpc26_ftrace"
ln -sf /lpc26-livepatch "${STAGE}/samples/lpc26_ftrace/coexistence_demo"

for ko in "${DEST}"/*.ko; do
    [[ -f "${ko}" ]] && echo "    module: $(basename "${ko}")"
done

if [[ -x "${DEST}/bpf_coexist_users" ]]; then
    echo "    linking: bpf_coexist_users"
    while read -r lib; do
        if [[ -n "${lib}" ]]; then
            copy_lib "${lib}"
        fi
    done < <(ldd "${DEST}/bpf_coexist_users" 2>/dev/null | awk '
        /=>/   { if ($3 ~ /^\//) print $3; next }
        /^\s*\// { print $1 }
    ')
fi

if [[ -f "${KDIR}/.config" ]]; then
    mkdir -p "${STAGE}/boot"
    cp "${KDIR}/.config" "${STAGE}/boot/config"
    echo "    config: /boot/config"
fi

# ------------------------------------------------------------------
# 9. Pack
# ------------------------------------------------------------------
say "Packing ${OUT}"
( cd "${STAGE}" && find . -print0 |
    cpio --null -o --format=newc -R 0:0 --quiet ) | gzip -9 > "${OUT}"

printf '\n\033[1;32m[+] Built %s (%s)\033[0m\n' "${OUT}" "$(du -h "${OUT}" | cut -f1)"

if [[ "${DO_RUN}" == "1" ]]; then
    say "Booting QEMU"
    sg kvm -c "qemu-system-x86_64 -enable-kvm -m 2048 \
        -kernel ${KDIR}/arch/x86/boot/bzImage \
        -initrd ${OUT} \
        -append 'console=ttyS0 earlyprintk=serial' \
        -nic user,model=virtio-net-pci \
        -nographic"
fi
