#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# vm_start.sh - Boot the LPC 2026 livepatch coexistence QEMU VM, rebuilding
# the initramfs and modules first if missing or out of date.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_KDIR="$(cd "${REPO_DIR}/../linux" 2>/dev/null && pwd || echo "/lib/modules/$(uname -r)/build")"
KDIR="${KDIR:-${DEFAULT_KDIR}}"
BUILDER="${REPO_DIR}/tools/build_initramfs.sh"
BZIMAGE="${KDIR}/arch/x86/boot/bzImage"
INITRAMFS="${INITRAMFS:-/tmp/initramfs-lpc26-livepatch.cpio.gz}"
VM_MEM="${VM_MEM:-2048}"
VM_SMP="${VM_SMP:-1}"

usage() {
    cat <<'USAGE'
Usage:
  ./vm_start.sh                                      # rebuild if stale, then boot interactively
  ./vm_start.sh -f                                   # always rebuild
  ./vm_start.sh -n                                   # never rebuild, boot whatever is there
  ./vm_start.sh -k /path/to/linux                    # specify kernel build directory
  ./vm_start.sh -a ./run_coexistence_experiment.sh   # run <script> in the guest, then power off
  ./vm_start.sh -- -s -S                             # extra args after -- go to qemu

Env overrides: KDIR (default ../linux), VM_MEM (default 2048), VM_SMP (default 1),
               INITRAMFS (default /tmp/initramfs-lpc26-livepatch.cpio.gz)
USAGE
}

FORCE=0
NOBUILD=0
AUTORUN=""
QEMU_EXTRA=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--force)    FORCE=1; shift ;;
        -n|--no-build) NOBUILD=1; shift ;;
        -k|--kdir)     KDIR="${2:-}"; BZIMAGE="${KDIR}/arch/x86/boot/bzImage"; shift 2 ;;
        -a|--autorun)  AUTORUN="${2:-}"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        --)            shift; QEMU_EXTRA=("$@"); break ;;
        *)             echo "Unknown option: $1 (use -- to pass args to qemu)" >&2; exit 1 ;;
    esac
done

say() { printf '\033[1;32m[*] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; exit 1; }

guest_path_for() {
    local p="$1" abs

    if [[ -f "${p}" ]]; then
        abs="$(cd "$(dirname "${p}")" && pwd)/$(basename "${p}")"
        if [[ "${abs}" == "${REPO_DIR}/"* ]]; then
            [[ -x "${abs}" ]] || die "not executable: ${abs}"
            echo "/lpc26-livepatch/${abs#"${REPO_DIR}/"}"
            return
        fi
    fi

    if [[ -f "${REPO_DIR}/${p}" ]]; then
        [[ -x "${REPO_DIR}/${p}" ]] || die "not executable: ${REPO_DIR}/${p}"
        echo "/lpc26-livepatch/${p#./}"
        return
    fi

    [[ "${p}" == /* ]] || die "no such script: ${p}"
    echo "${p}"
}

[[ -f "${BZIMAGE}" ]] || die "no kernel at ${BZIMAGE} - set KDIR=/path/to/linux or build bzImage first"

needs_rebuild() {
    [[ "${FORCE}" == "1" ]] && { echo "forced with -f"; return 0; }
    [[ -f "${INITRAMFS}" ]] || { echo "${INITRAMFS} does not exist"; return 0; }

    local newer
    if [[ "${BZIMAGE}" -nt "${INITRAMFS}" ]]; then
        echo "kernel is newer than the image (modules must be rebuilt against it)"
        return 0
    fi

    newer="$(find "${REPO_DIR}" -path "${REPO_DIR}/.git" -prune -o -type f -newer "${INITRAMFS}" -print -quit 2>/dev/null)"
    if [[ -n "${newer}" ]]; then
        echo "${newer#"${REPO_DIR}/"} is newer than the image"
        return 0
    fi

    return 1
}

if [[ "${NOBUILD}" == "1" ]]; then
    [[ -f "${INITRAMFS}" ]] || die "${INITRAMFS} missing and -n given"
    say "Skipping rebuild check (-n); using existing ${INITRAMFS}"
elif reason="$(needs_rebuild)"; then
    say "Rebuilding initramfs: ${reason}"
    [[ -x "${BUILDER}" ]] || die "builder not found or not executable: ${BUILDER}"
    "${BUILDER}" -o "${INITRAMFS}" -k "${KDIR}" --no-banner
else
    say "Initramfs up to date: ${INITRAMFS} ($(du -h "${INITRAMFS}" | cut -f1))"
fi

command -v qemu-system-x86_64 >/dev/null || die "qemu-system-x86_64 not installed"
[[ -e /dev/kvm ]] || die "/dev/kvm does not exist - is KVM enabled on this host?"
getent group kvm | awk -F: -v u="${USER}" '
    { n = split($4, m, ","); for (i = 1; i <= n; i++) if (m[i] == u) ok = 1 }
    END { exit ok ? 0 : 1 }' || \
    die "${USER} is not a member of the 'kvm' group; ask for access or run qemu without -enable-kvm"

APPEND="console=ttyS0 earlyprintk=serial"
if [[ -n "${AUTORUN}" ]]; then
    GUEST_SCRIPT="$(guest_path_for "${AUTORUN}")"
    APPEND+=" lpc26.autorun=${GUEST_SCRIPT}"
    QEMU_EXTRA+=(-no-reboot)
fi

QEMU_CMD="qemu-system-x86_64 -enable-kvm \
  -m ${VM_MEM} \
  -smp ${VM_SMP} \
  -kernel ${BZIMAGE} \
  -initrd ${INITRAMFS} \
  -append '${APPEND}' \
  -nic user,model=virtio-net-pci \
  -nographic ${QEMU_EXTRA[*]:-}"

if [[ -z "${AUTORUN}" ]]; then
    say "Booting (mem=${VM_MEM}M smp=${VM_SMP}, Ctrl+A X to quit)"
    exec sg kvm -c "${QEMU_CMD}"
fi

say "Autorun: ${GUEST_SCRIPT} (mem=${VM_MEM}M smp=${VM_SMP})"
LOG="$(mktemp -t "lpc26-livepatch-autorun.XXXXXX.log")"
say "Serial log: ${LOG}"

sg kvm -c "${QEMU_CMD}" 2>&1 | tee "${LOG}" || true

rc="$(sed 's/\r$//' "${LOG}" | sed -n 's/^LPC26_AUTORUN_EXIT:\([0-9]\+\)$/\1/p' | tail -1)"
if [[ -z "${rc}" ]]; then
    die "guest never reported LPC26_AUTORUN_EXIT - it panicked, hung, or never reached /init (see ${LOG})"
fi

if [[ "${rc}" == "0" ]]; then
    say "Autorun passed (exit 0)"
else
    printf '\033[1;31m[!] Autorun failed (exit %s)\033[0m\n' "${rc}" >&2
fi
exit "${rc}"
