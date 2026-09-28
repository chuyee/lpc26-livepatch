#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# lib_coexist.sh - Unified primitives for the 14 Ftrace Consumers & klp Scenarios
#
# Prepared for LPC 2026 Livepatching Microconference:
# "Ftrace Consumer Classification & Coexistence"
#
# The 14 Ftrace Consumers across Class 1, Class 2, and Class 3 on cmdline_proc_show:
#   Class 1: Execution Mutators
#     A : Kernel Livepatching (klp)               [Class 1 IPMODIFY | SAVE_REGS]
#     B : fail_function error injection           [Class 1: kprobe_ipmodify_ops (IPMODIFY)]
#     C : BPF bpf_override_return (trace_kprobe)  [Class 1: kprobe_ftrace_ops (no IPMODIFY)]
#     D : BPF fmod_ret / BPF LSM                  [Class 1: bpf_trampoline (DIRECT)]
#     E : Kprobes-on-ftrace with post_handler     [Class 1: kprobe_ipmodify_ops (IPMODIFY)]
#   Class 2: Stack Interceptors
#     F : BPF fexit                               [Class 2 bpf_trampoline (DIRECT)]
#     G : Function graph tracer (fgraph)          [Class 2: graph_ops + return_to_handler]
#     H : kretprobe / rethook                     [Class 2: kprobe_ftrace_ops + rethook]
#     I : fprobe (with exit_handler)              [Class 2: fprobe_graph_ops (fgraph)]
#   Class 3: Passive Observers
#     J : Passive ftrace_ops                      [Class 3 plain ftrace_ops]
#     K : BPF fentry                              [Class 3: bpf_trampoline (DIRECT)]
#     L : fprobe (no exit_handler)                [Class 3: fprobe_ftrace_ops (SAVE_ARGS)]
#     M : Kprobes-on-ftrace (no post_handler)     [Class 3: kprobe_ftrace_ops (SAVE_REGS)]
#     N : Core function tracer (tracefs)          [Class 3: trace_ops (function tracer)]

COEXIST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ORIG_FUNC="cmdline_proc_show"
KLP1_MOD="${COEXIST_DIR}/klp_sample_mutator.ko"
KLP1_NAME="klp_sample_mutator"
KLP2_MOD="${COEXIST_DIR}/klp_user2.ko"
KLP2_NAME="klp_user2"

KP1_MOD="${COEXIST_DIR}/kprobe_ph_user1.ko"
KP1_NAME="kprobe_ph_user1"

OBS1_MOD="${COEXIST_DIR}/ftrace_observer_user1.ko"
OBS1_NAME="ftrace_observer_user1"

KRET_MOD="${COEXIST_DIR}/kretprobe_user.ko"
KRET_NAME="kretprobe_user"
FP_EXIT_MOD="${COEXIST_DIR}/fprobe_exit_user.ko"
FP_EXIT_NAME="fprobe_exit_user"
FP_ENTRY_MOD="${COEXIST_DIR}/fprobe_entry_user.ko"
FP_ENTRY_NAME="fprobe_entry_user"
KP_ENTRY_MOD="${COEXIST_DIR}/kprobe_entry_user.ko"
KP_ENTRY_NAME="kprobe_entry_user"

BPF_BIN="${COEXIST_DIR}/bpf_coexist_users"
BPF_OBJ="${COEXIST_DIR}/bpf_coexist_users.bpf.o"

DEBUGFS="/sys/kernel/debug"
FAIL_FN_DIR="${DEBUGFS}/fail_function"
STATE_DIR="${TMPDIR:-/tmp}/lpc26_coexist"
mkdir -p "${STATE_DIR}"

PASS_COUNT=0
FAIL_COUNT=0

if [[ -t 1 ]]; then
	C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
	C_CYAN=$'\033[36m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
else
	C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_BOLD=''; C_OFF=''
fi

banner() {
	echo "=================================================================="
	echo " $*"
	echo "=================================================================="
}

check_eq() {
	local desc="$1" expect="$2" actual="$3"
	if [[ "${expect}" == "${actual}" ]]; then
		echo "${C_GREEN}[PASS]${C_OFF} ${desc} (${actual})"
		PASS_COUNT=$((PASS_COUNT + 1))
		return 0
	else
		echo "${C_RED}[FAIL]${C_OFF} ${desc} (expected '${expect}', got '${actual}')"
		FAIL_COUNT=$((FAIL_COUNT + 1))
		return 0
	fi
}

# Like check_eq, but only prints on failure (keeps per-scenario output compact
# without hiding which assertion failed).
check_eq_quiet() {
	local desc="$1" expect="$2" actual="$3"
	if [[ "${expect}" == "${actual}" ]]; then
		PASS_COUNT=$((PASS_COUNT + 1))
	else
		echo "${C_RED}[FAIL]${C_OFF} ${desc} (expected '${expect}', got '${actual}')"
		FAIL_COUNT=$((FAIL_COUNT + 1))
	fi
}

# Map a strerror() text (from insmod / echo / dd stderr) to an errno name.
errtxt_to_errno() {
	case "$1" in
	*"Device or resource busy"*)    echo "-EBUSY" ;;
	*"Invalid argument"*)           echo "-EINVAL" ;;
	*"No such file or directory"*)  echo "-ENOENT" ;;
	*"File exists"*)                echo "-EEXIST" ;;
	*"Operation not permitted"*)    echo "-EPERM" ;;
	*"Permission denied"*)          echo "-EACCES" ;;
	*"Unknown symbol"*)             echo "-ENOENT(symbol)" ;;
	*"Input/output error"*)         echo "-EIO" ;;
	"")                             echo "-E?" ;;
	*)                              echo "-E?($(echo "$1" | tr -s ' \n' '__' | cut -c1-40))" ;;
	esac
}

# Map a negative errno number (from libbpf) to its name.
errno_num_to_name() {
	case "$1" in
	-1) echo "-EPERM" ;; -2) echo "-ENOENT" ;; -13) echo "-EACCES" ;;
	-16) echo "-EBUSY" ;; -17) echo "-EEXIST" ;; -22) echo "-EINVAL" ;;
	-95) echo "-EOPNOTSUPP" ;; -524) echo "-ENOTSUPP" ;;
	*) echo "${1:-?}" ;;
	esac
}

# insmod <ko> -> echoes "ok" or "fail:<errno>" with the real error.
insmod_res() {
	local ko="$1" err
	if err="$(insmod "${ko}" 2>&1)"; then
		echo "ok"
	else
		echo "fail:$(errtxt_to_errno "${err}")"
	fi
}

# write_res <value> <file> -> echoes "ok" or "fail:<errno>" with the real error.
write_res() {
	local val="$1" file="$2" err
	if err="$( { echo "${val}" > "${file}"; } 2>&1)"; then
		echo "ok"
	else
		echo "fail:$(errtxt_to_errno "${err}")"
	fi
}

user_label() {
	case "$1" in
	A) echo "A:klp" ;;
	B) echo "B:fail_fn" ;;
	C) echo "C:bpf_override" ;;
	D) echo "D:fmod_ret" ;;
	E) echo "E:kprobe+ph" ;;
	F) echo "F:fexit" ;;
	G) echo "G:fgraph" ;;
	H) echo "H:kretprobe" ;;
	I) echo "I:fprobe+exit" ;;
	J) echo "J:ftrace_ops" ;;
	K) echo "K:fentry" ;;
	L) echo "L:fprobe_entry" ;;
	M) echo "M:kprobe_entry" ;;
	N) echo "N:func_tracer" ;;
	esac
}

user_class() {
	case "$1" in
	A|B|C|D|E) echo "Class 1 (Mutator)" ;;
	F|G|H|I)   echo "Class 2 (Interceptor)" ;;
	J|K|L|M|N) echo "Class 3 (Observer)" ;;
	esac
}

user_desc() {
	case "$1" in
	A) echo "User A - Kernel Livepatching (Class 1: IPMODIFY | SAVE_REGS)" ;;
	B) echo "User B - fail_function (Class 1: kprobe_ipmodify_ops [IPMODIFY])" ;;
	C) echo "User C - bpf_override_return (Class 1: kprobe_ftrace_ops [no IPMODIFY])" ;;
	D) echo "User D - BPF fmod_ret / BPF LSM (Class 1: bpf_trampoline [DIRECT])" ;;
	E) echo "User E - Kprobe with post_handler (Class 1: kprobe_ipmodify_ops [IPMODIFY])" ;;
	F) echo "User F - BPF fexit (Class 2: bpf_trampoline [DIRECT])" ;;
	G) echo "User G - Function graph tracer (Class 2: graph_ops + return_to_handler)" ;;
	H) echo "User H - kretprobe / rethook (Class 2: kprobe_ftrace_ops + rethook)" ;;
	I) echo "User I - fprobe with exit_handler (Class 2: fprobe_graph_ops [fgraph])" ;;
	J) echo "User J - Passive ftrace_ops (Class 3: plain ftrace_ops, as perf function events)" ;;
	K) echo "User K - BPF fentry (Class 3: bpf_trampoline [DIRECT])" ;;
	L) echo "User L - fprobe without exit_handler (Class 3: fprobe_ftrace_ops [SAVE_ARGS])" ;;
	M) echo "User M - Kprobe without post_handler (Class 3: kprobe_ftrace_ops [SAVE_REGS])" ;;
	N) echo "User N - Core function tracer (Class 3: trace_ops [tracefs function])" ;;
	esac
}

find_tracing_dir() {
	if [[ -r /sys/kernel/tracing/current_tracer ]]; then
		echo "/sys/kernel/tracing"
	else
		echo "/sys/kernel/debug/tracing"
	fi
}

preflight_coexist() {
	if [[ ${EUID} -ne 0 ]]; then
		echo "[-] Must run as root inside VM." >&2
		exit 1
	fi
	if ! mountpoint -q "${DEBUGFS}" 2>/dev/null; then
		mount -t debugfs none "${DEBUGFS}" 2>/dev/null || true
	fi
	for f in "${KLP1_MOD}" "${KLP2_MOD}" "${KP1_MOD}" \
		 "${OBS1_MOD}" "${KRET_MOD}" "${FP_EXIT_MOD}" \
		 "${FP_ENTRY_MOD}" "${KP_ENTRY_MOD}" "${BPF_BIN}" "${BPF_OBJ}"; do
		if [[ ! -e "${f}" ]]; then
			echo "[-] Missing artifact: ${f}" >&2
			exit 1
		fi
	done
}

# Read /sys/kernel/tracing/enabled_functions line for ORIG_FUNC (t_show in kernel/trace/ftrace.c):
# Returns "<count>:<flags>" e.g. "1:IM", "1:RIM", "2:RIDM", or "0:-", where rec->flags are:
#   R = FTRACE_FL_REGS     (at least one attached ftrace_ops set FTRACE_OPS_FL_SAVE_REGS)
#   I = FTRACE_FL_IPMODIFY (an attached ftrace_ops set FTRACE_OPS_FL_IPMODIFY)
#   D = FTRACE_FL_DIRECT   (direct_ops / register_ftrace_direct BPF trampoline attached)
#   M = FTRACE_FL_MODIFIED (sticky bit: function has had I or D attached since boot)
ftrace_site_state() {
	local fn="${1:-${ORIG_FUNC}}" line f cnt flags

	for f in /sys/kernel/tracing/enabled_functions \
		 /sys/kernel/debug/tracing/enabled_functions; do
		[[ -r "${f}" ]] || continue
		line="$(grep -m1 -E "^${fn} \(" "${f}" 2>/dev/null || true)"
		break
	done

	if [[ -z "${line:-}" ]]; then
		echo "0:-"
		return
	fi
	cnt="$(echo "${line}" | sed -n 's/^[^ ]* (\([0-9]\+\)).*/\1/p')"
	flags="$(echo "${line}" | sed -n 's/^[^ ]* ([0-9]\+)[[:space:]]*\([RIDM ]*\).*/\1/p' | tr -d ' ')"
	[[ -z "${flags}" ]] && flags="none"
	echo "${cnt}:${flags}"
}

ftrace_ops_count() {
	local st
	st="$(ftrace_site_state "${1:-${ORIG_FUNC}}")"
	echo "${st%%:*}"
}

ftrace_ops_flags() {
	local st
	st="$(ftrace_site_state "${1:-${ORIG_FUNC}}")"
	echo "${st#*:}"
}

klp_wait_mod() {
	local mod="$1"
	local f="/sys/kernel/livepatch/${mod}/transition" i
	for i in $(seq 1 100); do
		[[ -f "${f}" ]] || return 0
		[[ "$(< "${f}")" == "0" ]] && return 0
		sleep 0.05
	done
	return 1
}

start_bpf_slot() {
	local user="$1" slot="$2" mode="$3" retval="$4"
	local pid_file="${STATE_DIR}/bpf_${user}_${slot}.pid"
	local out_file="${STATE_DIR}/bpf_${user}_${slot}.out"
	local pid i

	: > "${out_file}"
	( cd "${COEXIST_DIR}" && exec ./bpf_coexist_users "${mode}" --retval "${retval}" --hold ) \
		> "${out_file}" 2>&1 &
	pid=$!
	echo "${pid}" > "${pid_file}"

	for i in $(seq 1 100); do
		if grep -q "LPC26_ATTACH: OK" "${out_file}" 2>/dev/null; then
			echo "ok"
			return
		fi
		if grep -q "LPC26_ATTACH: FAIL" "${out_file}" 2>/dev/null; then
			local err
			err="$(sed -n 's/.*errno=\(-\?[0-9]*\).*/\1/p' "${out_file}" | head -1)"
			rm -f "${pid_file}"
			echo "fail:$(errno_num_to_name "${err}")"
			return
		fi
		if ! kill -0 "${pid}" 2>/dev/null; then
			rm -f "${pid_file}"
			echo "fail:exited"
			return
		fi
		sleep 0.05
	done
	echo "fail:timeout"
}

stop_bpf_slot() {
	local user="$1" slot="$2"
	local pid_file="${STATE_DIR}/bpf_${user}_${slot}.pid"
	local out_file="${STATE_DIR}/bpf_${user}_${slot}.out"
	local pid i

	if [[ -r "${pid_file}" ]]; then
		pid="$(< "${pid_file}")"
		if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
			kill -TERM "${pid}" 2>/dev/null || true
			for i in $(seq 1 60); do
				kill -0 "${pid}" 2>/dev/null || break
				sleep 0.05
			done
			kill -0 "${pid}" 2>/dev/null && kill -KILL "${pid}" 2>/dev/null || true
		fi
	fi
	rm -f "${pid_file}" "${out_file}"
}

reset_bpf_slot() {
	local user="$1" slot="$2"
	local pid_file="${STATE_DIR}/bpf_${user}_${slot}.pid"
	local out_file="${STATE_DIR}/bpf_${user}_${slot}.out"
	local pid before after i

	[[ -r "${pid_file}" ]] || return 0
	pid="$(< "${pid_file}")"
	kill -0 "${pid}" 2>/dev/null || return 0
	before="$(grep -c "LPC26_RESET: OK" "${out_file}" 2>/dev/null || true)"
	kill -USR2 "${pid}" 2>/dev/null || return 0
	for i in $(seq 1 40); do
		after="$(grep -c "LPC26_RESET: OK" "${out_file}" 2>/dev/null || true)"
		[[ "${after}" -gt "${before}" ]] && return 0
		sleep 0.02
	done
}

dump_bpf_slot_line() {
	local user="$1" slot="$2"
	local pid_file="${STATE_DIR}/bpf_${user}_${slot}.pid"
	local out_file="${STATE_DIR}/bpf_${user}_${slot}.out"
	local pid before after i

	[[ -r "${pid_file}" ]] || return 0
	pid="$(< "${pid_file}")"
	if kill -0 "${pid}" 2>/dev/null; then
		before="$(grep -c "LPC26_HITS:" "${out_file}" 2>/dev/null || true)"
		kill -USR1 "${pid}" 2>/dev/null || true
		for i in $(seq 1 40); do
			after="$(grep -c "LPC26_HITS:" "${out_file}" 2>/dev/null || true)"
			[[ "${after}" -gt "${before}" ]] && break
			sleep 0.02
		done
	fi
	grep "LPC26_HITS:" "${out_file}" 2>/dev/null | tail -n 1 || true
}

# Attach consumer <ID> <slot:1|2> -> echoes "ok" or "fail:<errno>" (the real error)
attach_user() {
	local user="$1" slot="${2:-1}" td res

	case "${user}:${slot}" in
	A:1)
		res="$(insmod_res "${KLP1_MOD}")"
		if [[ "${res}" == "ok" ]] && ! klp_wait_mod "${KLP1_NAME}"; then
			res="fail:KLP_TRANSITION_TIMEOUT"
		fi
		echo "${res}"
		;;
	A:2)
		res="$(insmod_res "${KLP2_MOD}")"
		if [[ "${res}" == "ok" ]] && ! klp_wait_mod "${KLP2_NAME}"; then
			res="fail:KLP_TRANSITION_TIMEOUT"
		fi
		echo "${res}"
		;;
	B:1|B:2)
		res="$(write_res "${ORIG_FUNC}" "${FAIL_FN_DIR}/inject")"
		if [[ "${res}" == "ok" ]]; then
			printf '%#x\n' -5 > "${FAIL_FN_DIR}/${ORIG_FUNC}/retval"
			echo 0 > "${FAIL_FN_DIR}/verbose"
			echo 100 > "${FAIL_FN_DIR}/probability"
			echo 1000 > "${FAIL_FN_DIR}/times"
			echo 0 > "${FAIL_FN_DIR}/task-filter"
		fi
		echo "${res}"
		;;
	C:1) start_bpf_slot C 1 override -22 ;;
	C:2) start_bpf_slot C 2 override -13 ;;
	D:1) start_bpf_slot D 1 fmod_ret -1 ;;
	D:2) start_bpf_slot D 2 fmod_ret -2 ;;
	E:1)
		insmod_res "${KP1_MOD}"
		;;
	F:1) start_bpf_slot F 1 fexit 0 ;;
	F:2) start_bpf_slot F 2 fexit 0 ;;
	G:1|G:2)
		td="$(find_tracing_dir)"
		echo nop > "${td}/current_tracer" 2>/dev/null || true
		echo "${ORIG_FUNC}" > "${td}/set_ftrace_filter"
		res="$(write_res function_graph "${td}/current_tracer")"
		if [[ "${res}" == "ok" ]]; then
			: > "${td}/trace"
			echo 1 > "${td}/tracing_on"
		fi
		echo "${res}"
		;;
	H:1|H:2)
		insmod_res "${KRET_MOD}"
		;;
	I:1|I:2)
		insmod_res "${FP_EXIT_MOD}"
		;;
	J:1)
		insmod_res "${OBS1_MOD}"
		;;
	K:1) start_bpf_slot K 1 fentry 0 ;;
	K:2) start_bpf_slot K 2 fentry 0 ;;
	L:1|L:2)
		insmod_res "${FP_ENTRY_MOD}"
		;;
	M:1|M:2)
		insmod_res "${KP_ENTRY_MOD}"
		;;
	N:1|N:2)
		td="$(find_tracing_dir)"
		echo nop > "${td}/current_tracer" 2>/dev/null || true
		echo "${ORIG_FUNC}" > "${td}/set_ftrace_filter"
		res="$(write_res function "${td}/current_tracer")"
		if [[ "${res}" == "ok" ]]; then
			: > "${td}/trace"
			echo 1 > "${td}/tracing_on"
		fi
		echo "${res}"
		;;
	esac
}

detach_user() {
	local user="$1" slot="${2:-1}" td

	case "${user}:${slot}" in
	A:1)
		if [[ -d "/sys/kernel/livepatch/${KLP1_NAME}" ]]; then
			echo 0 > "/sys/kernel/livepatch/${KLP1_NAME}/enabled" 2>/dev/null || true
			if ! klp_wait_mod "${KLP1_NAME}"; then
				echo "${C_RED}[FAIL]${C_OFF} ${KLP1_NAME}: disable transition did not complete" >&2
				FAIL_COUNT=$((FAIL_COUNT + 1))
			fi
		fi
		rmmod "${KLP1_NAME}" 2>/dev/null || true
		;;
	A:2)
		if [[ -d "/sys/kernel/livepatch/${KLP2_NAME}" ]]; then
			echo 0 > "/sys/kernel/livepatch/${KLP2_NAME}/enabled" 2>/dev/null || true
			if ! klp_wait_mod "${KLP2_NAME}"; then
				echo "${C_RED}[FAIL]${C_OFF} ${KLP2_NAME}: disable transition did not complete" >&2
				FAIL_COUNT=$((FAIL_COUNT + 1))
			fi
		fi
		rmmod "${KLP2_NAME}" 2>/dev/null || true
		;;
	B:1)
		echo "" > "${FAIL_FN_DIR}/inject" 2>/dev/null || true
		echo 0 > "${FAIL_FN_DIR}/probability" 2>/dev/null || true
		;;
	B:2) ;;
	C:1) stop_bpf_slot C 1 ;;
	C:2) stop_bpf_slot C 2 ;;
	D:1) stop_bpf_slot D 1 ;;
	D:2) stop_bpf_slot D 2 ;;
	E:1) rmmod "${KP1_NAME}" 2>/dev/null || true ;;
	F:1) stop_bpf_slot F 1 ;;
	F:2) stop_bpf_slot F 2 ;;
	G:1|G:2|N:1|N:2)
		td="$(find_tracing_dir)"
		if [[ -w "${td}/current_tracer" ]]; then
			echo nop > "${td}/current_tracer" 2>/dev/null || true
			: > "${td}/set_ftrace_filter" 2>/dev/null || true
			: > "${td}/trace" 2>/dev/null || true
		fi
		;;
	H:1|H:2) rmmod "${KRET_NAME}" 2>/dev/null || true ;;
	I:1|I:2) rmmod "${FP_EXIT_NAME}" 2>/dev/null || true ;;
	J:1) rmmod "${OBS1_NAME}" 2>/dev/null || true ;;
	K:1) stop_bpf_slot K 1 ;;
	K:2) stop_bpf_slot K 2 ;;
	L:1|L:2) rmmod "${FP_ENTRY_NAME}" 2>/dev/null || true ;;
	M:1|M:2) rmmod "${KP_ENTRY_NAME}" 2>/dev/null || true ;;
	esac
}

reset_user_hits() {
	local user="$1" slot="${2:-1}" td

	case "${user}:${slot}" in
	A:1) [[ -w "/sys/module/${KLP1_NAME}/parameters/hits" ]] && echo 0 > "/sys/module/${KLP1_NAME}/parameters/hits" ;;
	A:2) [[ -w "/sys/module/${KLP2_NAME}/parameters/hits" ]] && echo 0 > "/sys/module/${KLP2_NAME}/parameters/hits" ;;
	B:1) [[ -w "${FAIL_FN_DIR}/times" ]] && echo 1000 > "${FAIL_FN_DIR}/times" ;;
	C:1|C:2|D:1|D:2|F:1|F:2|K:1|K:2) reset_bpf_slot "${user}" "${slot}" ;;
	E:1)
		[[ -w "/sys/module/${KP1_NAME}/parameters/pre_hits" ]] && echo 0 > "/sys/module/${KP1_NAME}/parameters/pre_hits"
		[[ -w "/sys/module/${KP1_NAME}/parameters/post_hits" ]] && echo 0 > "/sys/module/${KP1_NAME}/parameters/post_hits"
		[[ -w "/sys/module/${KP1_NAME}/parameters/last_ip" ]] && echo 0 > "/sys/module/${KP1_NAME}/parameters/last_ip"
		;;
	G:1|G:2|N:1|N:2)
		td="$(find_tracing_dir)"
		[[ -w "${td}/trace" ]] && : > "${td}/trace"
		;;
	H:1|H:2)
		[[ -w "/sys/module/${KRET_NAME}/parameters/hits" ]] && echo 0 > "/sys/module/${KRET_NAME}/parameters/hits"
		[[ -w "/sys/module/${KRET_NAME}/parameters/last_ip" ]] && echo 0 > "/sys/module/${KRET_NAME}/parameters/last_ip"
		;;
	I:1|I:2)
		[[ -w "/sys/module/${FP_EXIT_NAME}/parameters/hits" ]] && echo 0 > "/sys/module/${FP_EXIT_NAME}/parameters/hits"
		[[ -w "/sys/module/${FP_EXIT_NAME}/parameters/last_ip" ]] && echo 0 > "/sys/module/${FP_EXIT_NAME}/parameters/last_ip"
		[[ -w "/sys/module/${FP_EXIT_NAME}/parameters/last_regs_ip" ]] && echo 0 > "/sys/module/${FP_EXIT_NAME}/parameters/last_regs_ip"
		;;
	J:1)
		[[ -w "/sys/module/${OBS1_NAME}/parameters/hits" ]] && echo 0 > "/sys/module/${OBS1_NAME}/parameters/hits"
		[[ -w "/sys/module/${OBS1_NAME}/parameters/last_ip" ]] && echo 0 > "/sys/module/${OBS1_NAME}/parameters/last_ip"
		[[ -w "/sys/module/${OBS1_NAME}/parameters/last_regs_ip" ]] && echo 0 > "/sys/module/${OBS1_NAME}/parameters/last_regs_ip"
		;;
	L:1|L:2)
		[[ -w "/sys/module/${FP_ENTRY_NAME}/parameters/hits" ]] && echo 0 > "/sys/module/${FP_ENTRY_NAME}/parameters/hits"
		[[ -w "/sys/module/${FP_ENTRY_NAME}/parameters/last_ip" ]] && echo 0 > "/sys/module/${FP_ENTRY_NAME}/parameters/last_ip"
		[[ -w "/sys/module/${FP_ENTRY_NAME}/parameters/last_regs_ip" ]] && echo 0 > "/sys/module/${FP_ENTRY_NAME}/parameters/last_regs_ip"
		;;
	M:1|M:2)
		[[ -w "/sys/module/${KP_ENTRY_NAME}/parameters/hits" ]] && echo 0 > "/sys/module/${KP_ENTRY_NAME}/parameters/hits"
		[[ -w "/sys/module/${KP_ENTRY_NAME}/parameters/last_ip" ]] && echo 0 > "/sys/module/${KP_ENTRY_NAME}/parameters/last_ip"
		;;
	esac
}

read_user_hits() {
	local user="$1" slot="${2:-1}" line td cnt

	case "${user}:${slot}" in
	A:1) cat "/sys/module/${KLP1_NAME}/parameters/hits" 2>/dev/null || echo 0 ;;
	A:2) cat "/sys/module/${KLP2_NAME}/parameters/hits" 2>/dev/null || echo 0 ;;
	B:1)
		local rem
		rem="$(cat "${FAIL_FN_DIR}/times" 2>/dev/null || echo 1000)"
		echo $((1000 - rem))
		;;
	C:1|C:2)
		line="$(dump_bpf_slot_line "${user}" "${slot}")"
		echo "${line}" | sed -n 's/.*override=\([0-9]\+\).*/\1/p'
		;;
	D:1|D:2)
		line="$(dump_bpf_slot_line "${user}" "${slot}")"
		echo "${line}" | sed -n 's/.*fmod_ret=\([0-9]\+\).*/\1/p'
		;;
	E:1) cat "/sys/module/${KP1_NAME}/parameters/pre_hits" 2>/dev/null || echo 0 ;;
	F:1|F:2)
		line="$(dump_bpf_slot_line "${user}" "${slot}")"
		echo "${line}" | sed -n 's/.*fexit=\([0-9]\+\).*/\1/p'
		;;
	G:1|G:2)
		td="$(find_tracing_dir)"
		cnt="$(grep -cE "(livepatch_)?cmdline_proc_show\(" "${td}/trace" 2>/dev/null || true)"
		echo "${cnt:-0}"
		;;
	H:1|H:2) cat "/sys/module/${KRET_NAME}/parameters/hits" 2>/dev/null || echo 0 ;;
	I:1|I:2) cat "/sys/module/${FP_EXIT_NAME}/parameters/hits" 2>/dev/null || echo 0 ;;
	J:1) cat "/sys/module/${OBS1_NAME}/parameters/hits" 2>/dev/null || echo 0 ;;
	K:1|K:2)
		line="$(dump_bpf_slot_line "${user}" "${slot}")"
		echo "${line}" | sed -n 's/.*fentry=\([0-9]\+\).*/\1/p'
		;;
	L:1|L:2) cat "/sys/module/${FP_ENTRY_NAME}/parameters/hits" 2>/dev/null || echo 0 ;;
	M:1|M:2) cat "/sys/module/${KP_ENTRY_NAME}/parameters/hits" 2>/dev/null || echo 0 ;;
	N:1|N:2)
		td="$(find_tracing_dir)"
		cnt="$(grep -cE "(livepatch_)?cmdline_proc_show <-" "${td}/trace" 2>/dev/null || true)"
		echo "${cnt:-0}"
		;;
	*) echo 0 ;;
	esac
}

# Resolve a kernel instruction pointer (decimal or 0x hex) to orig_func, new_func,
# new_func2, or other_ip(<sym>). Uses real symbol extents: the containing symbol
# is the highest /proc/kallsyms entry whose address is <= ip. Addresses are
# compared as zero-padded 16-digit hex strings because (busybox) awk uses
# doubles and cannot hold 64-bit kernel addresses exactly.
resolve_ip_symbol() {
	local raw_ip="${1:-0}" ip_hex sym
	[[ -z "${raw_ip}" || "${raw_ip}" == "0" || "${raw_ip}" == "0x0" ]] && { echo "none"; return; }
	ip_hex="$(printf '%016x' "$((raw_ip))")"

	sym="$(awk -v ip="${ip_hex}" '
		{ a = $1 "" }
		length(a) == 16 && a <= ip "" && (name == "" || a > best) { best = a; name = $3 }
		END { print (name == "" ? "?" : name) }' /proc/kallsyms 2>/dev/null)"

	case "${sym}" in
	cmdline_proc_show)            echo "orig_func" ;;
	livepatch_cmdline_proc_show)  echo "new_func" ;;
	livepatch2_cmdline_proc_show) echo "new_func2" ;;
	*)                            echo "other_ip(${sym})" ;;
	esac
}

# Empirically determine which function (orig_func vs new_func vs new_func2 vs none)
# a consumer actually traced/executed during the last probe.
read_user_traced_func() {
	local user="$1" slot="${2:-1}" hits line ip_val td

	hits="$(read_user_hits "${user}" "${slot}")"
	if [[ -z "${hits}" || "${hits}" == "-" || "${hits}" -eq 0 ]]; then
		echo "none"
		return
	fi

	case "${user}:${slot}" in
	A:1) echo "new_func" ;;
	A:2) echo "new_func2" ;;
	B:1) echo "orig_func" ;;
	C:1|C:2|D:1|D:2|F:1|F:2|K:1|K:2)
		line="$(grep "LPC26_HITS:" "${STATE_DIR}/bpf_${user}_${slot}.out" 2>/dev/null | tail -n 1 || true)"
		ip_val="$(echo "${line}" | sed -n 's/.*traced_ip=\(0x[0-9a-fA-F]\+\).*/\1/p')"
		resolve_ip_symbol "${ip_val:-0}"
		;;
	E:1)
		ip_val="$(cat "/sys/module/${KP1_NAME}/parameters/last_ip" 2>/dev/null || echo 0)"
		resolve_ip_symbol "${ip_val}"
		;;
	G:1|G:2)
		td="$(find_tracing_dir)"
		if grep -q "livepatch_cmdline_proc_show(" "${td}/trace" 2>/dev/null; then
			echo "new_func"
		elif grep -q "cmdline_proc_show(" "${td}/trace" 2>/dev/null; then
			echo "orig_func"
		else
			echo "none"
		fi
		;;
	H:1|H:2)
		ip_val="$(cat "/sys/module/${KRET_NAME}/parameters/last_ip" 2>/dev/null || echo 0)"
		resolve_ip_symbol "${ip_val}"
		;;
	I:1|I:2)
		ip_val="$(cat "/sys/module/${FP_EXIT_NAME}/parameters/last_ip" 2>/dev/null || echo 0)"
		resolve_ip_symbol "${ip_val}"
		;;
	J:1)
		ip_val="$(cat "/sys/module/${OBS1_NAME}/parameters/last_ip" 2>/dev/null || echo 0)"
		resolve_ip_symbol "${ip_val}"
		;;
	L:1|L:2)
		ip_val="$(cat "/sys/module/${FP_ENTRY_NAME}/parameters/last_ip" 2>/dev/null || echo 0)"
		resolve_ip_symbol "${ip_val}"
		;;
	M:1|M:2)
		ip_val="$(cat "/sys/module/${KP_ENTRY_NAME}/parameters/last_ip" 2>/dev/null || echo 0)"
		resolve_ip_symbol "${ip_val}"
		;;
	N:1|N:2)
		td="$(find_tracing_dir)"
		if grep -q "livepatch_cmdline_proc_show <-" "${td}/trace" 2>/dev/null; then
			echo "new_func"
		elif grep -q "cmdline_proc_show <-" "${td}/trace" 2>/dev/null; then
			echo "orig_func"
		else
			echo "none"
		fi
		;;
	*) echo "none" ;;
	esac
}

# Trigger cmdline_proc_show once and identify which consumer's output/errno surfaced:
#   klp1        -> User A Slot 1 (livepatch_cmdline_proc_show)
#   klp2        -> User A Slot 2 (livepatch2_cmdline_proc_show)
#   B(EIO)      -> User B fail_function (-5)
#   C1(EINVAL)  -> User C Slot 1 bpf_override_return (-22)
#   C2(EACCES)  -> User C Slot 2 bpf_override_return (-13)
#   D1(EPERM)   -> User D Slot 1 fmod_ret (-1)
#   D2(ENOENT)  -> User D Slot 2 fmod_ret (-2)
#   orig        -> Original cmdline_proc_show body ran and returned 0
probe_cmdline() {
	local out err_file="${STATE_DIR}/probe_err.txt" rc errtxt

	out="$(dd if=/proc/cmdline bs=4096 count=1 2>"${err_file}")" && rc=0 || rc=$?
	if [[ ${rc} -ne 0 ]]; then
		errtxt="$(< "${err_file}")"
		case "${errtxt}" in
		*"Input/output error"*)       echo "B(EIO)" ;;
		*"Invalid argument"*)         echo "C1(EINVAL)" ;;
		*"Permission denied"*)        echo "C2(EACCES)" ;;
		*"Operation not permitted"*)  echo "D1(EPERM)" ;;
		*"No such file or directory"*) echo "D2(ENOENT)" ;;
		*)                            echo "err(${errtxt})" ;;
		esac
		return
	fi

	if [[ -z "${out}" ]]; then
		echo "empty(ret=0)"
	elif [[ "${out}" == *"CLASS 1 MUTATOR #2 ACTIVE"* ]]; then
		echo "klp2"
	elif [[ "${out}" == *"CLASS 1 MUTATOR ACTIVE"* ]]; then
		echo "klp1"
	else
		echo "orig"
	fi
}

# ftrace_regs instruction pointer seen by the peer's entry handler, or "-" for
# consumers that do not expose it. orig_func (fentry return address) means the
# handler ran before klp's; new_func means an older IPMODIFY ops (klp) already
# rewrote it, i.e. the redirect is visible to this consumer. kprobe-based users
# (E, H, M) cannot see it: kprobe_ftrace_handler() sets regs->ip = addr + 1.
read_user_regs_ip() {
	local user="$1" slot="${2:-1}" mod

	case "${user}:${slot}" in
	I:1|I:2) mod="${FP_EXIT_NAME}" ;;
	J:1)     mod="${OBS1_NAME}" ;;
	L:1|L:2) mod="${FP_ENTRY_NAME}" ;;
	*) echo "-"; return ;;
	esac
	resolve_ip_symbol "$(cat "/sys/module/${mod}/parameters/last_regs_ip" 2>/dev/null || echo 0)"
}

# Return value observed by a Class 2 consumer's return hook, or "-".
read_user_last_ret() {
	local user="$1" slot="${2:-1}" line

	case "${user}:${slot}" in
	F:1|F:2)
		line="$(dump_bpf_slot_line "${user}" "${slot}")"
		echo "${line}" | sed -n 's/.*fexit_last_ret=\(-\?[0-9]\+\).*/\1/p'
		;;
	H:1|H:2) cat "/sys/module/${KRET_NAME}/parameters/last_ret" 2>/dev/null || echo "-" ;;
	I:1|I:2) cat "/sys/module/${FP_EXIT_NAME}/parameters/last_ret" 2>/dev/null || echo "-" ;;
	*) echo "-" ;;
	esac
}

# Distinguish "return hook wraps new_func" from "return hook wraps orig_func":
# cmdline_proc_show() always returns 0, so make new_func return MAGIC_RET for
# one read and see which value the peer's return hook reports.
MAGIC_RET=7
probe_return_value() {
	local user="$1" slot="${2:-1}" p="/sys/module/${KLP1_NAME}/parameters/magic_ret" ret

	if [[ ! -w "${p}" ]]; then
		echo "-"
		return
	fi
	echo "${MAGIC_RET}" > "${p}"
	cat /proc/cmdline > /dev/null 2>&1 || true
	echo 0 > "${p}"
	ret="$(read_user_last_ret "${user}" "${slot}")"
	echo "${ret:--}"
}

cleanup_all_users() {
	detach_user A 2
	detach_user A 1
	detach_user B 1
	detach_user C 2
	detach_user C 1
	detach_user D 2
	detach_user D 1
	detach_user E 1
	detach_user F 2
	detach_user F 1
	detach_user G 1
	detach_user H 1
	detach_user I 1
	detach_user J 1
	detach_user K 2
	detach_user K 1
	detach_user L 1
	detach_user M 1
	detach_user N 1
}
