#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# order_experiment.sh - ftrace_ops handler order on a shared call site, and
# which instruction-pointer (ip) write wins.
#
# Prepared for LPC 2026 Livepatching Microconference:
# "Ftrace Consumer Classification & Coexistence"
#
# ftrace_order_probe.ko provides two passive ftrace_ops, "a" and "b", that can
# be registered at any point between other consumers. Each records a global
# sequence number (run order) and ftrace_regs_get_instruction_pointer() at the
# moment it ran. A probe that runs *after* klp sees ip=new_func; one that runs
# *before* klp sees ip=orig_func. The probe registered first therefore reports
# the final ip, i.e. where execution actually resumes.
#
# Every row asserts the expected /proc/cmdline outcome and run order.
#
#   T1-T2   plain ftrace_ops list order (LIFO)
#   T3      klp's position is just its registration time
#   T4-T5   C (bpf_override_return, no IPMODIFY) vs klp: last ip writer wins
#   T6-T7   M (passive kprobe) restores the ip it found, never clobbers klp
#   T8-T9   D (fmod_ret, DIRECT) is order-independent; pass-through reaches klp
#   T10     order is per ftrace_ops: a shared kprobe_ftrace_ops registered by
#           an unrelated kprobe makes C win although it attached after klp
#   T11     re-registration (klp reload / C re-attach) flips the winner
#
# Run: ./vm_start.sh -a ./order_experiment.sh

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib_coexist.sh
source "${SCRIPT_DIR}/lib_coexist.sh"

P=/sys/module/ftrace_order_probe/parameters
PROBE_MOD="${SCRIPT_DIR}/ftrace_order_probe.ko"
ATTACHED=()
JR="other_ip(just_return_func)"

banner "[LPC 2026] ftrace_ops Handler Order & ip-Write Arbitration (T1-T11)"
preflight_coexist
[[ -e "${PROBE_MOD}" ]] || { echo "[-] Missing artifact: ${PROBE_MOD}" >&2; exit 1; }
cleanup_all_users
insmod "${PROBE_MOD}" || { echo "[-] insmod ${PROBE_MOD} failed" >&2; exit 1; }

TD="$(find_tracing_dir)"
unrelated_on()  { echo 'p:lpc26_unrelated version_proc_show' >> "${TD}/kprobe_events" &&
		  echo 1 > "${TD}/events/kprobes/lpc26_unrelated/enable"; }
unrelated_off() { echo 0 > "${TD}/events/kprobes/lpc26_unrelated/enable" 2>/dev/null
		  echo '-:lpc26_unrelated' >> "${TD}/kprobe_events" 2>/dev/null; }

reg() { echo "$1" > "${P}/reg"; }
att() {
	local u="$1" r
	shift
	r="$(attach_user "${u}" 1 "$@")"
	check_eq_quiet "attach ${u}" "ok" "${r}"
	ATTACHED+=("${u}")
}
# D as a pass-through fmod_ret (bpf_coexist_users: --retval 1 => return 0)
att_d_pass() {
	local r
	r="$(start_bpf_slot D 1 fmod_ret 1)"
	check_eq_quiet "attach D(pass-through)" "ok" "${r}"
	ATTACHED+=(D)
}
drop() {	# detach one consumer, keep the others attached
	local u="$1" x keep=()
	detach_user "${u}" 1
	for x in "${ATTACHED[@]}"; do [[ "${x}" == "${u}" ]] || keep+=("${x}"); done
	ATTACHED=("${keep[@]}")
}
teardown() {
	local i
	reg -a; reg -b
	for (( i=${#ATTACHED[@]}-1; i>=0; i-- )); do detach_user "${ATTACHED[i]}" 1; done
	ATTACHED=()
	check_eq_quiet "site clean after teardown" "0:-" "$(ftrace_site_state)"
}
cleanup_order() {
	reg -a 2>/dev/null; reg -b 2>/dev/null
	unrelated_off
	cleanup_all_users
	rmmod ftrace_order_probe 2>/dev/null || true
}
trap cleanup_order EXIT

# measure <title> <expected /proc/cmdline outcome> <expected run order>
measure() {
	local title="$1" exp_win="$2" exp_order="$3" win order x h s ip u tag
	local f
	for f in a_seq b_seq a_ip b_ip a_hits b_hits; do echo 0 > "${P}/${f}"; done
	for u in "${ATTACHED[@]}"; do reset_user_hits "${u}" 1 >/dev/null 2>&1 || true; done

	win="$(probe_cmdline)"
	order=""
	for x in a b; do
		h="$(<"${P}/${x}_hits")"
		[[ "${h}" == 0 ]] && continue
		s="$(<"${P}/${x}_seq")"
		ip="$(resolve_ip_symbol "$(<"${P}/${x}_ip")")"
		order+="${s}:${x}(ip=${ip}) "
	done
	order="$(echo "${order}" | tr ' ' '\n' | sed '/^$/d' | sort -n | cut -d: -f2- | tr '\n' ' ')"
	order="${order% }"

	if [[ "${win}" == "${exp_win}" && "${order}" == "${exp_order}" ]]; then
		tag="${C_GREEN}[PASS]${C_OFF}"
		PASS_COUNT=$((PASS_COUNT + 1))
	else
		tag="${C_RED}[FAIL]${C_OFF}"
		FAIL_COUNT=$((FAIL_COUNT + 1))
	fi
	printf '%s %-40s | win=%-11s | run order: %-46s |' "${tag}" "${title}" "${win}" "${order:--}"
	for u in "${ATTACHED[@]}"; do printf ' %s_hits=%s' "${u}" "$(read_user_hits "${u}" 1)"; done
	echo
	if [[ "${tag}" == *FAIL* ]]; then
		echo "       expected: win=${exp_win} run order: ${exp_order:--}"
	fi
}

banner "T1/T2: plain ftrace_ops list order"
reg a; reg b;  measure "reg a -> reg b" orig "b(ip=orig_func) a(ip=orig_func)"; teardown
reg b; reg a;  measure "reg b -> reg a" orig "a(ip=orig_func) b(ip=orig_func)"; teardown

banner "T3: klp's handler position = its registration time"
reg a; att A; reg b;  measure "a -> klp -> b" klp1 "b(ip=orig_func) a(ip=new_func)"; teardown
att A; reg a; reg b;  measure "klp -> a -> b" klp1 "b(ip=orig_func) a(ip=orig_func)"; teardown
reg a; reg b; att A;  measure "a -> b -> klp" klp1 "b(ip=new_func) a(ip=new_func)";   teardown

banner "T4/T5: C (kprobe + bpf_override_return, no IPMODIFY) vs klp"
reg a; att A; att C; reg b;  measure "a -> klp -> C -> b" klp1         "b(ip=orig_func) a(ip=new_func)"; teardown
reg a; att C; att A; reg b;  measure "a -> C -> klp -> b" "C1(EINVAL)" "b(ip=orig_func) a(ip=${JR})";    teardown

banner "T6/T7: M (passive kprobe, restores the ip it found) vs klp"
reg a; att A; att M; reg b;  measure "a -> klp -> M -> b" klp1 "b(ip=orig_func) a(ip=new_func)"; teardown
reg a; att M; att A; reg b;  measure "a -> M -> klp -> b" klp1 "b(ip=orig_func) a(ip=new_func)"; teardown

banner "T8/T9: D (fmod_ret, DIRECT trampoline) vs klp"
att A; att D;       measure "klp -> D(-EPERM)"       "D1(EPERM)" ""; teardown
att D; att A;       measure "D(-EPERM) -> klp"       "D1(EPERM)" ""; teardown
att A; att_d_pass;  measure "klp -> D(pass-through)" klp1        ""; teardown
att_d_pass; att A;  measure "D(pass-through) -> klp" klp1        ""; teardown

banner "T10: order is per ftrace_ops, not per consumer (shared kprobe_ftrace_ops)"
if unrelated_on; then
	reg a; att A; att C; reg b
	measure "[kprobe@version_proc_show] a->klp->C->b" "C1(EINVAL)" "b(ip=orig_func) a(ip=new_func)"
	unrelated_off
	measure "  ...unrelated kprobe removed"          "C1(EINVAL)" "b(ip=orig_func) a(ip=new_func)"
	teardown
else
	check_eq_quiet "arm unrelated kprobe on version_proc_show" "ok" "fail"
fi

banner "T11: re-registration moves an ops to the list head and flips the winner"
# The raw enabled_functions line must be identical before and after the flip:
# nothing user-visible reveals handler order.
site_line() { sed -n "/^${ORIG_FUNC} (/p" "${TD}/enabled_functions"; }
reg a; att A; att C; reg b;  measure "a -> klp -> C -> b"        klp1         "b(ip=orig_func) a(ip=new_func)"
before="$(site_line)"
drop A; att A;               measure "  ...klp reloaded"         "C1(EINVAL)" "b(ip=new_func) a(ip=${JR})"
check_eq "enabled_functions unchanged across klp reload" "${before}" "$(site_line)"
teardown
reg a; att C; att A; reg b;  measure "a -> C -> klp -> b"        "C1(EINVAL)" "b(ip=orig_func) a(ip=${JR})"
before="$(site_line)"
drop C; att C;               measure "  ...C re-attached"        klp1         "b(ip=${JR}) a(ip=new_func)"
check_eq "enabled_functions unchanged across C re-attach" "${before}" "$(site_line)"
teardown

echo ""
banner "Order Experiment Completed (${PASS_COUNT} assertions passed, ${FAIL_COUNT} failed)"
[[ ${FAIL_COUNT} -eq 0 ]]
