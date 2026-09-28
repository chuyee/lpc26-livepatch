#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# run_coexistence_experiment.sh - Empirical klp Coexistence & Contention Runner
#
# Prepared for LPC 2026 Livepatching Microconference:
# "Ftrace Consumer Classification & Livepatch Coexistence"
#
# Evaluates the 2 directional scenarios for Kernel Livepatching (A: klp) against
# all 14 ftrace consumers across Class 1, Class 2, and Class 3 on cmdline_proc_show:
#   Scenario 1: klp (A) as Contender (Peer X attached first as Incumbent, klp attaches second)
#   Scenario 2: klp (A) as Incumbent (klp attached first as Incumbent, Peer X attaches second)
#
# Consumers under test:
#   Class 1 (Mutators):
#     A : Kernel Livepatching (klp)               [IPMODIFY | SAVE_REGS]
#     B : fail_function error injection           [kprobe_ipmodify_ops: IPMODIFY]
#     C : BPF bpf_override_return (trace_kprobe)  [kprobe_ftrace_ops: no IPMODIFY]
#     D : BPF fmod_ret / BPF LSM                  [bpf_trampoline: DIRECT]
#     E : Kprobes-on-ftrace with post_handler     [kprobe_ipmodify_ops: IPMODIFY]
#   Class 2 (Stack Interceptors):
#     F : BPF fexit                               [bpf_trampoline DIRECT]
#     G : Function graph tracer (fgraph)          [graph_ops + return_to_handler]
#     H : kretprobe / rethook                     [kprobe_ftrace_ops + rethook]
#     I : fprobe (with exit_handler)              [fprobe_graph_ops (fgraph)]
#   Class 3 (Passive Observers):
#     J : Passive ftrace_ops observer             [plain ftrace_ops]
#     K : BPF fentry                              [bpf_trampoline: DIRECT]
#     L : fprobe (no exit_handler)                [fprobe_ftrace_ops: SAVE_ARGS]
#     M : Kprobes-on-ftrace (no post_handler)     [kprobe_ftrace_ops: SAVE_REGS]
#     N : Core function tracer (tracefs)          [trace_ops: function tracer]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib_coexist.sh
source "${SCRIPT_DIR}/lib_coexist.sh"

echo "=================================================================="
echo " [LPC 2026] Livepatch (klp) Coexistence Test Suite (28 Scenarios)"
echo "=================================================================="

preflight_coexist
trap cleanup_all_users EXIT
cleanup_all_users

declare -A CELL_SUMMARY
declare -A CELL_DETAIL

SCENARIO_NUM=0
ALL_USERS=(A B C D E F G H I J K L M N)
TOTAL_SCENARIOS=$(( ${#ALL_USERS[@]} * 2 ))

# Run a single ordered pair: r = Incumbent (attached first), c = Contender (attaches second)
run_pair() {
	local r="$1" c="$2"
	local c_slot=1
	[[ "${r}" == "${c}" ]] && c_slot=2

	SCENARIO_NUM=$((SCENARIO_NUM + 1))
	local num_str
	num_str="$(printf "%02d" "${SCENARIO_NUM}")"

	local r_res
	r_res="$(attach_user "${r}" 1)"
	if [[ "${r_res}" != "ok" ]]; then
		echo "${C_RED}[FAIL]${C_OFF} #${num_str} (Inc=${r}, Cont=${c}): Incumbent ${r} failed to attach (${r_res})"
		FAIL_COUNT=$((FAIL_COUNT + 1))
		return
	fi

	local r_state
	r_state="$(ftrace_site_state)"

	# Attempt to attach Contender C
	local c_res both_state win r_hits c_hits
	c_res="$(attach_user "${c}" "${c_slot}")"
	both_state="$(ftrace_site_state)"

	reset_user_hits "${r}" 1
	if [[ "${c_res}" == "ok" ]]; then
		reset_user_hits "${c}" "${c_slot}"
	fi

	win="$(probe_cmdline)"
	r_hits="$(read_user_hits "${r}" 1)"
	local r_trace c_trace state_tag
	r_trace="$(read_user_traced_func "${r}" 1)"
	if [[ "${c_res}" == "ok" ]]; then
		c_hits="$(read_user_hits "${c}" "${c_slot}")"
		c_trace="$(read_user_traced_func "${c}" "${c_slot}")"
	else
		c_hits="-"
		c_trace="-"
	fi

	if [[ "${c_res}" != "ok" ]]; then
		if [[ "${r}" == "A" ]]; then
			state_tag="new_func"
		else
			state_tag="orig_func"
		fi
	elif [[ "${r}" == "A" && "${c}" == "A" ]]; then
		state_tag="new_func2(stacked)"
	elif [[ "${win}" == "klp1" && "${r_trace}" == "orig_func" ]]; then
		state_tag="orig_func(Inc_traces=orig_func,exec=new_func)"
	elif [[ "${win}" == "klp1" && "${c_trace}" == "orig_func" ]]; then
		state_tag="orig_func(Cont_traces=orig_func,exec=new_func)"
	elif [[ ( "${r}" == "A" || "${c}" == "A" ) && "${win}" != "klp1" ]]; then
		state_tag="orig_func(suppresses_new_func)"
	else
		state_tag="orig_func"
	fi

	# Return-value probe for Class 2 return hooks (must run while attached).
	local peer="${c}" peer_slot="${c_slot}" ret="-"
	if [[ "${c}" == "A" ]]; then
		peer="${r}"; peer_slot=1
	fi
	if [[ "${c_res}" == "ok" && "${peer}" =~ ^[FHI]$ ]]; then
		ret="$(probe_return_value "${peer}" "${peer_slot}")"
	fi
	# ftrace_regs ip seen by the peer's entry handler (J, L, I only).
	local rip="-"
	[[ "${c_res}" == "ok" && "${peer}" != "A" ]] && rip="$(read_user_regs_ip "${peer}" "${peer_slot}")"

	# Detach Contender C (always: a failed attach may leave partial state) then Incumbent R
	detach_user "${c}" "${c_slot}"
	detach_user "${r}" 1
	local post_state
	post_state="$(ftrace_site_state)"

	# Classify the *measured* outcome for (Incumbent r, Contender c), one side is A (klp):
	#   Self          : A x A, second patch stacks on the first (win=klp2)
	#   -E<errno>     : Contender registration failed with that errno
	#   Override      : Contender's behavior surfaced on the read (Contender wins)
	#   Suppressed    : Incumbent's behavior surfaced on the read (Incumbent wins)
	#   OK            : klp ran new_func AND the peer's return hook reported new_func's
	#                   return value (probe_return_value: new_func returns MAGIC_RET)
	#   Stale Symbols : klp ran new_func, the peer fired but attributes the call to
	#                   orig_func (and, for return hooks, did not see MAGIC_RET)
	#   Blind         : klp ran new_func, the peer never fired
	#   Unclassified  : anything else (see detail column)
	#   <summary>†    : the peer's entry handler saw ftrace_regs ip == new_func,
	#                   i.e. klp's redirect was visible to it (rip= in detail)
	local summary detail peer_hits winner=""
	if [[ "${c_res}" != "ok" ]]; then
		summary="${c_res#fail:}"
	elif [[ "${r}" == "${c}" ]]; then
		[[ "${win}" == "klp2" ]] && summary="Self" || summary="Unclassified"
	else
		case "${win}" in
		klp1) winner="A" ;;
		"B(EIO)"|"C1(EINVAL)"|"D1(EPERM)") winner="${win:0:1}" ;;
		esac
		if [[ "${peer}" == "${r}" ]]; then peer_hits="${r_hits}"; else peer_hits="${c_hits}"; fi

		if [[ -n "${winner}" && "${winner}" != "A" ]]; then
			[[ "${winner}" == "${c}" ]] && summary="Override" || summary="Suppressed"
		elif [[ "${winner}" == "A" && "${peer}" =~ ^[BCDE]$ ]]; then
			[[ "${c}" == "A" ]] && summary="Override" || summary="Suppressed"
		elif [[ "${winner}" == "A" ]]; then
			if [[ -z "${peer_hits}" || "${peer_hits}" == "0" ]]; then
				summary="Blind"
			elif [[ "${peer}" =~ ^[FHI]$ && "${ret}" == "${MAGIC_RET}" ]]; then
				summary="OK"
			else
				summary="Stale Symbols"
			fi
		else
			summary="Unclassified"
		fi
	fi

	[[ "${rip}" == "new_func" ]] && summary="${summary}†"

	detail="inc=${r_state} both=${both_state} res=${c_res} state=${state_tag} win=${win} Inc=${r_hits}(${r_trace}) Cont=${c_hits}(${c_trace}) ret=${ret} rip=${rip} post=${post_state}"

	CELL_SUMMARY["${r}_${c}"]="${summary}"
	CELL_DETAIL["${r}_${c}"]="${detail}"

	printf "[#%s/%d] Inc=%-15s Cont=%-15s | %-12s | %s\n" \
		"${num_str}" "${TOTAL_SCENARIOS}" \
		"$(user_label "${r}")" "$(user_label "${c}")" \
		"${summary}" "${detail}"
	check_eq_quiet "Post-${r}x${c} clean ftrace state" "0:-" "${post_state}"
}

banner "Scenario 1: klp (A) as Contender vs. All Class 1/2/3 Consumers as Incumbent"
for u in "${ALL_USERS[@]}"; do
	run_pair "${u}" "A"
done

echo ""
banner "Scenario 2: klp (A) as Incumbent vs. All Class 1/2/3 Consumers as Contender"
for u in "${ALL_USERS[@]}"; do
	run_pair "A" "${u}"
done

echo ""
banner "Empirical klp Coexistence & Contention Summary (2 Scenarios x 14 Consumers)"
echo "| Class | Consumer | Mechanism (\`enabled_functions\`) | Scenario 1: \`klp\` as Contender (\`klp\` 2nd) | Scenario 2: \`klp\` as Incumbent (\`klp\` 1st) |"
echo "| :--- | :--- | :--- | :--- | :--- |"  # Mechanism: sticky 'M' (FTRACE_FL_MODIFIED) stripped
for u in "${ALL_USERS[@]}"; do
	printf "| %s | **%s** | \`%s\` | %s | %s |\n" \
		"$(user_class "${u}")" \
		"$(user_label "${u}")" \
		"$(echo "${CELL_DETAIL["${u}_A"]:-}" | sed -n 's/^inc=\([^ ]*\).*/\1/p' | sed 's/^\([0-9]*\):\([RID]*\)M$/\1:\2/; s/:$/:none/')" \
		"${CELL_SUMMARY["${u}_A"]:-n/a}" \
		"${CELL_SUMMARY["A_${u}"]:-n/a}"
done
echo ""
echo "† Redirect visible: the peer's entry handler read ftrace_regs ip == new_func"
echo "  (its ftrace_ops is older than klp's, so it runs after klp's IPMODIFY handler)."

echo ""
banner "klp Coexistence Suite Completed: ${SCENARIO_NUM}/${TOTAL_SCENARIOS} scenarios measured (${PASS_COUNT} assertions passed, ${FAIL_COUNT} failed)"
[[ ${FAIL_COUNT} -eq 0 ]]
