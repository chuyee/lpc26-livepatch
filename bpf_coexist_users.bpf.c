// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bpf_coexist_users.bpf.c - BPF Ftrace Consumers for the LPC 2026 Coexistence Suite
 *
 * Prepared for LPC 2026 Livepatching Microconference:
 * "Ftrace Consumer Classification & Coexistence"
 *
 * Implements the four BPF-backed ftrace consumers on cmdline_proc_show:
 *   - User C (Class 1): SEC("kprobe/cmdline_proc_show") + bpf_override_return()
 *                       Registers via trace_kprobe -> kprobe_ftrace_ops (NO IPMODIFY).
 *   - User D (Class 1): SEC("fmod_ret/cmdline_proc_show")
 *                       Registers via bpf_trampoline -> register_ftrace_direct() (DIRECT).
 *   - User F (Class 2): SEC("fexit/cmdline_proc_show")
 *                       Registers via bpf_trampoline -> register_ftrace_direct() (DIRECT).
 *   - User K (Class 3): SEC("fentry/cmdline_proc_show")
 *                       Registers via bpf_trampoline -> register_ftrace_direct() (DIRECT).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct lpc26_state {
	__s64 inject_retval;
	__u64 override_hits;
	__u64 fmod_ret_hits;
	__u64 fexit_hits;
	__u64 fentry_hits;
	__s64 fexit_last_ret;
	__u64 last_traced_ip;
};

struct lpc26_state lpc26_state;

/*
 * User C: Class 1 Mutator via kprobe + bpf_override_return().
 */
SEC("kprobe/cmdline_proc_show")
int BPF_KPROBE(kprobe_override_cmdline_proc_show)
{
	__s64 ret = lpc26_state.inject_retval ? lpc26_state.inject_retval : -22;

	lpc26_state.override_hits++;
	lpc26_state.last_traced_ip = PT_REGS_IP(ctx);
	bpf_override_return(ctx, (__u64)ret);
	return 0;
}

/*
 * User D: Class 1 Mutator via BPF trampoline fmod_ret (same trampoline mechanism as BPF LSM).
 */
SEC("fmod_ret/cmdline_proc_show")
int BPF_PROG(fmod_ret_cmdline_proc_show, struct seq_file *m, void *v, int ret)
{
	__s64 inj = lpc26_state.inject_retval ? lpc26_state.inject_retval : -1;

	lpc26_state.fmod_ret_hits++;
	lpc26_state.last_traced_ip = bpf_get_func_ip(ctx);
	/*
	 * --retval 1 turns D into a pass-through fmod_ret (return 0, so the
	 * trampoline still calls the traced function). order_experiment.sh T9
	 * uses it to show which function the trampoline's call reaches when
	 * klp is active.
	 */
	if (inj == 1)
		return 0;
	return (int)inj;
}

/*
 * User F: Class 2 Stack Interceptor via BPF trampoline fexit.
 */
SEC("fexit/cmdline_proc_show")
int BPF_PROG(fexit_cmdline_proc_show, struct seq_file *m, void *v, int ret)
{
	lpc26_state.fexit_hits++;
	lpc26_state.fexit_last_ret = ret;
	lpc26_state.last_traced_ip = bpf_get_func_ip(ctx);
	return 0;
}

/*
 * User K: Class 3 Passive Observer via BPF trampoline fentry.
 */
SEC("fentry/cmdline_proc_show")
int BPF_PROG(fentry_cmdline_proc_show, struct seq_file *m, void *v)
{
	lpc26_state.fentry_hits++;
	lpc26_state.last_traced_ip = bpf_get_func_ip(ctx);
	return 0;
}
