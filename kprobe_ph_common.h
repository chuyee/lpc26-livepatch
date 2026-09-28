/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kprobe_ph_common.h - Shared implementation for User E (kprobe with post_handler)
 *
 * Included by kprobe_ph_user<N>.c; KPROBE_USER_SLOT selects the slot so
 * additional independent kprobes with post_handler != NULL can be added for
 * E x E tests.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>

static char *target_func = "cmdline_proc_show";
module_param(target_func, charp, 0444);
MODULE_PARM_DESC(target_func, "Symbol to probe (default: cmdline_proc_show)");

static unsigned long pre_hits;
module_param(pre_hits, ulong, 0644);
MODULE_PARM_DESC(pre_hits, "Number of times pre_handler executed");

static unsigned long post_hits;
module_param(post_hits, ulong, 0644);
MODULE_PARM_DESC(post_hits, "Number of times post_handler executed");

static unsigned long last_ip;
module_param(last_ip, ulong, 0644);
MODULE_PARM_DESC(last_ip, "Probed address (p->addr) observed by pre_handler");

static int lpc26_kp_pre(struct kprobe *p, struct pt_regs *regs)
{
	WRITE_ONCE(pre_hits, READ_ONCE(pre_hits) + 1);
	WRITE_ONCE(last_ip, (unsigned long)p->addr);
	return 0;
}

/*
 * Non-NULL post_handler forces arm_kprobe_ftrace() to select
 * kprobe_ipmodify_ops (FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_SAVE_REGS).
 *
 * Note: on kprobes-on-ftrace there is no single-step. kprobe_ftrace_handler()
 * only *temporarily* sets regs->ip = ip + MCOUNT_INSN_SIZE to emulate it for
 * post_handler, then restores the original ip. The IPMODIFY claim is thus
 * declared but control flow is not actually diverted.
 */
static void lpc26_kp_post(struct kprobe *p, struct pt_regs *regs,
			  unsigned long flags)
{
	WRITE_ONCE(post_hits, READ_ONCE(post_hits) + 1);
}

static struct kprobe kp = {
	.pre_handler  = lpc26_kp_pre,
	.post_handler = lpc26_kp_post,
};

static int __init kprobe_ph_init(void)
{
	int ret;

	kp.symbol_name = target_func;
	ret = register_kprobe(&kp);
	if (ret) {
		pr_warn("register_kprobe(%s) failed: %d\n", target_func, ret);
		return ret;
	}
	pr_info("registered kprobe+post_handler #%d on %s\n",
		KPROBE_USER_SLOT, target_func);
	return 0;
}

static void __exit kprobe_ph_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("unregistered kprobe+post_handler #%d from %s\n",
		KPROBE_USER_SLOT, target_func);
}

module_init(kprobe_ph_init);
module_exit(kprobe_ph_exit);

MODULE_LICENSE("GPL");
