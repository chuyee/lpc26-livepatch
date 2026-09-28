// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kprobe_entry_user.c - User M: Class 3 Passive Observer (kprobe without post_handler)
 *
 * Registers a kprobe with pre_handler only (post_handler == NULL) on
 * cmdline_proc_show. Because kp.post_handler == NULL, arm_kprobe_ftrace()
 * selects kprobe_ftrace_ops (FTRACE_OPS_FL_SAVE_REGS, NO IPMODIFY).
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>

static char *target_func = "cmdline_proc_show";
module_param(target_func, charp, 0444);
MODULE_PARM_DESC(target_func, "Symbol to probe (default: cmdline_proc_show)");

static unsigned long hits;
module_param(hits, ulong, 0644);
MODULE_PARM_DESC(hits, "Number of times kprobe pre_handler executed");

static unsigned long last_ip;
module_param(last_ip, ulong, 0644);
MODULE_PARM_DESC(last_ip, "Probed address (p->addr) observed by pre_handler");

static int lpc26_kp_entry_pre(struct kprobe *p, struct pt_regs *regs)
{
	WRITE_ONCE(hits, READ_ONCE(hits) + 1);
	WRITE_ONCE(last_ip, (unsigned long)p->addr);
	return 0;
}

static struct kprobe kp = {
	.pre_handler  = lpc26_kp_entry_pre,
	.post_handler = NULL,
};

static int __init kprobe_entry_user_init(void)
{
	int ret;

	kp.symbol_name = target_func;
	ret = register_kprobe(&kp);
	if (ret) {
		pr_warn("register_kprobe(%s, no post_handler) failed: %d\n",
			target_func, ret);
		return ret;
	}
	pr_info("registered kprobe (no post_handler) on %s\n", target_func);
	return 0;
}

static void __exit kprobe_entry_user_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("unregistered kprobe (no post_handler) from %s (hits=%lu)\n",
		target_func, READ_ONCE(hits));
}

module_init(kprobe_entry_user_init);
module_exit(kprobe_entry_user_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LPC 2026 Coexistence Demo - User M (Class 3 kprobe without post_handler)");
