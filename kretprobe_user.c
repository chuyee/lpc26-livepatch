// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kretprobe_user.c - User H: Class 2 Stack Interceptor (kretprobe / rethook)
 *
 * Registers a kretprobe on cmdline_proc_show. Under CONFIG_KPROBES_ON_FTRACE
 * and CONFIG_KRETPROBE_ON_RETHOOK, rp.kp.post_handler is NULL, so
 * arm_kprobe_ftrace() attaches via kprobe_ftrace_ops (SAVE_REGS, no IPMODIFY)
 * and replaces stack[0] with arch_rethook_trampoline.
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
MODULE_PARM_DESC(hits, "Number of times kretprobe return handler executed");

static unsigned long last_ip;
module_param(last_ip, ulong, 0644);
MODULE_PARM_DESC(last_ip, "Probed address (rp->kp.addr) observed at entry");

static long last_ret;
module_param(last_ret, long, 0644);
MODULE_PARM_DESC(last_ret, "Return value observed by kretprobe return handler");

static int lpc26_kretprobe_entry(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct kretprobe *rp = get_kretprobe(ri);

	if (rp)
		WRITE_ONCE(last_ip, (unsigned long)rp->kp.addr);
	return 0;
}

static int lpc26_kretprobe_ret(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	WRITE_ONCE(hits, READ_ONCE(hits) + 1);
	WRITE_ONCE(last_ret, regs_return_value(regs));
	return 0;
}

static struct kretprobe rp = {
	.entry_handler = lpc26_kretprobe_entry,
	.handler       = lpc26_kretprobe_ret,
	.maxactive     = 32,
};

static int __init kretprobe_user_init(void)
{
	int ret;

	rp.kp.symbol_name = target_func;
	ret = register_kretprobe(&rp);
	if (ret) {
		pr_warn("register_kretprobe(%s) failed: %d\n", target_func, ret);
		return ret;
	}
	pr_info("registered kretprobe on %s\n", target_func);
	return 0;
}

static void __exit kretprobe_user_exit(void)
{
	unregister_kretprobe(&rp);
	pr_info("unregistered kretprobe from %s (hits=%lu)\n",
		target_func, READ_ONCE(hits));
}

module_init(kretprobe_user_init);
module_exit(kretprobe_user_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LPC 2026 Coexistence Demo - User H (Class 2 kretprobe/rethook)");
