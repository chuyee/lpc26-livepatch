// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * fprobe_exit_user.c - User I: Class 2 Stack Interceptor (fprobe with exit_handler)
 *
 * Registers an fprobe with a non-NULL exit_handler on cmdline_proc_show.
 * Because fp.exit_handler != NULL, fprobe_is_ftrace(&fp) is false, so fprobe
 * attaches via fprobe_graph_ops (register_ftrace_graph + return_to_handler).
 */

#include <linux/fprobe.h>
#include <linux/kernel.h>
#include <linux/module.h>

static char *target_func = "cmdline_proc_show";
module_param(target_func, charp, 0444);
MODULE_PARM_DESC(target_func, "Symbol to probe (default: cmdline_proc_show)");

static unsigned long hits;
module_param(hits, ulong, 0644);
MODULE_PARM_DESC(hits, "Number of times fprobe exit_handler executed");

static unsigned long last_ip;
module_param(last_ip, ulong, 0644);
MODULE_PARM_DESC(last_ip, "entry_ip passed to fprobe exit_handler");

static long last_ret;
module_param(last_ret, long, 0644);
MODULE_PARM_DESC(last_ret, "Return value observed by fprobe exit_handler");

static unsigned long last_regs_ip;
module_param(last_regs_ip, ulong, 0644);
MODULE_PARM_DESC(last_regs_ip, "ftrace_regs instruction pointer seen at entry (new_func if an older IPMODIFY handler already redirected)");

static int lpc26_fprobe_exit_entry(struct fprobe *fp, unsigned long entry_ip,
				   unsigned long ret_ip,
				   struct ftrace_regs *fregs, void *entry_data)
{
	WRITE_ONCE(last_ip, entry_ip);
	WRITE_ONCE(last_regs_ip, fregs ? ftrace_regs_get_instruction_pointer(fregs) : 0);
	return 0;
}

static void lpc26_fprobe_exit_handler(struct fprobe *fp, unsigned long entry_ip,
				      unsigned long ret_ip,
				      struct ftrace_regs *fregs,
				      void *entry_data)
{
	WRITE_ONCE(hits, READ_ONCE(hits) + 1);
	WRITE_ONCE(last_ip, entry_ip);
	WRITE_ONCE(last_ret, (long)ftrace_regs_get_return_value(fregs));
}

static struct fprobe fp = {
	.entry_handler = lpc26_fprobe_exit_entry,
	.exit_handler  = lpc26_fprobe_exit_handler,
};

static int __init fprobe_exit_user_init(void)
{
	int ret;

	ret = register_fprobe(&fp, target_func, NULL);
	if (ret) {
		pr_warn("register_fprobe(%s, with exit_handler) failed: %d\n",
			target_func, ret);
		return ret;
	}
	pr_info("registered fprobe (with exit_handler) on %s\n", target_func);
	return 0;
}

static void __exit fprobe_exit_user_exit(void)
{
	unregister_fprobe(&fp);
	pr_info("unregistered fprobe (with exit_handler) from %s (hits=%lu)\n",
		target_func, READ_ONCE(hits));
}

module_init(fprobe_exit_user_init);
module_exit(fprobe_exit_user_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LPC 2026 Coexistence Demo - User I (Class 2 fprobe with exit_handler)");
