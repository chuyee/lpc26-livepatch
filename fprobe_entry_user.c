// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * fprobe_entry_user.c - User L: Class 3 Passive Observer (fprobe without exit_handler)
 *
 * Registers an fprobe with entry_handler only (exit_handler == NULL) on
 * cmdline_proc_show. Because fp.exit_handler == NULL, fprobe_is_ftrace(&fp) is
 * true, so fprobe attaches via fprobe_ftrace_ops (FTRACE_OPS_FL_SAVE_ARGS).
 */

#include <linux/fprobe.h>
#include <linux/kernel.h>
#include <linux/module.h>

static char *target_func = "cmdline_proc_show";
module_param(target_func, charp, 0444);
MODULE_PARM_DESC(target_func, "Symbol to probe (default: cmdline_proc_show)");

static unsigned long hits;
module_param(hits, ulong, 0644);
MODULE_PARM_DESC(hits, "Number of times fprobe entry_handler executed");

static unsigned long last_ip;
module_param(last_ip, ulong, 0644);
MODULE_PARM_DESC(last_ip, "entry_ip passed to fprobe entry_handler");

static unsigned long last_regs_ip;
module_param(last_regs_ip, ulong, 0644);
MODULE_PARM_DESC(last_regs_ip, "ftrace_regs instruction pointer seen at entry (new_func if an older IPMODIFY handler already redirected)");

static int lpc26_fprobe_only_entry(struct fprobe *fp, unsigned long entry_ip,
				   unsigned long ret_ip,
				   struct ftrace_regs *fregs, void *entry_data)
{
	WRITE_ONCE(hits, READ_ONCE(hits) + 1);
	WRITE_ONCE(last_ip, entry_ip);
	WRITE_ONCE(last_regs_ip, fregs ? ftrace_regs_get_instruction_pointer(fregs) : 0);
	return 0;
}

static struct fprobe fp = {
	.entry_handler = lpc26_fprobe_only_entry,
	.exit_handler  = NULL,
};

static int __init fprobe_entry_user_init(void)
{
	int ret;

	ret = register_fprobe(&fp, target_func, NULL);
	if (ret) {
		pr_warn("register_fprobe(%s, entry-only) failed: %d\n",
			target_func, ret);
		return ret;
	}
	pr_info("registered fprobe (no exit_handler) on %s\n", target_func);
	return 0;
}

static void __exit fprobe_entry_user_exit(void)
{
	unregister_fprobe(&fp);
	pr_info("unregistered fprobe (no exit_handler) from %s (hits=%lu)\n",
		target_func, READ_ONCE(hits));
}

module_init(fprobe_entry_user_init);
module_exit(fprobe_entry_user_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LPC 2026 Coexistence Demo - User L (Class 3 fprobe without exit_handler)");
