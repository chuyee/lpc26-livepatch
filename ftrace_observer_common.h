/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ftrace_observer_common.h - Shared implementation for User J (Class 3 Passive Observer)
 *
 * Included by ftrace_observer_user<N>.c; OBSERVER_USER_SLOT selects the slot so
 * additional independent passive ftrace_ops consumers (.flags = 0) can be
 * added for J x J tests.
 */

#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

static char *target_func = "cmdline_proc_show";
module_param(target_func, charp, 0444);
MODULE_PARM_DESC(target_func, "Target function to observe (default: cmdline_proc_show)");

static unsigned long hits;
module_param(hits, ulong, 0644);
MODULE_PARM_DESC(hits, "Number of times passive ftrace callback executed");

static unsigned long last_ip;
module_param(last_ip, ulong, 0644);
MODULE_PARM_DESC(last_ip, "Instruction pointer (ip) passed to passive ftrace callback");

static unsigned long last_regs_ip;
module_param(last_regs_ip, ulong, 0644);
MODULE_PARM_DESC(last_regs_ip, "ftrace_regs instruction pointer seen at entry (new_func if an older IPMODIFY handler already redirected)");

static void notrace observer_ftrace_handler(unsigned long ip,
					    unsigned long parent_ip,
					    struct ftrace_ops *fops,
					    struct ftrace_regs *fregs)
{
	WRITE_ONCE(hits, READ_ONCE(hits) + 1);
	WRITE_ONCE(last_ip, ip);
	WRITE_ONCE(last_regs_ip, fregs ? ftrace_regs_get_instruction_pointer(fregs) : 0);
}

/*
 * Canonical Class 3 Passive Observer: .flags = 0 (no IPMODIFY, no DIRECT, no SAVE_REGS).
 */
static struct ftrace_ops observer_ops = {
	.func = observer_ftrace_handler,
};

static int __init observer_user_init(void)
{
	int ret;

	ret = ftrace_set_filter(&observer_ops, (unsigned char *)target_func,
				strlen(target_func), 0);
	if (ret) {
		pr_err("ftrace_set_filter failed: %d\n", ret);
		return ret;
	}

	ret = register_ftrace_function(&observer_ops);
	if (ret) {
		pr_err("register_ftrace_function failed: %d\n", ret);
		ftrace_free_filter(&observer_ops);
		return ret;
	}

	pr_info("Passive ftrace_ops observer #%d registered on %s\n",
		OBSERVER_USER_SLOT, target_func);
	return 0;
}

static void __exit observer_user_exit(void)
{
	unregister_ftrace_function(&observer_ops);
	ftrace_free_filter(&observer_ops);
	pr_info("Passive ftrace_ops observer #%d unregistered from %s (hits=%lu)\n",
		OBSERVER_USER_SLOT, target_func, READ_ONCE(hits));
}

module_init(observer_user_init);
module_exit(observer_user_exit);

MODULE_LICENSE("GPL");
