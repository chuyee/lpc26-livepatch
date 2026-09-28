// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * klp_user2.c - Second Livepatch Module for A x A (klp stacking) Coexistence Test
 *
 * Prepared for LPC 2026 Livepatching Microconference:
 * "Ftrace Consumer Classification & Coexistence"
 *
 * Demonstrates:
 *  - When a second livepatch targets the same function (cmdline_proc_show),
 *    klp_patch_func() finds the existing klp_ops via klp_find_ops(func->old_func)
 *    and appends the new klp_func to ops->func_stack WITHOUT calling
 *    register_ftrace_function() a second time.
 *  - Only ONE ftrace_ops (with FTRACE_OPS_FL_IPMODIFY) remains registered at
 *    the call site, and klp_ftrace_handler() dispatches to the top of
 *    ops->func_stack (livepatch2_cmdline_proc_show).
 */

#define pr_fmt(fmt) "lpc26_klp_user2: " fmt

#include <linux/error-injection.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/module.h>
#include <linux/seq_file.h>

static unsigned long hits;
module_param(hits, ulong, 0644);
MODULE_PARM_DESC(hits, "Number of times livepatch2_cmdline_proc_show executed");

int livepatch2_cmdline_proc_show(struct seq_file *m, void *v);

noinline int livepatch2_cmdline_proc_show(struct seq_file *m, void *v)
{
	WRITE_ONCE(hits, READ_ONCE(hits) + 1);
	seq_puts(m, "=== [LPC 2026] CLASS 1 MUTATOR #2 ACTIVE ===\n");
	seq_puts(m, "Mechanism: klp ops->func_stack stacking (single ftrace_ops)\n");
	return 0;
}
ALLOW_ERROR_INJECTION(livepatch2_cmdline_proc_show, ERRNO);

static struct klp_func funcs[] = {
	{
		.old_name = "cmdline_proc_show",
		.new_func = livepatch2_cmdline_proc_show,
	}, { }
};

static struct klp_object objs[] = {
	{
		.name = NULL,
		.funcs = funcs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

static int __init klp_user2_init(void)
{
	int ret;

	ret = klp_enable_patch(&patch);
	if (ret) {
		pr_err("klp_enable_patch failed: %d\n", ret);
		return ret;
	}
	pr_info("Livepatch #2 enabled on cmdline_proc_show.\n");
	return 0;
}

static void __exit klp_user2_exit(void)
{
	pr_info("Livepatch #2 module exit.\n");
}

module_init(klp_user2_init);
module_exit(klp_user2_exit);

MODULE_DESCRIPTION("LPC 2026 Livepatch User #2 (klp func_stack stacking)");
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
