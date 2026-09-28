// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * klp_sample_mutator.c - Canonical Class 1 Mutator Sample (Kernel Livepatching)
 *
 * Prepared for LPC 2026 Livepatching Microconference:
 * "Ftrace Consumer Classification & Coexistence"
 *
 * Demonstrates:
 *  - Class 1: Mutator behavior.
 *  - Ftrace mechanism: FTRACE_OPS_FL_IPMODIFY (klp adds FTRACE_OPS_FL_SAVE_REGS
 *    only on architectures without CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS; on
 *    x86_64 it uses ftrace_regs, so enabled_functions shows "IM", not "RIM").
 *  - Full Redirection: Alters regs->ip to new_func, completely skipping orig_func.
 *  - Exclusivity: Enforces exclusive ownership of the call site (max 1 per function).
 */

#define pr_fmt(fmt) "lpc26_klp_mutator: " fmt

#include <linux/error-injection.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/seq_file.h>

/*
 * Target function: cmdline_proc_show
 * In vmlinux, cmdline_proc_show() prints the boot command line to /proc/cmdline.
 *
 * Mutator Replacement:
 * livepatch_cmdline_proc_show completely replaces the original body.
 */
int livepatch_cmdline_proc_show(struct seq_file *m, void *v);

/*
 * Return value for livepatch_cmdline_proc_show(), normally 0.
 *
 * cmdline_proc_show() is a seq_file ->show() callback and can only ever
 * return 0. Setting magic_ret to a distinctive value lets the runner's
 * return-value probe (probe_return_values() in lib_coexist.sh) prove that a
 * return hook attached to orig_func is really reporting *new_func's* return
 * value - with both functions returning 0 the mis-attribution is invisible.
 *
 * Deliberately not the default: seq_read_iter() treats any positive ->show()
 * return as "skip this record" (fs/seq_file.c, 'err > 0' -> m->count = offs),
 * so /proc/cmdline reads back EMPTY while this is armed. The runner arms it
 * only around that single probe.
 */
static int magic_ret;
module_param(magic_ret, int, 0644);
MODULE_PARM_DESC(magic_ret,
		 "Return value for livepatch_cmdline_proc_show (default 0). Positive makes /proc/cmdline read empty; negative surfaces as a read() error.");

static unsigned long hits;
module_param(hits, ulong, 0644);
MODULE_PARM_DESC(hits, "Number of times livepatch_cmdline_proc_show executed");

noinline int livepatch_cmdline_proc_show(struct seq_file *m, void *v)
{
	WRITE_ONCE(hits, READ_ONCE(hits) + 1);
	seq_puts(m, "=== [LPC 2026] CLASS 1 MUTATOR ACTIVE ===\n");
	seq_puts(m, "Mechanism: ftrace IPMODIFY (klp_ftrace_handler)\n");
	seq_printf(m, "Effect   : regs->ip altered to %pS; orig_func body SKIPPED!\n",
		   livepatch_cmdline_proc_show);
	seq_printf(m, "Callsite : %pS [mutated]\n", livepatch_cmdline_proc_show);
	return magic_ret;
}

/*
 * new_func is whitelisted for error injection as well as orig_func (see
 * patches/0002-*.patch). That is what makes "spatial decoupling" of Class 1
 * consumers testable: a second Class 1 consumer that is rejected with -EBUSY
 * on cmdline_proc_show can instead attach to livepatch_cmdline_proc_show,
 * because new_func has its own independent fentry site that no IPMODIFY ops
 * owns yet.
 */
ALLOW_ERROR_INJECTION(livepatch_cmdline_proc_show, ERRNO);

static struct klp_func funcs[] = {
	{
		.old_name = "cmdline_proc_show",
		.new_func = livepatch_cmdline_proc_show,
	}, { }
};

static struct klp_object objs[] = {
	{
		/* name NULL designates vmlinux */
		.name = NULL,
		.funcs = funcs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

static int __init klp_mutator_init(void)
{
	int ret;

	pr_info("Initializing Canonical Class 1 Mutator (klp)\n");
	pr_info("Target function: cmdline_proc_show\n");
	pr_info("Registration flags under the hood: FTRACE_OPS_FL_IPMODIFY%s\n",
		IS_ENABLED(CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS) ?
		" (ftrace_regs, no SAVE_REGS)" : " | FTRACE_OPS_FL_SAVE_REGS");

	ret = klp_enable_patch(&patch);
	if (ret) {
		pr_err("klp_enable_patch failed: %d (check if another IPMODIFY consumer is attached)\n", ret);
		return ret;
	}

	pr_info("Livepatch enabled. Read /proc/cmdline to observe execution mutation.\n");
	return 0;
}

static void __exit klp_mutator_exit(void)
{
	pr_info("Livepatch module exit requested.\n");
}

module_init(klp_mutator_init);
module_exit(klp_mutator_exit);

MODULE_DESCRIPTION("LPC 2026 Class 1 Mutator Sample (Kernel Livepatching)");
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
