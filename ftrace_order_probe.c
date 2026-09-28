// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ftrace_order_probe.c - Measure ftrace_ops handler invocation order and the
 * instruction pointer each handler sees on a shared ftrace call site.
 *
 * Two passive ftrace_ops ("a" and "b") on cmdline_proc_show that can be
 * registered/unregistered independently at runtime, interleaved with other
 * consumers (klp, kprobes, ...):
 *
 *   echo a  > /sys/module/ftrace_order_probe/parameters/reg    # register a
 *   echo -a > /sys/module/ftrace_order_probe/parameters/reg    # unregister a
 *
 * Each handler records:
 *   {a,b}_seq  : global invocation sequence number (higher = ran later)
 *   {a,b}_ip   : ftrace_regs_get_instruction_pointer(fregs) at the time it ran,
 *                i.e. where execution will resume if nobody changes it again
 *   {a,b}_hits : number of invocations
 */

#define pr_fmt(fmt) "ftrace_order_probe: " fmt

#include <linux/atomic.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>

static char *target_func = "cmdline_proc_show";
module_param(target_func, charp, 0444);

static atomic_long_t order_counter = ATOMIC_LONG_INIT(0);

static unsigned long seq[2], seen_ip[2], hits[2];
module_param_named(a_seq, seq[0], ulong, 0644);
module_param_named(b_seq, seq[1], ulong, 0644);
module_param_named(a_ip, seen_ip[0], ulong, 0644);
module_param_named(b_ip, seen_ip[1], ulong, 0644);
module_param_named(a_hits, hits[0], ulong, 0644);
module_param_named(b_hits, hits[1], ulong, 0644);

static void notrace order_handler(int idx, struct ftrace_regs *fregs)
{
	WRITE_ONCE(seq[idx], atomic_long_inc_return(&order_counter));
	WRITE_ONCE(seen_ip[idx],
		   fregs ? ftrace_regs_get_instruction_pointer(fregs) : 0);
	WRITE_ONCE(hits[idx], READ_ONCE(hits[idx]) + 1);
}

static void notrace handler_a(unsigned long ip, unsigned long parent_ip,
			      struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	order_handler(0, fregs);
}

static void notrace handler_b(unsigned long ip, unsigned long parent_ip,
			      struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	order_handler(1, fregs);
}

/* Plain passive ops: no IPMODIFY, no DIRECT, no SAVE_REGS. */
static struct ftrace_ops probe_ops[2] = {
	{ .func = handler_a },
	{ .func = handler_b },
};
static bool registered[2];
static DEFINE_MUTEX(reg_lock);

static int reg_set(const char *val, const struct kernel_param *kp)
{
	bool unreg = false;
	int idx, ret = 0;

	if (*val == '-') {
		unreg = true;
		val++;
	}
	switch (*val) {
	case 'a': idx = 0; break;
	case 'b': idx = 1; break;
	default: return -EINVAL;
	}

	mutex_lock(&reg_lock);
	if (unreg && registered[idx]) {
		ret = unregister_ftrace_function(&probe_ops[idx]);
		if (!ret)
			registered[idx] = false;
	} else if (!unreg && !registered[idx]) {
		ret = register_ftrace_function(&probe_ops[idx]);
		if (!ret)
			registered[idx] = true;
	}
	mutex_unlock(&reg_lock);
	if (ret)
		pr_err("%sregister %c failed: %d\n", unreg ? "un" : "", 'a' + idx, ret);
	return ret;
}

static const struct kernel_param_ops reg_ops = {
	.set = reg_set,
};
module_param_cb(reg, &reg_ops, NULL, 0200);
MODULE_PARM_DESC(reg, "a|b register, -a|-b unregister");

static int __init order_probe_init(void)
{
	int i, ret;

	for (i = 0; i < 2; i++) {
		ret = ftrace_set_filter(&probe_ops[i], (unsigned char *)target_func,
					strlen(target_func), 0);
		if (ret) {
			while (--i >= 0)
				ftrace_free_filter(&probe_ops[i]);
			return ret;
		}
	}
	return 0;
}

static void __exit order_probe_exit(void)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (registered[i])
			unregister_ftrace_function(&probe_ops[i]);
		ftrace_free_filter(&probe_ops[i]);
	}
}

module_init(order_probe_init);
module_exit(order_probe_exit);

MODULE_DESCRIPTION("LPC 2026: ftrace_ops invocation order probe");
MODULE_LICENSE("GPL");
