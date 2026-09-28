// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bpf_coexist_users.c - Userspace loader for BPF Ftrace Consumers (Users C, D, F, K)
 *
 * Prepared for LPC 2026 Livepatching Microconference.
 *
 * Usage:
 *   bpf_coexist_users <override|fmod_ret|fexit|fentry> [--retval <err>] [--hold]
 *     (fmod_ret with --retval 1 passes through: returns 0 and calls the function)
 *
 * Signals supported in --hold mode:
 *   SIGUSR2 : Reset hit counters in .bss (preserving inject_retval), emit LPC26_RESET: OK
 *   SIGUSR1 : Read and emit LPC26_HITS: override=<n> fmod_ret=<n> fexit=<n> fentry=<n> ...
 *   SIGTERM / SIGINT : Emit LPC26_HITS, detach, and exit cleanly.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define BPF_OBJ_FILE	"bpf_coexist_users.bpf.o"

struct lpc26_state {
	__s64 inject_retval;
	__u64 override_hits;
	__u64 fmod_ret_hits;
	__u64 fexit_hits;
	__u64 fentry_hits;
	__s64 fexit_last_ret;
	__u64 last_traced_ip;
};

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t dump_req;
static volatile sig_atomic_t reset_req;

static void sig_handler(int sig)
{
	if (sig == SIGUSR1)
		dump_req = 1;
	else if (sig == SIGUSR2)
		reset_req = 1;
	else
		exiting = 1;
}

static int libbpf_quiet(enum libbpf_print_level level, const char *fmt,
			va_list args)
{
	if (level == LIBBPF_WARN)
		return vfprintf(stderr, fmt, args);
	return 0;
}

static void write_state(struct bpf_object *obj, const struct lpc26_state *st)
{
	struct bpf_map *bss = bpf_object__find_map_by_name(obj, ".bss");
	unsigned char *buf;
	size_t value_size;
	__u32 key = 0;

	if (!bss)
		return;
	value_size = bpf_map__value_size(bss);
	buf = calloc(1, value_size);
	if (!buf)
		return;
	memcpy(buf, st, value_size < sizeof(*st) ? value_size : sizeof(*st));
	bpf_map__update_elem(bss, &key, sizeof(key), buf, value_size, 0);
	free(buf);
}

static void read_state(struct bpf_object *obj, struct lpc26_state *st)
{
	struct bpf_map *bss = bpf_object__find_map_by_name(obj, ".bss");
	unsigned char *buf;
	size_t value_size;
	__u32 key = 0;

	memset(st, 0, sizeof(*st));
	if (!bss)
		return;
	value_size = bpf_map__value_size(bss);
	buf = calloc(1, value_size);
	if (!buf)
		return;
	if (!bpf_map__lookup_elem(bss, &key, sizeof(key), buf, value_size, 0))
		memcpy(st, buf,
		       value_size < sizeof(*st) ? value_size : sizeof(*st));
	free(buf);
}

static void report_hits(struct bpf_object *obj)
{
	struct lpc26_state st;

	read_state(obj, &st);
	printf("LPC26_HITS: override=%llu fmod_ret=%llu fexit=%llu fentry=%llu fexit_last_ret=%lld traced_ip=0x%llx\n",
	       (unsigned long long)st.override_hits,
	       (unsigned long long)st.fmod_ret_hits,
	       (unsigned long long)st.fexit_hits,
	       (unsigned long long)st.fentry_hits,
	       (long long)st.fexit_last_ret,
	       (unsigned long long)st.last_traced_ip);
	fflush(stdout);
}

static void reset_hits(struct bpf_object *obj, __s64 inject_retval)
{
	struct lpc26_state st = {
		.inject_retval = inject_retval,
	};

	write_state(obj, &st);
	printf("LPC26_RESET: OK\n");
	fflush(stdout);
}

int main(int argc, char **argv)
{
	const char *prog_name, *mode;
	struct bpf_program *prog, *iter;
	struct bpf_object *obj;
	struct bpf_link *link;
	__s64 inject_retval = 0;
	bool hold = false;
	int i, err, ret = 1;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s <override|fmod_ret|fexit|fentry> [--retval <err>] [--hold]\n",
			argv[0]);
		return 2;
	}

	mode = argv[1];
	if (!strcmp(mode, "override")) {
		prog_name = "kprobe_override_cmdline_proc_show";
		inject_retval = -22; /* default -EINVAL */
	} else if (!strcmp(mode, "fmod_ret")) {
		prog_name = "fmod_ret_cmdline_proc_show";
		inject_retval = -1;  /* default -EPERM */
	} else if (!strcmp(mode, "fexit")) {
		prog_name = "fexit_cmdline_proc_show";
		inject_retval = 0;
	} else if (!strcmp(mode, "fentry")) {
		prog_name = "fentry_cmdline_proc_show";
		inject_retval = 0;
	} else {
		fprintf(stderr, "unknown mode: %s\n", mode);
		return 2;
	}

	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--hold")) {
			hold = true;
		} else if (!strcmp(argv[i], "--retval") && i + 1 < argc) {
			inject_retval = strtoll(argv[++i], NULL, 0);
		} else {
			fprintf(stderr, "unknown arg: %s\n", argv[i]);
			return 2;
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGUSR1, sig_handler);
	signal(SIGUSR2, sig_handler);
	libbpf_set_print(libbpf_quiet);

	obj = bpf_object__open_file(BPF_OBJ_FILE, NULL);
	if (!obj) {
		fprintf(stderr, "[-] bpf_object__open_file(%s) failed: %s\n",
			BPF_OBJ_FILE, strerror(errno));
		return 1;
	}

	bpf_object__for_each_program(iter, obj)
		bpf_program__set_autoload(iter,
			!strcmp(bpf_program__name(iter), prog_name));

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "[-] bpf_object__load failed: %d (%s)\n",
			err, strerror(-err));
		goto out_close;
	}

	reset_hits(obj, inject_retval);

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "[-] program %s not found in %s\n",
			prog_name, BPF_OBJ_FILE);
		goto out_close;
	}

	link = bpf_program__attach(prog);
	if (!link) {
		err = -errno;
		printf("LPC26_ATTACH: FAIL errno=%d (%s)\n", err,
		       strerror(-err));
		fflush(stdout);
		goto out_close;
	}

	printf("LPC26_ATTACH: OK\n");
	fflush(stdout);

	if (hold) {
		while (!exiting) {
			pause();
			if (reset_req) {
				reset_req = 0;
				reset_hits(obj, inject_retval);
			}
			if (dump_req) {
				dump_req = 0;
				report_hits(obj);
			}
		}
	} else {
		if (system("cat /proc/cmdline > /dev/null 2>&1") == -1)
			fprintf(stderr, "[!] trigger failed: %s\n",
				strerror(errno));
	}

	report_hits(obj);
	bpf_link__destroy(link);
	ret = 0;

out_close:
	bpf_object__close(obj);
	return ret;
}
