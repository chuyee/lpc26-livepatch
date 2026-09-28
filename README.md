# LPC 2026: Ftrace Consumer Classification & Livepatch (`klp`) Coexistence Suite

Standalone empirical test suite and reference documentation for the **LPC 2026 Livepatching & Tracing** presentation:
**"Ftrace Consumer Classification & Livepatch Coexistence"**.

This repository tests **Kernel Livepatching (`klp`)** against all **14 distinct ftrace attach mechanisms (`A`–`N`)** across **Class 1 (Execution Mutators)**, **Class 2 (Stack Interceptors)**, and **Class 3 (Passive Observers)** on a single target function (`cmdline_proc_show`, `orig_func`) in two attachment orders (`2 × 14 = 28` scenarios):

- **Scenario 1 (`klp` as Contender)**: Peer consumer (`A`–`N`) attaches first as **Incumbent**; `klp` (`A`) attaches second as **Contender**.
- **Scenario 2 (`klp` as Incumbent)**: `klp` (`A`) attaches first as **Incumbent**; Peer consumer (`A`–`N`) attaches second as **Contender**.

---

## 1. The 14 Ftrace Consumers (`A`–`N`)

| ID | Class | Consumer | Mechanism / Source | `enabled_functions` | Standalone Behavior on `/proc/cmdline` |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **A** | **Class 1: Mutator** | **Kernel Livepatching (`klp`)** | `klp_sample_mutator.ko` (`klp_user2.ko` for `A×A`) | `1:I` | Redirects `regs->ip` to `livepatch_cmdline_proc_show` (`new_func`) |
| **B** | **Class 1: Mutator** | **`fail_function` error injection** | `/sys/kernel/debug/fail_function` (`kprobe_ipmodify_ops`) | `1:RI` | Short-circuits body (`just_return_func`); `cat /proc/cmdline` fails with `-EIO` (`-5`) |
| **C** | **Class 1: Mutator** | **BPF `bpf_override_return`** | `bpf_coexist_users` (`SEC("kprobe/cmdline_proc_show")`) | `1:R` | Short-circuits body (`just_return_func`) **without** `IPMODIFY`; returns `-EINVAL` (`-22`) |
| **D** | **Class 1: Mutator** | **BPF `fmod_ret` / BPF LSM** | `bpf_coexist_users` (`SEC("fmod_ret/cmdline_proc_show")`) | `1:RD` | Branches past `call orig_func` in BPF trampoline; returns `-EPERM` (`-1`) |
| **E** | **Class 1: Mutator** | **Kprobes-on-ftrace + `post_handler`** | `kprobe_ph_user1.ko` | `1:RI` | Sets `kprobe_ipmodify_ops` (`post_handler != NULL`); emulated single-step, ip restored; increments `pre_hits` & `post_hits` |
| **F** | **Class 2: Interceptor** | **BPF `fexit`** | `bpf_coexist_users` (`SEC("fexit/cmdline_proc_show")`) | `1:RD` | Hooks exit via `BPF_TRAMP_F_CALL_ORIG`; negotiates `SHARE_IPMODIFY` |
| **G** | **Class 2: Interceptor** | **Function graph tracer (`fgraph`)** | `tracefs` (`current_tracer = function_graph`) | `1:none` | Hijacks stack return address via `return_to_handler` to record duration |
| **H** | **Class 2: Interceptor** | **`kretprobe` / `rethook`** | `kretprobe_user.ko` (`register_kretprobe`) | `1:R` | Replaces stack return address with `arch_rethook_trampoline`; counts `entry_hits` & `ret_hits` |
| **I** | **Class 2: Interceptor** | **`fprobe` (with `exit_handler`)** | `fprobe_exit_user.ko` (`fprobe_graph_ops`) | `1:none` | Registers `fprobe` backed by `fgraph`; counts `entry_hits` & `exit_hits` |
| **J** | **Class 3: Observer** | **Passive `ftrace_ops`** (same mechanism as perf function events) | `ftrace_observer_user1.ko` | `1:none` | Standard read-only `ftrace_ops` entry callback; increments `hits` |
| **K** | **Class 3: Observer** | **BPF `fentry`** | `bpf_coexist_users` (`SEC("fentry/cmdline_proc_show")`) | `1:RD` | Read-only JITed BPF trampoline at entry; increments `hits` |
| **L** | **Class 3: Observer** | **`fprobe` (no `exit_handler`)** | `fprobe_entry_user.ko` (`FTRACE_OPS_FL_SAVE_ARGS`) | `1:none` | Entry-only `fprobe` (`fprobe_ftrace_ops`); increments `entry_hits` |
| **M** | **Class 3: Observer** | **Kprobes-on-ftrace (no `post_handler`)** | `kprobe_entry_user.ko` (`kprobe_ftrace_ops`) | `1:R` | Entry-only `kprobe` without `IPMODIFY`; increments `pre_hits` |
| **N** | **Class 3: Observer** | **Core `function` tracer\*** | `tracefs` (`current_tracer = function`) | `1:none` | Logs `cmdline_proc_show <- seq_read_iter` in `/sys/kernel/tracing/trace` |

*\*Note: `irqsoff`/`wakeup` latency tracers (default mode), `stack_tracer` and `pstore` attach via the same standard `ftrace_ops` entry callback as **User N** (not run by the suite). The function profiler (`function_profile_enabled`) and latency tracers with `display-graph` use fgraph like **G** (Class 2).*

*The `enabled_functions` column shows each consumer alone, with the sticky `M` bit stripped (`1:none` = no flags).*

**`enabled_functions` format (`<count>:<flags>`)**: Parsed from `/sys/kernel/tracing/enabled_functions` (`t_show()` in `kernel/trace/ftrace.c`), where `<count>` is `ftrace_rec_count(rec)` and `<flags>` are the `struct dyn_ftrace` record flags (`include/linux/ftrace.h`):
- **`R` (`FTRACE_FL_REGS`)**: Callsite saves full `struct pt_regs` (`FTRACE_OPS_FL_SAVE_REGS`, used by `kprobes` and `direct_ops`). On x86_64 with `CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS=y`, `klp` (**A**), `fprobe` (**I**, **L**), and plain `ftrace_ops` (**G**, **J**, **N**) use `ftrace_regs` without `R`.
- **`I` (`FTRACE_FL_IPMODIFY`)**: An attached `ftrace_ops` set `FTRACE_OPS_FL_IPMODIFY` (**A**: `klp`, **B**: `fail_function`, **E**: `kprobe + post_handler`).
- **`D` (`FTRACE_FL_DIRECT`)**: A direct trampoline (`register_ftrace_direct`, used by BPF trampolines **D**: `fmod_ret`, **F**: `fexit`, **K**: `fentry`) is attached.
- **`M` (`FTRACE_FL_MODIFIED`)**: Sticky history flag (`FTRACE_NOCLEAR_FLAGS`) set once the function has had `I` (`IPMODIFY`) or `D` (`DIRECT`) attached since boot.

---

## 2. Empirical `klp` Coexistence & Contention Results (`2 × 14 = 28` Scenarios)

Every label is **measured**: which mutator's result surfaced on one `read(/proc/cmdline)`, each consumer's hit counter, and — for return hooks — the return value they report while `new_func` is made to return `7` (`klp_sample_mutator` `magic_ret`).

- **`Self`**: the second livepatch's `new_func2` surfaced (it stacks onto `klp_ops->func_stack`; no second `ftrace_ops`).
- **`-EBUSY`**: Contender registration failed with that errno (the real errno is reported); incumbent keeps its behavior.
- **`Override`**: registration returned `0` and the **contender's** result surfaced.
- **`Suppressed`**: registration returned `0` and the **incumbent's** result surfaced. For **C**, "incumbent" means the *older `ftrace_ops`* (see section 3); for **D**, both labels describe one outcome — D wins in either order.
- **`OK`**: `klp` ran `new_func` and the peer's return hook reported `new_func`'s return value (`ret=7`) — **F**, **H** and **I** alike, with or without `SHARE_IPMODIFY` negotiation.
- **`Stale Symbols`**: `klp` ran `new_func`; the peer fired but attributes the call to `orig_func` (`cmdline_proc_show`). All of **F**–**N** file the *entry* under `orig_func`.
- **`†`** (redirect visible): the peer's entry handler read `ftrace_regs_get_instruction_pointer() == new_func` (module param `last_regs_ip`). Recorded only by **I**, **J**, **L**: `new_func` in Scenario 1 (peer's `ftrace_ops` is older, so it runs after `klp`), `orig_func` in Scenario 2. **E**/**H**/**M** cannot see it (`kprobe_ftrace_handler()` sets `regs->ip = addr + 1` around user handlers); **G**/**N** record only the `ip` argument; **K** is outside the `ftrace_ops` list. Such an observer could attribute each call by checking `fregs` ip `!= ip + MCOUNT_INSN_SIZE`, but only while it happens to be older than every `IPMODIFY` ops (see section 3).

| Class | Consumer (Peer) | `enabled_functions` (Standalone / Both) | Scenario 1: `klp` as Contender (`Peer` 1st, `klp` 2nd) | Scenario 2: `klp` as Incumbent (`klp` 1st, `Peer` 2nd) |
| :--- | :--- | :---: | :---: | :---: |
| **Class 1 (Mutator)** | **A**: `klp` | `1:I` / `1:IM` *(stacked)* | `Self` | `Self` |
| **Class 1 (Mutator)** | **B**: `fail_function` | `1:RI` / `1:RIM` | `-EBUSY` | `-EBUSY` |
| **Class 1 (Mutator)** | **C**: `bpf_override_return` | `1:R` / `2:RIM` | `Suppressed` | `Suppressed` |
| **Class 1 (Mutator)** | **D**: `BPF fmod_ret` / LSM | `1:RD` / `2:RIDM` | `Suppressed` | `Override` |
| **Class 1 (Mutator)** | **E**: `kprobe + post_handler` | `1:RI` / `1:RIM` | `-EBUSY` | `-EBUSY` |
| **Class 2 (Interceptor)** | **F**: `BPF fexit` | `1:RD` / `2:RIDM` | `OK` | `OK` |
| **Class 2 (Interceptor)** | **G**: `fgraph` (`function_graph`) | `1:none` / `2:IM` | `Stale Symbols` | `Stale Symbols` |
| **Class 2 (Interceptor)** | **H**: `kretprobe` / `rethook` | `1:R` / `2:RIM` | `OK` | `OK` |
| **Class 2 (Interceptor)** | **I**: `fprobe` (with `exit_handler`) | `1:none` / `2:IM` | `OK`† | `OK` |
| **Class 3 (Observer)** | **J**: plain `ftrace_ops` | `1:none` / `2:IM` | `Stale Symbols`† | `Stale Symbols` |
| **Class 3 (Observer)** | **K**: `BPF fentry` | `1:RD` / `2:RIDM` | `Stale Symbols` | `Stale Symbols` |
| **Class 3 (Observer)** | **L**: `fprobe` (no `exit_handler`) | `1:none` / `2:IM` | `Stale Symbols`† | `Stale Symbols` |
| **Class 3 (Observer)** | **M**: `kprobe` (no `post_handler`) | `1:R` / `2:RIM` | `Stale Symbols` | `Stale Symbols` |
| **Class 3 (Observer)** | **N**: Core `function` tracer\* | `1:none` / `2:IM` | `Stale Symbols` | `Stale Symbols` |

---

## 3. Handler Order & ip-Write Arbitration (`order_experiment.sh`, T1–T11)

`ftrace_order_probe.ko` adds two passive `ftrace_ops` (`a`, `b`) that can be registered between other consumers and record their run order and the ip they see. All 19 rows pass (64 assertions):

| Test | Finding |
| :--- | :--- |
| **T1–T3** | The `ftrace_ops` list is LIFO (`add_ftrace_ops()` inserts at the head). `klp`'s position is just its registration time; an observer registered *before* `klp` runs after it and sees `ftrace_regs` ip = `new_func`. |
| **T4–T5** | **C** vs `klp`: both write the ip; the handler that runs last — the **older ops** — wins (`klp1` vs `EINVAL`). |
| **T6–T7** | **M** (passive kprobe) saves and restores the ip it found, so it never clobbers `klp` in either order. |
| **T8–T9** | **D** is outside the list: `-EPERM` wins in both orders; a pass-through `fmod_ret` reaches `new_func` in both orders. |
| **T10** | Order is per `ftrace_ops`, not per consumer: an **unrelated** kprobe on `version_proc_show` registers the shared `kprobe_ftrace_ops` early, so **C** wins even though it attached after `klp`. |
| **T11** | Reloading `klp` (or re-attaching **C**) moves its ops to the head and flips the winner, while the raw `enabled_functions` line stays byte-identical. |

---

## 4. Kernel Prerequisites & Patches

To run all 14 consumers (`A`–`N`) and all 28 scenarios against a target Linux kernel build tree (`KDIR`):

1. **Apply the two patches in [`patches/`](patches/)** to your kernel tree:
   - [`patches/0001-kprobes-Propagate-arm_kprobe-error-in-__register_kpr.patch`](patches/0001-kprobes-Propagate-arm_kprobe-error-in-__register_kpr.patch): Propagates `arm_kprobe_ftrace()` `-EBUSY` return codes from `__register_kprobe()` (fixes regression `587e8e6d640b`).
   - [`patches/0002-NOT-FOR-UPSTREAM-proc-cmdline-allow-error-injection-.patch`](patches/0002-NOT-FOR-UPSTREAM-proc-cmdline-allow-error-injection-.patch): Marks `cmdline_proc_show` with `ALLOW_ERROR_INJECTION(cmdline_proc_show, ERRNO)` so Class 1 Mutators **B** (`fail_function`), **C** (`bpf_override_return`), and **D** (`fmod_ret`) can attach to the same target function as `klp`.
2. **Required Kernel Config Options**:
   - `CONFIG_DYNAMIC_FTRACE_WITH_REGS=y`, `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y`, `CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y`
   - `CONFIG_LIVEPATCH=y`, `CONFIG_KPROBES=y`, `CONFIG_KPROBE_EVENTS=y`, `CONFIG_KPROBES_ON_FTRACE=y`, `CONFIG_KRETPROBES=y`, `CONFIG_FPROBE=y`
   - `CONFIG_FUNCTION_TRACER=y`, `CONFIG_FUNCTION_GRAPH_TRACER=y`
   - `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`
   - `CONFIG_FUNCTION_ERROR_INJECTION=y`, `CONFIG_FAIL_FUNCTION=y`, `CONFIG_BPF_KPROBE_OVERRIDE=y`

---

## 5. Building & Running in QEMU

```bash
# Build all 9 kernel modules + BPF object + loader against KDIR (defaults to ../linux)
make KDIR=/path/to/linux

# Run all 28 klp Contender & Incumbent coexistence scenarios non-interactively in QEMU:
./vm_start.sh -k /path/to/linux -a ./run_coexistence_experiment.sh

# Run the handler-order experiment (T1–T11):
./vm_start.sh -k /path/to/linux -a ./order_experiment.sh
```

See [`docs/lpc26-ftrace.rst`](docs/lpc26-ftrace.rst) for the complete technical analysis and kernel code walkthroughs, and [`docs/lpc26-livepatch-slides.pdf`](docs/lpc26-livepatch-slides.pdf) / [`docs/lpc26-livepatch-slides.pptx`](docs/lpc26-livepatch-slides.pptx) for the LPC 2026 presentation slides.
