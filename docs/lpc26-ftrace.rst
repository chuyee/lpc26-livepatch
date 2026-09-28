.. SPDX-License-Identifier: GPL-2.0

============================================
Ftrace Consumer Classification and Inventory
============================================

This document classifies in-kernel ftrace consumers by their *runtime behavior*
at a function call site (``-fpatchable-function-entry`` / ``-mfentry``), and
inventories how each one interacts with that site.

The motivating question is coexistence: which consumers can share a function,
which cannot, and why.

.. contents::
   :local:
   :depth: 2


1. Ftrace Behavioral Class Definitions
======================================

A consumer's class is a property of **its declared registration flags and its
actual runtime capability**, not of which subsystem it belongs to. Several
subsystems appear in more than one class depending on configuration (kprobes
with or without a ``post_handler``, fprobe with or without an
``exit_handler``), so the classification below is keyed on observable traits
rather than on subsystem names.

Registration flags alone are not sufficient. ``BPF_MODIFY_RETURN`` and
``fexit`` register identically — same ``register_ftrace_direct()`` call, same
``BPF_TRAMP_F_CALL_ORIG | BPF_TRAMP_F_SKIP_FRAME`` trampoline flags — yet only
the former can suppress the original body. The attach type, not the ops flags,
determines that runtime capability.

The decision procedure::

    Does it set FTRACE_OPS_FL_IPMODIFY (or otherwise write regs->ip)?
        yes -> Class 1: Mutator
    Can it skip the original body or replace its return value?
    (BPF_TRAMP_MODIFY_RETURN: the JIT branches past 'call orig_call')
        yes -> Class 1: Mutator
    Does it install a return hook (rethook / fgraph / direct exit stub)?
        yes -> Class 2: Stack Interceptor
    Otherwise                                -> Class 3: Passive Observer

Note that the kernel's own conflict detection keys on registration flags only,
so it cannot see that ``fmod_ret`` is semantically a Mutator.

Class 1: Mutators (Execution & Logic Modifiers)
-----------------------------------------------

:Definition:
    Consumers that actively divert the CPU execution path: skip the original
    function body, alter the instruction pointer (``regs->ip``), or override
    return codes.

:Mechanism:
    Registered with ``FTRACE_OPS_FL_IPMODIFY``. ``SAVE_REGS`` is only added on
    architectures without ``CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS``
    (``kernel/livepatch/patch.c``); on x86-64 livepatch writes the ip through
    ``ftrace_regs`` and its site shows ``I`` without ``R``.

:Coexistence rule:
    **Exclusive by default.** Ftrace permits only one ``IPMODIFY`` handler per
    function; a second registration fails with ``-EBUSY``.

    This exclusivity is not absolute. A DIRECT ops may negotiate shared
    residency with an ``IPMODIFY`` ops through the ``ftrace_ops::ops_func``
    callback — see :ref:`negotiated_ipmodify_sharing`. Nor does it cover
    handlers that write the ip without declaring ``IPMODIFY``; those are
    arbitrated only by ``ftrace_ops`` list order — see :ref:`handler_order`.

Class 2: Stack Interceptors (Return Flow Wrappers)
--------------------------------------------------

:Definition:
    Consumers that preserve the original function body and execution logic, but
    manipulate the call stack by replacing the caller's return address with an
    exit trampoline.

:Mechanism:
    Dynamic exit trampolines: ``arch_rethook_trampoline`` (rethook/kretprobes;
    the older ``kretprobe_trampoline`` name survives only on architectures that
    do not use rethook), fgraph's ``return_to_handler``, or a BPF ``fexit``
    exit stub.

:Coexistence rule:
    **Range-occupying.** A return hook registers without ``IPMODIFY``, so it
    never collides with a Mutator at registration time. The cost is paid during
    livepatch *transitions*: the substituted return address keeps the hooked
    function's address range occupied for the duration of the call, and
    ``klp_check_stack_func()`` rejects any task holding an in-range address.
    Unwinding itself is **not** the problem on x86-64 — the ORC unwinder
    recovers both rethook return addresses and BPF trampoline frames. See
    :ref:`transition_pinning`.

Class 3: Passive Observers (Read-Only Tracers & Profilers)
----------------------------------------------------------

:Definition:
    Consumers that inspect entry arguments, record timestamps, sample
    instruction pointers, or collect counters without modifying registers, call
    stacks, or control flow.

:Mechanism:
    Standard ``ftrace_ops`` (via ``ftrace_ops_list_func``) or read-only direct
    trampolines (BPF ``fentry``). Note that a true passive observer needs no
    flags at all; ``SAVE_REGS`` is only required if the callback actually
    dereferences ``ftrace_regs``.

:Coexistence rule:
    **Unlimited concurrency, but metadata-sensitive.** Multiple passive
    observers multiplex cleanly on one call site. However, offline profilers
    (AutoFDO, perf) depend on static binary symbol mapping, and livepatching
    moves execution from ``vmlinux`` text into module address space.


2. Kernel Ftrace Consumer Inventory
===================================

The canonical representative of each class is marked.

Class 1: Mutator
----------------

.. list-table::
   :widths: 22 20 20 38
   :header-rows: 1

   * - Subsystem / Mechanism
     - Key source files
     - Ftrace mechanism / flags
     - Behavior & impact on function
   * - **Kernel Livepatching (klp)**
     - ``kernel/livepatch/``
     - ``FTRACE_OPS_FL_IPMODIFY`` (+ ``SAVE_REGS`` only without
       ``HAVE_DYNAMIC_FTRACE_WITH_ARGS``)
     - **Full redirection:** ``klp_ftrace_handler()`` sets ``regs->ip`` to
       ``new_func``; the ``orig_func`` body is skipped entirely. Effectively a
       tail call — ``new_func`` inherits ``orig_func``'s return-address slot.
   * - **Error Injection (fail_function)**
     - ``kernel/fail_function.c``, ``lib/error-inject.c``
     - ``kprobe_ipmodify_ops`` (``IPMODIFY``)
     - **Short-circuit:** calls ``override_function_with_return()``; skips the
       body and injects an error code.
   * - **BPF error injection (bpf_override_return)**
     - ``kernel/trace/bpf_trace.c``, ``kernel/trace/trace_kprobe.c``
     - kprobe path (``CONFIG_BPF_KPROBE_OVERRIDE``) +
       ``override_function_with_return()``, armed with ``kprobe_ftrace_ops`` —
       **no** ``IPMODIFY``
     - **Short-circuit:** forces an early return with an injected value.
       Behaviourally identical to ``fail_function``, but it does **not** ride
       the ``IPMODIFY`` path: BPF kprobe programs attach through
       ``trace_kprobe``, which never assigns ``kp.post_handler``, and
       ``arm_kprobe_ftrace()`` keys the ops choice on precisely that pointer.
       It therefore attaches to a livepatched function without complaint.
       See :ref:`measured_class1_contention`.
   * - **BPF LSM hooks**
     - ``kernel/bpf/bpf_lsm.c``, ``kernel/bpf/trampoline.c``
     - ``bpf_trampoline`` ``fmod_ret`` (``BPF_TRAMP_MODIFY_RETURN``)
     - **Policy enforcement:** can override the return value (e.g. ``-EPERM``).
       ``fexit`` programs cannot do this; that is precisely why ``fmod_ret``
       exists as a separate attach type.
   * - **Kprobes-on-ftrace** *(with* ``post_handler`` *)*
     - ``kernel/kprobes.c``
     - ``kprobe_ipmodify_ops`` (``IPMODIFY``)
     - **Flow/register mutation.** The selection is literal:
       ``bool ipmodify = (p->post_handler != NULL);`` in
       ``arm_kprobe_ftrace()``. The same subsystem is Class 3 without a
       ``post_handler``. Note that on ftrace there is no real single-step:
       ``kprobe_ftrace_handler()`` *emulates* it (``ip + MCOUNT_INSN_SIZE``),
       calls ``post_handler`` and then restores the ip it found, so a probe
       with a ``post_handler`` declares ``IPMODIFY`` without diverting flow.

Class 2: Stack Interceptor
--------------------------

.. list-table::
   :widths: 22 20 20 38
   :header-rows: 1

   * - Subsystem / Mechanism
     - Key source files
     - Ftrace mechanism / flags
     - Behavior & impact on function
   * - **BPF trampoline fexit**
     - ``kernel/bpf/trampoline.c``
     - ``register_ftrace_direct``
     - **Return wrap:** replaces the return address with a BPF exit stub to
       capture return values and latency. The generated trampoline registers a
       frame-pointer range, so reliable unwinding still works through it; it is
       also the one Class 2 consumer that negotiates with ``IPMODIFY``
       (:ref:`negotiated_ipmodify_sharing`) — although, as measured in
       :ref:`klp_coexistence_table`, **H** and **I** end up observing the same
       ``new_func`` return value without any negotiation.
   * - **Function graph tracer (fgraph)**
     - ``kernel/trace/fgraph.c``
     - ``ftrace_ops`` + ``return_to_handler``
     - **Return wrap:** measures exact function execution duration.
   * - **kretprobes / rethook**
     - ``kernel/trace/rethook.c``, ``kernel/kprobes.c``
     - ``kprobe_ftrace_ops`` + ``arch_rethook_trampoline``
     - **Return wrap:** ``arch_rethook_prepare()`` saves the real return
       address into ``rh->ret_addr`` and writes the trampoline into
       ``stack[0]``.
   * - **Fprobe** *(with* ``exit_handler`` *)*
     - ``kernel/trace/fprobe.c``
     - fgraph (``fprobe_graph_ops``)
     - **Return wrap.** Fprobe registers fgraph exactly when an exit handler is
       present (``return !fp->exit_handler;`` gates the ftrace-only path), so
       this configuration is Class 2, not Class 3. The same applies to
       ``bpf_kprobe_multi_link`` in return mode.
   * - **Function profiler**
     - ``kernel/trace/ftrace.c``
     - fgraph (``fprofiler_ops``, ``register_ftrace_graph()``)
     - **Return wrap:** call counts and duration histograms. With
       ``CONFIG_FUNCTION_GRAPH_TRACER`` the profiler is an fgraph user, hence
       Class 2, not Class 3.
   * - **Latency tracers** *(irqsoff, wakeup, with* ``display-graph`` *)*
     - ``kernel/trace/trace_irqsoff.c``, ``trace_sched_wakeup.c``
     - fgraph (``register_ftrace_graph()``)
     - **Return wrap** when the ``display-graph`` option is set; otherwise
       Class 3 (plain ``ftrace_ops``, below).

Class 3: Passive Observer
-------------------------

.. list-table::
   :widths: 22 20 20 38
   :header-rows: 1

   * - Subsystem / Mechanism
     - Key source files
     - Ftrace mechanism / flags
     - Behavior & impact on function
   * - **perf function events**
     - ``kernel/trace/trace_event_perf.c``
     - ``ftrace_ops`` (``perf_ftrace_function_register()``)
     - **Read-only:** per-event entry callback feeding perf. PMU sampling
       (AutoFDO, LBR, ``perf record -e cycles``) is **not** an ftrace consumer,
       but it is the victim of the attribution split in
       :ref:`spatial_decoupling`: samples land in ``new_func``'s module text.
   * - **BPF trampoline fentry**
     - ``kernel/bpf/trampoline.c``
     - ``register_ftrace_direct``
     - **Read-only:** JITed argument inspection at entry, no register mutation.
   * - **Fprobe / multi-kprobes** *(no* ``exit_handler`` *)*
     - ``kernel/trace/fprobe.c``
     - ``ftrace_ops`` with ``FTRACE_OPS_FL_SAVE_ARGS``
     - **Read-only:** lightweight batch probing for BPF
       (``bpf_kprobe_multi_link``).
   * - **Kprobes-on-ftrace** *(no* ``post_handler`` *)*
     - ``kernel/kprobes.c``
     - ``kprobe_ftrace_ops`` (``SAVE_REGS``)
     - **Read-only:** inspects register arguments at entry.
   * - **Core function tracer**
     - ``kernel/trace/trace_functions.c``
     - ``ftrace_ops``
     - **Read-only:** logs call events into the trace ring buffer.
   * - **Latency tracers** *(irqsoff, wakeup; default mode)*
     - ``kernel/trace/trace_irqsoff.c``, ``trace_sched_wakeup.c``
     - ``ftrace_ops`` (fgraph with ``display-graph``, see Class 2)
     - **Read-only:** measures irq-disabled, preempt-disabled and wakeup
       latencies.
   * - **Stack tracer**
     - ``kernel/trace/trace_stack.c``
     - ``ftrace_ops``
     - **Read-only:** inspects stack depth to find maximum kernel stack usage.
   * - **Persistent store (pstore)**
     - ``fs/pstore/ftrace.c``
     - ``pstore_ftrace_ops``
     - **Read-only:** writes a function trace log to NVRAM for post-mortem
       analysis.


3. Coexistence Implications
===========================

.. _negotiated_ipmodify_sharing:

3.0 Prior art: negotiated IPMODIFY sharing
------------------------------------------

Ftrace already supports one form of mutator/observability coexistence, and any
new proposal must be compared against it.

When an ``IPMODIFY`` ops is added to a function that already carries a DIRECT
ops (or vice versa), ftrace does not simply return ``-EBUSY``. It asks the
DIRECT ops whether it can cope, via ``ftrace_ops::ops_func``:

* ``FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_SELF`` — a DIRECT ops is being added
  to a function that already has ``IPMODIFY`` (``kernel/trace/ftrace.c``).
* ``FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_PEER`` — an ``IPMODIFY`` ops is being
  added to a function that already has a DIRECT ops.
* ``FTRACE_OPS_CMD_DISABLE_SHARE_IPMODIFY_PEER`` — the ``IPMODIFY`` ops left.

BPF implements this in ``bpf_tramp_ftrace_ops_func()``
(``kernel/bpf/trampoline.c``): it sets ``BPF_TRAMP_F_SHARE_IPMODIFY``, returns
``-EAGAIN`` so that registration retries, and **regenerates the trampoline**
with ``BPF_TRAMP_F_ORIG_STACK``. That flag makes the JIT emit
``mov rbx, [rbp+8]; call *rbx`` (``arch/x86/net/bpf_jit_comp.c``) in place of a
direct call to the recorded ``orig_func``, so the trampoline calls whatever
address the ``IPMODIFY`` chain left in the return slot — that is, ``new_func``.
A BPF trampoline and a livepatch can therefore already share one function
today, and the negotiation is order-independent (``..._SELF`` when the DIRECT
ops arrives second, ``..._PEER`` when the ``IPMODIFY`` ops does).

Note what that negotiation settles, and what it does not. It settles *who owns
the fentry site and how the original is reached*. It says nothing about whether
the arriving program may suppress the patched body: a ``fmod_ret`` program,
which can veto the return value, registers through exactly the same DIRECT path
as an ``fexit`` program, which cannot. Scenarios **D** of
:ref:`klp_coexistence_table` confirm this — the handshake admits a Class 1
mutator onto a livepatched function and the mutator then suppresses
``new_func`` entirely, in both attach orders (``order_experiment.sh``:
``klp`` hits = 0 while ``fmod_ret`` returns ``-EPERM``, ``klp`` hits = 1 when
the same program passes through). The existing mechanism is thus prior art for
call-site *sharing*, not for mutator *arbitration*.

Spatial decoupling (below) solves a broader problem by different means:

.. list-table::
   :widths: 25 37 38
   :header-rows: 1

   * -
     - Negotiated sharing (``SHARE_IPMODIFY``)
     - Spatial decoupling
   * - Scope
     - DIRECT ops only (BPF trampolines)
     - Any Class 2 or Class 3 consumer
   * - Cost
     - Trampoline regeneration on every ``IPMODIFY`` transition
     - One exported symbol; no regeneration
   * - Attribution
     - Coherent but split: the trampoline follows the redirect, so the event
       describes ``new_func``'s execution — yet it is filed under
       ``orig_func``'s symbol, so entry counts and PMU cycles still land in
       two different objects
     - Events and cycles both attributed to ``new_func``
   * - Transition pinning
     - ``ORIG_STACK`` turns the redirect into a nested call, so the trampoline
       frame occupies ``orig_func``'s checked range for the whole call
     - Occupancy moves to ``new_func``'s range: obstructs patch *removal*
       rather than *application*

.. _measured_class1_contention:

3.1 Mutator contention
----------------------

Class 1 consumers cannot *meaningfully* share a call site: simultaneous
``IPMODIFY`` operations are physically contradictory, because only one value
can be written to ``regs->ip``. The kernel, however, only enforces that for
some of them.

``run_coexistence_experiment.sh`` pairs livepatching with each of the other
Class 1 rows from section 2 on one shared call site (``cmdline_proc_show``). All four contenders do the same observable thing —
they stop the function from returning what it otherwise would. The kernel
admits half of them:

.. list-table::
   :widths: 26 32 42
   :header-rows: 1

   * - Contender
     - Registers with
     - Result against an active livepatch
   * - ``fail_function``
     - ``kprobe_ipmodify_ops`` (``IPMODIFY``)
     - **Refused,** ``-EBUSY``
   * - ``bpf_override_return``
     - ``kprobe_ftrace_ops`` (no flags)
     - **Admitted, unnoticed**
   * - BPF ``fmod_ret`` / BPF LSM
     - ``register_ftrace_direct()`` (``DIRECT``)
     - **Admitted, after negotiation**
   * - Kprobe with ``post_handler``
     - ``kprobe_ipmodify_ops`` (``IPMODIFY``)
     - **Refused,** ``-EBUSY``

The split does not track behaviour. It tracks only which ``ftrace_ops`` each
consumer happened to register with. ``__ftrace_hash_update_ipmodify()`` opens
with ``if (!is_ipmodify && !is_direct) return 0;``, so a plain
``kprobe_ftrace_ops`` never consults livepatch's exclusive claim at all.

The ``bpf_override_return`` case is the sharpest form of this. Both mutators
attach, both write ``regs->ip`` from the same ``ftrace_ops_list_func()`` walk,
and the winner is decided by attach order (the BPF program injects
``-EINVAL``)::

    Order A (livepatch, then BPF) -> read(/proc/cmdline) == livepatch banner
    Order B (BPF, then livepatch) -> read(/proc/cmdline) == EINVAL

Nothing arbitrated that, and the livepatch transition completed successfully in
both directions. The kernel reports success to both consumers while silently
discarding one of them. "Attach order" is itself only an approximation; the
real rule is the registration order of the underlying ``ftrace_ops``, see
:ref:`handler_order`.

Consumers **E** and **M** isolate the discriminator to a single pointer: both
are kprobes on the same livepatched function, differing only in whether
``post_handler`` is set. **E** is refused with ``-EBUSY`` (the call site stays
at ``1:RIM``); **M** is admitted and the refcount goes from 1 to 2
(``2:RIM``) — even though neither changes what the function does. ``arm_kprobe_ftrace()`` is the whole of the policy::

    bool ipmodify = (p->post_handler != NULL);

    return __arm_kprobe_ftrace(p,
            ipmodify ? &kprobe_ipmodify_ops : &kprobe_ftrace_ops,
            ipmodify ? &kprobe_ipmodify_enabled : &kprobe_ftrace_enabled);

So the taxonomy the kernel enforces is not the taxonomy that matters. A
consumer is refused for *declaring* ``IPMODIFY``, not for *using* it. The
strictly more dangerous consumers — the ones that mutate control flow without
declaring it — are the ones that get through.

This raises a policy question the kernel does not currently answer. Should
livepatching always outrank other ``IPMODIFY`` users such as diagnostic error
injection? If not, some user-specified priority scheme is needed to arbitrate
between Class 1 consumers. Either answer first requires that conflicting
consumers be *identifiable*, which today they are not.

A related, easily overlooked constraint: livepatch is safe to unload because it
provides a consistency model (``TIF_PATCH_PENDING`` plus ``klp_check_stack()``)
guaranteeing no task is still executing in ``new_func`` when the module text is
freed. An arbitrary second Class 1 consumer that redirects into its own text
has no such guarantee — ``unregister_ftrace_function()`` relies on
``synchronize_rcu_tasks()``, which treats a task *blocked inside* the target
function as already quiesced. Coexistence of mutators is therefore not only a
registration problem but a lifetime problem.

3.1.1 An aside: the rejection path had regressed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The two ``-EBUSY`` rows above initially reported *success*. ``arm_kprobe()``
returned ``-EBUSY`` correctly and the probe was removed from ``kprobe_table``,
but ``__register_kprobe()`` then dropped the error and returned 0. Commit
587e8e6d640b ("kprobes: Adopt guard() and scoped_guard()") rewrote the old
``goto out; ... return ret;`` as a bare ``return 0;``, silently reverting
commit 12310e343755 ("kprobes: Propagate error from arm_kprobe_ftrace()") —
whose changelog describes this exact livepatch/``IPMODIFY`` scenario.
``enable_kprobe()`` is unaffected.

The relevance here is methodological. A registration call returning 0 does not
mean the consumer is attached, so every assertion in the sample suite is
corroborated against ftrace's own state: the refcount column of
``tracing/enabled_functions`` and the contents of ``kprobes/list``. Under the
regression, ``register_kprobe()`` reported success, ``kprobes/list`` was empty,
and the call site's refcount never left 1.

.. _klp_coexistence_table:

3.1.2 Empirical ``klp`` coexistence across all Class 1, Class 2, and Class 3 consumers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``run_coexistence_experiment.sh`` evaluates livepatching (**A**: ``klp``) against all 14 ftrace consumer
mechanisms across Class 1, Class 2, and Class 3 on ``cmdline_proc_show`` in
both attachment orders:

* **Scenario 1 (** ``klp`` **as Contender)**: Peer consumer is attached first
  as **Incumbent**; ``klp`` attaches second as **Contender**.
* **Scenario 2 (** ``klp`` **as Incumbent)**: ``klp`` is attached first as
  **Incumbent**; Peer consumer attaches second as **Contender**.

Every outcome is *measured*, not assigned: the runner reads
``/proc/cmdline`` once (which mutator's result surfaced), reads each consumer's
hit counter, and — for return hooks — arms ``klp_sample_mutator``'s
``magic_ret`` so that ``new_func`` returns ``7`` for one read and records which
value the peer's return hook reports. Each scenario is classified into one of
these states:

* ``Self``: ``klp`` paired with itself; the second livepatch's ``new_func2``
  surfaced (it stacks onto ``klp``'s internal ``ops->func_stack``; no second
  ``ftrace_ops`` is registered, the count stays at 1).
* ``-E<errno>``: Contender registration failed with that errno (all failures
  observed are ``-EBUSY``); the incumbent keeps its behavior.
* ``Override``: registration returns 0 and the **contender's** result surfaced.
* ``Suppressed``: registration returns 0 and the **incumbent's** result
  surfaced; the contender's mutation was overwritten or bypassed.
* ``OK``: ``klp`` ran ``new_func`` **and** the peer's return hook reported
  ``new_func``'s return value (``ret=7``).
* ``Stale Symbols``: ``klp`` ran ``new_func``; the peer fired but attributes
  the call to ``orig_func`` (and, for return hooks, did not report ``7``).
* ``Blind`` / ``Unclassified``: the peer never fired / anything else (not
  observed).
* ``†`` suffix (redirect visible): the peer's entry handler read
  ``ftrace_regs_get_instruction_pointer() == new_func``. Only **I**, **J** and
  **L** record this value (``last_regs_ip``); it is ``new_func`` in Scenario 1
  and ``orig_func`` in Scenario 2 for all three. **E**/**H**/**M** cannot see
  it (``kprobe_ftrace_handler()`` sets ``regs->ip = p->addr + 1`` around the
  user handlers), **G**/**N** record only the ``ip`` argument, and **K** runs
  outside the ``ftrace_ops`` list.

In the ``enabled_functions`` column (``<count>:<flags>`` from
``/sys/kernel/tracing/enabled_functions``, formatted by ``t_show()`` in
``kernel/trace/ftrace.c``), ``<count>`` is ``ftrace_rec_count(rec)`` and
``<flags>`` are the ``struct dyn_ftrace`` record flags:

* ``R`` (``FTRACE_FL_REGS``): Callsite saves full ``struct pt_regs``
  (``FTRACE_OPS_FL_SAVE_REGS``, requested by ``kprobes`` and ``direct_ops``;
  omitted by ``klp``, ``fprobe``, and standard ``ftrace_ops`` when
  ``CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS=y``).
* ``I`` (``FTRACE_FL_IPMODIFY``): An attached ``ftrace_ops`` declared
  ``FTRACE_OPS_FL_IPMODIFY`` (**A** ``klp``, **B** ``fail_function``, **E**
  ``kprobe + post_handler``).
* ``D`` (``FTRACE_FL_DIRECT``): A direct trampoline
  (``register_ftrace_direct``, used by BPF trampolines **D** ``fmod_ret``,
  **F** ``fexit``, **K** ``fentry``) is attached.
* ``M`` (``FTRACE_FL_MODIFIED``): Sticky history bit
  (``FTRACE_NOCLEAR_FLAGS``) set once the function has had ``I`` or ``D``
  attached since boot. Because the suite starts with ``A × A``, every later
  "standalone" reading carries ``M``; the Standalone column below therefore
  strips it, while the Both column shows the raw value.

.. list-table:: Empirical ``klp`` Contention & Coexistence (2 Scenarios × 14 Consumers)
   :widths: 18 26 16 20 20
   :header-rows: 1

   * - Class
     - Consumer (``Peer``)
     - ``enabled_functions`` (Standalone / Both)
     - Scenario 1: ``klp`` as Contender (``Peer`` 1st, ``klp`` 2nd)
     - Scenario 2: ``klp`` as Incumbent (``klp`` 1st, ``Peer`` 2nd)
   * - **Class 1 (Mutator)**
     - **A:** ``klp``
     - ``1:I`` / ``1:IM``
     - ``Self``
     - ``Self``
   * - **Class 1 (Mutator)**
     - **B:** ``fail_function``
     - ``1:RI`` / ``1:RIM``
     - ``-EBUSY``
     - ``-EBUSY``
   * - **Class 1 (Mutator)**
     - **C:** ``bpf_override_return``
     - ``1:R`` / ``2:RIM``
     - ``Suppressed``
     - ``Suppressed``
   * - **Class 1 (Mutator)**
     - **D:** BPF ``fmod_ret`` / LSM
     - ``1:RD`` / ``2:RIDM``
     - ``Suppressed``
     - ``Override``
   * - **Class 1 (Mutator)**
     - **E:** ``kprobe`` + ``post_handler``
     - ``1:RI`` / ``1:RIM``
     - ``-EBUSY``
     - ``-EBUSY``
   * - **Class 2 (Interceptor)**
     - **F:** BPF ``fexit``
     - ``1:RD`` / ``2:RIDM``
     - ``OK``
     - ``OK``
   * - **Class 2 (Interceptor)**
     - **G:** ``fgraph`` (``function_graph``)
     - ``1:none`` / ``2:IM``
     - ``Stale Symbols``
     - ``Stale Symbols``
   * - **Class 2 (Interceptor)**
     - **H:** ``kretprobe`` / ``rethook``
     - ``1:R`` / ``2:RIM``
     - ``OK``
     - ``OK``
   * - **Class 2 (Interceptor)**
     - **I:** ``fprobe`` (with ``exit_handler``)
     - ``1:none`` / ``2:IM``
     - ``OK``†
     - ``OK``
   * - **Class 3 (Observer)**
     - **J:** ``perf`` / ``ftrace_ops``
     - ``1:none`` / ``2:IM``
     - ``Stale Symbols``†
     - ``Stale Symbols``
   * - **Class 3 (Observer)**
     - **K:** BPF ``fentry``
     - ``1:RD`` / ``2:RIDM``
     - ``Stale Symbols``
     - ``Stale Symbols``
   * - **Class 3 (Observer)**
     - **L:** ``fprobe`` (no ``exit_handler``)
     - ``1:none`` / ``2:IM``
     - ``Stale Symbols``†
     - ``Stale Symbols``
   * - **Class 3 (Observer)**
     - **M:** ``kprobe`` (no ``post_handler``)
     - ``1:R`` / ``2:RIM``
     - ``Stale Symbols``
     - ``Stale Symbols``
   * - **Class 3 (Observer)**
     - **N:** Core ``function`` tracer\ *
     - ``1:none`` / ``2:IM``
     - ``Stale Symbols``
     - ``Stale Symbols``

\* *Note: Latency tracers in their default mode (* ``irqsoff``, ``wakeup``
*),* ``stack_tracer`` *, and* ``pstore`` *(* ``pstore_ftrace_ops`` *) share the
same standard read-only* ``ftrace_ops`` *mechanism as* **J** / **N** *(expected
to yield* ``Stale Symbols`` *in both scenarios; not run by the suite). The
function profiler is an fgraph user like* **G** *(Class 2).*

Three structural patterns govern all 28 scenarios:

1. **Class 1 Mutator arbitration depends on registration mechanism, not
   authority**:

   * **Explicit** ``IPMODIFY`` (**B** ``fail_function``, **E**
     ``kprobe + post_handler``) is rejected with ``-EBUSY`` in both directions.
   * **Undeclared** ``regs->ip`` **mutation on** ``ftrace_ops_list`` (**C**
     ``bpf_override_return``) attaches without error in both directions.
     Because ``add_ftrace_ops()`` prepends each newly registered ops to the
     head of ``ftrace_ops_list`` and ``__ftrace_ops_list_func()`` walks it
     from head to tail, the **older ops** runs last and overwrites
     ``regs->ip`` last — so the contender is ``Suppressed`` in both Scenario 1
     (``C`` suppresses ``klp``) and Scenario 2 (``klp`` suppresses ``C``).
     "Incumbent" here means *older* ``ftrace_ops``, which is not always the
     consumer that attached first (:ref:`handler_order`).
   * **BPF trampoline** ``fmod_ret`` (**D**) registers as ``DIRECT`` without
     ``IPMODIFY`` and negotiates ``SHARE_IPMODIFY``. Because
     ``call_direct_funcs()`` always executes *after* all regular
     ``ftrace_ops`` handlers, ``D``'s trampoline runs after ``klp`` in both
     attachment orders and skips ``new_func`` whenever ``fmod_ret != 0`` —
     resulting in ``Suppressed`` when ``klp`` is Contender and ``Override``
     when ``klp`` is Incumbent. The two labels describe one physical outcome
     (**D wins regardless of order**); with a pass-through ``fmod_ret`` the
     trampoline's call reaches ``new_func`` in both orders
     (:ref:`handler_order`).
2. **In Class 2, negotiation is not what makes a return hook correct.** Only
   BPF ``fexit`` (**F**) negotiates ``SHARE_IPMODIFY``: it regenerates its
   trampoline with ``BPF_TRAMP_F_ORIG_STACK`` (``mov rbx, [rbp+8]; call
   *rbx``) so that its call reaches ``new_func`` (``ENABLE_SHARE_IPMODIFY_PEER``
   in Scenario 1, ``..._SELF`` in Scenario 2). ``kretprobe`` / ``rethook``
   (**H**) and ``fprobe`` with ``exit_handler`` (**I**) have no handshake at
   all, yet reach the same result for free: the livepatch redirect is a tail
   call, ``new_func`` inherits ``orig_func``'s hijacked return slot, and their
   return trampolines fire when ``new_func`` returns. All three report
   ``new_func``'s return value (``ret=7``, ``OK``) and all three still file the
   event under ``orig_func`` (``bpf_get_func_ip()`` / ``kp.addr`` /
   ``entry_ip``). ``fgraph`` (**G**) is the same mechanism as **I**; the suite
   only checks its symbol (the kernel under test lacks
   ``CONFIG_FUNCTION_GRAPH_RETVAL``), hence ``Stale Symbols``.
3. **Every Class 3 Passive Observer (** **J** – **N** **) remains bound to**
   ``orig_func``: whether registered via plain ``ftrace_ops`` (**J**, **N**),
   ``fprobe_ftrace_ops`` (**L**), ``kprobe_ftrace_ops`` (**M**), or a read-only
   ``DIRECT`` trampoline (**K** ``BPF fentry``, where ``BPF_TRAMP_F_CALL_ORIG``
   is not set so ``bpf_tramp_ftrace_ops_func()`` returns 0 without regenerating
   the trampoline), the observer executes at ``orig_func``'s ``__fentry__``
   site before ``ftrace_regs_caller`` transfers control to ``new_func``. Thus
   both Scenario 1 and Scenario 2 yield ``Stale Symbols``. The redirect is not
   invisible to all of them, though: handlers share one ``ftrace_regs``, so an
   ``ftrace_ops`` handler that runs *after* ``klp`` (i.e. registered *before*
   it) sees ``ftrace_regs_get_instruction_pointer() == new_func``. The suite
   measures this for **J**, **L** and **I** (``†``: Scenario 1 only), and
   :ref:`handler_order` shows the same with standalone probes. The ``ip``
   argument every handler receives is always ``orig_func``. Consequently an
   observer *can* attribute each call correctly by checking
   ``ftrace_regs_get_instruction_pointer(fregs) != ip + MCOUNT_INSN_SIZE``
   (which also follows ``klp``'s per-task transition, unlike a patch-state
   notifier), but only if its ``ftrace_ops`` is older than every
   ``IPMODIFY`` ops on the function — a condition it neither controls nor can
   observe (:ref:`handler_order`).

.. _handler_order:

3.1.3 Handler order on a shared call site
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All ``ftrace_ops`` on a function share one ``ftrace_regs``.
``add_ftrace_ops()`` (``kernel/trace/ftrace.c``) inserts at the head of
``ftrace_ops_list`` and ``__ftrace_ops_list_func()`` walks it head to tail, so
the list is LIFO and the last ip write, i.e. the oldest ops, wins.
``order_experiment.sh`` confirms this with two passive probe ops
(``ftrace_order_probe.c``) registered around other consumers:

* ``klp`` is not special in the list: its handler position is simply its
  registration time.
* Between ``klp`` and an undeclared ip writer (**C**) the oldest ops wins. A
  passive kprobe restores the ip it found, so it never clobbers the redirect.
  DIRECT trampolines (**D**, **F**, **K**) run after the list and wrap
  whatever ip it selected, so order does not apply to them.
* Order is per ``ftrace_ops``, not per consumer. All ftrace-based kprobes share
  one ``kprobe_ftrace_ops`` (``__arm_kprobe_ftrace()`` in
  ``kernel/kprobes.c``), so an unrelated kprobe armed before ``klp`` loads
  makes **C** win, and reloading ``klp`` flips the winner again. The raw
  ``enabled_functions`` line is byte-identical in both states; nothing
  user-visible reveals handler order.
* Between livepatches the *newest* patch wins (``klp``'s ``func_stack``);
  between ``klp`` and an undeclared ip writer the *oldest* ``ftrace_ops``
  wins. Neither is a policy; both fall out of data-structure order.

.. _spatial_decoupling:

3.2 Spatial decoupling
----------------------

Instead of forcing Mutators and observability consumers into conflict on
``orig_func``, livepatching exports the compiler-generated entry site of
``new_func``. Class 2 consumers (BPF ``fexit``, kretprobes, fgraph) and Class 3
consumers (AutoFDO, BPF ``fentry``) attach there instead.

Because ``new_func`` is ordinary module text with its own ``__fentry__`` site
recorded in ``__mcount_loc``, it is an uncontended call site. The mutator keeps
exclusive ownership of ``orig_func``; the observer gets a site of its own.

This also repairs attribution. A hook on ``orig_func`` under an active
livepatch reports an accurate *entry* event for a function whose body never
ran, while the cycles are spent in a different binary object — entry counts and
PMU (Performance Monitoring Unit) samples end up attributed to two different
files. Attaching to ``new_func`` puts both halves back together.

The in-place alternative, per-call attribution from ``ftrace_regs`` (pattern 3
in :ref:`klp_coexistence_table`), works only for ``ftrace_ops`` observers that
happen to run after every ``IPMODIFY`` handler; spatial decoupling does not
depend on handler order.

.. _transition_pinning:

3.3 Unwinder interaction and transition pinning
-----------------------------------------------

Return hooks are commonly said to interact with livepatch in two distinct ways:
by perturbing reliable stack unwinding, and by pinning address ranges that a
transition must find empty. The first turns out to be a non-issue on x86-64;
the second is real, and moving a Class 2 hook from ``orig_func`` to
``new_func`` *changes its shape* rather than eliminating it. A task may also
sleep in ``orig_func`` for reasons that have nothing to do with tracing.

Stating this precisely matters, because the commonly repeated version of the
claim — that return hooks and generated trampolines defeat the reliable
unwinder — does not survive contact with the current code.

* ``unwind_recover_rethook()`` (``arch/x86/include/asm/unwind.h``), called from
  ``unwind_next_frame()`` for all three ORC frame types, detects
  ``arch_rethook_trampoline`` and recovers the real return address through
  ``rethook_find_ret_addr()``. The trampoline itself carries
  ``UNWIND_HINT_FUNC`` and pushes a deliberate fake return address for exactly
  this purpose.

* Generated code is covered too. A BPF trampoline records a frame-pointer range
  in its ``bpf_tramp_image`` ksym (``fp_start`` set immediately after
  ``push rbp; mov rbp, rsp``, ``fp_end`` immediately after ``leave``;
  ``arch/x86/net/bpf_jit_comp.c``). ``orc_bpf_find()`` answers that range with
  ``orc_fp_entry`` *from inside* ``orc_find()``
  (``arch/x86/kernel/unwind_orc.c``), so the ``state->error = true`` fallback
  used for genuinely uncovered code is never taken. Walking through a BPF
  trampoline frame leaves the unwind **reliable**.

That leaves two ways to lose a task for a transition round, and the first is
effectively unreachable from livepatch:

a) **Recovery can fail.** ``rethook_find_ret_addr()`` returns 0 if the per-task
   rethook llist is out of sync, and ``arch_stack_walk_reliable()`` turns a zero
   address into ``-EINVAL``, logged as "an unreliable stack". Its other
   bail-out, ``task_is_running()``, cannot fire on this path:
   ``klp_check_and_switch_task()`` has already returned ``-EBUSY`` for such
   tasks. An llist desync is not a consequence of coupling.

b) **Address-range occupancy is irreducible.** ``klp_check_stack_func()``
   (``kernel/livepatch/transition.c``) rejects a task if *any* recovered
   address lies inside the checked range, returning ``-EAGAIN`` and ultimately
   ``-EADDRINUSE``. No recovery machinery helps here. Two details matter, and
   both cut against the naive reading:

   * **The range flips with the transition direction.** When patching, the
     checked range is ``[old_func, old_func + old_size)``. When *unpatching*,
     ``klp_target_state == KLP_TRANSITION_UNPATCHED`` selects
     ``[new_func, new_size)`` instead. A return hook parked on ``new_func``
     therefore obstructs patch *removal* exactly the way a hook on
     ``orig_func`` obstructs patch *application*.

   * **Only descheduled tasks reach the check.**
     ``klp_check_and_switch_task()`` short-circuits with ``-EBUSY`` for any
     task that is currently running on another CPU, before walking its stack
     at all. ``-EADDRINUSE`` is reported only for tasks that are sleeping,
     blocked or preempted with an in-range frame on their saved stack — hence
     the ``"%s:%d is sleeping on function %s"`` debug message. Tasks returning
     to userspace switch unconditionally with no stack check
     (``kernel/entry/common.c``), so short non-sleeping leaf functions are
     nearly impossible to stall on. The realistic victims are functions that
     block, and kthread loop functions that are permanently on a stack.

Spatial decoupling therefore does **not** eliminate hazard (b); it *relocates*
it. What it fixes is the incoherence of the coupled arrangement. A Class 2 hook
on ``orig_func`` under an active patch obstructs transitions on the very
function whose body it never observes, while reporting ``new_func``'s data
under ``orig_func``'s name — wrong in both directions at once. Decoupled, the
hook pins the code it actually instruments: it delays removal of ``new_func``,
which is a defensible thing for an observer of ``new_func`` to do, and leaves
``orig_func``'s range clear so that patch application and atomic-replace
transitions converge.

The dwell-time argument should be dropped altogether rather than merely
qualified: a coupled Class 2 hook adds no measurable transition-blocking
exposure at all. ``trace_test_and_set_recursion()``
(``include/linux/trace_recursion.h``) calls ``preempt_disable_notrace()`` around
every ftrace handler, so a task can never be sampled *descheduled* inside the
interceptor's entry handler — and only descheduled tasks are ever stack-checked.
Independently, once the patch is applied ``orig_func``'s body never executes:
``klp_ftrace_handler()`` redirects ``regs->ip`` at the ``__fentry__`` site, and
the redirect behaves as a tail call, so ``new_func`` inherits ``orig_func``'s
return-address slot and no address in ``[old_func, old_func + old_size)`` is
live while ``new_func`` runs. The load-bearing argument for decoupling is
attribution (:ref:`spatial_decoupling`) and coherence — correctness, not
contention.


4. Test Suite in This Repository
================================

All measurements in section 3 come from this repository and run
non-interactively in QEMU via ``vm_start.sh`` (boot, run, power off, exit with
the suite's status):

* ``run_coexistence_experiment.sh`` — ``klp`` (**A**) against the 14 consumers
  **A**–**N** in both attach orders (28 scenarios, :ref:`klp_coexistence_table`).
  Consumers are built from ``klp_sample_mutator.c`` / ``klp_user2.c`` (A),
  ``fail_function`` via debugfs (B), ``bpf_coexist_users`` (C, D, F, K),
  ``kprobe_ph_user1.c`` (E), tracefs ``function_graph`` / ``function`` (G, N),
  ``kretprobe_user.c`` (H), ``fprobe_exit_user.c`` / ``fprobe_entry_user.c``
  (I, L), ``ftrace_observer_user1.c`` (J) and ``kprobe_entry_user.c`` (M)::

      ./vm_start.sh -a ./run_coexistence_experiment.sh

* ``order_experiment.sh`` — handler order and ip-write arbitration
  (:ref:`handler_order`), using ``ftrace_order_probe.c``::

      ./vm_start.sh -a ./order_experiment.sh

Every registration assertion is corroborated against
``tracing/enabled_functions`` rather than trusting a return value; see
section 3.1.1 for why. ``patches/0001`` restores ``-EBUSY`` propagation in
``__register_kprobe()``; ``patches/0002`` (not for upstream) allows error
injection on ``cmdline_proc_show`` so that **B**, **C** and **D** can attach.
