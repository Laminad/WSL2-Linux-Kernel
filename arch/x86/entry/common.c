// SPDX-License-Identifier: GPL-2.0-only
/*
 * common.c - C code for kernel entry and exit
 * Copyright (c) 2015 Andrew Lutomirski
 *
 * Based on asm and ptrace code by many authors.  The code here originated
 * in ptrace.c and signal.c.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/entry-common.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/export.h>
#include <linux/nospec.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#ifdef CONFIG_XEN_PV
#include <xen/xen-ops.h>
#include <xen/events.h>
#endif

#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/traps.h>
#include <asm/vdso.h>
#include <asm/cpufeature.h>
<<<<<<< HEAD
#include <asm/fpu/api.h>
#include <asm/nospec-branch.h>
#include <asm/io_bitmap.h>
#include <asm/syscall.h>
#include <asm/irq_stack.h>
=======
#include <asm/nospec-branch.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

#ifdef CONFIG_CONTEXT_TRACKING
/* Called on entry from user mode with IRQs off. */
__visible inline void enter_from_user_mode(void)
{
	CT_WARN_ON(ct_state() != CONTEXT_USER);
	user_exit_irqoff();
}
#else
static inline void enter_from_user_mode(void) {}
#endif

static void do_audit_syscall_entry(struct pt_regs *regs, u32 arch)
{
#ifdef CONFIG_X86_64
	if (arch == AUDIT_ARCH_X86_64) {
		audit_syscall_entry(regs->orig_ax, regs->di,
				    regs->si, regs->dx, regs->r10);
	} else
#endif
	{
		audit_syscall_entry(regs->orig_ax, regs->bx,
				    regs->cx, regs->dx, regs->si);
	}
}

/*
 * Returns the syscall nr to run (which should match regs->orig_ax) or -1
 * to skip the syscall.
 */
static long syscall_trace_enter(struct pt_regs *regs)
{
	u32 arch = in_ia32_syscall() ? AUDIT_ARCH_I386 : AUDIT_ARCH_X86_64;

	struct thread_info *ti = current_thread_info();
	unsigned long ret = 0;
	bool emulated = false;
	u32 work;

	if (IS_ENABLED(CONFIG_DEBUG_ENTRY))
		BUG_ON(regs != task_pt_regs(current));

	work = READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY;

	if (unlikely(work & _TIF_SYSCALL_EMU))
		emulated = true;

	if ((emulated || (work & _TIF_SYSCALL_TRACE)) &&
	    tracehook_report_syscall_entry(regs))
		return -1L;

	if (emulated)
		return -1L;

#ifdef CONFIG_SECCOMP
	/*
	 * Do seccomp after ptrace, to catch any tracer changes.
	 */
	if (work & _TIF_SECCOMP) {
		struct seccomp_data sd;

		sd.arch = arch;
		sd.nr = regs->orig_ax;
		sd.instruction_pointer = regs->ip;
#ifdef CONFIG_X86_64
		if (arch == AUDIT_ARCH_X86_64) {
			sd.args[0] = regs->di;
			sd.args[1] = regs->si;
			sd.args[2] = regs->dx;
			sd.args[3] = regs->r10;
			sd.args[4] = regs->r8;
			sd.args[5] = regs->r9;
		} else
#endif
		{
			sd.args[0] = regs->bx;
			sd.args[1] = regs->cx;
			sd.args[2] = regs->dx;
			sd.args[3] = regs->si;
			sd.args[4] = regs->di;
			sd.args[5] = regs->bp;
		}

		ret = __secure_computing(&sd);
		if (ret == -1)
			return ret;
	}
#endif

	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
		trace_sys_enter(regs, regs->orig_ax);

	do_audit_syscall_entry(regs, arch);

	return ret ?: regs->orig_ax;
}

#define EXIT_TO_USERMODE_LOOP_FLAGS				\
	(_TIF_SIGPENDING | _TIF_NOTIFY_RESUME | _TIF_UPROBE |	\
	 _TIF_NEED_RESCHED | _TIF_USER_RETURN_NOTIFY | _TIF_PATCH_PENDING)

static void exit_to_usermode_loop(struct pt_regs *regs, u32 cached_flags)
{
	/*
	 * In order to return to user mode, we need to have IRQs off with
	 * none of EXIT_TO_USERMODE_LOOP_FLAGS set.  Several of these flags
	 * can be set at any time on preemptable kernels if we have IRQs on,
	 * so we need to loop.  Disabling preemption wouldn't help: doing the
	 * work to clear some of the flags can sleep.
	 */
	while (true) {
		/* We have work to do. */
		local_irq_enable();

		if (cached_flags & _TIF_NEED_RESCHED)
			schedule();

		if (cached_flags & _TIF_UPROBE)
			uprobe_notify_resume(regs);

		if (cached_flags & _TIF_PATCH_PENDING)
			klp_update_patch_state(current);

		/* deal with pending signal delivery */
		if (cached_flags & _TIF_SIGPENDING)
			do_signal(regs);

		if (cached_flags & _TIF_NOTIFY_RESUME) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			tracehook_notify_resume(regs);
			rseq_handle_notify_resume(NULL, regs);
		}

		if (cached_flags & _TIF_USER_RETURN_NOTIFY)
			fire_user_return_notifiers();

		/* Disable IRQs and retry */
		local_irq_disable();

		cached_flags = READ_ONCE(current_thread_info()->flags);

		if (!(cached_flags & EXIT_TO_USERMODE_LOOP_FLAGS))
			break;
	}
}

/* Called with IRQs disabled. */
__visible inline void prepare_exit_to_usermode(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	u32 cached_flags;

	addr_limit_user_check();

	lockdep_assert_irqs_disabled();
	lockdep_sys_exit();

	cached_flags = READ_ONCE(ti->flags);

	if (unlikely(cached_flags & EXIT_TO_USERMODE_LOOP_FLAGS))
		exit_to_usermode_loop(regs, cached_flags);

#ifdef CONFIG_COMPAT
	/*
	 * Compat syscalls set TS_COMPAT.  Make sure we clear it before
	 * returning to user mode.  We need to clear it *after* signal
	 * handling, because syscall restart has a fixup for compat
	 * syscalls.  The fixup is exercised by the ptrace_syscall_32
	 * selftest.
	 *
	 * We also need to clear TS_REGS_POKED_I386: the 32-bit tracer
	 * special case only applies after poking regs and before the
	 * very next return to user mode.
	 */
	ti->status &= ~(TS_COMPAT|TS_I386_REGS_POKED);
#endif

	user_enter_irqoff();

	mds_user_clear_cpu_buffers();
}

#define SYSCALL_EXIT_WORK_FLAGS				\
	(_TIF_SYSCALL_TRACE | _TIF_SYSCALL_AUDIT |	\
	 _TIF_SINGLESTEP | _TIF_SYSCALL_TRACEPOINT)

static void syscall_slow_exit_work(struct pt_regs *regs, u32 cached_flags)
{
	bool step;

	audit_syscall_exit(regs);

	if (cached_flags & _TIF_SYSCALL_TRACEPOINT)
		trace_sys_exit(regs, regs->ax);

	/*
	 * If TIF_SYSCALL_EMU is set, we only get here because of
	 * TIF_SINGLESTEP (i.e. this is PTRACE_SYSEMU_SINGLESTEP).
	 * We already reported this syscall instruction in
	 * syscall_trace_enter().
	 */
	step = unlikely(
		(cached_flags & (_TIF_SINGLESTEP | _TIF_SYSCALL_EMU))
		== _TIF_SINGLESTEP);
	if (step || cached_flags & _TIF_SYSCALL_TRACE)
		tracehook_report_syscall_exit(regs, step);
}

/*
 * Called with IRQs on and fully valid regs.  Returns with IRQs off in a
 * state such that we can immediately switch to user mode.
 */
__visible inline void syscall_return_slowpath(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	u32 cached_flags = READ_ONCE(ti->flags);

	CT_WARN_ON(ct_state() != CONTEXT_KERNEL);

	if (IS_ENABLED(CONFIG_PROVE_LOCKING) &&
	    WARN(irqs_disabled(), "syscall %ld left IRQs disabled", regs->orig_ax))
		local_irq_enable();

	rseq_syscall(regs);

	/*
	 * First do one-time work.  If these work items are enabled, we
	 * want to run them exactly once per syscall exit with IRQs on.
	 */
	if (unlikely(cached_flags & SYSCALL_EXIT_WORK_FLAGS))
		syscall_slow_exit_work(regs, cached_flags);

	local_irq_disable();
	prepare_exit_to_usermode(regs);
}
>>>>>>> master

#ifdef CONFIG_X86_64

static __always_inline bool do_syscall_x64(struct pt_regs *regs, int nr)
{
	/*
	 * Convert negative numbers to very high and thus out of range
	 * numbers for comparisons.
	 */
	unsigned int unr = nr;

	if (likely(unr < NR_syscalls)) {
		unr = array_index_nospec(unr, NR_syscalls);
		regs->ax = x64_sys_call(regs, unr);
		return true;
	}
	return false;
}

static __always_inline bool do_syscall_x32(struct pt_regs *regs, int nr)
{
	/*
	 * Adjust the starting offset of the table, and convert numbers
	 * < __X32_SYSCALL_BIT to very high and thus out of range
	 * numbers for comparisons.
	 */
	unsigned int xnr = nr - __X32_SYSCALL_BIT;

	if (IS_ENABLED(CONFIG_X86_X32_ABI) && likely(xnr < X32_NR_syscalls)) {
		xnr = array_index_nospec(xnr, X32_NR_syscalls);
		regs->ax = x32_sys_call(regs, xnr);
		return true;
	}
	return false;
}

__visible noinstr void do_syscall_64(struct pt_regs *regs, int nr)
{
	add_random_kstack_offset();
	nr = syscall_enter_from_user_mode(regs, nr);

	instrumentation_begin();

	if (!do_syscall_x64(regs, nr) && !do_syscall_x32(regs, nr) && nr != -1) {
		/* Invalid system call, but still a system call. */
		regs->ax = __x64_sys_ni_syscall(regs);
	}

	instrumentation_end();
	syscall_exit_to_user_mode(regs);
}
#endif

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
static __always_inline int syscall_32_enter(struct pt_regs *regs)
{
	if (IS_ENABLED(CONFIG_IA32_EMULATION))
		current_thread_info()->status |= TS_COMPAT;

	return (int)regs->orig_ax;
}

#ifdef CONFIG_IA32_EMULATION
bool __ia32_enabled __ro_after_init = true;
#endif

/*
 * Invoke a 32-bit syscall.  Called with IRQs on in CONTEXT_KERNEL.
 */
static __always_inline void do_syscall_32_irqs_on(struct pt_regs *regs, int nr)
{
	/*
	 * Convert negative numbers to very high and thus out of range
	 * numbers for comparisons.
	 */
	unsigned int unr = nr;

	if (likely(unr < IA32_NR_syscalls)) {
		unr = array_index_nospec(unr, IA32_NR_syscalls);
		regs->ax = ia32_sys_call(regs, unr);
	} else if (nr != -1) {
		regs->ax = __ia32_sys_ni_syscall(regs);
	}
}

#ifdef CONFIG_IA32_EMULATION
static __always_inline bool int80_is_external(void)
{
	const unsigned int offs = (0x80 / 32) * 0x10;
	const u32 bit = BIT(0x80 % 32);

	/* The local APIC on XENPV guests is fake */
	if (cpu_feature_enabled(X86_FEATURE_XENPV))
		return false;

	/*
	 * If vector 0x80 is set in the APIC ISR then this is an external
	 * interrupt. Either from broken hardware or injected by a VMM.
	 *
	 * Note: In guest mode this is only valid for secure guests where
	 * the secure module fully controls the vAPIC exposed to the guest.
	 */
	return apic_read(APIC_ISR + offs) & bit;
}

/**
 * do_int80_emulation - 32-bit legacy syscall C entry from asm
 *
 * This entry point can be used by 32-bit and 64-bit programs to perform
 * 32-bit system calls.  Instances of INT $0x80 can be found inline in
 * various programs and libraries.  It is also used by the vDSO's
 * __kernel_vsyscall fallback for hardware that doesn't support a faster
 * entry method.  Restarted 32-bit system calls also fall back to INT
 * $0x80 regardless of what instruction was originally used to do the
 * system call.
 *
 * This is considered a slow path.  It is not used by most libc
 * implementations on modern hardware except during process startup.
 *
 * The arguments for the INT $0x80 based syscall are on stack in the
 * pt_regs structure:
 *   eax:				system call number
 *   ebx, ecx, edx, esi, edi, ebp:	arg1 - arg 6
 */
__visible noinstr void do_int80_emulation(struct pt_regs *regs)
{
	int nr;

	/* Kernel does not use INT $0x80! */
	if (unlikely(!user_mode(regs))) {
		irqentry_enter(regs);
		instrumentation_begin();
		panic("Unexpected external interrupt 0x80\n");
	}

	/*
	 * Establish kernel context for instrumentation, including for
	 * int80_is_external() below which calls into the APIC driver.
	 * Identical for soft and external interrupts.
	 */
	enter_from_user_mode(regs);

	instrumentation_begin();
	add_random_kstack_offset();

	/* Validate that this is a soft interrupt to the extent possible */
	if (unlikely(int80_is_external()))
		panic("Unexpected external interrupt 0x80\n");

	/*
	 * The low level idtentry code pushed -1 into regs::orig_ax
	 * and regs::ax contains the syscall number.
	 *
	 * User tracing code (ptrace or signal handlers) might assume
	 * that the regs::orig_ax contains a 32-bit number on invoking
	 * a 32-bit syscall.
	 *
	 * Establish the syscall convention by saving the 32bit truncated
	 * syscall number in regs::orig_ax and by invalidating regs::ax.
	 */
	regs->orig_ax = regs->ax & GENMASK(31, 0);
	regs->ax = -ENOSYS;

	nr = syscall_32_enter(regs);

	local_irq_enable();
	nr = syscall_enter_from_user_mode_work(regs, nr);
	do_syscall_32_irqs_on(regs, nr);

	instrumentation_end();
	syscall_exit_to_user_mode(regs);
}
#else /* CONFIG_IA32_EMULATION */

/* Handles int $0x80 on a 32bit kernel */
__visible noinstr void do_int80_syscall_32(struct pt_regs *regs)
{
	int nr = syscall_32_enter(regs);

	add_random_kstack_offset();
	/*
	 * Subtlety here: if ptrace pokes something larger than 2^31-1 into
	 * orig_ax, the int return value truncates it. This matches
	 * the semantics of syscall_get_nr().
	 */
	nr = syscall_enter_from_user_mode(regs, nr);
	instrumentation_begin();

	do_syscall_32_irqs_on(regs, nr);

	instrumentation_end();
	syscall_exit_to_user_mode(regs);
}
#endif /* !CONFIG_IA32_EMULATION */

static noinstr bool __do_fast_syscall_32(struct pt_regs *regs)
{
	int nr = syscall_32_enter(regs);
	int res;

	add_random_kstack_offset();
	/*
	 * This cannot use syscall_enter_from_user_mode() as it has to
	 * fetch EBP before invoking any of the syscall entry work
	 * functions.
	 */
	syscall_enter_from_user_mode_prepare(regs);

	instrumentation_begin();
	/* Fetch EBP from where the vDSO stashed it. */
	if (IS_ENABLED(CONFIG_X86_64)) {
		/*
		 * Micro-optimization: the pointer we're following is
		 * explicitly 32 bits, so it can't be out of range.
		 */
		res = __get_user(*(u32 *)&regs->bp,
			 (u32 __user __force *)(unsigned long)(u32)regs->sp);
	} else {
		res = get_user(*(u32 *)&regs->bp,
		       (u32 __user __force *)(unsigned long)(u32)regs->sp);
	}

	if (res) {
		/* User code screwed up. */
		regs->ax = -EFAULT;

		local_irq_disable();
		instrumentation_end();
		irqentry_exit_to_user_mode(regs);
		return false;
	}

	nr = syscall_enter_from_user_mode_work(regs, nr);

	/* Now this is just like a normal syscall. */
	do_syscall_32_irqs_on(regs, nr);

	instrumentation_end();
	syscall_exit_to_user_mode(regs);
	return true;
}

/* Returns 0 to return using IRET or 1 to return using SYSEXIT/SYSRETL. */
__visible noinstr long do_fast_syscall_32(struct pt_regs *regs)
{
	/*
	 * Called using the internal vDSO SYSENTER/SYSCALL32 calling
	 * convention.  Adjust regs so it looks like we entered using int80.
	 */
	unsigned long landing_pad = (unsigned long)current->mm->context.vdso +
					vdso_image_32.sym_int80_landing_pad;

	/*
	 * SYSENTER loses EIP, and even SYSCALL32 needs us to skip forward
	 * so that 'regs->ip -= 2' lands back on an int $0x80 instruction.
	 * Fix it up.
	 */
	regs->ip = landing_pad;

	/* Invoke the syscall. If it failed, keep it simple: use IRET. */
	if (!__do_fast_syscall_32(regs))
		return 0;

#ifdef CONFIG_X86_64
	/*
	 * Opportunistic SYSRETL: if possible, try to return using SYSRETL.
	 * SYSRETL is available on all 64-bit CPUs, so we don't need to
	 * bother with SYSEXIT.
	 *
	 * Unlike 64-bit opportunistic SYSRET, we can't check that CX == IP,
	 * because the ECX fixup above will ensure that this is essentially
	 * never the case.
	 */
	return regs->cs == __USER32_CS && regs->ss == __USER_DS &&
		regs->ip == landing_pad &&
		(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF)) == 0;
#else
	/*
	 * Opportunistic SYSEXIT: if possible, try to return using SYSEXIT.
	 *
	 * Unlike 64-bit opportunistic SYSRET, we can't check that CX == IP,
	 * because the ECX fixup above will ensure that this is essentially
	 * never the case.
	 *
	 * We don't allow syscalls at all from VM86 mode, but we still
	 * need to check VM, because we might be returning from sys_vm86.
	 */
	return static_cpu_has(X86_FEATURE_SEP) &&
		regs->cs == __USER_CS && regs->ss == __USER_DS &&
		regs->ip == landing_pad &&
		(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF | X86_EFLAGS_VM)) == 0;
#endif
}

/* Returns 0 to return using IRET or 1 to return using SYSEXIT/SYSRETL. */
__visible noinstr long do_SYSENTER_32(struct pt_regs *regs)
{
	/* SYSENTER loses RSP, but the vDSO saved it in RBP. */
	regs->sp = regs->bp;

	/* SYSENTER clobbers EFLAGS.IF.  Assume it was set in usermode. */
	regs->flags |= X86_EFLAGS_IF;

	return do_fast_syscall_32(regs);
}
#endif

SYSCALL_DEFINE0(ni_syscall)
{
	return -ENOSYS;
}

#ifdef CONFIG_XEN_PV
#ifndef CONFIG_PREEMPTION
/*
 * Some hypercalls issued by the toolstack can take many 10s of
 * seconds. Allow tasks running hypercalls via the privcmd driver to
 * be voluntarily preempted even if full kernel preemption is
 * disabled.
 *
 * Such preemptible hypercalls are bracketed by
 * xen_preemptible_hcall_begin() and xen_preemptible_hcall_end()
 * calls.
 */
DEFINE_PER_CPU(bool, xen_in_preemptible_hcall);
EXPORT_SYMBOL_GPL(xen_in_preemptible_hcall);

/*
 * In case of scheduling the flag must be cleared and restored after
 * returning from schedule as the task might move to a different CPU.
 */
static __always_inline bool get_and_clear_inhcall(void)
{
	bool inhcall = __this_cpu_read(xen_in_preemptible_hcall);

	__this_cpu_write(xen_in_preemptible_hcall, false);
	return inhcall;
}

static __always_inline void restore_inhcall(bool inhcall)
{
	__this_cpu_write(xen_in_preemptible_hcall, inhcall);
}
#else
static __always_inline bool get_and_clear_inhcall(void) { return false; }
static __always_inline void restore_inhcall(bool inhcall) { }
#endif

static void __xen_pv_evtchn_do_upcall(struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	inc_irq_stat(irq_hv_callback_count);

	xen_evtchn_do_upcall();

	set_irq_regs(old_regs);
}

__visible noinstr void xen_pv_evtchn_do_upcall(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);
	bool inhcall;

	instrumentation_begin();
	run_sysvec_on_irqstack_cond(__xen_pv_evtchn_do_upcall, regs);

	inhcall = get_and_clear_inhcall();
	if (inhcall && !WARN_ON_ONCE(state.exit_rcu)) {
		irqentry_exit_cond_resched();
		instrumentation_end();
		restore_inhcall(inhcall);
	} else {
		instrumentation_end();
		irqentry_exit(regs, state);
	}
}
#endif /* CONFIG_XEN_PV */
