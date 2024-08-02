/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_TRAPS_H
#define _ASM_X86_TRAPS_H

#include <linux/context_tracking_state.h>
#include <linux/kprobes.h>

#include <asm/debugreg.h>
#include <asm/idtentry.h>
#include <asm/siginfo.h>			/* TRAP_TRACE, ... */
#include <asm/trap_pf.h>

#ifdef CONFIG_X86_64
<<<<<<< HEAD
asmlinkage __visible notrace struct pt_regs *sync_regs(struct pt_regs *eregs);
asmlinkage __visible notrace
struct pt_regs *fixup_bad_iret(struct pt_regs *bad_regs);
void __init trap_init(void);
asmlinkage __visible noinstr struct pt_regs *vc_switch_off_ist(struct pt_regs *eregs);
=======
asmlinkage void double_fault(void);
#endif
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void async_page_fault(void);
asmlinkage void spurious_interrupt_bug(void);
asmlinkage void coprocessor_error(void);
asmlinkage void alignment_check(void);
#ifdef CONFIG_X86_MCE
asmlinkage void machine_check(void);
#endif /* CONFIG_X86_MCE */
asmlinkage void simd_coprocessor_error(void);

#if defined(CONFIG_X86_64) && defined(CONFIG_XEN_PV)
asmlinkage void xen_divide_error(void);
asmlinkage void xen_xennmi(void);
asmlinkage void xen_xendebug(void);
asmlinkage void xen_int3(void);
asmlinkage void xen_overflow(void);
asmlinkage void xen_bounds(void);
asmlinkage void xen_invalid_op(void);
asmlinkage void xen_device_not_available(void);
asmlinkage void xen_double_fault(void);
asmlinkage void xen_coprocessor_segment_overrun(void);
asmlinkage void xen_invalid_TSS(void);
asmlinkage void xen_segment_not_present(void);
asmlinkage void xen_stack_segment(void);
asmlinkage void xen_general_protection(void);
asmlinkage void xen_page_fault(void);
asmlinkage void xen_spurious_interrupt_bug(void);
asmlinkage void xen_coprocessor_error(void);
asmlinkage void xen_alignment_check(void);
#ifdef CONFIG_X86_MCE
asmlinkage void xen_machine_check(void);
#endif /* CONFIG_X86_MCE */
asmlinkage void xen_simd_coprocessor_error(void);
>>>>>>> master
#endif

extern int ibt_selftest(void);
extern int ibt_selftest_noendbr(void);

#ifdef CONFIG_X86_F00F_BUG
/* For handling the FOOF bug */
void handle_invalid_op(struct pt_regs *regs);
#endif

static inline int get_si_code(unsigned long condition)
{
	if (condition & DR_STEP)
		return TRAP_TRACE;
	else if (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3))
		return TRAP_HWBKPT;
	else
		return TRAP_BRKPT;
}

extern int panic_on_unrecovered_nmi;

void math_emulate(struct math_emu_info *);
<<<<<<< HEAD
=======
#ifndef CONFIG_X86_32
asmlinkage void smp_thermal_interrupt(struct pt_regs *regs);
asmlinkage void smp_threshold_interrupt(struct pt_regs *regs);
asmlinkage void smp_deferred_error_interrupt(struct pt_regs *regs);
#endif
>>>>>>> master

bool fault_in_kernel_space(unsigned long address);

#ifdef CONFIG_VMAP_STACK
void __noreturn handle_stack_overflow(struct pt_regs *regs,
				      unsigned long fault_address,
				      struct stack_info *info);
#endif

static inline void cond_local_irq_enable(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_enable();
}

static inline void cond_local_irq_disable(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_disable();
}

#endif /* _ASM_X86_TRAPS_H */
