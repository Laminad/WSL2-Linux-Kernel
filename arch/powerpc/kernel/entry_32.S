/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  PowerPC version
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *  Rewritten by Cort Dougan (cort@fsmlabs.com) for PReP
 *    Copyright (C) 1996 Cort Dougan <cort@fsmlabs.com>
 *  Adapted for Power Macintosh by Paul Mackerras.
 *  Low-level exception handlers and MMU support
 *  rewritten by Paul Mackerras.
 *    Copyright (C) 1996 Paul Mackerras.
 *  MPC8xx modifications Copyright (C) 1997 Dan Malek (dmalek@jlc.net).
 *
 *  This file contains the system call entry code, context switch
 *  code, and exception/interrupt return code for PowerPC.
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/sys.h>
#include <linux/threads.h>
#include <linux/linkage.h>

#include <asm/reg.h>
#include <asm/page.h>
#include <asm/mmu.h>
#include <asm/cputable.h>
#include <asm/thread_info.h>
#include <asm/ppc_asm.h>
#include <asm/asm-offsets.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>
#include <asm/feature-fixups.h>
#include <asm/barrier.h>
#include <asm/kup.h>
#include <asm/bug.h>
#include <asm/interrupt.h>

#include "head_32.h"

/*
 * powerpc relies on return from interrupt/syscall being context synchronising
 * (which rfi is) to support ARCH_HAS_MEMBARRIER_SYNC_CORE without additional
 * synchronisation instructions.
 */

/*
 * Align to 4k in order to ensure that all functions modyfing srr0/srr1
 * fit into one page in order to not encounter a TLB miss between the
 * modification of srr0/srr1 and the associated rfi.
 */
	.align	12

#if defined(CONFIG_PPC_BOOK3S_32) || defined(CONFIG_PPC_E500)
	.globl	prepare_transfer_to_handler
prepare_transfer_to_handler:
	/* if from kernel, check interrupted DOZE/NAP mode */
	lwz	r12,TI_LOCAL_FLAGS(r2)
	mtcrf	0x01,r12
	bt-	31-TLF_NAPPING,4f
	bt-	31-TLF_SLEEPING,7f
	blr

4:	rlwinm	r12,r12,0,~_TLF_NAPPING
	stw	r12,TI_LOCAL_FLAGS(r2)
	b	power_save_ppc32_restore

7:	rlwinm	r12,r12,0,~_TLF_SLEEPING
	stw	r12,TI_LOCAL_FLAGS(r2)
	lwz	r9,_MSR(r11)		/* if sleeping, clear MSR.EE */
	rlwinm	r9,r9,0,~MSR_EE
	lwz	r12,_LINK(r11)		/* and return to address in LR */
	REST_GPR(2, r11)
	b	fast_exception_return
_ASM_NOKPROBE_SYMBOL(prepare_transfer_to_handler)
#endif /* CONFIG_PPC_BOOK3S_32 || CONFIG_PPC_E500 */

#if defined(CONFIG_PPC_KUEP) && defined(CONFIG_PPC_BOOK3S_32)
SYM_FUNC_START(__kuep_lock)
	lwz	r9, THREAD+THSR0(r2)
	update_user_segments_by_4 r9, r10, r11, r12
	blr
SYM_FUNC_END(__kuep_lock)

SYM_FUNC_START_LOCAL(__kuep_unlock)
	lwz	r9, THREAD+THSR0(r2)
	rlwinm  r9,r9,0,~SR_NX
	update_user_segments_by_4 r9, r10, r11, r12
	blr
SYM_FUNC_END(__kuep_unlock)

.macro	kuep_lock
	bl	__kuep_lock
.endm
.macro	kuep_unlock
	bl	__kuep_unlock
.endm
#else
.macro	kuep_lock
.endm
.macro	kuep_unlock
.endm
#endif

	.globl	transfer_to_syscall
transfer_to_syscall:
	stw	r3, ORIG_GPR3(r1)
	stw	r11, GPR1(r1)
	stw	r11, 0(r1)
	mflr	r12
	stw	r12, _LINK(r1)
#ifdef CONFIG_BOOKE_OR_40x
	rlwinm	r9,r9,0,14,12		/* clear MSR_WE (necessary?) */
#endif
	lis	r12,STACK_FRAME_REGS_MARKER@ha /* exception frame marker */
	SAVE_GPR(2, r1)
	addi	r12,r12,STACK_FRAME_REGS_MARKER@l
	stw	r9,_MSR(r1)
	li	r2, INTERRUPT_SYSCALL
	stw	r12,STACK_INT_FRAME_MARKER(r1)
	stw	r2,_TRAP(r1)
	SAVE_GPR(0, r1)
	SAVE_GPRS(3, 8, r1)
	addi	r2,r10,-THREAD
	SAVE_NVGPRS(r1)
	kuep_lock

	/* Calling convention has r3 = regs, r4 = orig r0 */
	addi	r3,r1,STACK_INT_FRAME_REGS
	mr	r4,r0
	bl	system_call_exception

ret_from_syscall:
	addi    r4,r1,STACK_INT_FRAME_REGS
	li	r5,0
	bl	syscall_exit_prepare
#ifdef CONFIG_PPC_47x
	lis	r4,icache_44x_need_flush@ha
	lwz	r5,icache_44x_need_flush@l(r4)
	cmplwi	cr0,r5,0
	bne-	.L44x_icache_flush
#endif /* CONFIG_PPC_47x */
.L44x_icache_flush_return:
	kuep_unlock
	lwz	r4,_LINK(r1)
	lwz	r5,_CCR(r1)
	mtlr	r4
	lwz	r7,_NIP(r1)
	lwz	r8,_MSR(r1)
	cmpwi	r3,0
	REST_GPR(3, r1)
syscall_exit_finish:
	mtspr	SPRN_SRR0,r7
	mtspr	SPRN_SRR1,r8

	bne	3f
	mtcr	r5

1:	REST_GPR(2, r1)
	REST_GPR(1, r1)
	rfi
#ifdef CONFIG_40x
	b .	/* Prevent prefetch past rfi */
#endif

3:	mtcr	r5
	lwz	r4,_CTR(r1)
	lwz	r5,_XER(r1)
	REST_NVGPRS(r1)
	mtctr	r4
	mtxer	r5
	REST_GPR(0, r1)
	REST_GPRS(3, 12, r1)
	b	1b

#ifdef CONFIG_44x
.L44x_icache_flush:
	li	r7,0
	iccci	r0,r0
	stw	r7,icache_44x_need_flush@l(r4)
	b	.L44x_icache_flush_return
#endif  /* CONFIG_44x */

	.globl	ret_from_fork
ret_from_fork:
	REST_NVGPRS(r1)
	bl	schedule_tail
	li	r3,0	/* fork() return value */
	b	ret_from_syscall

	.globl	ret_from_kernel_user_thread
ret_from_kernel_user_thread:
	bl	schedule_tail
	mtctr	r14
	mr	r3,r15
	PPC440EP_ERR42
	bctrl
	li	r3,0
	b	ret_from_syscall

	.globl	start_kernel_thread
start_kernel_thread:
	bl	schedule_tail
	mtctr	r14
	mr	r3,r15
	PPC440EP_ERR42
	bctrl
	/*
	 * This must not return. We actually want to BUG here, not WARN,
	 * because BUG will exit the process which is what the kernel thread
	 * should have done, which may give some hope of continuing.
	 */
100:	trap
	EMIT_BUG_ENTRY 100b,__FILE__,__LINE__,0

	.globl	fast_exception_return
fast_exception_return:
#if !(defined(CONFIG_4xx) || defined(CONFIG_BOOKE))
	andi.	r10,r9,MSR_RI		/* check for recoverable interrupt */
	beq	3f			/* if not, we've got problems */
#endif

2:	lwz	r10,_CCR(r11)
	REST_GPRS(1, 6, r11)
	mtcr	r10
	lwz	r10,_LINK(r11)
	mtlr	r10
<<<<<<< HEAD
	/* Clear the exception marker on the stack to avoid confusing stacktrace */
=======
	/* Clear the exception_marker on the stack to avoid confusing stacktrace */
>>>>>>> master
	li	r10, 0
	stw	r10, 8(r11)
	REST_GPR(10, r11)
#if defined(CONFIG_PPC_8xx) && defined(CONFIG_PERF_EVENTS)
	mtspr	SPRN_NRI, r0
#endif
	mtspr	SPRN_SRR1,r9
	mtspr	SPRN_SRR0,r12
	REST_GPR(9, r11)
	REST_GPR(12, r11)
	REST_GPR(11, r11)
	rfi
#ifdef CONFIG_40x
	b .	/* Prevent prefetch past rfi */
#endif
_ASM_NOKPROBE_SYMBOL(fast_exception_return)

/* aargh, a nonrecoverable interrupt, panic */
/* aargh, we don't know which trap this is */
3:
	li	r10,-1
	stw	r10,_TRAP(r11)
	prepare_transfer_to_handler
	bl	unrecoverable_exception
	trap	/* should not get here */

	.globl interrupt_return
interrupt_return:
	lwz	r4,_MSR(r1)
	addi	r3,r1,STACK_INT_FRAME_REGS
	andi.	r0,r4,MSR_PR
	beq	.Lkernel_interrupt_return
	bl	interrupt_exit_user_prepare
	cmpwi	r3,0
	kuep_unlock
	bne-	.Lrestore_nvgprs

<<<<<<< HEAD
.Lfast_user_interrupt_return:
=======
	.globl	ret_from_except
ret_from_except:
	/* Hard-disable interrupts so that current_thread_info()->flags
	 * can't change between when we test it and when we return
	 * from the interrupt. */
	/* Note: We don't bother telling lockdep about it */
	LOAD_MSR_KERNEL(r10,MSR_KERNEL)
	SYNC			/* Some chip revs have problems here... */
	MTMSRD(r10)		/* disable interrupts */

	lwz	r3,_MSR(r1)	/* Returning to user mode? */
	andi.	r0,r3,MSR_PR
	beq	resume_kernel

user_exc_return:		/* r10 contains MSR_KERNEL here */
	/* Check current_thread_info()->flags */
	CURRENT_THREAD_INFO(r9, r1)
	lwz	r9,TI_FLAGS(r9)
	andi.	r0,r9,_TIF_USER_WORK_MASK
	bne	do_work

restore_user:
#if defined(CONFIG_4xx) || defined(CONFIG_BOOKE)
	/* Check whether this process has its own DBCR0 value.  The internal
	   debug mode bit tells us that dbcr0 should be loaded. */
	lwz	r0,THREAD+THREAD_DBCR0(r2)
	andis.	r10,r0,DBCR0_IDM@h
	bnel-	load_dbcr0
#endif
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
	CURRENT_THREAD_INFO(r9, r1)
	ACCOUNT_CPU_USER_EXIT(r9, r10, r11)
#endif

	b	restore

/* N.B. the only way to get here is from the beq following ret_from_except. */
resume_kernel:
	/* check current_thread_info, _TIF_EMULATE_STACK_STORE */
	CURRENT_THREAD_INFO(r9, r1)
	lwz	r8,TI_FLAGS(r9)
	andis.	r0,r8,_TIF_EMULATE_STACK_STORE@h
	beq+	1f

	addi	r8,r1,INT_FRAME_SIZE	/* Get the kprobed function entry */

	lwz	r3,GPR1(r1)
	subi	r3,r3,INT_FRAME_SIZE	/* dst: Allocate a trampoline exception frame */
	mr	r4,r1			/* src:  current exception frame */
	mr	r1,r3			/* Reroute the trampoline frame to r1 */

	/* Copy from the original to the trampoline. */
	li	r5,INT_FRAME_SIZE/4	/* size: INT_FRAME_SIZE */
	li	r6,0			/* start offset: 0 */
	mtctr	r5
2:	lwzx	r0,r6,r4
	stwx	r0,r6,r3
	addi	r6,r6,4
	bdnz	2b

	/* Do real store operation to complete stwu */
	lwz	r5,GPR1(r1)
	stw	r8,0(r5)

	/* Clear _TIF_EMULATE_STACK_STORE flag */
	lis	r11,_TIF_EMULATE_STACK_STORE@h
	addi	r5,r9,TI_FLAGS
0:	lwarx	r8,0,r5
	andc	r8,r8,r11
#ifdef CONFIG_IBM405_ERR77
	dcbt	0,r5
#endif
	stwcx.	r8,0,r5
	bne-	0b
1:

#ifdef CONFIG_PREEMPT
	/* check current_thread_info->preempt_count */
	lwz	r0,TI_PREEMPT(r9)
	cmpwi	0,r0,0		/* if non-zero, just restore regs and return */
	bne	restore
	andi.	r8,r8,_TIF_NEED_RESCHED
	beq+	restore
	lwz	r3,_MSR(r1)
	andi.	r0,r3,MSR_EE	/* interrupts off? */
	beq	restore		/* don't schedule if so */
#ifdef CONFIG_TRACE_IRQFLAGS
	/* Lockdep thinks irqs are enabled, we need to call
	 * preempt_schedule_irq with IRQs off, so we inform lockdep
	 * now that we -did- turn them off already
	 */
	bl	trace_hardirqs_off
#endif
1:	bl	preempt_schedule_irq
	CURRENT_THREAD_INFO(r9, r1)
	lwz	r3,TI_FLAGS(r9)
	andi.	r0,r3,_TIF_NEED_RESCHED
	bne-	1b
#ifdef CONFIG_TRACE_IRQFLAGS
	/* And now, to properly rebalance the above, we tell lockdep they
	 * are being turned back on, which will happen when we return
	 */
	bl	trace_hardirqs_on
#endif
#endif /* CONFIG_PREEMPT */

	/* interrupts are hard-disabled at this point */
restore:
#ifdef CONFIG_44x
BEGIN_MMU_FTR_SECTION
	b	1f
END_MMU_FTR_SECTION_IFSET(MMU_FTR_TYPE_47x)
	lis	r4,icache_44x_need_flush@ha
	lwz	r5,icache_44x_need_flush@l(r4)
	cmplwi	cr0,r5,0
	beq+	1f
	li	r6,0
	iccci	r0,r0
	stw	r6,icache_44x_need_flush@l(r4)
1:
#endif  /* CONFIG_44x */

	lwz	r9,_MSR(r1)
#ifdef CONFIG_TRACE_IRQFLAGS
	/* Lockdep doesn't know about the fact that IRQs are temporarily turned
	 * off in this assembly code while peeking at TI_FLAGS() and such. However
	 * we need to inform it if the exception turned interrupts off, and we
	 * are about to trun them back on.
	 *
	 * The problem here sadly is that we don't know whether the exceptions was
	 * one that turned interrupts off or not. So we always tell lockdep about
	 * turning them on here when we go back to wherever we came from with EE
	 * on, even if that may meen some redudant calls being tracked. Maybe later
	 * we could encode what the exception did somewhere or test the exception
	 * type in the pt_regs but that sounds overkill
	 */
	andi.	r10,r9,MSR_EE
	beq	1f
	/*
	 * Since the ftrace irqsoff latency trace checks CALLER_ADDR1,
	 * which is the stack frame here, we need to force a stack frame
	 * in case we came from user space.
	 */
	stwu	r1,-32(r1)
	mflr	r0
	stw	r0,4(r1)
	stwu	r1,-32(r1)
	bl	trace_hardirqs_on
	lwz	r1,0(r1)
	lwz	r1,0(r1)
	lwz	r9,_MSR(r1)
1:
#endif /* CONFIG_TRACE_IRQFLAGS */

	lwz	r0,GPR0(r1)
	lwz	r2,GPR2(r1)
	REST_4GPRS(3, r1)
	REST_2GPRS(7, r1)

	lwz	r10,_XER(r1)
	lwz	r11,_CTR(r1)
	mtspr	SPRN_XER,r10
	mtctr	r11

	PPC405_ERR77(0,r1)
BEGIN_FTR_SECTION
	lwarx	r11,0,r1
END_FTR_SECTION_IFSET(CPU_FTR_NEED_PAIRED_STWCX)
	stwcx.	r0,0,r1			/* to clear the reservation */

#if !(defined(CONFIG_4xx) || defined(CONFIG_BOOKE))
	andi.	r10,r9,MSR_RI		/* check if this exception occurred */
	beql	nonrecoverable		/* at a bad place (MSR:RI = 0) */

	lwz	r10,_CCR(r1)
	lwz	r11,_LINK(r1)
	mtcrf	0xFF,r10
	mtlr	r11

	/* Clear the exception_marker on the stack to avoid confusing stacktrace */
	li	r10, 0
	stw	r10, 8(r1)
	/*
	 * Once we put values in SRR0 and SRR1, we are in a state
	 * where exceptions are not recoverable, since taking an
	 * exception will trash SRR0 and SRR1.  Therefore we clear the
	 * MSR:RI bit to indicate this.  If we do take an exception,
	 * we can't return to the point of the exception but we
	 * can restart the exception exit path at the label
	 * exc_exit_restart below.  -- paulus
	 */
	LOAD_MSR_KERNEL(r10,MSR_KERNEL & ~MSR_RI)
	SYNC
	MTMSRD(r10)		/* clear the RI bit */
	.globl exc_exit_restart
exc_exit_restart:
	lwz	r12,_NIP(r1)
#if defined(CONFIG_PPC_8xx) && defined(CONFIG_PERF_EVENTS)
	mtspr	SPRN_NRI, r0
#endif
	mtspr	SPRN_SRR0,r12
	mtspr	SPRN_SRR1,r9
	REST_4GPRS(9, r1)
	lwz	r1,GPR1(r1)
	.globl exc_exit_restart_end
exc_exit_restart_end:
	SYNC
	RFI

#else /* !(CONFIG_4xx || CONFIG_BOOKE) */
	/*
	 * This is a bit different on 4xx/Book-E because it doesn't have
	 * the RI bit in the MSR.
	 * The TLB miss handler checks if we have interrupted
	 * the exception exit path and restarts it if so
	 * (well maybe one day it will... :).
	 */
	lwz	r11,_LINK(r1)
	mtlr	r11
	lwz	r10,_CCR(r1)
	mtcrf	0xff,r10
	/* Clear the exception_marker on the stack to avoid confusing stacktrace */
	li	r10, 0
	stw	r10, 8(r1)
	REST_2GPRS(9, r1)
	.globl exc_exit_restart
exc_exit_restart:
>>>>>>> master
	lwz	r11,_NIP(r1)
	lwz	r12,_MSR(r1)
	mtspr	SPRN_SRR0,r11
	mtspr	SPRN_SRR1,r12

BEGIN_FTR_SECTION
	stwcx.	r0,0,r1		/* to clear the reservation */
FTR_SECTION_ELSE
	lwarx	r0,0,r1
ALT_FTR_SECTION_END_IFCLR(CPU_FTR_STCX_CHECKS_ADDRESS)

	lwz	r3,_CCR(r1)
	lwz	r4,_LINK(r1)
	lwz	r5,_CTR(r1)
	lwz	r6,_XER(r1)
	li	r0,0

	/*
	 * Leaving a stale exception marker on the stack can confuse
	 * the reliable stack unwinder later on. Clear it.
	 */
	stw	r0,8(r1)
	REST_GPRS(7, 12, r1)

	mtcr	r3
	mtlr	r4
	mtctr	r5
	mtspr	SPRN_XER,r6

	REST_GPRS(2, 6, r1)
	REST_GPR(0, r1)
	REST_GPR(1, r1)
	rfi
#ifdef CONFIG_40x
	b .	/* Prevent prefetch past rfi */
#endif

.Lrestore_nvgprs:
	REST_NVGPRS(r1)
	b	.Lfast_user_interrupt_return

.Lkernel_interrupt_return:
	bl	interrupt_exit_kernel_prepare

.Lfast_kernel_interrupt_return:
	cmpwi	cr1,r3,0
	lwz	r11,_NIP(r1)
	lwz	r12,_MSR(r1)
	mtspr	SPRN_SRR0,r11
	mtspr	SPRN_SRR1,r12

BEGIN_FTR_SECTION
	stwcx.	r0,0,r1		/* to clear the reservation */
FTR_SECTION_ELSE
	lwarx	r0,0,r1
ALT_FTR_SECTION_END_IFCLR(CPU_FTR_STCX_CHECKS_ADDRESS)

	lwz	r3,_LINK(r1)
	lwz	r4,_CTR(r1)
	lwz	r5,_XER(r1)
	lwz	r6,_CCR(r1)
	li	r0,0

	REST_GPRS(7, 12, r1)

	mtlr	r3
	mtctr	r4
	mtspr	SPRN_XER,r5

	/*
	 * Leaving a stale exception marker on the stack can confuse
	 * the reliable stack unwinder later on. Clear it.
	 */
	stw	r0,8(r1)

	REST_GPRS(2, 5, r1)

	bne-	cr1,1f /* emulate stack store */
	mtcr	r6
	REST_GPR(6, r1)
	REST_GPR(0, r1)
	REST_GPR(1, r1)
	rfi
#ifdef CONFIG_40x
	b .	/* Prevent prefetch past rfi */
#endif

1:	/*
	 * Emulate stack store with update. New r1 value was already calculated
	 * and updated in our interrupt regs by emulate_loadstore, but we can't
	 * store the previous value of r1 to the stack before re-loading our
	 * registers from it, otherwise they could be clobbered.  Use
	 * SPRG Scratch0 as temporary storage to hold the store
	 * data, as interrupts are disabled here so it won't be clobbered.
	 */
	mtcr	r6
#ifdef CONFIG_BOOKE
	mtspr	SPRN_SPRG_WSCRATCH0, r9
#else
	mtspr	SPRN_SPRG_SCRATCH0, r9
#endif
	addi	r9,r1,INT_FRAME_SIZE /* get original r1 */
	REST_GPR(6, r1)
	REST_GPR(0, r1)
	REST_GPR(1, r1)
	stw	r9,0(r1) /* perform store component of stwu */
#ifdef CONFIG_BOOKE
	mfspr	r9, SPRN_SPRG_RSCRATCH0
#else
	mfspr	r9, SPRN_SPRG_SCRATCH0
#endif
	rfi
#ifdef CONFIG_40x
	b .	/* Prevent prefetch past rfi */
#endif
_ASM_NOKPROBE_SYMBOL(interrupt_return)

#if defined(CONFIG_4xx) || defined(CONFIG_BOOKE)

/*
 * Returning from a critical interrupt in user mode doesn't need
 * to be any different from a normal exception.  For a critical
 * interrupt in the kernel, we just return (without checking for
 * preemption) since the interrupt may have happened at some crucial
 * place (e.g. inside the TLB miss handler), and because we will be
 * running with r1 pointing into critical_stack, not the current
 * process's kernel stack (and therefore current_thread_info() will
 * give the wrong answer).
 * We have to restore various SPRs that may have been in use at the
 * time of the critical interrupt.
 *
 */
#ifdef CONFIG_40x
#define PPC_40x_TURN_OFF_MSR_DR						    \
	/* avoid any possible TLB misses here by turning off MSR.DR, we	    \
	 * assume the instructions here are mapped by a pinned TLB entry */ \
	li	r10,MSR_IR;						    \
	mtmsr	r10;							    \
	isync;								    \
	tophys(r1, r1);
#else
#define PPC_40x_TURN_OFF_MSR_DR
#endif

#define RET_FROM_EXC_LEVEL(exc_lvl_srr0, exc_lvl_srr1, exc_lvl_rfi)	\
	REST_NVGPRS(r1);						\
	lwz	r3,_MSR(r1);						\
	andi.	r3,r3,MSR_PR;						\
	bne	interrupt_return;					\
	REST_GPR(0, r1);						\
	REST_GPRS(2, 8, r1);						\
	lwz	r10,_XER(r1);						\
	lwz	r11,_CTR(r1);						\
	mtspr	SPRN_XER,r10;						\
	mtctr	r11;							\
	stwcx.	r0,0,r1;		/* to clear the reservation */	\
	lwz	r11,_LINK(r1);						\
	mtlr	r11;							\
	lwz	r10,_CCR(r1);						\
	mtcrf	0xff,r10;						\
	PPC_40x_TURN_OFF_MSR_DR;					\
	lwz	r9,_DEAR(r1);						\
	lwz	r10,_ESR(r1);						\
	mtspr	SPRN_DEAR,r9;						\
	mtspr	SPRN_ESR,r10;						\
	lwz	r11,_NIP(r1);						\
	lwz	r12,_MSR(r1);						\
	mtspr	exc_lvl_srr0,r11;					\
	mtspr	exc_lvl_srr1,r12;					\
	REST_GPRS(9, 12, r1);						\
	REST_GPR(1, r1);						\
	exc_lvl_rfi;							\
	b	.;		/* prevent prefetch past exc_lvl_rfi */

#define	RESTORE_xSRR(exc_lvl_srr0, exc_lvl_srr1)			\
	lwz	r9,_##exc_lvl_srr0(r1);					\
	lwz	r10,_##exc_lvl_srr1(r1);				\
	mtspr	SPRN_##exc_lvl_srr0,r9;					\
	mtspr	SPRN_##exc_lvl_srr1,r10;

#if defined(CONFIG_PPC_E500)
#ifdef CONFIG_PHYS_64BIT
#define	RESTORE_MAS7							\
	lwz	r11,MAS7(r1);						\
	mtspr	SPRN_MAS7,r11;
#else
#define	RESTORE_MAS7
#endif /* CONFIG_PHYS_64BIT */
#define RESTORE_MMU_REGS						\
	lwz	r9,MAS0(r1);						\
	lwz	r10,MAS1(r1);						\
	lwz	r11,MAS2(r1);						\
	mtspr	SPRN_MAS0,r9;						\
	lwz	r9,MAS3(r1);						\
	mtspr	SPRN_MAS1,r10;						\
	lwz	r10,MAS6(r1);						\
	mtspr	SPRN_MAS2,r11;						\
	mtspr	SPRN_MAS3,r9;						\
	mtspr	SPRN_MAS6,r10;						\
	RESTORE_MAS7;
#elif defined(CONFIG_44x)
#define RESTORE_MMU_REGS						\
	lwz	r9,MMUCR(r1);						\
	mtspr	SPRN_MMUCR,r9;
#else
#define RESTORE_MMU_REGS
#endif

#ifdef CONFIG_40x
	.globl	ret_from_crit_exc
ret_from_crit_exc:
	lis	r9,crit_srr0@ha;
	lwz	r9,crit_srr0@l(r9);
	lis	r10,crit_srr1@ha;
	lwz	r10,crit_srr1@l(r10);
	mtspr	SPRN_SRR0,r9;
	mtspr	SPRN_SRR1,r10;
	RET_FROM_EXC_LEVEL(SPRN_CSRR0, SPRN_CSRR1, PPC_RFCI)
_ASM_NOKPROBE_SYMBOL(ret_from_crit_exc)
#endif /* CONFIG_40x */

#ifdef CONFIG_BOOKE
	.globl	ret_from_crit_exc
ret_from_crit_exc:
	RESTORE_xSRR(SRR0,SRR1);
	RESTORE_MMU_REGS;
	RET_FROM_EXC_LEVEL(SPRN_CSRR0, SPRN_CSRR1, PPC_RFCI)
_ASM_NOKPROBE_SYMBOL(ret_from_crit_exc)

	.globl	ret_from_debug_exc
ret_from_debug_exc:
	RESTORE_xSRR(SRR0,SRR1);
	RESTORE_xSRR(CSRR0,CSRR1);
	RESTORE_MMU_REGS;
	RET_FROM_EXC_LEVEL(SPRN_DSRR0, SPRN_DSRR1, PPC_RFDI)
_ASM_NOKPROBE_SYMBOL(ret_from_debug_exc)

	.globl	ret_from_mcheck_exc
ret_from_mcheck_exc:
	RESTORE_xSRR(SRR0,SRR1);
	RESTORE_xSRR(CSRR0,CSRR1);
	RESTORE_xSRR(DSRR0,DSRR1);
	RESTORE_MMU_REGS;
	RET_FROM_EXC_LEVEL(SPRN_MCSRR0, SPRN_MCSRR1, PPC_RFMCI)
_ASM_NOKPROBE_SYMBOL(ret_from_mcheck_exc)
#endif /* CONFIG_BOOKE */
#endif /* !(CONFIG_4xx || CONFIG_BOOKE) */
