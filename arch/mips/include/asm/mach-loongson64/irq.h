/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_MACH_LOONGSON64_IRQ_H_
#define __ASM_MACH_LOONGSON64_IRQ_H_

/* cpu core interrupt numbers */
#define NR_IRQS_LEGACY		16
#define NR_MIPS_CPU_IRQS	8
#define NR_MAX_CHAINED_IRQS	40 /* Chained IRQs means those not directly used by devices */
#define NR_IRQS			(NR_IRQS_LEGACY + NR_MIPS_CPU_IRQS + NR_MAX_CHAINED_IRQS + 256)
#define MAX_IO_PICS		1
#define MIPS_CPU_IRQ_BASE 	NR_IRQS_LEGACY
#define GSI_MIN_CPU_IRQ		0

<<<<<<< HEAD
#include <asm/mach-generic/irq.h>
=======
#define LOONGSON_UART_IRQ   (MIPS_CPU_IRQ_BASE + 2) /* UART */
#define LOONGSON_BRIDGE_IRQ (MIPS_CPU_IRQ_BASE + 3) /* CASCADE */
#define LOONGSON_TIMER_IRQ  (MIPS_CPU_IRQ_BASE + 7) /* CPU Timer */
>>>>>>> master

#endif /* __ASM_MACH_LOONGSON64_IRQ_H_ */
