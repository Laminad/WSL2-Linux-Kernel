/*
 * arch/xtensa/kernel/xtensa_ksyms.c
 *
 * Export Xtensa-specific functions for loadable modules.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2005  Tensilica Inc.
 *
 * Joe Taylor <joe@tensilica.com>
 */

#include <linux/module.h>
#include <asm/pgtable.h>

EXPORT_SYMBOL(empty_zero_page);

unsigned int __sync_fetch_and_and_4(volatile void *p, unsigned int v)
{
	BUG();
}
EXPORT_SYMBOL(__sync_fetch_and_and_4);

unsigned int __sync_fetch_and_or_4(volatile void *p, unsigned int v)
{
	BUG();
}
EXPORT_SYMBOL(__sync_fetch_and_or_4);
<<<<<<< HEAD
=======

/*
 * Networking support
 */
EXPORT_SYMBOL(csum_partial);
EXPORT_SYMBOL(csum_partial_copy_generic);

/*
 * Architecture-specific symbols
 */
EXPORT_SYMBOL(__xtensa_copy_user);
EXPORT_SYMBOL(__invalidate_icache_range);

/*
 * Kernel hacking ...
 */

#if defined(CONFIG_VGA_CONSOLE) || defined(CONFIG_DUMMY_CONSOLE)
// FIXME EXPORT_SYMBOL(screen_info);
#endif

extern long common_exception_return;
EXPORT_SYMBOL(common_exception_return);

#ifdef CONFIG_FUNCTION_TRACER
EXPORT_SYMBOL(_mcount);
#endif

EXPORT_SYMBOL(__invalidate_dcache_range);
#if XCHAL_DCACHE_IS_WRITEBACK
EXPORT_SYMBOL(__flush_dcache_range);
#endif
>>>>>>> master
