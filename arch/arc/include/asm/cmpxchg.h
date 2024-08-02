/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 */

#ifndef __ASM_ARC_CMPXCHG_H
#define __ASM_ARC_CMPXCHG_H

#include <linux/build_bug.h>
#include <linux/types.h>

#include <asm/barrier.h>
#include <asm/smp.h>

#ifdef CONFIG_ARC_HAS_LLSC

<<<<<<< HEAD
=======
static inline unsigned long
__cmpxchg(volatile void *ptr, unsigned long expected, unsigned long new)
{
	unsigned long prev;

	/*
	 * Explicit full memory barrier needed before/after as
	 * LLOCK/SCOND thmeselves don't provide any such semantics
	 */
	smp_mb();

	__asm__ __volatile__(
	"1:	llock   %0, [%1]	\n"
	"	brne    %0, %2, 2f	\n"
	"	scond   %3, [%1]	\n"
	"	bnz     1b		\n"
	"2:				\n"
	: "=&r"(prev)	/* Early clobber, to prevent reg reuse */
	: "r"(ptr),	/* Not "m": llock only supports reg direct addr mode */
	  "ir"(expected),
	  "r"(new)	/* can't be "ir". scond can't take LIMM for "b" */
	: "cc", "memory"); /* so that gcc knows memory is being written here */

	smp_mb();

	return prev;
}

#elif !defined(CONFIG_ARC_PLAT_EZNPS)

static inline unsigned long
__cmpxchg(volatile void *ptr, unsigned long expected, unsigned long new)
{
	unsigned long flags;
	int prev;
	volatile unsigned long *p = ptr;

	/*
	 * spin lock/unlock provide the needed smp_mb() before/after
	 */
	atomic_ops_lock(flags);
	prev = *p;
	if (prev == expected)
		*p = new;
	atomic_ops_unlock(flags);
	return prev;
}

#else /* CONFIG_ARC_PLAT_EZNPS */

static inline unsigned long
__cmpxchg(volatile void *ptr, unsigned long expected, unsigned long new)
{
	/*
	 * Explicit full memory barrier needed before/after
	 */
	smp_mb();

	write_aux_reg(CTOP_AUX_GPA1, expected);

	__asm__ __volatile__(
	"	mov r2, %0\n"
	"	mov r3, %1\n"
	"	.word %2\n"
	"	mov %0, r2"
	: "+r"(new)
	: "r"(ptr), "i"(CTOP_INST_EXC_DI_R2_R2_R3)
	: "r2", "r3", "memory");

	smp_mb();

	return new;
}

#endif /* CONFIG_ARC_HAS_LLSC */

#define cmpxchg(ptr, o, n) ({				\
	(typeof(*(ptr)))__cmpxchg((ptr),		\
				  (unsigned long)(o),	\
				  (unsigned long)(n));	\
})

>>>>>>> master
/*
 * if (*ptr == @old)
 *      *ptr = @new
 */
#define __cmpxchg(ptr, old, new)					\
({									\
	__typeof__(*(ptr)) _prev;					\
									\
	__asm__ __volatile__(						\
	"1:	llock  %0, [%1]	\n"					\
	"	brne   %0, %2, 2f	\n"				\
	"	scond  %3, [%1]	\n"					\
	"	bnz     1b		\n"				\
	"2:				\n"				\
	: "=&r"(_prev)	/* Early clobber prevent reg reuse */		\
	: "r"(ptr),	/* Not "m": llock only supports reg */		\
	  "ir"(old),							\
	  "r"(new)	/* Not "ir": scond can't take LIMM */		\
	: "cc",								\
	  "memory");	/* gcc knows memory is clobbered */		\
									\
	_prev;								\
})

#define arch_cmpxchg_relaxed(ptr, old, new)				\
({									\
	__typeof__(ptr) _p_ = (ptr);					\
	__typeof__(*(ptr)) _o_ = (old);					\
	__typeof__(*(ptr)) _n_ = (new);					\
	__typeof__(*(ptr)) _prev_;					\
									\
	switch(sizeof((_p_))) {						\
	case 4:								\
		_prev_ = __cmpxchg(_p_, _o_, _n_);			\
		break;							\
	default:							\
		BUILD_BUG();						\
	}								\
	_prev_;								\
})

#else

#define arch_cmpxchg(ptr, old, new)				        \
({									\
	volatile __typeof__(ptr) _p_ = (ptr);				\
	__typeof__(*(ptr)) _o_ = (old);					\
	__typeof__(*(ptr)) _n_ = (new);					\
	__typeof__(*(ptr)) _prev_;					\
	unsigned long __flags;						\
									\
	BUILD_BUG_ON(sizeof(_p_) != 4);					\
									\
	/*								\
	 * spin lock/unlock provide the needed smp_mb() before/after	\
	 */								\
	atomic_ops_lock(__flags);					\
	_prev_ = *_p_;							\
	if (_prev_ == _o_)						\
		*_p_ = _n_;						\
	atomic_ops_unlock(__flags);					\
	_prev_;								\
})

#endif

<<<<<<< HEAD
=======
#else /* CONFIG_ARC_PLAT_EZNPS */

static inline unsigned long __xchg(unsigned long val, volatile void *ptr,
				   int size)
{
	extern unsigned long __xchg_bad_pointer(void);

	switch (size) {
	case 4:
		/*
		 * Explicit full memory barrier needed before/after
		 */
		smp_mb();

		__asm__ __volatile__(
		"	mov r2, %0\n"
		"	mov r3, %1\n"
		"	.word %2\n"
		"	mov %0, r2\n"
		: "+r"(val)
		: "r"(ptr), "i"(CTOP_INST_XEX_DI_R2_R2_R3)
		: "r2", "r3", "memory");

		smp_mb();

		return val;
	}
	return __xchg_bad_pointer();
}

#define xchg(ptr, with) ({				\
	(typeof(*(ptr)))__xchg((unsigned long)(with),	\
			       (ptr),			\
			       sizeof(*(ptr)));		\
})

#endif /* CONFIG_ARC_PLAT_EZNPS */

>>>>>>> master
/*
 * xchg
 */
#ifdef CONFIG_ARC_HAS_LLSC

#define __arch_xchg(ptr, val)						\
({									\
	__asm__ __volatile__(						\
	"	ex  %0, [%1]	\n"	/* set new value */	        \
	: "+r"(val)							\
	: "r"(ptr)							\
	: "memory");							\
	_val_;		/* get old value */				\
})

#define arch_xchg_relaxed(ptr, val)					\
({									\
	__typeof__(ptr) _p_ = (ptr);					\
	__typeof__(*(ptr)) _val_ = (val);				\
									\
	switch(sizeof(*(_p_))) {					\
	case 4:								\
		_val_ = __arch_xchg(_p_, _val_);			\
		break;							\
	default:							\
		BUILD_BUG();						\
	}								\
	_val_;								\
})

#else  /* !CONFIG_ARC_HAS_LLSC */

/*
 * EX instructions is baseline and present in !LLSC too. But in this
 * regime it still needs use @atomic_ops_lock spinlock to allow interop
 * with cmpxchg() which uses spinlock in !LLSC
 * (llist.h use xchg and cmpxchg on sama data)
 */

#define arch_xchg(ptr, val)					        \
({									\
	__typeof__(ptr) _p_ = (ptr);					\
	__typeof__(*(ptr)) _val_ = (val);				\
									\
	unsigned long __flags;						\
									\
	atomic_ops_lock(__flags);					\
									\
	__asm__ __volatile__(						\
	"	ex  %0, [%1]	\n"					\
	: "+r"(_val_)							\
	: "r"(_p_)							\
	: "memory");							\
									\
	atomic_ops_unlock(__flags);					\
	_val_;								\
})

#endif

#endif
