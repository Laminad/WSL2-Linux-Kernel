/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LKDTM_H
#define __LKDTM_H

#define pr_fmt(fmt) "lkdtm: " fmt

#include <linux/kernel.h>

extern char *lkdtm_kernel_info;

#define pr_expected_config(kconfig)				\
do {								\
	if (IS_ENABLED(kconfig)) 				\
		pr_err("Unexpected! This %s was built with " #kconfig "=y\n", \
			lkdtm_kernel_info);			\
	else							\
		pr_warn("This is probably expected, since this %s was built *without* " #kconfig "=y\n", \
			lkdtm_kernel_info);			\
} while (0)

#ifndef MODULE
int lkdtm_check_bool_cmdline(const char *param);
#define pr_expected_config_param(kconfig, param)		\
do {								\
	if (IS_ENABLED(kconfig)) {				\
		switch (lkdtm_check_bool_cmdline(param)) {	\
		case 0:						\
			pr_warn("This is probably expected, since this %s was built with " #kconfig "=y but booted with '" param "=N'\n", \
				lkdtm_kernel_info);		\
			break;					\
		case 1:						\
			pr_err("Unexpected! This %s was built with " #kconfig "=y and booted with '" param "=Y'\n", \
				lkdtm_kernel_info);		\
			break;					\
		default:					\
			pr_err("Unexpected! This %s was built with " #kconfig "=y (and booted without '" param "' specified)\n", \
				lkdtm_kernel_info);		\
		}						\
	} else {						\
		switch (lkdtm_check_bool_cmdline(param)) {	\
		case 0:						\
			pr_warn("This is probably expected, as this %s was built *without* " #kconfig "=y and booted with '" param "=N'\n", \
				lkdtm_kernel_info);		\
			break;					\
		case 1:						\
			pr_err("Unexpected! This %s was built *without* " #kconfig "=y but booted with '" param "=Y'\n", \
				lkdtm_kernel_info);		\
			break;					\
		default:					\
			pr_err("This is probably expected, since this %s was built *without* " #kconfig "=y (and booted without '" param "' specified)\n", \
				lkdtm_kernel_info);		\
			break;					\
		}						\
	}							\
} while (0)
#else
#define pr_expected_config_param(kconfig, param) pr_expected_config(kconfig)
#endif

/* Crash types. */
struct crashtype {
	const char *name;
	void (*func)(void);
};

#define CRASHTYPE(_name)			\
	{					\
		.name = __stringify(_name),	\
		.func = lkdtm_ ## _name,	\
	}

/* Category's collection of crashtypes. */
struct crashtype_category {
	struct crashtype *crashtypes;
	size_t len;
};

/* Each category's crashtypes list. */
extern struct crashtype_category bugs_crashtypes;
extern struct crashtype_category heap_crashtypes;
extern struct crashtype_category perms_crashtypes;
extern struct crashtype_category refcount_crashtypes;
extern struct crashtype_category usercopy_crashtypes;
extern struct crashtype_category stackleak_crashtypes;
extern struct crashtype_category cfi_crashtypes;
extern struct crashtype_category fortify_crashtypes;
extern struct crashtype_category powerpc_crashtypes;

/* Each category's init/exit routines. */
void __init lkdtm_bugs_init(int *recur_param);
void __init lkdtm_heap_init(void);
void __exit lkdtm_heap_exit(void);
void __init lkdtm_perms_init(void);
<<<<<<< HEAD
=======
void lkdtm_WRITE_RO(void);
void lkdtm_WRITE_RO_AFTER_INIT(void);
void lkdtm_WRITE_KERN(void);
void lkdtm_EXEC_DATA(void);
void lkdtm_EXEC_STACK(void);
void lkdtm_EXEC_KMALLOC(void);
void lkdtm_EXEC_VMALLOC(void);
void lkdtm_EXEC_RODATA(void);
void lkdtm_EXEC_USERSPACE(void);
void lkdtm_EXEC_NULL(void);
void lkdtm_ACCESS_USERSPACE(void);
void lkdtm_ACCESS_NULL(void);

/* lkdtm_refcount.c */
void lkdtm_REFCOUNT_INC_OVERFLOW(void);
void lkdtm_REFCOUNT_ADD_OVERFLOW(void);
void lkdtm_REFCOUNT_INC_NOT_ZERO_OVERFLOW(void);
void lkdtm_REFCOUNT_ADD_NOT_ZERO_OVERFLOW(void);
void lkdtm_REFCOUNT_DEC_ZERO(void);
void lkdtm_REFCOUNT_DEC_NEGATIVE(void);
void lkdtm_REFCOUNT_DEC_AND_TEST_NEGATIVE(void);
void lkdtm_REFCOUNT_SUB_AND_TEST_NEGATIVE(void);
void lkdtm_REFCOUNT_INC_ZERO(void);
void lkdtm_REFCOUNT_ADD_ZERO(void);
void lkdtm_REFCOUNT_INC_SATURATED(void);
void lkdtm_REFCOUNT_DEC_SATURATED(void);
void lkdtm_REFCOUNT_ADD_SATURATED(void);
void lkdtm_REFCOUNT_INC_NOT_ZERO_SATURATED(void);
void lkdtm_REFCOUNT_ADD_NOT_ZERO_SATURATED(void);
void lkdtm_REFCOUNT_DEC_AND_TEST_SATURATED(void);
void lkdtm_REFCOUNT_SUB_AND_TEST_SATURATED(void);
void lkdtm_REFCOUNT_TIMING(void);
void lkdtm_ATOMIC_TIMING(void);

/* lkdtm_rodata.c */
void lkdtm_rodata_do_nothing(void);

/* lkdtm_usercopy.c */
>>>>>>> master
void __init lkdtm_usercopy_init(void);
void __exit lkdtm_usercopy_exit(void);

/* Special declaration for function-in-rodata. */
void lkdtm_rodata_do_nothing(void);

#endif
