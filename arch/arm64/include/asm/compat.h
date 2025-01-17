/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_COMPAT_H
#define __ASM_COMPAT_H

#define compat_mode_t compat_mode_t
typedef u16		compat_mode_t;

#define __compat_uid_t	__compat_uid_t
typedef u16		__compat_uid_t;
typedef u16		__compat_gid_t;

#define compat_ipc_pid_t compat_ipc_pid_t
typedef u16		compat_ipc_pid_t;

#define compat_statfs	compat_statfs

#include <asm-generic/compat.h>

#ifdef CONFIG_COMPAT

/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>

#ifdef __AARCH64EB__
#define COMPAT_UTS_MACHINE	"armv8b\0\0"
#else
#define COMPAT_UTS_MACHINE	"armv8l\0\0"
#endif

typedef u16		__compat_uid16_t;
typedef u16		__compat_gid16_t;
typedef s32		compat_nlink_t;

struct compat_stat {
#ifdef __AARCH64EB__
	short		st_dev;
	short		__pad1;
#else
	compat_dev_t	st_dev;
#endif
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_ushort_t	st_nlink;
	__compat_uid16_t	st_uid;
	__compat_gid16_t	st_gid;
#ifdef __AARCH64EB__
	short		st_rdev;
	short		__pad2;
#else
	compat_dev_t	st_rdev;
#endif
	compat_off_t	st_size;
	compat_off_t	st_blksize;
	compat_off_t	st_blocks;
	old_time32_t	st_atime;
	compat_ulong_t	st_atime_nsec;
	old_time32_t	st_mtime;
	compat_ulong_t	st_mtime_nsec;
	old_time32_t	st_ctime;
	compat_ulong_t	st_ctime_nsec;
	compat_ulong_t	__unused4[2];
};

struct compat_statfs {
	int		f_type;
	int		f_bsize;
	int		f_blocks;
	int		f_bfree;
	int		f_bavail;
	int		f_files;
	int		f_ffree;
	compat_fsid_t	f_fsid;
	int		f_namelen;	/* SunOS ignores this field. */
	int		f_frsize;
	int		f_flags;
	int		f_spare[4];
};

#define compat_user_stack_pointer() (user_stack_pointer(task_pt_regs(current)))
#define COMPAT_MINSIGSTKSZ	2048
<<<<<<< HEAD
=======

static inline void __user *arch_compat_alloc_user_space(long len)
{
	return (void __user *)compat_user_stack_pointer() - len;
}

struct compat_ipc64_perm {
	compat_key_t key;
	__compat_uid32_t uid;
	__compat_gid32_t gid;
	__compat_uid32_t cuid;
	__compat_gid32_t cgid;
	unsigned short mode;
	unsigned short __pad1;
	unsigned short seq;
	unsigned short __pad2;
	compat_ulong_t unused1;
	compat_ulong_t unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	compat_ulong_t sem_otime;
	compat_ulong_t sem_otime_high;
	compat_ulong_t sem_ctime;
	compat_ulong_t sem_ctime_high;
	compat_ulong_t sem_nsems;
	compat_ulong_t __unused3;
	compat_ulong_t __unused4;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	compat_ulong_t msg_stime;
	compat_ulong_t msg_stime_high;
	compat_ulong_t msg_rtime;
	compat_ulong_t msg_rtime_high;
	compat_ulong_t msg_ctime;
	compat_ulong_t msg_ctime_high;
	compat_ulong_t msg_cbytes;
	compat_ulong_t msg_qnum;
	compat_ulong_t msg_qbytes;
	compat_pid_t   msg_lspid;
	compat_pid_t   msg_lrpid;
	compat_ulong_t __unused4;
	compat_ulong_t __unused5;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	compat_size_t  shm_segsz;
	compat_ulong_t shm_atime;
	compat_ulong_t shm_atime_high;
	compat_ulong_t shm_dtime;
	compat_ulong_t shm_dtime_high;
	compat_ulong_t shm_ctime;
	compat_ulong_t shm_ctime_high;
	compat_pid_t   shm_cpid;
	compat_pid_t   shm_lpid;
	compat_ulong_t shm_nattch;
	compat_ulong_t __unused4;
	compat_ulong_t __unused5;
};
>>>>>>> master

static inline int is_compat_task(void)
{
	return test_thread_flag(TIF_32BIT);
}

static inline int is_compat_thread(struct thread_info *thread)
{
	return test_ti_thread_flag(thread, TIF_32BIT);
}

long compat_arm_syscall(struct pt_regs *regs, int scno);

#else /* !CONFIG_COMPAT */

static inline int is_compat_thread(struct thread_info *thread)
{
	return 0;
}

#endif /* CONFIG_COMPAT */
#endif /* __ASM_COMPAT_H */
