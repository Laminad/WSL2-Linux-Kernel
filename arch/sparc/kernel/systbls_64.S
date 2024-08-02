/* SPDX-License-Identifier: GPL-2.0 */
/* systbls.S: System call entry point tables for OS compatibility.
 *            The native Linux system call table lives here also.
 *
 * Copyright (C) 1995, 1996, 2007 David S. Miller (davem@davemloft.net)
 * Copyright (C) 1997 Jakub Jelinek (jj@sunsite.mff.cuni.cz)
 *
 * Based upon preliminary work which is:
 *
 * Copyright (C) 1995 Adrian M. Rodriguez (adrian@remus.rutgers.edu)
 */

#define __SYSCALL(nr, entry) .word entry
	.text
	.align	4
#ifdef CONFIG_COMPAT
	.globl sys_call_table32
sys_call_table32:
<<<<<<< HEAD
#define __SYSCALL_WITH_COMPAT(nr, native, compat)	__SYSCALL(nr, compat)
#include <asm/syscall_table_32.h>	/* Compat syscalls */
#undef __SYSCALL_WITH_COMPAT
=======
/*0*/	.word sys_restart_syscall, sparc_exit, sys_fork, sys_read, sys_write
/*5*/	.word compat_sys_open, sys_close, compat_sys_wait4, sys_creat, sys_link
/*10*/  .word sys_unlink, sunos_execv, sys_chdir, sys_chown16, sys_mknod
/*15*/	.word sys_chmod, sys_lchown16, sys_brk, sys_nis_syscall, compat_sys_lseek
/*20*/	.word sys_getpid, sys_capget, sys_capset, sys_setuid16, sys_getuid16
/*25*/	.word compat_sys_vmsplice, compat_sys_ptrace, sys_alarm, compat_sys_sigaltstack, sys_pause
/*30*/	.word compat_sys_utime, sys_lchown, sys_fchown, sys_access, sys_nice
	.word sys_chown, sys_sync, sys_kill, compat_sys_newstat, compat_sys_sendfile
/*40*/	.word compat_sys_newlstat, sys_dup, sys_sparc_pipe, compat_sys_times, sys_getuid
	.word sys_umount, sys_setgid16, sys_getgid16, sys_signal, sys_geteuid16
/*50*/	.word sys_getegid16, sys_acct, sys_nis_syscall, sys_getgid, compat_sys_ioctl
	.word sys_reboot, sys32_mmap2, sys_symlink, sys_readlink, sys32_execve
/*60*/	.word sys_umask, sys_chroot, compat_sys_newfstat, compat_sys_fstat64, sys_getpagesize
	.word sys_msync, sys_vfork, compat_sys_pread64, compat_sys_pwrite64, sys_geteuid
/*70*/	.word sys_getegid, sys_mmap, sys_setreuid, sys_munmap, sys_mprotect
	.word sys_madvise, sys_vhangup, compat_sys_truncate64, sys_mincore, sys_getgroups16
/*80*/	.word sys_setgroups16, sys_getpgrp, sys_setgroups, compat_sys_setitimer, compat_sys_ftruncate64
	.word sys_swapon, compat_sys_getitimer, sys_setuid, sys_sethostname, sys_setgid
/*90*/	.word sys_dup2, sys_setfsuid, compat_sys_fcntl, compat_sys_select, sys_setfsgid
	.word sys_fsync, sys_setpriority, sys_socket, sys_connect, sys_accept
/*100*/ .word sys_getpriority, sys32_rt_sigreturn, compat_sys_rt_sigaction, compat_sys_rt_sigprocmask, compat_sys_rt_sigpending
	.word compat_sys_rt_sigtimedwait, compat_sys_rt_sigqueueinfo, compat_sys_rt_sigsuspend, sys_setresuid, sys_getresuid
/*110*/	.word sys_setresgid, sys_getresgid, sys_setregid, compat_sys_recvmsg, compat_sys_sendmsg
	.word sys_getgroups, compat_sys_gettimeofday, compat_sys_getrusage, compat_sys_getsockopt, sys_getcwd
/*120*/	.word compat_sys_readv, compat_sys_writev, compat_sys_settimeofday, sys_fchown16, sys_fchmod
	.word sys_recvfrom, sys_setreuid16, sys_setregid16, sys_rename, compat_sys_truncate
/*130*/	.word compat_sys_ftruncate, sys_flock, compat_sys_lstat64, sys_sendto, sys_shutdown
	.word sys_socketpair, sys_mkdir, sys_rmdir, compat_sys_utimes, compat_sys_stat64
/*140*/	.word sys_sendfile64, sys_getpeername, compat_sys_futex, sys_gettid, compat_sys_getrlimit
	.word compat_sys_setrlimit, sys_pivot_root, sys_prctl, sys_pciconfig_read, sys_pciconfig_write
/*150*/	.word sys_getsockname, sys_inotify_init, sys_inotify_add_watch, sys_poll, sys_getdents64
	.word compat_sys_fcntl64, sys_inotify_rm_watch, compat_sys_statfs, compat_sys_fstatfs, sys_oldumount
/*160*/	.word compat_sys_sched_setaffinity, compat_sys_sched_getaffinity, sys_getdomainname, sys_setdomainname, sys_nis_syscall
	.word sys_quotactl, sys_set_tid_address, compat_sys_mount, compat_sys_ustat, sys_setxattr
/*170*/	.word sys_lsetxattr, sys_fsetxattr, sys_getxattr, sys_lgetxattr, compat_sys_getdents
	.word sys_setsid, sys_fchdir, sys_fgetxattr, sys_listxattr, sys_llistxattr
/*180*/	.word sys_flistxattr, sys_removexattr, sys_lremovexattr, compat_sys_sigpending, sys_ni_syscall
	.word sys_setpgid, sys_fremovexattr, sys_tkill, sparc_exit_group, sys_newuname
/*190*/	.word sys_init_module, sys_sparc64_personality, sys_remap_file_pages, sys_epoll_create, sys_epoll_ctl
	.word sys_epoll_wait, sys_ioprio_set, sys_getppid, compat_sys_sparc_sigaction, sys_sgetmask
/*200*/	.word sys_ssetmask, sys_sigsuspend, compat_sys_newlstat, sys_uselib, compat_sys_old_readdir
	.word compat_sys_readahead, sys32_socketcall, sys_syslog, compat_sys_lookup_dcookie, compat_sys_fadvise64
/*210*/	.word compat_sys_fadvise64_64, sys_tgkill, sys_waitpid, sys_swapoff, compat_sys_sysinfo
	.word compat_sys_ipc, sys32_sigreturn, sys_clone, sys_ioprio_get, compat_sys_adjtimex
/*220*/	.word compat_sys_sigprocmask, sys_ni_syscall, sys_delete_module, sys_ni_syscall, sys_getpgid
	.word sys_bdflush, sys_sysfs, sys_nis_syscall, sys_setfsuid16, sys_setfsgid16
/*230*/	.word compat_sys_select, compat_sys_time, sys_splice, compat_sys_stime, compat_sys_statfs64
	.word compat_sys_fstatfs64, sys_llseek, sys_mlock, sys_munlock, sys_mlockall
/*240*/	.word sys_munlockall, sys_sched_setparam, sys_sched_getparam, sys_sched_setscheduler, sys_sched_getscheduler
	.word sys_sched_yield, sys_sched_get_priority_max, sys_sched_get_priority_min, compat_sys_sched_rr_get_interval, compat_sys_nanosleep
/*250*/	.word sys_mremap, compat_sys_sysctl, sys_getsid, sys_fdatasync, sys_nis_syscall
	.word compat_sys_sync_file_range, compat_sys_clock_settime, compat_sys_clock_gettime, compat_sys_clock_getres, compat_sys_clock_nanosleep
/*260*/	.word compat_sys_sched_getaffinity, compat_sys_sched_setaffinity, compat_sys_timer_settime, compat_sys_timer_gettime, sys_timer_getoverrun
	.word sys_timer_delete, compat_sys_timer_create, sys_ni_syscall, compat_sys_io_setup, sys_io_destroy
/*270*/	.word compat_sys_io_submit, sys_io_cancel, compat_sys_io_getevents, compat_sys_mq_open, sys_mq_unlink
	.word compat_sys_mq_timedsend, compat_sys_mq_timedreceive, compat_sys_mq_notify, compat_sys_mq_getsetattr, compat_sys_waitid
/*280*/	.word sys_tee, sys_add_key, sys_request_key, compat_sys_keyctl, compat_sys_openat
	.word sys_mkdirat, sys_mknodat, sys_fchownat, compat_sys_futimesat, compat_sys_fstatat64
/*290*/	.word sys_unlinkat, sys_renameat, sys_linkat, sys_symlinkat, sys_readlinkat
	.word sys_fchmodat, sys_faccessat, compat_sys_pselect6, compat_sys_ppoll, sys_unshare
/*300*/	.word compat_sys_set_robust_list, compat_sys_get_robust_list, compat_sys_migrate_pages, compat_sys_mbind, compat_sys_get_mempolicy
	.word compat_sys_set_mempolicy, compat_sys_kexec_load, compat_sys_move_pages, sys_getcpu, compat_sys_epoll_pwait
/*310*/	.word compat_sys_utimensat, compat_sys_signalfd, sys_timerfd_create, sys_eventfd, compat_sys_fallocate
	.word compat_sys_timerfd_settime, compat_sys_timerfd_gettime, compat_sys_signalfd4, sys_eventfd2, sys_epoll_create1
/*320*/	.word sys_dup3, sys_pipe2, sys_inotify_init1, sys_accept4, compat_sys_preadv
	.word compat_sys_pwritev, compat_sys_rt_tgsigqueueinfo, sys_perf_event_open, compat_sys_recvmmsg, sys_fanotify_init
/*330*/	.word compat_sys_fanotify_mark, sys_prlimit64, sys_name_to_handle_at, compat_sys_open_by_handle_at, compat_sys_clock_adjtime
	.word sys_syncfs, compat_sys_sendmmsg, sys_setns, compat_sys_process_vm_readv, compat_sys_process_vm_writev
/*340*/	.word sys_kern_features, sys_kcmp, sys_finit_module, sys_sched_setattr, sys_sched_getattr
	.word sys_renameat2, sys_seccomp, sys_getrandom, sys_memfd_create, sys_bpf
/*350*/	.word sys32_execveat, sys_membarrier, sys_userfaultfd, sys_bind, sys_listen
	.word compat_sys_setsockopt, sys_mlock2, sys_copy_file_range, compat_sys_preadv2, compat_sys_pwritev2
/*360*/	.word sys_statx, compat_sys_io_pgetevents

>>>>>>> master
#endif /* CONFIG_COMPAT */

	.align	4
	.globl sys_call_table64, sys_call_table
sys_call_table64:
sys_call_table:
#define __SYSCALL_WITH_COMPAT(nr, native, compat)	__SYSCALL(nr, native)
#include <asm/syscall_table_64.h>	/* 64-bit native syscalls */
