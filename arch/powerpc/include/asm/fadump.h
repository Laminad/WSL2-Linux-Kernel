/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Firmware Assisted dump header file.
 *
 * Copyright 2011 IBM Corporation
 * Author: Mahesh Salgaonkar <mahesh@linux.vnet.ibm.com>
 */

#ifndef _ASM_POWERPC_FADUMP_H
#define _ASM_POWERPC_FADUMP_H

#ifdef CONFIG_FA_DUMP

extern int crashing_cpu;

<<<<<<< HEAD
extern int is_fadump_memory_area(u64 addr, ulong size);
=======
/* Kernel Dump section info */
struct fadump_section {
	__be32	request_flag;
	__be16	source_data_type;
	__be16	error_flags;
	__be64	source_address;
	__be64	source_len;
	__be64	bytes_dumped;
	__be64	destination_address;
};

/* ibm,configure-kernel-dump header. */
struct fadump_section_header {
	__be32	dump_format_version;
	__be16	dump_num_sections;
	__be16	dump_status_flag;
	__be32	offset_first_dump_section;

	/* Fields for disk dump option. */
	__be32	dd_block_size;
	__be64	dd_block_offset;
	__be64	dd_num_blocks;
	__be32	dd_offset_disk_path;

	/* Maximum time allowed to prevent an automatic dump-reboot. */
	__be32	max_time_auto;
};

/*
 * Firmware Assisted dump memory structure. This structure is required for
 * registering future kernel dump with power firmware through rtas call.
 *
 * No disk dump option. Hence disk dump path string section is not included.
 */
struct fadump_mem_struct {
	struct fadump_section_header	header;

	/* Kernel dump sections */
	struct fadump_section		cpu_state_data;
	struct fadump_section		hpte_region;
	struct fadump_section		rmr_region;
};

/* Firmware-assisted dump configuration details. */
struct fw_dump {
	unsigned long	cpu_state_data_size;
	unsigned long	hpte_region_size;
	unsigned long	boot_memory_size;
	unsigned long	reserve_dump_area_start;
	unsigned long	reserve_dump_area_size;
	/* cmd line option during boot */
	unsigned long	reserve_bootvar;

	unsigned long	fadumphdr_addr;
	unsigned long	cpu_notes_buf;
	unsigned long	cpu_notes_buf_size;

	int		ibm_configure_kernel_dump;

	unsigned long	fadump_enabled:1;
	unsigned long	fadump_supported:1;
	unsigned long	dump_active:1;
	unsigned long	dump_registered:1;
};

/*
 * Copy the ascii values for first 8 characters from a string into u64
 * variable at their respective indexes.
 * e.g.
 *  The string "FADMPINF" will be converted into 0x4641444d50494e46
 */
static inline u64 str_to_u64(const char *str)
{
	u64 val = 0;
	int i;

	for (i = 0; i < sizeof(val); i++)
		val = (*str) ? (val << 8) | *str++ : val << 8;
	return val;
}
#define STR_TO_HEX(x)	str_to_u64(x)
#define REG_ID(x)	str_to_u64(x)

#define FADUMP_CRASH_INFO_MAGIC		STR_TO_HEX("FADMPINF")
#define REGSAVE_AREA_MAGIC		STR_TO_HEX("REGSAVE")

/* The firmware-assisted dump format.
 *
 * The register save area is an area in the partition's memory used to preserve
 * the register contents (CPU state data) for the active CPUs during a firmware
 * assisted dump. The dump format contains register save area header followed
 * by register entries. Each list of registers for a CPU starts with
 * "CPUSTRT" and ends with "CPUEND".
 */

/* Register save area header. */
struct fadump_reg_save_area_header {
	__be64		magic_number;
	__be32		version;
	__be32		num_cpu_offset;
};

/* Register entry. */
struct fadump_reg_entry {
	__be64		reg_id;
	__be64		reg_value;
};

/* fadump crash info structure */
struct fadump_crash_info_header {
	u64		magic_number;
	u64		elfcorehdr_addr;
	u32		crashing_cpu;
	struct pt_regs	regs;
	struct cpumask	online_mask;
};

struct fad_crash_memory_ranges {
	unsigned long long	base;
	unsigned long long	size;
};

extern int is_fadump_memory_area(u64 addr, ulong size);
extern int early_init_dt_scan_fw_dump(unsigned long node,
		const char *uname, int depth, void *data);
extern int fadump_reserve_mem(void);
>>>>>>> master
extern int setup_fadump(void);
extern int is_fadump_active(void);
extern int should_fadump_crash(void);
extern void crash_fadump(struct pt_regs *, const char *);
extern void fadump_cleanup(void);

#else	/* CONFIG_FA_DUMP */
static inline int is_fadump_active(void) { return 0; }
static inline int should_fadump_crash(void) { return 0; }
static inline void crash_fadump(struct pt_regs *regs, const char *str) { }
static inline void fadump_cleanup(void) { }
#endif /* !CONFIG_FA_DUMP */

#if defined(CONFIG_FA_DUMP) || defined(CONFIG_PRESERVE_FA_DUMP)
extern int early_init_dt_scan_fw_dump(unsigned long node, const char *uname,
				      int depth, void *data);
extern int fadump_reserve_mem(void);
#endif
#endif /* _ASM_POWERPC_FADUMP_H */
