// SPDX-License-Identifier: GPL-2.0
#include <linux/acpi.h>
#include <linux/export.h>
#include <linux/mm.h>

#include <xen/hvc-console.h>

#include <asm/io_apic.h>
#include <asm/hypervisor.h>
#include <asm/e820/api.h>

#include <xen/xen.h>
#include <asm/xen/interface.h>
#include <asm/xen/hypercall.h>

#include <xen/interface/memory.h>

#include "xen-ops.h"

/*
 * PVH variables.
 *
 * The variable xen_pvh needs to live in a data segment since it is used
 * after startup_{32|64} is invoked, which will clear the .bss segment.
 */
bool __ro_after_init xen_pvh;
EXPORT_SYMBOL_GPL(xen_pvh);

<<<<<<< HEAD
void __init xen_pvh_init(struct boot_params *boot_params)
=======
unsigned int pvh_start_info_sz = sizeof(pvh_start_info);

static u64 pvh_get_root_pointer(void)
{
	return pvh_start_info.rsdp_paddr;
}

static void __init init_pvh_bootparams(void)
{
	struct xen_memory_map memmap;
	int rc;

	memset(&pvh_bootparams, 0, sizeof(pvh_bootparams));

	memmap.nr_entries = ARRAY_SIZE(pvh_bootparams.e820_table);
	set_xen_guest_handle(memmap.buffer, pvh_bootparams.e820_table);
	rc = HYPERVISOR_memory_op(XENMEM_memory_map, &memmap);
	if (rc) {
		xen_raw_printk("XENMEM_memory_map failed (%d)\n", rc);
		BUG();
	}
	pvh_bootparams.e820_entries = memmap.nr_entries;

	if (pvh_bootparams.e820_entries < E820_MAX_ENTRIES_ZEROPAGE - 1) {
		pvh_bootparams.e820_table[pvh_bootparams.e820_entries].addr =
			ISA_START_ADDRESS;
		pvh_bootparams.e820_table[pvh_bootparams.e820_entries].size =
			ISA_END_ADDRESS - ISA_START_ADDRESS;
		pvh_bootparams.e820_table[pvh_bootparams.e820_entries].type =
			E820_TYPE_RESERVED;
		pvh_bootparams.e820_entries++;
	} else
		xen_raw_printk("Warning: Can fit ISA range into e820\n");

	pvh_bootparams.hdr.cmd_line_ptr =
		pvh_start_info.cmdline_paddr;

	/* The first module is always ramdisk. */
	if (pvh_start_info.nr_modules) {
		struct hvm_modlist_entry *modaddr =
			__va(pvh_start_info.modlist_paddr);
		pvh_bootparams.hdr.ramdisk_image = modaddr->paddr;
		pvh_bootparams.hdr.ramdisk_size = modaddr->size;
	}

	/*
	 * See Documentation/x86/boot.txt.
	 *
	 * Version 2.12 supports Xen entry point but we will use default x86/PC
	 * environment (i.e. hardware_subarch 0).
	 */
	pvh_bootparams.hdr.version = (2 << 8) | 12;
	pvh_bootparams.hdr.type_of_loader = (9 << 4) | 0; /* Xen loader */

	x86_init.acpi.get_root_pointer = pvh_get_root_pointer;
}

/*
 * This routine (and those that it might call) should not use
 * anything that lives in .bss since that segment will be cleared later.
 */
void __init xen_prepare_pvh(void)
>>>>>>> master
{
	u32 msr;
	u64 pfn;

	xen_pvh = 1;
	xen_domain_type = XEN_HVM_DOMAIN;
	xen_start_flags = pvh_start_info.flags;

	msr = cpuid_ebx(xen_cpuid_base() + 2);
	pfn = __pa(hypercall_page);
	wrmsr_safe(msr, (u32)pfn, (u32)(pfn >> 32));

	if (xen_initial_domain())
		x86_init.oem.arch_setup = xen_add_preferred_consoles;
	x86_init.oem.banner = xen_banner;

	xen_efi_init(boot_params);

	if (xen_initial_domain()) {
		struct xen_platform_op op = {
			.cmd = XENPF_get_dom0_console,
		};
		int ret = HYPERVISOR_platform_op(&op);

		if (ret > 0)
			xen_init_vga(&op.u.dom0_console,
				     min(ret * sizeof(char),
					 sizeof(op.u.dom0_console)),
				     &boot_params->screen_info);
	}
}

void __init mem_map_via_hcall(struct boot_params *boot_params_p)
{
	struct xen_memory_map memmap;
	int rc;

	memmap.nr_entries = ARRAY_SIZE(boot_params_p->e820_table);
	set_xen_guest_handle(memmap.buffer, boot_params_p->e820_table);
	rc = HYPERVISOR_memory_op(XENMEM_memory_map, &memmap);
	if (rc) {
		xen_raw_printk("XENMEM_memory_map failed (%d)\n", rc);
		BUG();
	}
	boot_params_p->e820_entries = memmap.nr_entries;
}

/*
 * Reserve e820 UNUSABLE regions to inflate the memory balloon.
 *
 * On PVH dom0 the host memory map is used, RAM regions available to dom0 are
 * located as the same place as in the native memory map, but since dom0 gets
 * less memory than the total amount of host RAM the ranges that can't be
 * populated are converted from RAM -> UNUSABLE.  Use such regions (up to the
 * ratio signaled in EXTRA_MEM_RATIO) in order to inflate the balloon driver at
 * boot.  Doing so prevents the guest (even if just temporary) from using holes
 * in the memory map in order to map grants or foreign addresses, and
 * hopefully limits the risk of a clash with a device MMIO region.  Ideally the
 * hypervisor should notify us which memory ranges are suitable for creating
 * foreign mappings, but that's not yet implemented.
 */
void __init xen_reserve_extra_memory(struct boot_params *bootp)
{
	unsigned int i, ram_pages = 0, extra_pages;

	for (i = 0; i < bootp->e820_entries; i++) {
		struct boot_e820_entry *e = &bootp->e820_table[i];

		if (e->type != E820_TYPE_RAM)
			continue;
		ram_pages += PFN_DOWN(e->addr + e->size) - PFN_UP(e->addr);
	}

	/* Max amount of extra memory. */
	extra_pages = EXTRA_MEM_RATIO * ram_pages;

	/*
	 * Convert UNUSABLE ranges to RAM and reserve them for foreign mapping
	 * purposes.
	 */
	for (i = 0; i < bootp->e820_entries && extra_pages; i++) {
		struct boot_e820_entry *e = &bootp->e820_table[i];
		unsigned long pages;

		if (e->type != E820_TYPE_UNUSABLE)
			continue;

		pages = min(extra_pages,
			PFN_DOWN(e->addr + e->size) - PFN_UP(e->addr));

		if (pages != (PFN_DOWN(e->addr + e->size) - PFN_UP(e->addr))) {
			struct boot_e820_entry *next;

			if (bootp->e820_entries ==
			    ARRAY_SIZE(bootp->e820_table))
				/* No space left to split - skip region. */
				continue;

			/* Split entry. */
			next = e + 1;
			memmove(next, e,
				(bootp->e820_entries - i) * sizeof(*e));
			bootp->e820_entries++;
			next->addr = PAGE_ALIGN(e->addr) + PFN_PHYS(pages);
			e->size = next->addr - e->addr;
			next->size -= e->size;
		}
		e->type = E820_TYPE_RAM;
		extra_pages -= pages;

		xen_add_extra_mem(PFN_UP(e->addr), pages);
	}
}
