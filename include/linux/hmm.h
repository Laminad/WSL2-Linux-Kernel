/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright 2013 Red Hat Inc.
 *
 * Authors: Jérôme Glisse <jglisse@redhat.com>
 *
 * See Documentation/mm/hmm.rst for reasons and overview of what HMM is.
 */
#ifndef LINUX_HMM_H
#define LINUX_HMM_H

#include <linux/mm.h>

struct mmu_interval_notifier;

/*
 * On output:
 * 0             - The page is faultable and a future call with 
 *                 HMM_PFN_REQ_FAULT could succeed.
 * HMM_PFN_VALID - the pfn field points to a valid PFN. This PFN is at
 *                 least readable. If dev_private_owner is !NULL then this could
 *                 point at a DEVICE_PRIVATE page.
 * HMM_PFN_WRITE - if the page memory can be written to (requires HMM_PFN_VALID)
 * HMM_PFN_ERROR - accessing the pfn is impossible and the device should
 *                 fail. ie poisoned memory, special pages, no vma, etc
 *
 * On input:
 * 0                 - Return the current state of the page, do not fault it.
 * HMM_PFN_REQ_FAULT - The output must have HMM_PFN_VALID or hmm_range_fault()
 *                     will fail
 * HMM_PFN_REQ_WRITE - The output must have HMM_PFN_WRITE or hmm_range_fault()
 *                     will fail. Must be combined with HMM_PFN_REQ_FAULT.
 */
enum hmm_pfn_flags {
	/* Output fields and flags */
	HMM_PFN_VALID = 1UL << (BITS_PER_LONG - 1),
	HMM_PFN_WRITE = 1UL << (BITS_PER_LONG - 2),
	HMM_PFN_ERROR = 1UL << (BITS_PER_LONG - 3),
	HMM_PFN_ORDER_SHIFT = (BITS_PER_LONG - 8),

	/* Input flags */
	HMM_PFN_REQ_FAULT = HMM_PFN_VALID,
	HMM_PFN_REQ_WRITE = HMM_PFN_WRITE,

	HMM_PFN_FLAGS = 0xFFUL << HMM_PFN_ORDER_SHIFT,
};

/*
 * hmm_pfn_to_page() - return struct page pointed to by a device entry
 *
 * This must be called under the caller 'user_lock' after a successful
 * mmu_interval_read_begin(). The caller must have tested for HMM_PFN_VALID
 * already.
 */
static inline struct page *hmm_pfn_to_page(unsigned long hmm_pfn)
{
	return pfn_to_page(hmm_pfn & ~HMM_PFN_FLAGS);
}

/*
 * hmm_pfn_to_map_order() - return the CPU mapping size order
 *
 * This is optionally useful to optimize processing of the pfn result
 * array. It indicates that the page starts at the order aligned VA and is
 * 1<<order bytes long.  Every pfn within an high order page will have the
 * same pfn flags, both access protections and the map_order.  The caller must
 * be careful with edge cases as the start and end VA of the given page may
 * extend past the range used with hmm_range_fault().
 *
 * This must be called under the caller 'user_lock' after a successful
 * mmu_interval_read_begin(). The caller must have tested for HMM_PFN_VALID
 * already.
 */
static inline unsigned int hmm_pfn_to_map_order(unsigned long hmm_pfn)
{
	return (hmm_pfn >> HMM_PFN_ORDER_SHIFT) & 0x1F;
}

/*
 * struct hmm_range - track invalidation lock on virtual address range
 *
 * @notifier: a mmu_interval_notifier that includes the start/end
 * @notifier_seq: result of mmu_interval_read_begin()
 * @start: range virtual start address (inclusive)
 * @end: range virtual end address (exclusive)
 * @hmm_pfns: array of pfns (big enough for the range)
 * @default_flags: default flags for the range (write, read, ... see hmm doc)
 * @pfn_flags_mask: allows to mask pfn flags so that only default_flags matter
 * @dev_private_owner: owner of device private pages
 */
struct hmm_range {
	struct mmu_interval_notifier *notifier;
	unsigned long		notifier_seq;
	unsigned long		start;
	unsigned long		end;
	unsigned long		*hmm_pfns;
	unsigned long		default_flags;
	unsigned long		pfn_flags_mask;
	void			*dev_private_owner;
};

/*
 * Please see Documentation/mm/hmm.rst for how to use the range API.
 */
int hmm_range_fault(struct hmm_range *range);

/*
 * HMM_RANGE_DEFAULT_TIMEOUT - default timeout (ms) when waiting for a range
 *
 * When waiting for mmu notifiers we need some kind of time out otherwise we
 * could potentially wait for ever, 1000ms ie 1s sounds like a long time to
 * wait already.
 */
<<<<<<< HEAD
#define HMM_RANGE_DEFAULT_TIMEOUT 1000
=======
static inline unsigned long hmm_pfn_to_pfn(const struct hmm_range *range,
					   uint64_t pfn)
{
	if (pfn == range->values[HMM_PFN_NONE])
		return -1UL;
	if (pfn == range->values[HMM_PFN_ERROR])
		return -1UL;
	if (pfn == range->values[HMM_PFN_SPECIAL])
		return -1UL;
	if (!(pfn & range->flags[HMM_PFN_VALID]))
		return -1UL;
	return (pfn >> range->pfn_shift);
}

/*
 * hmm_pfn_from_page() - create a valid HMM pfn value from struct page
 * @range: range use to encode HMM pfn value
 * @page: struct page pointer for which to create the HMM pfn
 * Returns: valid HMM pfn for the page
 */
static inline uint64_t hmm_pfn_from_page(const struct hmm_range *range,
					 struct page *page)
{
	return (page_to_pfn(page) << range->pfn_shift) |
		range->flags[HMM_PFN_VALID];
}

/*
 * hmm_pfn_from_pfn() - create a valid HMM pfn value from pfn
 * @range: range use to encode HMM pfn value
 * @pfn: pfn value for which to create the HMM pfn
 * Returns: valid HMM pfn for the pfn
 */
static inline uint64_t hmm_pfn_from_pfn(const struct hmm_range *range,
					unsigned long pfn)
{
	return (pfn << range->pfn_shift) |
		range->flags[HMM_PFN_VALID];
}


#if IS_ENABLED(CONFIG_HMM_MIRROR)
/*
 * Mirroring: how to synchronize device page table with CPU page table.
 *
 * A device driver that is participating in HMM mirroring must always
 * synchronize with CPU page table updates. For this, device drivers can either
 * directly use mmu_notifier APIs or they can use the hmm_mirror API. Device
 * drivers can decide to register one mirror per device per process, or just
 * one mirror per process for a group of devices. The pattern is:
 *
 *      int device_bind_address_space(..., struct mm_struct *mm, ...)
 *      {
 *          struct device_address_space *das;
 *
 *          // Device driver specific initialization, and allocation of das
 *          // which contains an hmm_mirror struct as one of its fields.
 *          ...
 *
 *          ret = hmm_mirror_register(&das->mirror, mm, &device_mirror_ops);
 *          if (ret) {
 *              // Cleanup on error
 *              return ret;
 *          }
 *
 *          // Other device driver specific initialization
 *          ...
 *      }
 *
 * Once an hmm_mirror is registered for an address space, the device driver
 * will get callbacks through sync_cpu_device_pagetables() operation (see
 * hmm_mirror_ops struct).
 *
 * Device driver must not free the struct containing the hmm_mirror struct
 * before calling hmm_mirror_unregister(). The expected usage is to do that when
 * the device driver is unbinding from an address space.
 *
 *
 *      void device_unbind_address_space(struct device_address_space *das)
 *      {
 *          // Device driver specific cleanup
 *          ...
 *
 *          hmm_mirror_unregister(&das->mirror);
 *
 *          // Other device driver specific cleanup, and now das can be freed
 *          ...
 *      }
 */

struct hmm_mirror;

/*
 * enum hmm_update_type - type of update
 * @HMM_UPDATE_INVALIDATE: invalidate range (no indication as to why)
 */
enum hmm_update_type {
	HMM_UPDATE_INVALIDATE,
};

/*
 * struct hmm_mirror_ops - HMM mirror device operations callback
 *
 * @update: callback to update range on a device
 */
struct hmm_mirror_ops {
	/* release() - release hmm_mirror
	 *
	 * @mirror: pointer to struct hmm_mirror
	 *
	 * This is called when the mm_struct is being released.
	 * The callback should make sure no references to the mirror occur
	 * after the callback returns.
	 */
	void (*release)(struct hmm_mirror *mirror);

	/* sync_cpu_device_pagetables() - synchronize page tables
	 *
	 * @mirror: pointer to struct hmm_mirror
	 * @update_type: type of update that occurred to the CPU page table
	 * @start: virtual start address of the range to update
	 * @end: virtual end address of the range to update
	 *
	 * This callback ultimately originates from mmu_notifiers when the CPU
	 * page table is updated. The device driver must update its page table
	 * in response to this callback. The update argument tells what action
	 * to perform.
	 *
	 * The device driver must not return from this callback until the device
	 * page tables are completely updated (TLBs flushed, etc); this is a
	 * synchronous call.
	 */
	void (*sync_cpu_device_pagetables)(struct hmm_mirror *mirror,
					   enum hmm_update_type update_type,
					   unsigned long start,
					   unsigned long end);
};

/*
 * struct hmm_mirror - mirror struct for a device driver
 *
 * @hmm: pointer to struct hmm (which is unique per mm_struct)
 * @ops: device driver callback for HMM mirror operations
 * @list: for list of mirrors of a given mm
 *
 * Each address space (mm_struct) being mirrored by a device must register one
 * instance of an hmm_mirror struct with HMM. HMM will track the list of all
 * mirrors for each mm_struct.
 */
struct hmm_mirror {
	struct hmm			*hmm;
	const struct hmm_mirror_ops	*ops;
	struct list_head		list;
};

int hmm_mirror_register(struct hmm_mirror *mirror, struct mm_struct *mm);
void hmm_mirror_unregister(struct hmm_mirror *mirror);


/*
 * To snapshot the CPU page table, call hmm_vma_get_pfns(), then take a device
 * driver lock that serializes device page table updates, then call
 * hmm_vma_range_done(), to check if the snapshot is still valid. The same
 * device driver page table update lock must also be used in the
 * hmm_mirror_ops.sync_cpu_device_pagetables() callback, so that CPU page
 * table invalidation serializes on it.
 *
 * YOU MUST CALL hmm_vma_range_done() ONCE AND ONLY ONCE EACH TIME YOU CALL
 * hmm_vma_get_pfns() WITHOUT ERROR !
 *
 * IF YOU DO NOT FOLLOW THE ABOVE RULE THE SNAPSHOT CONTENT MIGHT BE INVALID !
 */
int hmm_vma_get_pfns(struct hmm_range *range);
bool hmm_vma_range_done(struct hmm_range *range);


/*
 * Fault memory on behalf of device driver. Unlike handle_mm_fault(), this will
 * not migrate any device memory back to system memory. The HMM pfn array will
 * be updated with the fault result and current snapshot of the CPU page table
 * for the range.
 *
 * The mmap_sem must be taken in read mode before entering and it might be
 * dropped by the function if the block argument is false. In that case, the
 * function returns -EAGAIN.
 *
 * Return value does not reflect if the fault was successful for every single
 * address or not. Therefore, the caller must to inspect the HMM pfn array to
 * determine fault status for each address.
 *
 * Trying to fault inside an invalid vma will result in -EINVAL.
 *
 * See the function description in mm/hmm.c for further documentation.
 */
int hmm_vma_fault(struct hmm_range *range, bool block);

/* Below are for HMM internal use only! Not to be used by device driver! */
void hmm_mm_destroy(struct mm_struct *mm);

static inline void hmm_mm_init(struct mm_struct *mm)
{
	mm->hmm = NULL;
}
#else /* IS_ENABLED(CONFIG_HMM_MIRROR) */
static inline void hmm_mm_destroy(struct mm_struct *mm) {}
static inline void hmm_mm_init(struct mm_struct *mm) {}
#endif /* IS_ENABLED(CONFIG_HMM_MIRROR) */

#if IS_ENABLED(CONFIG_DEVICE_PRIVATE) ||  IS_ENABLED(CONFIG_DEVICE_PUBLIC)
struct hmm_devmem;

struct page *hmm_vma_alloc_locked_page(struct vm_area_struct *vma,
				       unsigned long addr);

/*
 * struct hmm_devmem_ops - callback for ZONE_DEVICE memory events
 *
 * @free: call when refcount on page reach 1 and thus is no longer use
 * @fault: call when there is a page fault to unaddressable memory
 *
 * Both callback happens from page_free() and page_fault() callback of struct
 * dev_pagemap respectively. See include/linux/memremap.h for more details on
 * those.
 *
 * The hmm_devmem_ops callback are just here to provide a coherent and
 * uniq API to device driver and device driver should not register their
 * own page_free() or page_fault() but rely on the hmm_devmem_ops call-
 * back.
 */
struct hmm_devmem_ops {
	/*
	 * free() - free a device page
	 * @devmem: device memory structure (see struct hmm_devmem)
	 * @page: pointer to struct page being freed
	 *
	 * Call back occurs whenever a device page refcount reach 1 which
	 * means that no one is holding any reference on the page anymore
	 * (ZONE_DEVICE page have an elevated refcount of 1 as default so
	 * that they are not release to the general page allocator).
	 *
	 * Note that callback has exclusive ownership of the page (as no
	 * one is holding any reference).
	 */
	void (*free)(struct hmm_devmem *devmem, struct page *page);
	/*
	 * fault() - CPU page fault or get user page (GUP)
	 * @devmem: device memory structure (see struct hmm_devmem)
	 * @vma: virtual memory area containing the virtual address
	 * @addr: virtual address that faulted or for which there is a GUP
	 * @page: pointer to struct page backing virtual address (unreliable)
	 * @flags: FAULT_FLAG_* (see include/linux/mm.h)
	 * @pmdp: page middle directory
	 * Returns: VM_FAULT_MINOR/MAJOR on success or one of VM_FAULT_ERROR
	 *   on error
	 *
	 * The callback occurs whenever there is a CPU page fault or GUP on a
	 * virtual address. This means that the device driver must migrate the
	 * page back to regular memory (CPU accessible).
	 *
	 * The device driver is free to migrate more than one page from the
	 * fault() callback as an optimization. However if device decide to
	 * migrate more than one page it must always priotirize the faulting
	 * address over the others.
	 *
	 * The struct page pointer is only given as an hint to allow quick
	 * lookup of internal device driver data. A concurrent migration
	 * might have already free that page and the virtual address might
	 * not longer be back by it. So it should not be modified by the
	 * callback.
	 *
	 * Note that mmap semaphore is held in read mode at least when this
	 * callback occurs, hence the vma is valid upon callback entry.
	 */
	int (*fault)(struct hmm_devmem *devmem,
		     struct vm_area_struct *vma,
		     unsigned long addr,
		     const struct page *page,
		     unsigned int flags,
		     pmd_t *pmdp);
};

/*
 * struct hmm_devmem - track device memory
 *
 * @completion: completion object for device memory
 * @pfn_first: first pfn for this resource (set by hmm_devmem_add())
 * @pfn_last: last pfn for this resource (set by hmm_devmem_add())
 * @resource: IO resource reserved for this chunk of memory
 * @pagemap: device page map for that chunk
 * @device: device to bind resource to
 * @ops: memory operations callback
 * @ref: per CPU refcount
 *
 * This an helper structure for device drivers that do not wish to implement
 * the gory details related to hotplugging new memoy and allocating struct
 * pages.
 *
 * Device drivers can directly use ZONE_DEVICE memory on their own if they
 * wish to do so.
 */
struct hmm_devmem {
	struct completion		completion;
	unsigned long			pfn_first;
	unsigned long			pfn_last;
	struct resource			*resource;
	struct device			*device;
	struct dev_pagemap		pagemap;
	const struct hmm_devmem_ops	*ops;
	struct percpu_ref		ref;
};

/*
 * To add (hotplug) device memory, HMM assumes that there is no real resource
 * that reserves a range in the physical address space (this is intended to be
 * use by unaddressable device memory). It will reserve a physical range big
 * enough and allocate struct page for it.
 *
 * The device driver can wrap the hmm_devmem struct inside a private device
 * driver struct.
 */
struct hmm_devmem *hmm_devmem_add(const struct hmm_devmem_ops *ops,
				  struct device *device,
				  unsigned long size);
struct hmm_devmem *hmm_devmem_add_resource(const struct hmm_devmem_ops *ops,
					   struct device *device,
					   struct resource *res);

/*
 * hmm_devmem_page_set_drvdata - set per-page driver data field
 *
 * @page: pointer to struct page
 * @data: driver data value to set
 *
 * Because page can not be on lru we have an unsigned long that driver can use
 * to store a per page field. This just a simple helper to do that.
 */
static inline void hmm_devmem_page_set_drvdata(struct page *page,
					       unsigned long data)
{
	page->hmm_data = data;
}

/*
 * hmm_devmem_page_get_drvdata - get per page driver data field
 *
 * @page: pointer to struct page
 * Return: driver data value
 */
static inline unsigned long hmm_devmem_page_get_drvdata(const struct page *page)
{
	return page->hmm_data;
}


/*
 * struct hmm_device - fake device to hang device memory onto
 *
 * @device: device struct
 * @minor: device minor number
 */
struct hmm_device {
	struct device		device;
	unsigned int		minor;
};

/*
 * A device driver that wants to handle multiple devices memory through a
 * single fake device can use hmm_device to do so. This is purely a helper and
 * it is not strictly needed, in order to make use of any HMM functionality.
 */
struct hmm_device *hmm_device_new(void *drvdata);
void hmm_device_put(struct hmm_device *hmm_device);
#endif /* CONFIG_DEVICE_PRIVATE || CONFIG_DEVICE_PUBLIC */
#else /* IS_ENABLED(CONFIG_HMM) */
static inline void hmm_mm_destroy(struct mm_struct *mm) {}
static inline void hmm_mm_init(struct mm_struct *mm) {}
#endif /* IS_ENABLED(CONFIG_HMM) */
>>>>>>> master

#endif /* LINUX_HMM_H */
