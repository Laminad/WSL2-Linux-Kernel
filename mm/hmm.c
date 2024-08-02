// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2013 Red Hat Inc.
 *
 * Authors: Jérôme Glisse <jglisse@redhat.com>
 */
/*
 * Refer to include/linux/hmm.h for information about heterogeneous memory
 * management or HMM for short.
 */
#include <linux/pagewalk.h>
#include <linux/hmm.h>
#include <linux/init.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mmzone.h>
#include <linux/pagemap.h>
#include <linux/swapops.h>
#include <linux/hugetlb.h>
#include <linux/memremap.h>
#include <linux/sched/mm.h>
#include <linux/jump_label.h>
#include <linux/dma-mapping.h>
#include <linux/mmu_notifier.h>
#include <linux/memory_hotplug.h>

<<<<<<< HEAD
#include "internal.h"
=======
#define PA_SECTION_SIZE (1UL << PA_SECTION_SHIFT)

#if IS_ENABLED(CONFIG_HMM_MIRROR)
static const struct mmu_notifier_ops hmm_mmu_notifier_ops;

/*
 * struct hmm - HMM per mm struct
 *
 * @mm: mm struct this HMM struct is bound to
 * @lock: lock protecting ranges list
 * @sequence: we track updates to the CPU page table with a sequence number
 * @ranges: list of range being snapshotted
 * @mirrors: list of mirrors for this mm
 * @mmu_notifier: mmu notifier to track updates to CPU page table
 * @mirrors_sem: read/write semaphore protecting the mirrors list
 */
struct hmm {
	struct mm_struct	*mm;
	spinlock_t		lock;
	atomic_t		sequence;
	struct list_head	ranges;
	struct list_head	mirrors;
	struct mmu_notifier	mmu_notifier;
	struct rw_semaphore	mirrors_sem;
};

/*
 * hmm_register - register HMM against an mm (HMM internal)
 *
 * @mm: mm struct to attach to
 *
 * This is not intended to be used directly by device drivers. It allocates an
 * HMM struct if mm does not have one, and initializes it.
 */
static struct hmm *hmm_register(struct mm_struct *mm)
{
	struct hmm *hmm = READ_ONCE(mm->hmm);
	bool cleanup = false;

	/*
	 * The hmm struct can only be freed once the mm_struct goes away,
	 * hence we should always have pre-allocated an new hmm struct
	 * above.
	 */
	if (hmm)
		return hmm;

	hmm = kmalloc(sizeof(*hmm), GFP_KERNEL);
	if (!hmm)
		return NULL;
	INIT_LIST_HEAD(&hmm->mirrors);
	init_rwsem(&hmm->mirrors_sem);
	atomic_set(&hmm->sequence, 0);
	hmm->mmu_notifier.ops = NULL;
	INIT_LIST_HEAD(&hmm->ranges);
	spin_lock_init(&hmm->lock);
	hmm->mm = mm;

	spin_lock(&mm->page_table_lock);
	if (!mm->hmm)
		mm->hmm = hmm;
	else
		cleanup = true;
	spin_unlock(&mm->page_table_lock);

	if (cleanup)
		goto error;

	/*
	 * We should only get here if hold the mmap_sem in write mode ie on
	 * registration of first mirror through hmm_mirror_register()
	 */
	hmm->mmu_notifier.ops = &hmm_mmu_notifier_ops;
	if (__mmu_notifier_register(&hmm->mmu_notifier, mm))
		goto error_mm;

	return mm->hmm;

error_mm:
	spin_lock(&mm->page_table_lock);
	if (mm->hmm == hmm)
		mm->hmm = NULL;
	spin_unlock(&mm->page_table_lock);
error:
	kfree(hmm);
	return NULL;
}

void hmm_mm_destroy(struct mm_struct *mm)
{
	kfree(mm->hmm);
}

static void hmm_invalidate_range(struct hmm *hmm,
				 enum hmm_update_type action,
				 unsigned long start,
				 unsigned long end)
{
	struct hmm_mirror *mirror;
	struct hmm_range *range;

	spin_lock(&hmm->lock);
	list_for_each_entry(range, &hmm->ranges, list) {
		unsigned long addr, idx, npages;

		if (end < range->start || start >= range->end)
			continue;

		range->valid = false;
		addr = max(start, range->start);
		idx = (addr - range->start) >> PAGE_SHIFT;
		npages = (min(range->end, end) - addr) >> PAGE_SHIFT;
		memset(&range->pfns[idx], 0, sizeof(*range->pfns) * npages);
	}
	spin_unlock(&hmm->lock);

	down_read(&hmm->mirrors_sem);
	list_for_each_entry(mirror, &hmm->mirrors, list)
		mirror->ops->sync_cpu_device_pagetables(mirror, action,
							start, end);
	up_read(&hmm->mirrors_sem);
}

static void hmm_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct hmm_mirror *mirror;
	struct hmm *hmm = mm->hmm;

	down_write(&hmm->mirrors_sem);
	mirror = list_first_entry_or_null(&hmm->mirrors, struct hmm_mirror,
					  list);
	while (mirror) {
		list_del_init(&mirror->list);
		if (mirror->ops->release) {
			/*
			 * Drop mirrors_sem so callback can wait on any pending
			 * work that might itself trigger mmu_notifier callback
			 * and thus would deadlock with us.
			 */
			up_write(&hmm->mirrors_sem);
			mirror->ops->release(mirror);
			down_write(&hmm->mirrors_sem);
		}
		mirror = list_first_entry_or_null(&hmm->mirrors,
						  struct hmm_mirror, list);
	}
	up_write(&hmm->mirrors_sem);
}

static int hmm_invalidate_range_start(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long start,
				       unsigned long end,
				       bool blockable)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	atomic_inc(&hmm->sequence);

	return 0;
}

static void hmm_invalidate_range_end(struct mmu_notifier *mn,
				     struct mm_struct *mm,
				     unsigned long start,
				     unsigned long end)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	hmm_invalidate_range(mm->hmm, HMM_UPDATE_INVALIDATE, start, end);
}

static const struct mmu_notifier_ops hmm_mmu_notifier_ops = {
	.release		= hmm_release,
	.invalidate_range_start	= hmm_invalidate_range_start,
	.invalidate_range_end	= hmm_invalidate_range_end,
};

/*
 * hmm_mirror_register() - register a mirror against an mm
 *
 * @mirror: new mirror struct to register
 * @mm: mm to register against
 *
 * To start mirroring a process address space, the device driver must register
 * an HMM mirror struct.
 *
 * THE mm->mmap_sem MUST BE HELD IN WRITE MODE !
 */
int hmm_mirror_register(struct hmm_mirror *mirror, struct mm_struct *mm)
{
	/* Sanity check */
	if (!mm || !mirror || !mirror->ops)
		return -EINVAL;

again:
	mirror->hmm = hmm_register(mm);
	if (!mirror->hmm)
		return -ENOMEM;

	down_write(&mirror->hmm->mirrors_sem);
	if (mirror->hmm->mm == NULL) {
		/*
		 * A racing hmm_mirror_unregister() is about to destroy the hmm
		 * struct. Try again to allocate a new one.
		 */
		up_write(&mirror->hmm->mirrors_sem);
		mirror->hmm = NULL;
		goto again;
	} else {
		list_add(&mirror->list, &mirror->hmm->mirrors);
		up_write(&mirror->hmm->mirrors_sem);
	}

	return 0;
}
EXPORT_SYMBOL(hmm_mirror_register);

/*
 * hmm_mirror_unregister() - unregister a mirror
 *
 * @mirror: new mirror struct to register
 *
 * Stop mirroring a process address space, and cleanup.
 */
void hmm_mirror_unregister(struct hmm_mirror *mirror)
{
	bool should_unregister = false;
	struct mm_struct *mm;
	struct hmm *hmm;

	if (mirror->hmm == NULL)
		return;

	hmm = mirror->hmm;
	down_write(&hmm->mirrors_sem);
	list_del_init(&mirror->list);
	should_unregister = list_empty(&hmm->mirrors);
	mirror->hmm = NULL;
	mm = hmm->mm;
	hmm->mm = NULL;
	up_write(&hmm->mirrors_sem);

	if (!should_unregister || mm == NULL)
		return;

	mmu_notifier_unregister_no_release(&hmm->mmu_notifier, mm);

	spin_lock(&mm->page_table_lock);
	if (mm->hmm == hmm)
		mm->hmm = NULL;
	spin_unlock(&mm->page_table_lock);

	kfree(hmm);
}
EXPORT_SYMBOL(hmm_mirror_unregister);
>>>>>>> master

struct hmm_vma_walk {
	struct hmm_range	*range;
	unsigned long		last;
};

enum {
	HMM_NEED_FAULT = 1 << 0,
	HMM_NEED_WRITE_FAULT = 1 << 1,
	HMM_NEED_ALL_BITS = HMM_NEED_FAULT | HMM_NEED_WRITE_FAULT,
};

static int hmm_pfns_fill(unsigned long addr, unsigned long end,
			 struct hmm_range *range, unsigned long cpu_flags)
{
	unsigned long i = (addr - range->start) >> PAGE_SHIFT;

	for (; addr < end; addr += PAGE_SIZE, i++)
		range->hmm_pfns[i] = cpu_flags;
	return 0;
}

/*
 * hmm_vma_fault() - fault in a range lacking valid pmd or pte(s)
 * @addr: range virtual start address (inclusive)
 * @end: range virtual end address (exclusive)
 * @required_fault: HMM_NEED_* flags
 * @walk: mm_walk structure
 * Return: -EBUSY after page fault, or page fault error
 *
 * This function will be called whenever pmd_none() or pte_none() returns true,
 * or whenever there is no page directory covering the virtual address range.
 */
static int hmm_vma_fault(unsigned long addr, unsigned long end,
			 unsigned int required_fault, struct mm_walk *walk)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct vm_area_struct *vma = walk->vma;
	unsigned int fault_flags = FAULT_FLAG_REMOTE;

	WARN_ON_ONCE(!required_fault);
	hmm_vma_walk->last = addr;

	if (required_fault & HMM_NEED_WRITE_FAULT) {
		if (!(vma->vm_flags & VM_WRITE))
			return -EPERM;
		fault_flags |= FAULT_FLAG_WRITE;
	}

	for (; addr < end; addr += PAGE_SIZE)
		if (handle_mm_fault(vma, addr, fault_flags, NULL) &
		    VM_FAULT_ERROR)
			return -EFAULT;
	return -EBUSY;
}

static unsigned int hmm_pte_need_fault(const struct hmm_vma_walk *hmm_vma_walk,
				       unsigned long pfn_req_flags,
				       unsigned long cpu_flags)
{
	struct hmm_range *range = hmm_vma_walk->range;

	/*
	 * So we not only consider the individual per page request we also
	 * consider the default flags requested for the range. The API can
	 * be used 2 ways. The first one where the HMM user coalesces
	 * multiple page faults into one request and sets flags per pfn for
	 * those faults. The second one where the HMM user wants to pre-
	 * fault a range with specific flags. For the latter one it is a
	 * waste to have the user pre-fill the pfn arrays with a default
	 * flags value.
	 */
	pfn_req_flags &= range->pfn_flags_mask;
	pfn_req_flags |= range->default_flags;

	/* We aren't ask to do anything ... */
	if (!(pfn_req_flags & HMM_PFN_REQ_FAULT))
		return 0;

	/* Need to write fault ? */
	if ((pfn_req_flags & HMM_PFN_REQ_WRITE) &&
	    !(cpu_flags & HMM_PFN_WRITE))
		return HMM_NEED_FAULT | HMM_NEED_WRITE_FAULT;

	/* If CPU page table is not valid then we need to fault */
	if (!(cpu_flags & HMM_PFN_VALID))
		return HMM_NEED_FAULT;
	return 0;
}

static unsigned int
hmm_range_need_fault(const struct hmm_vma_walk *hmm_vma_walk,
		     const unsigned long hmm_pfns[], unsigned long npages,
		     unsigned long cpu_flags)
{
	struct hmm_range *range = hmm_vma_walk->range;
	unsigned int required_fault = 0;
	unsigned long i;

	/*
	 * If the default flags do not request to fault pages, and the mask does
	 * not allow for individual pages to be faulted, then
	 * hmm_pte_need_fault() will always return 0.
	 */
	if (!((range->default_flags | range->pfn_flags_mask) &
	      HMM_PFN_REQ_FAULT))
		return 0;

	for (i = 0; i < npages; ++i) {
		required_fault |= hmm_pte_need_fault(hmm_vma_walk, hmm_pfns[i],
						     cpu_flags);
		if (required_fault == HMM_NEED_ALL_BITS)
			return required_fault;
	}
	return required_fault;
}

static int hmm_vma_walk_hole(unsigned long addr, unsigned long end,
			     __always_unused int depth, struct mm_walk *walk)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct hmm_range *range = hmm_vma_walk->range;
	unsigned int required_fault;
	unsigned long i, npages;
	unsigned long *hmm_pfns;

	i = (addr - range->start) >> PAGE_SHIFT;
	npages = (end - addr) >> PAGE_SHIFT;
	hmm_pfns = &range->hmm_pfns[i];
	required_fault =
		hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, 0);
	if (!walk->vma) {
		if (required_fault)
			return -EFAULT;
		return hmm_pfns_fill(addr, end, range, HMM_PFN_ERROR);
	}
	if (required_fault)
		return hmm_vma_fault(addr, end, required_fault, walk);
	return hmm_pfns_fill(addr, end, range, 0);
}

static inline unsigned long hmm_pfn_flags_order(unsigned long order)
{
	return order << HMM_PFN_ORDER_SHIFT;
}

static inline unsigned long pmd_to_hmm_pfn_flags(struct hmm_range *range,
						 pmd_t pmd)
{
	if (pmd_protnone(pmd))
		return 0;
	return (pmd_write(pmd) ? (HMM_PFN_VALID | HMM_PFN_WRITE) :
				 HMM_PFN_VALID) |
	       hmm_pfn_flags_order(PMD_SHIFT - PAGE_SHIFT);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static int hmm_vma_handle_pmd(struct mm_walk *walk, unsigned long addr,
			      unsigned long end, unsigned long hmm_pfns[],
			      pmd_t pmd)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct hmm_range *range = hmm_vma_walk->range;
	unsigned long pfn, npages, i;
	unsigned int required_fault;
	unsigned long cpu_flags;

	npages = (end - addr) >> PAGE_SHIFT;
	cpu_flags = pmd_to_hmm_pfn_flags(range, pmd);
	required_fault =
		hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, cpu_flags);
	if (required_fault)
		return hmm_vma_fault(addr, end, required_fault, walk);

	pfn = pmd_pfn(pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	for (i = 0; addr < end; addr += PAGE_SIZE, i++, pfn++)
		hmm_pfns[i] = pfn | cpu_flags;
	return 0;
}
#else /* CONFIG_TRANSPARENT_HUGEPAGE */
/* stub to allow the code below to compile */
int hmm_vma_handle_pmd(struct mm_walk *walk, unsigned long addr,
		unsigned long end, unsigned long hmm_pfns[], pmd_t pmd);
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

static inline unsigned long pte_to_hmm_pfn_flags(struct hmm_range *range,
						 pte_t pte)
{
	if (pte_none(pte) || !pte_present(pte) || pte_protnone(pte))
		return 0;
	return pte_write(pte) ? (HMM_PFN_VALID | HMM_PFN_WRITE) : HMM_PFN_VALID;
}

static int hmm_vma_handle_pte(struct mm_walk *walk, unsigned long addr,
			      unsigned long end, pmd_t *pmdp, pte_t *ptep,
			      unsigned long *hmm_pfn)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct hmm_range *range = hmm_vma_walk->range;
	unsigned int required_fault;
	unsigned long cpu_flags;
	pte_t pte = ptep_get(ptep);
	uint64_t pfn_req_flags = *hmm_pfn;

	if (pte_none_mostly(pte)) {
		required_fault =
			hmm_pte_need_fault(hmm_vma_walk, pfn_req_flags, 0);
		if (required_fault)
			goto fault;
		*hmm_pfn = 0;
		return 0;
	}

	if (!pte_present(pte)) {
		swp_entry_t entry = pte_to_swp_entry(pte);

		/*
		 * Don't fault in device private pages owned by the caller,
		 * just report the PFN.
		 */
		if (is_device_private_entry(entry) &&
		    pfn_swap_entry_to_page(entry)->pgmap->owner ==
		    range->dev_private_owner) {
			cpu_flags = HMM_PFN_VALID;
			if (is_writable_device_private_entry(entry))
				cpu_flags |= HMM_PFN_WRITE;
			*hmm_pfn = swp_offset_pfn(entry) | cpu_flags;
			return 0;
		}

		required_fault =
			hmm_pte_need_fault(hmm_vma_walk, pfn_req_flags, 0);
		if (!required_fault) {
			*hmm_pfn = 0;
			return 0;
		}

		if (!non_swap_entry(entry))
			goto fault;

		if (is_device_private_entry(entry))
			goto fault;

		if (is_device_exclusive_entry(entry))
			goto fault;

		if (is_migration_entry(entry)) {
			pte_unmap(ptep);
			hmm_vma_walk->last = addr;
			migration_entry_wait(walk->mm, pmdp, addr);
			return -EBUSY;
		}

		/* Report error for everything else */
		pte_unmap(ptep);
		return -EFAULT;
	}

	cpu_flags = pte_to_hmm_pfn_flags(range, pte);
	required_fault =
		hmm_pte_need_fault(hmm_vma_walk, pfn_req_flags, cpu_flags);
	if (required_fault)
		goto fault;

	/*
	 * Bypass devmap pte such as DAX page when all pfn requested
	 * flags(pfn_req_flags) are fulfilled.
	 * Since each architecture defines a struct page for the zero page, just
	 * fall through and treat it like a normal page.
	 */
	if (!vm_normal_page(walk->vma, addr, pte) &&
	    !pte_devmap(pte) &&
	    !is_zero_pfn(pte_pfn(pte))) {
		if (hmm_pte_need_fault(hmm_vma_walk, pfn_req_flags, 0)) {
			pte_unmap(ptep);
			return -EFAULT;
		}
		*hmm_pfn = HMM_PFN_ERROR;
		return 0;
	}

	*hmm_pfn = pte_pfn(pte) | cpu_flags;
	return 0;

fault:
	pte_unmap(ptep);
	/* Fault any virtual address we were asked to fault */
	return hmm_vma_fault(addr, end, required_fault, walk);
}

static int hmm_vma_walk_pmd(pmd_t *pmdp,
			    unsigned long start,
			    unsigned long end,
			    struct mm_walk *walk)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct hmm_range *range = hmm_vma_walk->range;
	unsigned long *hmm_pfns =
		&range->hmm_pfns[(start - range->start) >> PAGE_SHIFT];
	unsigned long npages = (end - start) >> PAGE_SHIFT;
	unsigned long addr = start;
	pte_t *ptep;
	pmd_t pmd;

again:
	pmd = pmdp_get_lockless(pmdp);
	if (pmd_none(pmd))
		return hmm_vma_walk_hole(start, end, -1, walk);

	if (thp_migration_supported() && is_pmd_migration_entry(pmd)) {
		if (hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, 0)) {
			hmm_vma_walk->last = addr;
			pmd_migration_entry_wait(walk->mm, pmdp);
			return -EBUSY;
		}
		return hmm_pfns_fill(start, end, range, 0);
	}

	if (!pmd_present(pmd)) {
		if (hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, 0))
			return -EFAULT;
		return hmm_pfns_fill(start, end, range, HMM_PFN_ERROR);
	}

	if (pmd_devmap(pmd) || pmd_trans_huge(pmd)) {
		/*
		 * No need to take pmd_lock here, even if some other thread
		 * is splitting the huge pmd we will get that event through
		 * mmu_notifier callback.
		 *
		 * So just read pmd value and check again it's a transparent
		 * huge or device mapping one and compute corresponding pfn
		 * values.
		 */
		pmd = pmdp_get_lockless(pmdp);
		if (!pmd_devmap(pmd) && !pmd_trans_huge(pmd))
			goto again;

		return hmm_vma_handle_pmd(walk, addr, end, hmm_pfns, pmd);
	}

	/*
	 * We have handled all the valid cases above ie either none, migration,
	 * huge or transparent huge. At this point either it is a valid pmd
	 * entry pointing to pte directory or it is a bad pmd that will not
	 * recover.
	 */
	if (pmd_bad(pmd)) {
		if (hmm_range_need_fault(hmm_vma_walk, hmm_pfns, npages, 0))
			return -EFAULT;
		return hmm_pfns_fill(start, end, range, HMM_PFN_ERROR);
	}

	ptep = pte_offset_map(pmdp, addr);
	if (!ptep)
		goto again;
	for (; addr < end; addr += PAGE_SIZE, ptep++, hmm_pfns++) {
		int r;

		r = hmm_vma_handle_pte(walk, addr, end, pmdp, ptep, hmm_pfns);
		if (r) {
			/* hmm_vma_handle_pte() did pte_unmap() */
			return r;
		}
	}
	pte_unmap(ptep - 1);
	return 0;
}

#if defined(CONFIG_ARCH_HAS_PTE_DEVMAP) && \
    defined(CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD)
static inline unsigned long pud_to_hmm_pfn_flags(struct hmm_range *range,
						 pud_t pud)
{
	if (!pud_present(pud))
		return 0;
	return (pud_write(pud) ? (HMM_PFN_VALID | HMM_PFN_WRITE) :
				 HMM_PFN_VALID) |
	       hmm_pfn_flags_order(PUD_SHIFT - PAGE_SHIFT);
}

static int hmm_vma_walk_pud(pud_t *pudp, unsigned long start, unsigned long end,
		struct mm_walk *walk)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct hmm_range *range = hmm_vma_walk->range;
	unsigned long addr = start;
	pud_t pud;
	spinlock_t *ptl = pud_trans_huge_lock(pudp, walk->vma);

	if (!ptl)
		return 0;

	/* Normally we don't want to split the huge page */
	walk->action = ACTION_CONTINUE;

	pud = READ_ONCE(*pudp);
	if (pud_none(pud)) {
		spin_unlock(ptl);
		return hmm_vma_walk_hole(start, end, -1, walk);
	}

	if (pud_huge(pud) && pud_devmap(pud)) {
		unsigned long i, npages, pfn;
		unsigned int required_fault;
		unsigned long *hmm_pfns;
		unsigned long cpu_flags;

		if (!pud_present(pud)) {
			spin_unlock(ptl);
			return hmm_vma_walk_hole(start, end, -1, walk);
		}

		i = (addr - range->start) >> PAGE_SHIFT;
		npages = (end - addr) >> PAGE_SHIFT;
		hmm_pfns = &range->hmm_pfns[i];

		cpu_flags = pud_to_hmm_pfn_flags(range, pud);
		required_fault = hmm_range_need_fault(hmm_vma_walk, hmm_pfns,
						      npages, cpu_flags);
		if (required_fault) {
			spin_unlock(ptl);
			return hmm_vma_fault(addr, end, required_fault, walk);
		}

		pfn = pud_pfn(pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
		for (i = 0; i < npages; ++i, ++pfn)
			hmm_pfns[i] = pfn | cpu_flags;
		goto out_unlock;
	}

	/* Ask for the PUD to be split */
	walk->action = ACTION_SUBTREE;

out_unlock:
	spin_unlock(ptl);
	return 0;
}
#else
#define hmm_vma_walk_pud	NULL
#endif

#ifdef CONFIG_HUGETLB_PAGE
static int hmm_vma_walk_hugetlb_entry(pte_t *pte, unsigned long hmask,
				      unsigned long start, unsigned long end,
				      struct mm_walk *walk)
{
	unsigned long addr = start, i, pfn;
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct hmm_range *range = hmm_vma_walk->range;
	struct vm_area_struct *vma = walk->vma;
	unsigned int required_fault;
	unsigned long pfn_req_flags;
	unsigned long cpu_flags;
	spinlock_t *ptl;
	pte_t entry;

	ptl = huge_pte_lock(hstate_vma(vma), walk->mm, pte);
	entry = huge_ptep_get(pte);

	i = (start - range->start) >> PAGE_SHIFT;
	pfn_req_flags = range->hmm_pfns[i];
	cpu_flags = pte_to_hmm_pfn_flags(range, entry) |
		    hmm_pfn_flags_order(huge_page_order(hstate_vma(vma)));
	required_fault =
		hmm_pte_need_fault(hmm_vma_walk, pfn_req_flags, cpu_flags);
	if (required_fault) {
		int ret;

		spin_unlock(ptl);
		hugetlb_vma_unlock_read(vma);
		/*
		 * Avoid deadlock: drop the vma lock before calling
		 * hmm_vma_fault(), which will itself potentially take and
		 * drop the vma lock. This is also correct from a
		 * protection point of view, because there is no further
		 * use here of either pte or ptl after dropping the vma
		 * lock.
		 */
		ret = hmm_vma_fault(addr, end, required_fault, walk);
		hugetlb_vma_lock_read(vma);
		return ret;
	}

	pfn = pte_pfn(entry) + ((start & ~hmask) >> PAGE_SHIFT);
	for (; addr < end; addr += PAGE_SIZE, i++, pfn++)
		range->hmm_pfns[i] = pfn | cpu_flags;

	spin_unlock(ptl);
	return 0;
}
#else
#define hmm_vma_walk_hugetlb_entry NULL
#endif /* CONFIG_HUGETLB_PAGE */

static int hmm_vma_walk_test(unsigned long start, unsigned long end,
			     struct mm_walk *walk)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct hmm_range *range = hmm_vma_walk->range;
	struct vm_area_struct *vma = walk->vma;

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP)) &&
	    vma->vm_flags & VM_READ)
		return 0;

	/*
	 * vma ranges that don't have struct page backing them or map I/O
	 * devices directly cannot be handled by hmm_range_fault().
	 *
	 * If the vma does not allow read access, then assume that it does not
	 * allow write access either. HMM does not support architectures that
	 * allow write without read.
	 *
	 * If a fault is requested for an unsupported range then it is a hard
	 * failure.
	 */
	if (hmm_range_need_fault(hmm_vma_walk,
				 range->hmm_pfns +
					 ((start - range->start) >> PAGE_SHIFT),
				 (end - start) >> PAGE_SHIFT, 0))
		return -EFAULT;

	hmm_pfns_fill(start, end, range, HMM_PFN_ERROR);

	/* Skip this vma and continue processing the next vma. */
	return 1;
}

static const struct mm_walk_ops hmm_walk_ops = {
	.pud_entry	= hmm_vma_walk_pud,
	.pmd_entry	= hmm_vma_walk_pmd,
	.pte_hole	= hmm_vma_walk_hole,
	.hugetlb_entry	= hmm_vma_walk_hugetlb_entry,
	.test_walk	= hmm_vma_walk_test,
	.walk_lock	= PGWALK_RDLOCK,
};

/**
 * hmm_range_fault - try to fault some address in a virtual address range
 * @range:	argument structure
 *
 * Returns 0 on success or one of the following error codes:
 *
 * -EINVAL:	Invalid arguments or mm or virtual address is in an invalid vma
 *		(e.g., device file vma).
 * -ENOMEM:	Out of memory.
 * -EPERM:	Invalid permission (e.g., asking for write and range is read
 *		only).
 * -EBUSY:	The range has been invalidated and the caller needs to wait for
 *		the invalidation to finish.
 * -EFAULT:     A page was requested to be valid and could not be made valid
 *              ie it has no backing VMA or it is illegal to access
 *
 * This is similar to get_user_pages(), except that it can read the page tables
 * without mutating them (ie causing faults).
 */
int hmm_range_fault(struct hmm_range *range)
{
	struct hmm_vma_walk hmm_vma_walk = {
		.range = range,
		.last = range->start,
	};
	struct mm_struct *mm = range->notifier->mm;
	int ret;

	mmap_assert_locked(mm);

	do {
		/* If range is no longer valid force retry. */
		if (mmu_interval_check_retry(range->notifier,
					     range->notifier_seq))
			return -EBUSY;
		ret = walk_page_range(mm, hmm_vma_walk.last, range->end,
				      &hmm_walk_ops, &hmm_vma_walk);
		/*
		 * When -EBUSY is returned the loop restarts with
		 * hmm_vma_walk.last set to an address that has not been stored
		 * in pfns. All entries < last in the pfn array are set to their
		 * output, and all >= are still at their input values.
		 */
	} while (ret == -EBUSY);
	return ret;
}
<<<<<<< HEAD
EXPORT_SYMBOL(hmm_range_fault);
=======
EXPORT_SYMBOL(hmm_vma_fault);
#endif /* IS_ENABLED(CONFIG_HMM_MIRROR) */


#if IS_ENABLED(CONFIG_DEVICE_PRIVATE) ||  IS_ENABLED(CONFIG_DEVICE_PUBLIC)
struct page *hmm_vma_alloc_locked_page(struct vm_area_struct *vma,
				       unsigned long addr)
{
	struct page *page;

	page = alloc_page_vma(GFP_HIGHUSER, vma, addr);
	if (!page)
		return NULL;
	lock_page(page);
	return page;
}
EXPORT_SYMBOL(hmm_vma_alloc_locked_page);


static void hmm_devmem_ref_release(struct percpu_ref *ref)
{
	struct hmm_devmem *devmem;

	devmem = container_of(ref, struct hmm_devmem, ref);
	complete(&devmem->completion);
}

static void hmm_devmem_ref_exit(void *data)
{
	struct percpu_ref *ref = data;
	struct hmm_devmem *devmem;

	devmem = container_of(ref, struct hmm_devmem, ref);
	percpu_ref_exit(ref);
}

static void hmm_devmem_ref_kill(void *data)
{
	struct percpu_ref *ref = data;
	struct hmm_devmem *devmem;

	devmem = container_of(ref, struct hmm_devmem, ref);
	percpu_ref_kill(ref);
	wait_for_completion(&devmem->completion);
}

static int hmm_devmem_fault(struct vm_area_struct *vma,
			    unsigned long addr,
			    const struct page *page,
			    unsigned int flags,
			    pmd_t *pmdp)
{
	struct hmm_devmem *devmem = page->pgmap->data;

	return devmem->ops->fault(devmem, vma, addr, page, flags, pmdp);
}

static void hmm_devmem_free(struct page *page, void *data)
{
	struct hmm_devmem *devmem = data;

	page->mapping = NULL;

	devmem->ops->free(devmem, page);
}

static DEFINE_MUTEX(hmm_devmem_lock);
static RADIX_TREE(hmm_devmem_radix, GFP_KERNEL);

static void hmm_devmem_radix_release(struct resource *resource)
{
	resource_size_t key;

	mutex_lock(&hmm_devmem_lock);
	for (key = resource->start;
	     key <= resource->end;
	     key += PA_SECTION_SIZE)
		radix_tree_delete(&hmm_devmem_radix, key >> PA_SECTION_SHIFT);
	mutex_unlock(&hmm_devmem_lock);
}

static void hmm_devmem_release(void *data)
{
	struct hmm_devmem *devmem = data;
	struct resource *resource = devmem->resource;
	unsigned long start_pfn, npages;
	struct zone *zone;
	struct page *page;

	/* pages are dead and unused, undo the arch mapping */
	start_pfn = (resource->start & ~(PA_SECTION_SIZE - 1)) >> PAGE_SHIFT;
	npages = ALIGN(resource_size(resource), PA_SECTION_SIZE) >> PAGE_SHIFT;

	page = pfn_to_page(start_pfn);
	zone = page_zone(page);

	mem_hotplug_begin();
	if (resource->desc == IORES_DESC_DEVICE_PRIVATE_MEMORY)
		__remove_pages(zone, start_pfn, npages, NULL);
	else
		arch_remove_memory(start_pfn << PAGE_SHIFT,
				   npages << PAGE_SHIFT, NULL);
	mem_hotplug_done();

	hmm_devmem_radix_release(resource);
}

static int hmm_devmem_pages_create(struct hmm_devmem *devmem)
{
	resource_size_t key, align_start, align_size, align_end;
	struct device *device = devmem->device;
	int ret, nid, is_ram;
	unsigned long pfn;

	align_start = devmem->resource->start & ~(PA_SECTION_SIZE - 1);
	align_size = ALIGN(devmem->resource->start +
			   resource_size(devmem->resource),
			   PA_SECTION_SIZE) - align_start;

	is_ram = region_intersects(align_start, align_size,
				   IORESOURCE_SYSTEM_RAM,
				   IORES_DESC_NONE);
	if (is_ram == REGION_MIXED) {
		WARN_ONCE(1, "%s attempted on mixed region %pr\n",
				__func__, devmem->resource);
		return -ENXIO;
	}
	if (is_ram == REGION_INTERSECTS)
		return -ENXIO;

	if (devmem->resource->desc == IORES_DESC_DEVICE_PUBLIC_MEMORY)
		devmem->pagemap.type = MEMORY_DEVICE_PUBLIC;
	else
		devmem->pagemap.type = MEMORY_DEVICE_PRIVATE;

	devmem->pagemap.res = *devmem->resource;
	devmem->pagemap.page_fault = hmm_devmem_fault;
	devmem->pagemap.page_free = hmm_devmem_free;
	devmem->pagemap.dev = devmem->device;
	devmem->pagemap.ref = &devmem->ref;
	devmem->pagemap.data = devmem;

	mutex_lock(&hmm_devmem_lock);
	align_end = align_start + align_size - 1;
	for (key = align_start; key <= align_end; key += PA_SECTION_SIZE) {
		struct hmm_devmem *dup;

		dup = radix_tree_lookup(&hmm_devmem_radix,
					key >> PA_SECTION_SHIFT);
		if (dup) {
			dev_err(device, "%s: collides with mapping for %s\n",
				__func__, dev_name(dup->device));
			mutex_unlock(&hmm_devmem_lock);
			ret = -EBUSY;
			goto error;
		}
		ret = radix_tree_insert(&hmm_devmem_radix,
					key >> PA_SECTION_SHIFT,
					devmem);
		if (ret) {
			dev_err(device, "%s: failed: %d\n", __func__, ret);
			mutex_unlock(&hmm_devmem_lock);
			goto error_radix;
		}
	}
	mutex_unlock(&hmm_devmem_lock);

	nid = dev_to_node(device);
	if (nid < 0)
		nid = numa_mem_id();

	mem_hotplug_begin();
	/*
	 * For device private memory we call add_pages() as we only need to
	 * allocate and initialize struct page for the device memory. More-
	 * over the device memory is un-accessible thus we do not want to
	 * create a linear mapping for the memory like arch_add_memory()
	 * would do.
	 *
	 * For device public memory, which is accesible by the CPU, we do
	 * want the linear mapping and thus use arch_add_memory().
	 */
	if (devmem->pagemap.type == MEMORY_DEVICE_PUBLIC)
		ret = arch_add_memory(nid, align_start, align_size, NULL,
				false);
	else
		ret = add_pages(nid, align_start >> PAGE_SHIFT,
				align_size >> PAGE_SHIFT, NULL, false);
	if (ret) {
		mem_hotplug_done();
		goto error_add_memory;
	}
	move_pfn_range_to_zone(&NODE_DATA(nid)->node_zones[ZONE_DEVICE],
				align_start >> PAGE_SHIFT,
				align_size >> PAGE_SHIFT, NULL);
	mem_hotplug_done();

	for (pfn = devmem->pfn_first; pfn < devmem->pfn_last; pfn++) {
		struct page *page = pfn_to_page(pfn);

		page->pgmap = &devmem->pagemap;
	}
	return 0;

error_add_memory:
	untrack_pfn(NULL, PHYS_PFN(align_start), align_size);
error_radix:
	hmm_devmem_radix_release(devmem->resource);
error:
	return ret;
}

/*
 * hmm_devmem_add() - hotplug ZONE_DEVICE memory for device memory
 *
 * @ops: memory event device driver callback (see struct hmm_devmem_ops)
 * @device: device struct to bind the resource too
 * @size: size in bytes of the device memory to add
 * Returns: pointer to new hmm_devmem struct ERR_PTR otherwise
 *
 * This function first finds an empty range of physical address big enough to
 * contain the new resource, and then hotplugs it as ZONE_DEVICE memory, which
 * in turn allocates struct pages. It does not do anything beyond that; all
 * events affecting the memory will go through the various callbacks provided
 * by hmm_devmem_ops struct.
 *
 * Device driver should call this function during device initialization and
 * is then responsible of memory management. HMM only provides helpers.
 */
struct hmm_devmem *hmm_devmem_add(const struct hmm_devmem_ops *ops,
				  struct device *device,
				  unsigned long size)
{
	struct hmm_devmem *devmem;
	resource_size_t addr;
	int ret;

	dev_pagemap_get_ops();

	devmem = devm_kzalloc(device, sizeof(*devmem), GFP_KERNEL);
	if (!devmem)
		return ERR_PTR(-ENOMEM);

	init_completion(&devmem->completion);
	devmem->pfn_first = -1UL;
	devmem->pfn_last = -1UL;
	devmem->resource = NULL;
	devmem->device = device;
	devmem->ops = ops;

	ret = percpu_ref_init(&devmem->ref, &hmm_devmem_ref_release,
			      0, GFP_KERNEL);
	if (ret)
		return ERR_PTR(ret);

	ret = devm_add_action_or_reset(device, hmm_devmem_ref_exit, &devmem->ref);
	if (ret)
		return ERR_PTR(ret);

	size = ALIGN(size, PA_SECTION_SIZE);
	addr = min((unsigned long)iomem_resource.end,
		   (1UL << MAX_PHYSMEM_BITS) - 1);
	addr = addr - size + 1UL;

	/*
	 * FIXME add a new helper to quickly walk resource tree and find free
	 * range
	 *
	 * FIXME what about ioport_resource resource ?
	 */
	for (; addr > size && addr >= iomem_resource.start; addr -= size) {
		ret = region_intersects(addr, size, 0, IORES_DESC_NONE);
		if (ret != REGION_DISJOINT)
			continue;

		devmem->resource = devm_request_mem_region(device, addr, size,
							   dev_name(device));
		if (!devmem->resource)
			return ERR_PTR(-ENOMEM);
		break;
	}
	if (!devmem->resource)
		return ERR_PTR(-ERANGE);

	devmem->resource->desc = IORES_DESC_DEVICE_PRIVATE_MEMORY;
	devmem->pfn_first = devmem->resource->start >> PAGE_SHIFT;
	devmem->pfn_last = devmem->pfn_first +
			   (resource_size(devmem->resource) >> PAGE_SHIFT);

	ret = hmm_devmem_pages_create(devmem);
	if (ret)
		return ERR_PTR(ret);

	ret = devm_add_action_or_reset(device, hmm_devmem_release, devmem);
	if (ret)
		return ERR_PTR(ret);

	return devmem;
}
EXPORT_SYMBOL_GPL(hmm_devmem_add);

struct hmm_devmem *hmm_devmem_add_resource(const struct hmm_devmem_ops *ops,
					   struct device *device,
					   struct resource *res)
{
	struct hmm_devmem *devmem;
	int ret;

	if (res->desc != IORES_DESC_DEVICE_PUBLIC_MEMORY)
		return ERR_PTR(-EINVAL);

	dev_pagemap_get_ops();

	devmem = devm_kzalloc(device, sizeof(*devmem), GFP_KERNEL);
	if (!devmem)
		return ERR_PTR(-ENOMEM);

	init_completion(&devmem->completion);
	devmem->pfn_first = -1UL;
	devmem->pfn_last = -1UL;
	devmem->resource = res;
	devmem->device = device;
	devmem->ops = ops;

	ret = percpu_ref_init(&devmem->ref, &hmm_devmem_ref_release,
			      0, GFP_KERNEL);
	if (ret)
		return ERR_PTR(ret);

	ret = devm_add_action_or_reset(device, hmm_devmem_ref_exit,
			&devmem->ref);
	if (ret)
		return ERR_PTR(ret);

	devmem->pfn_first = devmem->resource->start >> PAGE_SHIFT;
	devmem->pfn_last = devmem->pfn_first +
			   (resource_size(devmem->resource) >> PAGE_SHIFT);

	ret = hmm_devmem_pages_create(devmem);
	if (ret)
		return ERR_PTR(ret);

	ret = devm_add_action_or_reset(device, hmm_devmem_release, devmem);
	if (ret)
		return ERR_PTR(ret);

	ret = devm_add_action_or_reset(device, hmm_devmem_ref_kill,
			&devmem->ref);
	if (ret)
		return ERR_PTR(ret);

	return devmem;
}
EXPORT_SYMBOL_GPL(hmm_devmem_add_resource);

/*
 * A device driver that wants to handle multiple devices memory through a
 * single fake device can use hmm_device to do so. This is purely a helper
 * and it is not needed to make use of any HMM functionality.
 */
#define HMM_DEVICE_MAX 256

static DECLARE_BITMAP(hmm_device_mask, HMM_DEVICE_MAX);
static DEFINE_SPINLOCK(hmm_device_lock);
static struct class *hmm_device_class;
static dev_t hmm_device_devt;

static void hmm_device_release(struct device *device)
{
	struct hmm_device *hmm_device;

	hmm_device = container_of(device, struct hmm_device, device);
	spin_lock(&hmm_device_lock);
	clear_bit(hmm_device->minor, hmm_device_mask);
	spin_unlock(&hmm_device_lock);

	kfree(hmm_device);
}

struct hmm_device *hmm_device_new(void *drvdata)
{
	struct hmm_device *hmm_device;

	hmm_device = kzalloc(sizeof(*hmm_device), GFP_KERNEL);
	if (!hmm_device)
		return ERR_PTR(-ENOMEM);

	spin_lock(&hmm_device_lock);
	hmm_device->minor = find_first_zero_bit(hmm_device_mask, HMM_DEVICE_MAX);
	if (hmm_device->minor >= HMM_DEVICE_MAX) {
		spin_unlock(&hmm_device_lock);
		kfree(hmm_device);
		return ERR_PTR(-EBUSY);
	}
	set_bit(hmm_device->minor, hmm_device_mask);
	spin_unlock(&hmm_device_lock);

	dev_set_name(&hmm_device->device, "hmm_device%d", hmm_device->minor);
	hmm_device->device.devt = MKDEV(MAJOR(hmm_device_devt),
					hmm_device->minor);
	hmm_device->device.release = hmm_device_release;
	dev_set_drvdata(&hmm_device->device, drvdata);
	hmm_device->device.class = hmm_device_class;
	device_initialize(&hmm_device->device);

	return hmm_device;
}
EXPORT_SYMBOL(hmm_device_new);

void hmm_device_put(struct hmm_device *hmm_device)
{
	put_device(&hmm_device->device);
}
EXPORT_SYMBOL(hmm_device_put);

static int __init hmm_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&hmm_device_devt, 0,
				  HMM_DEVICE_MAX,
				  "hmm_device");
	if (ret)
		return ret;

	hmm_device_class = class_create(THIS_MODULE, "hmm_device");
	if (IS_ERR(hmm_device_class)) {
		unregister_chrdev_region(hmm_device_devt, HMM_DEVICE_MAX);
		return PTR_ERR(hmm_device_class);
	}
	return 0;
}

device_initcall(hmm_init);
#endif /* CONFIG_DEVICE_PRIVATE || CONFIG_DEVICE_PUBLIC */
>>>>>>> master
