// SPDX-License-Identifier: GPL-2.0
/*
 *	linux/mm/mlock.c
 *
 *  (C) Copyright 1995 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 */

#include <linux/capability.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/sched/user.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/pagewalk.h>
#include <linux/mempolicy.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/rmap.h>
#include <linux/mmzone.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/secretmem.h>

#include "internal.h"

struct mlock_fbatch {
	local_lock_t lock;
	struct folio_batch fbatch;
};

static DEFINE_PER_CPU(struct mlock_fbatch, mlock_fbatch) = {
	.lock = INIT_LOCAL_LOCK(lock),
};

bool can_do_mlock(void)
{
	if (rlimit(RLIMIT_MEMLOCK) != 0)
		return true;
	if (capable(CAP_IPC_LOCK))
		return true;
	return false;
}
EXPORT_SYMBOL(can_do_mlock);

/*
 * Mlocked folios are marked with the PG_mlocked flag for efficient testing
 * in vmscan and, possibly, the fault path; and to support semi-accurate
 * statistics.
 *
 * An mlocked folio [folio_test_mlocked(folio)] is unevictable.  As such, it
 * will be ostensibly placed on the LRU "unevictable" list (actually no such
 * list exists), rather than the [in]active lists. PG_unevictable is set to
 * indicate the unevictable state.
 */

static struct lruvec *__mlock_folio(struct folio *folio, struct lruvec *lruvec)
{
	/* There is nothing more we can do while it's off LRU */
	if (!folio_test_clear_lru(folio))
		return lruvec;

	lruvec = folio_lruvec_relock_irq(folio, lruvec);

	if (unlikely(folio_evictable(folio))) {
		/*
		 * This is a little surprising, but quite possible: PG_mlocked
		 * must have got cleared already by another CPU.  Could this
		 * folio be unevictable?  I'm not sure, but move it now if so.
		 */
		if (folio_test_unevictable(folio)) {
			lruvec_del_folio(lruvec, folio);
			folio_clear_unevictable(folio);
			lruvec_add_folio(lruvec, folio);

			__count_vm_events(UNEVICTABLE_PGRESCUED,
					  folio_nr_pages(folio));
		}
		goto out;
	}

	if (folio_test_unevictable(folio)) {
		if (folio_test_mlocked(folio))
			folio->mlock_count++;
		goto out;
	}

	lruvec_del_folio(lruvec, folio);
	folio_clear_active(folio);
	folio_set_unevictable(folio);
	folio->mlock_count = !!folio_test_mlocked(folio);
	lruvec_add_folio(lruvec, folio);
	__count_vm_events(UNEVICTABLE_PGCULLED, folio_nr_pages(folio));
out:
	folio_set_lru(folio);
	return lruvec;
}

static struct lruvec *__mlock_new_folio(struct folio *folio, struct lruvec *lruvec)
{
	VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);

	lruvec = folio_lruvec_relock_irq(folio, lruvec);

	/* As above, this is a little surprising, but possible */
	if (unlikely(folio_evictable(folio)))
		goto out;

	folio_set_unevictable(folio);
	folio->mlock_count = !!folio_test_mlocked(folio);
	__count_vm_events(UNEVICTABLE_PGCULLED, folio_nr_pages(folio));
out:
	lruvec_add_folio(lruvec, folio);
	folio_set_lru(folio);
	return lruvec;
}

static struct lruvec *__munlock_folio(struct folio *folio, struct lruvec *lruvec)
{
	int nr_pages = folio_nr_pages(folio);
	bool isolated = false;

	if (!folio_test_clear_lru(folio))
		goto munlock;

	isolated = true;
	lruvec = folio_lruvec_relock_irq(folio, lruvec);

	if (folio_test_unevictable(folio)) {
		/* Then mlock_count is maintained, but might undercount */
		if (folio->mlock_count)
			folio->mlock_count--;
		if (folio->mlock_count)
			goto out;
	}
	/* else assume that was the last mlock: reclaim will fix it if not */

munlock:
	if (folio_test_clear_mlocked(folio)) {
		__zone_stat_mod_folio(folio, NR_MLOCK, -nr_pages);
		if (isolated || !folio_test_unevictable(folio))
			__count_vm_events(UNEVICTABLE_PGMUNLOCKED, nr_pages);
		else
			__count_vm_events(UNEVICTABLE_PGSTRANDED, nr_pages);
	}

	/* folio_evictable() has to be checked *after* clearing Mlocked */
	if (isolated && folio_test_unevictable(folio) && folio_evictable(folio)) {
		lruvec_del_folio(lruvec, folio);
		folio_clear_unevictable(folio);
		lruvec_add_folio(lruvec, folio);
		__count_vm_events(UNEVICTABLE_PGRESCUED, nr_pages);
	}
out:
	if (isolated)
		folio_set_lru(folio);
	return lruvec;
}

/*
 * Flags held in the low bits of a struct folio pointer on the mlock_fbatch.
 */
#define LRU_FOLIO 0x1
#define NEW_FOLIO 0x2
static inline struct folio *mlock_lru(struct folio *folio)
{
	return (struct folio *)((unsigned long)folio + LRU_FOLIO);
}

static inline struct folio *mlock_new(struct folio *folio)
{
	return (struct folio *)((unsigned long)folio + NEW_FOLIO);
}

/*
 * mlock_folio_batch() is derived from folio_batch_move_lru(): perhaps that can
 * make use of such folio pointer flags in future, but for now just keep it for
 * mlock.  We could use three separate folio batches instead, but one feels
 * better (munlocking a full folio batch does not need to drain mlocking folio
 * batches first).
 */
static void mlock_folio_batch(struct folio_batch *fbatch)
{
	struct lruvec *lruvec = NULL;
	unsigned long mlock;
	struct folio *folio;
	int i;

	for (i = 0; i < folio_batch_count(fbatch); i++) {
		folio = fbatch->folios[i];
		mlock = (unsigned long)folio & (LRU_FOLIO | NEW_FOLIO);
		folio = (struct folio *)((unsigned long)folio - mlock);
		fbatch->folios[i] = folio;

		if (mlock & LRU_FOLIO)
			lruvec = __mlock_folio(folio, lruvec);
		else if (mlock & NEW_FOLIO)
			lruvec = __mlock_new_folio(folio, lruvec);
		else
			lruvec = __munlock_folio(folio, lruvec);
	}

	if (lruvec)
		unlock_page_lruvec_irq(lruvec);
	folios_put(fbatch->folios, folio_batch_count(fbatch));
	folio_batch_reinit(fbatch);
}

void mlock_drain_local(void)
{
	struct folio_batch *fbatch;

	local_lock(&mlock_fbatch.lock);
	fbatch = this_cpu_ptr(&mlock_fbatch.fbatch);
	if (folio_batch_count(fbatch))
		mlock_folio_batch(fbatch);
	local_unlock(&mlock_fbatch.lock);
}

void mlock_drain_remote(int cpu)
{
	struct folio_batch *fbatch;

	WARN_ON_ONCE(cpu_online(cpu));
	fbatch = &per_cpu(mlock_fbatch.fbatch, cpu);
	if (folio_batch_count(fbatch))
		mlock_folio_batch(fbatch);
}

bool need_mlock_drain(int cpu)
{
	return folio_batch_count(&per_cpu(mlock_fbatch.fbatch, cpu));
}

/**
 * mlock_folio - mlock a folio already on (or temporarily off) LRU
 * @folio: folio to be mlocked.
 */
void mlock_folio(struct folio *folio)
{
	struct folio_batch *fbatch;

	local_lock(&mlock_fbatch.lock);
	fbatch = this_cpu_ptr(&mlock_fbatch.fbatch);

	if (!folio_test_set_mlocked(folio)) {
		int nr_pages = folio_nr_pages(folio);

		zone_stat_mod_folio(folio, NR_MLOCK, nr_pages);
		__count_vm_events(UNEVICTABLE_PGMLOCKED, nr_pages);
	}

	folio_get(folio);
	if (!folio_batch_add(fbatch, mlock_lru(folio)) ||
	    folio_test_large(folio) || lru_cache_disabled())
		mlock_folio_batch(fbatch);
	local_unlock(&mlock_fbatch.lock);
}

/**
 * mlock_new_folio - mlock a newly allocated folio not yet on LRU
 * @folio: folio to be mlocked, either normal or a THP head.
 */
void mlock_new_folio(struct folio *folio)
{
	struct folio_batch *fbatch;
	int nr_pages = folio_nr_pages(folio);

	local_lock(&mlock_fbatch.lock);
	fbatch = this_cpu_ptr(&mlock_fbatch.fbatch);
	folio_set_mlocked(folio);

	zone_stat_mod_folio(folio, NR_MLOCK, nr_pages);
	__count_vm_events(UNEVICTABLE_PGMLOCKED, nr_pages);

	folio_get(folio);
	if (!folio_batch_add(fbatch, mlock_new(folio)) ||
	    folio_test_large(folio) || lru_cache_disabled())
		mlock_folio_batch(fbatch);
	local_unlock(&mlock_fbatch.lock);
}

/**
 * munlock_folio - munlock a folio
 * @folio: folio to be munlocked, either normal or a THP head.
 */
void munlock_folio(struct folio *folio)
{
	struct folio_batch *fbatch;

	local_lock(&mlock_fbatch.lock);
	fbatch = this_cpu_ptr(&mlock_fbatch.fbatch);
	/*
	 * folio_test_clear_mlocked(folio) must be left to __munlock_folio(),
	 * which will check whether the folio is multiply mlocked.
	 */
	folio_get(folio);
	if (!folio_batch_add(fbatch, folio) ||
	    folio_test_large(folio) || lru_cache_disabled())
		mlock_folio_batch(fbatch);
	local_unlock(&mlock_fbatch.lock);
}

static int mlock_pte_range(pmd_t *pmd, unsigned long addr,
			   unsigned long end, struct mm_walk *walk)

{
	struct vm_area_struct *vma = walk->vma;
	spinlock_t *ptl;
	pte_t *start_pte, *pte;
	pte_t ptent;
	struct folio *folio;

	ptl = pmd_trans_huge_lock(pmd, vma);
	if (ptl) {
		if (!pmd_present(*pmd))
			goto out;
		if (is_huge_zero_pmd(*pmd))
			goto out;
		folio = page_folio(pmd_page(*pmd));
		if (vma->vm_flags & VM_LOCKED)
			mlock_folio(folio);
		else
			munlock_folio(folio);
		goto out;
	}

	start_pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	if (!start_pte) {
		walk->action = ACTION_AGAIN;
		return 0;
	}
	for (pte = start_pte; addr != end; pte++, addr += PAGE_SIZE) {
		ptent = ptep_get(pte);
		if (!pte_present(ptent))
			continue;
		folio = vm_normal_folio(vma, addr, ptent);
		if (!folio || folio_is_zone_device(folio))
			continue;
		if (folio_test_large(folio))
			continue;
		if (vma->vm_flags & VM_LOCKED)
			mlock_folio(folio);
		else
			munlock_folio(folio);
	}
	pte_unmap(start_pte);
out:
	spin_unlock(ptl);
	cond_resched();
	return 0;
}

/*
 * mlock_vma_pages_range() - mlock any pages already in the range,
 *                           or munlock all pages in the range.
 * @vma - vma containing range to be mlock()ed or munlock()ed
 * @start - start address in @vma of the range
 * @end - end of range in @vma
 * @newflags - the new set of flags for @vma.
 *
 * Called for mlock(), mlock2() and mlockall(), to set @vma VM_LOCKED;
 * called for munlock() and munlockall(), to clear VM_LOCKED from @vma.
 */
static void mlock_vma_pages_range(struct vm_area_struct *vma,
	unsigned long start, unsigned long end, vm_flags_t newflags)
{
	static const struct mm_walk_ops mlock_walk_ops = {
		.pmd_entry = mlock_pte_range,
		.walk_lock = PGWALK_WRLOCK_VERIFY,
	};

	/*
	 * There is a slight chance that concurrent page migration,
	 * or page reclaim finding a page of this now-VM_LOCKED vma,
	 * will call mlock_vma_folio() and raise page's mlock_count:
	 * double counting, leaving the page unevictable indefinitely.
	 * Communicate this danger to mlock_vma_folio() with VM_IO,
	 * which is a VM_SPECIAL flag not allowed on VM_LOCKED vmas.
	 * mmap_lock is held in write mode here, so this weird
	 * combination should not be visible to other mmap_lock users;
	 * but WRITE_ONCE so rmap walkers must see VM_IO if VM_LOCKED.
	 */
	if (newflags & VM_LOCKED)
		newflags |= VM_IO;
	vma_start_write(vma);
	vm_flags_reset_once(vma, newflags);

	lru_add_drain();
	walk_page_range(vma->vm_mm, start, end, &mlock_walk_ops, NULL);
	lru_add_drain();

	if (newflags & VM_IO) {
		newflags &= ~VM_IO;
		vm_flags_reset_once(vma, newflags);
	}
}

/*
 * mlock_fixup  - handle mlock[all]/munlock[all] requests.
 *
 * Filters out "special" vmas -- VM_LOCKED never gets set for these, and
 * munlock is a no-op.  However, for some special vmas, we go ahead and
 * populate the ptes.
 *
 * For vmas that pass the filters, merge/split as appropriate.
 */
static int mlock_fixup(struct vma_iterator *vmi, struct vm_area_struct *vma,
	       struct vm_area_struct **prev, unsigned long start,
	       unsigned long end, vm_flags_t newflags)
{
	struct mm_struct *mm = vma->vm_mm;
	pgoff_t pgoff;
	int nr_pages;
	int ret = 0;
	vm_flags_t oldflags = vma->vm_flags;

	if (newflags == oldflags || (oldflags & VM_SPECIAL) ||
	    is_vm_hugetlb_page(vma) || vma == get_gate_vma(current->mm) ||
	    vma_is_dax(vma) || vma_is_secretmem(vma))
		/* don't set VM_LOCKED or VM_LOCKONFAULT and don't count */
		goto out;

	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
	*prev = vma_merge(vmi, mm, *prev, start, end, newflags,
			vma->anon_vma, vma->vm_file, pgoff, vma_policy(vma),
			vma->vm_userfaultfd_ctx, anon_vma_name(vma));
	if (*prev) {
		vma = *prev;
		goto success;
	}

	if (start != vma->vm_start) {
		ret = split_vma(vmi, vma, start, 1);
		if (ret)
			goto out;
	}

	if (end != vma->vm_end) {
		ret = split_vma(vmi, vma, end, 0);
		if (ret)
			goto out;
	}

success:
	/*
	 * Keep track of amount of locked VM.
	 */
	nr_pages = (end - start) >> PAGE_SHIFT;
	if (!(newflags & VM_LOCKED))
		nr_pages = -nr_pages;
	else if (oldflags & VM_LOCKED)
		nr_pages = 0;
	mm->locked_vm += nr_pages;

	/*
	 * vm_flags is protected by the mmap_lock held in write mode.
	 * It's okay if try_to_unmap_one unmaps a page just after we
	 * set VM_LOCKED, populate_vma_page_range will bring it back.
	 */
	if ((newflags & VM_LOCKED) && (oldflags & VM_LOCKED)) {
		/* No work to do, and mlocking twice would be wrong */
		vma_start_write(vma);
		vm_flags_reset(vma, newflags);
	} else {
		mlock_vma_pages_range(vma, start, end, newflags);
	}
out:
	*prev = vma;
	return ret;
}

static int apply_vma_lock_flags(unsigned long start, size_t len,
				vm_flags_t flags)
{
	unsigned long nstart, end, tmp;
	struct vm_area_struct *vma, *prev;
	VMA_ITERATOR(vmi, current->mm, start);

	VM_BUG_ON(offset_in_page(start));
	VM_BUG_ON(len != PAGE_ALIGN(len));
	end = start + len;
	if (end < start)
		return -EINVAL;
	if (end == start)
		return 0;
	vma = vma_iter_load(&vmi);
	if (!vma)
		return -ENOMEM;

	prev = vma_prev(&vmi);
	if (start > vma->vm_start)
		prev = vma;

	nstart = start;
	tmp = vma->vm_start;
	for_each_vma_range(vmi, vma, end) {
		int error;
		vm_flags_t newflags;

		if (vma->vm_start != tmp)
			return -ENOMEM;

		newflags = vma->vm_flags & ~VM_LOCKED_MASK;
		newflags |= flags;
		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */
		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mlock_fixup(&vmi, vma, &prev, nstart, tmp, newflags);
		if (error)
			return error;
		tmp = vma_iter_end(&vmi);
		nstart = tmp;
	}

	if (tmp < end)
		return -ENOMEM;

	return 0;
}

/*
 * Go through vma areas and sum size of mlocked
 * vma pages, as return value.
 * Note deferred memory locking case(mlock2(,,MLOCK_ONFAULT)
 * is also counted.
 * Return value: previously mlocked page counts
 */
static unsigned long count_mm_mlocked_page_nr(struct mm_struct *mm,
		unsigned long start, size_t len)
{
	struct vm_area_struct *vma;
	unsigned long count = 0;
	unsigned long end;
	VMA_ITERATOR(vmi, mm, start);

	/* Don't overflow past ULONG_MAX */
	if (unlikely(ULONG_MAX - len < start))
		end = ULONG_MAX;
	else
		end = start + len;

	for_each_vma_range(vmi, vma, end) {
		if (vma->vm_flags & VM_LOCKED) {
			if (start > vma->vm_start)
				count -= (start - vma->vm_start);
			if (end < vma->vm_end) {
				count += end - vma->vm_start;
				break;
			}
			count += vma->vm_end - vma->vm_start;
		}
	}

	return count >> PAGE_SHIFT;
}

/*
 * convert get_user_pages() return value to posix mlock() error
 */
static int __mlock_posix_error_return(long retval)
{
	if (retval == -EFAULT)
		retval = -ENOMEM;
	else if (retval == -ENOMEM)
		retval = -EAGAIN;
	return retval;
}

<<<<<<< HEAD
=======
/*
 * Prepare page for fast batched LRU putback via putback_lru_evictable_pagevec()
 *
 * The fast path is available only for evictable pages with single mapping.
 * Then we can bypass the per-cpu pvec and get better performance.
 * when mapcount > 1 we need try_to_munlock() which can fail.
 * when !page_evictable(), we need the full redo logic of putback_lru_page to
 * avoid leaving evictable page in unevictable list.
 *
 * In case of success, @page is added to @pvec and @pgrescued is incremented
 * in case that the page was previously unevictable. @page is also unlocked.
 */
static bool __putback_lru_fast_prepare(struct page *page, struct pagevec *pvec,
		int *pgrescued)
{
	VM_BUG_ON_PAGE(PageLRU(page), page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (page_mapcount(page) <= 1 && page_evictable(page)) {
		pagevec_add(pvec, page);
		if (TestClearPageUnevictable(page))
			(*pgrescued)++;
		unlock_page(page);
		return true;
	}

	return false;
}

/*
 * Putback multiple evictable pages to the LRU
 *
 * Batched putback of evictable pages that bypasses the per-cpu pvec. Some of
 * the pages might have meanwhile become unevictable but that is OK.
 */
static void __putback_lru_fast(struct pagevec *pvec, int pgrescued)
{
	count_vm_events(UNEVICTABLE_PGMUNLOCKED, pagevec_count(pvec));
	/*
	 *__pagevec_lru_add() calls release_pages() so we don't call
	 * put_page() explicitly
	 */
	__pagevec_lru_add(pvec);
	count_vm_events(UNEVICTABLE_PGRESCUED, pgrescued);
}

/*
 * Munlock a batch of pages from the same zone
 *
 * The work is split to two main phases. First phase clears the Mlocked flag
 * and attempts to isolate the pages, all under a single zone lru lock.
 * The second phase finishes the munlock only for pages where isolation
 * succeeded.
 *
 * Note that the pagevec may be modified during the process.
 */
static void __munlock_pagevec(struct pagevec *pvec, struct zone *zone)
{
	int i;
	int nr = pagevec_count(pvec);
	int delta_munlocked = -nr;
	struct pagevec pvec_putback;
	int pgrescued = 0;

	pagevec_init(&pvec_putback);

	/* Phase 1: page isolation */
	spin_lock_irq(zone_lru_lock(zone));
	for (i = 0; i < nr; i++) {
		struct page *page = pvec->pages[i];

		if (TestClearPageMlocked(page)) {
			/*
			 * We already have pin from follow_page_mask()
			 * so we can spare the get_page() here.
			 */
			if (__munlock_isolate_lru_page(page, false))
				continue;
			else
				__munlock_isolation_failed(page);
		} else {
			delta_munlocked++;
		}

		/*
		 * We won't be munlocking this page in the next phase
		 * but we still need to release the follow_page_mask()
		 * pin. We cannot do it under lru_lock however. If it's
		 * the last pin, __page_cache_release() would deadlock.
		 */
		pagevec_add(&pvec_putback, pvec->pages[i]);
		pvec->pages[i] = NULL;
	}
	__mod_zone_page_state(zone, NR_MLOCK, delta_munlocked);
	spin_unlock_irq(zone_lru_lock(zone));

	/* Now we can release pins of pages that we are not munlocking */
	pagevec_release(&pvec_putback);

	/* Phase 2: page munlock */
	for (i = 0; i < nr; i++) {
		struct page *page = pvec->pages[i];

		if (page) {
			lock_page(page);
			if (!__putback_lru_fast_prepare(page, &pvec_putback,
					&pgrescued)) {
				/*
				 * Slow path. We don't want to lose the last
				 * pin before unlock_page()
				 */
				get_page(page); /* for putback_lru_page() */
				__munlock_isolated_page(page);
				unlock_page(page);
				put_page(page); /* from follow_page_mask() */
			}
		}
	}

	/*
	 * Phase 3: page putback for pages that qualified for the fast path
	 * This will also call put_page() to return pin from follow_page_mask()
	 */
	if (pagevec_count(&pvec_putback))
		__putback_lru_fast(&pvec_putback, pgrescued);
}

/*
 * Fill up pagevec for __munlock_pagevec using pte walk
 *
 * The function expects that the struct page corresponding to @start address is
 * a non-TPH page already pinned and in the @pvec, and that it belongs to @zone.
 *
 * The rest of @pvec is filled by subsequent pages within the same pmd and same
 * zone, as long as the pte's are present and vm_normal_page() succeeds. These
 * pages also get pinned.
 *
 * Returns the address of the next page that should be scanned. This equals
 * @start + PAGE_SIZE when no page could be added by the pte walk.
 */
static unsigned long __munlock_pagevec_fill(struct pagevec *pvec,
			struct vm_area_struct *vma, struct zone *zone,
			unsigned long start, unsigned long end)
{
	pte_t *pte;
	spinlock_t *ptl;

	/*
	 * Initialize pte walk starting at the already pinned page where we
	 * are sure that there is a pte, as it was pinned under the same
	 * mmap_sem write op.
	 */
	pte = get_locked_pte(vma->vm_mm, start,	&ptl);
	/* Make sure we do not cross the page table boundary */
	end = pgd_addr_end(start, end);
	end = p4d_addr_end(start, end);
	end = pud_addr_end(start, end);
	end = pmd_addr_end(start, end);

	/* The page next to the pinned page is the first we will try to get */
	start += PAGE_SIZE;
	while (start < end) {
		struct page *page = NULL;
		pte++;
		if (pte_present(*pte))
			page = vm_normal_page(vma, start, *pte);
		/*
		 * Break if page could not be obtained or the page's node+zone does not
		 * match
		 */
		if (!page || page_zone(page) != zone)
			break;

		/*
		 * Do not use pagevec for PTE-mapped THP,
		 * munlock_vma_pages_range() will handle them.
		 */
		if (PageTransCompound(page))
			break;

		get_page(page);
		/*
		 * Increase the address that will be returned *before* the
		 * eventual break due to pvec becoming full by adding the page
		 */
		start += PAGE_SIZE;
		if (pagevec_add(pvec, page) == 0)
			break;
	}
	pte_unmap_unlock(pte, ptl);
	return start;
}

/*
 * munlock_vma_pages_range() - munlock all pages in the vma range.'
 * @vma - vma containing range to be munlock()ed.
 * @start - start address in @vma of the range
 * @end - end of range in @vma.
 *
 *  For mremap(), munmap() and exit().
 *
 * Called with @vma VM_LOCKED.
 *
 * Returns with VM_LOCKED cleared.  Callers must be prepared to
 * deal with this.
 *
 * We don't save and restore VM_LOCKED here because pages are
 * still on lru.  In unmap path, pages might be scanned by reclaim
 * and re-mlocked by try_to_{munlock|unmap} before we unmap and
 * free them.  This will result in freeing mlocked pages.
 */
void munlock_vma_pages_range(struct vm_area_struct *vma,
			     unsigned long start, unsigned long end)
{
	vma->vm_flags &= VM_LOCKED_CLEAR_MASK;

	while (start < end) {
		struct page *page;
		unsigned int page_mask = 0;
		unsigned long page_increm;
		struct pagevec pvec;
		struct zone *zone;

		pagevec_init(&pvec);
		/*
		 * Although FOLL_DUMP is intended for get_dump_page(),
		 * it just so happens that its special treatment of the
		 * ZERO_PAGE (returning an error instead of doing get_page)
		 * suits munlock very well (and if somehow an abnormal page
		 * has sneaked into the range, we won't oops here: great).
		 */
		page = follow_page(vma, start, FOLL_GET | FOLL_DUMP);

		if (page && !IS_ERR(page)) {
			if (PageTransTail(page)) {
				VM_BUG_ON_PAGE(PageMlocked(page), page);
				put_page(page); /* follow_page_mask() */
			} else if (PageTransHuge(page)) {
				lock_page(page);
				/*
				 * Any THP page found by follow_page_mask() may
				 * have gotten split before reaching
				 * munlock_vma_page(), so we need to compute
				 * the page_mask here instead.
				 */
				page_mask = munlock_vma_page(page);
				unlock_page(page);
				put_page(page); /* follow_page_mask() */
			} else {
				/*
				 * Non-huge pages are handled in batches via
				 * pagevec. The pin from follow_page_mask()
				 * prevents them from collapsing by THP.
				 */
				pagevec_add(&pvec, page);
				zone = page_zone(page);

				/*
				 * Try to fill the rest of pagevec using fast
				 * pte walk. This will also update start to
				 * the next page to process. Then munlock the
				 * pagevec.
				 */
				start = __munlock_pagevec_fill(&pvec, vma,
						zone, start, end);
				__munlock_pagevec(&pvec, zone);
				goto next;
			}
		}
		page_increm = 1 + page_mask;
		start += page_increm * PAGE_SIZE;
next:
		cond_resched();
	}
}

/*
 * mlock_fixup  - handle mlock[all]/munlock[all] requests.
 *
 * Filters out "special" vmas -- VM_LOCKED never gets set for these, and
 * munlock is a no-op.  However, for some special vmas, we go ahead and
 * populate the ptes.
 *
 * For vmas that pass the filters, merge/split as appropriate.
 */
static int mlock_fixup(struct vm_area_struct *vma, struct vm_area_struct **prev,
	unsigned long start, unsigned long end, vm_flags_t newflags)
{
	struct mm_struct *mm = vma->vm_mm;
	pgoff_t pgoff;
	int nr_pages;
	int ret = 0;
	int lock = !!(newflags & VM_LOCKED);
	vm_flags_t old_flags = vma->vm_flags;

	if (newflags == vma->vm_flags || (vma->vm_flags & VM_SPECIAL) ||
	    is_vm_hugetlb_page(vma) || vma == get_gate_vma(current->mm) ||
	    vma_is_dax(vma))
		/* don't set VM_LOCKED or VM_LOCKONFAULT and don't count */
		goto out;

	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
	*prev = vma_merge(mm, *prev, start, end, newflags, vma->anon_vma,
			  vma->vm_file, pgoff, vma_policy(vma),
			  vma->vm_userfaultfd_ctx);
	if (*prev) {
		vma = *prev;
		goto success;
	}

	if (start != vma->vm_start) {
		ret = split_vma(mm, vma, start, 1);
		if (ret)
			goto out;
	}

	if (end != vma->vm_end) {
		ret = split_vma(mm, vma, end, 0);
		if (ret)
			goto out;
	}

success:
	/*
	 * Keep track of amount of locked VM.
	 */
	nr_pages = (end - start) >> PAGE_SHIFT;
	if (!lock)
		nr_pages = -nr_pages;
	else if (old_flags & VM_LOCKED)
		nr_pages = 0;
	mm->locked_vm += nr_pages;

	/*
	 * vm_flags is protected by the mmap_sem held in write mode.
	 * It's okay if try_to_unmap_one unmaps a page just after we
	 * set VM_LOCKED, populate_vma_page_range will bring it back.
	 */

	if (lock)
		vma->vm_flags = newflags;
	else
		munlock_vma_pages_range(vma, start, end);

out:
	*prev = vma;
	return ret;
}

static int apply_vma_lock_flags(unsigned long start, size_t len,
				vm_flags_t flags)
{
	unsigned long nstart, end, tmp;
	struct vm_area_struct * vma, * prev;
	int error;

	VM_BUG_ON(offset_in_page(start));
	VM_BUG_ON(len != PAGE_ALIGN(len));
	end = start + len;
	if (end < start)
		return -EINVAL;
	if (end == start)
		return 0;
	vma = find_vma(current->mm, start);
	if (!vma || vma->vm_start > start)
		return -ENOMEM;

	prev = vma->vm_prev;
	if (start > vma->vm_start)
		prev = vma;

	for (nstart = start ; ; ) {
		vm_flags_t newflags = vma->vm_flags & VM_LOCKED_CLEAR_MASK;

		newflags |= flags;

		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */
		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mlock_fixup(vma, &prev, nstart, tmp, newflags);
		if (error)
			break;
		nstart = tmp;
		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end)
			break;

		vma = prev->vm_next;
		if (!vma || vma->vm_start != nstart) {
			error = -ENOMEM;
			break;
		}
	}
	return error;
}

/*
 * Go through vma areas and sum size of mlocked
 * vma pages, as return value.
 * Note deferred memory locking case(mlock2(,,MLOCK_ONFAULT)
 * is also counted.
 * Return value: previously mlocked page counts
 */
static unsigned long count_mm_mlocked_page_nr(struct mm_struct *mm,
		unsigned long start, size_t len)
{
	struct vm_area_struct *vma;
	unsigned long count = 0;

	if (mm == NULL)
		mm = current->mm;

	vma = find_vma(mm, start);
	if (vma == NULL)
		vma = mm->mmap;

	for (; vma ; vma = vma->vm_next) {
		if (start >= vma->vm_end)
			continue;
		if (start + len <=  vma->vm_start)
			break;
		if (vma->vm_flags & VM_LOCKED) {
			if (start > vma->vm_start)
				count -= (start - vma->vm_start);
			if (start + len < vma->vm_end) {
				count += start + len - vma->vm_start;
				break;
			}
			count += vma->vm_end - vma->vm_start;
		}
	}

	return count >> PAGE_SHIFT;
}

>>>>>>> master
static __must_check int do_mlock(unsigned long start, size_t len, vm_flags_t flags)
{
	unsigned long locked;
	unsigned long lock_limit;
	int error = -ENOMEM;

	start = untagged_addr(start);

	if (!can_do_mlock())
		return -EPERM;

	len = PAGE_ALIGN(len + (offset_in_page(start)));
	start &= PAGE_MASK;

	lock_limit = rlimit(RLIMIT_MEMLOCK);
	lock_limit >>= PAGE_SHIFT;
	locked = len >> PAGE_SHIFT;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;

	locked += current->mm->locked_vm;
	if ((locked > lock_limit) && (!capable(CAP_IPC_LOCK))) {
		/*
		 * It is possible that the regions requested intersect with
		 * previously mlocked areas, that part area in "mm->locked_vm"
		 * should not be counted to new mlock increment count. So check
		 * and adjust locked count if necessary.
		 */
		locked -= count_mm_mlocked_page_nr(current->mm,
				start, len);
	}

	/* check against resource limits */
	if ((locked <= lock_limit) || capable(CAP_IPC_LOCK))
		error = apply_vma_lock_flags(start, len, flags);

	mmap_write_unlock(current->mm);
	if (error)
		return error;

	error = __mm_populate(start, len, 0);
	if (error)
		return __mlock_posix_error_return(error);
	return 0;
}

SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
{
	return do_mlock(start, len, VM_LOCKED);
}

SYSCALL_DEFINE3(mlock2, unsigned long, start, size_t, len, int, flags)
{
	vm_flags_t vm_flags = VM_LOCKED;

	if (flags & ~MLOCK_ONFAULT)
		return -EINVAL;

	if (flags & MLOCK_ONFAULT)
		vm_flags |= VM_LOCKONFAULT;

	return do_mlock(start, len, vm_flags);
}

SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len)
{
	int ret;

	start = untagged_addr(start);

	len = PAGE_ALIGN(len + (offset_in_page(start)));
	start &= PAGE_MASK;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;
	ret = apply_vma_lock_flags(start, len, 0);
	mmap_write_unlock(current->mm);

	return ret;
}

/*
 * Take the MCL_* flags passed into mlockall (or 0 if called from munlockall)
 * and translate into the appropriate modifications to mm->def_flags and/or the
 * flags for all current VMAs.
 *
 * There are a couple of subtleties with this.  If mlockall() is called multiple
 * times with different flags, the values do not necessarily stack.  If mlockall
 * is called once including the MCL_FUTURE flag and then a second time without
 * it, VM_LOCKED and VM_LOCKONFAULT will be cleared from mm->def_flags.
 */
static int apply_mlockall_flags(int flags)
{
	VMA_ITERATOR(vmi, current->mm, 0);
	struct vm_area_struct *vma, *prev = NULL;
	vm_flags_t to_add = 0;

	current->mm->def_flags &= ~VM_LOCKED_MASK;
	if (flags & MCL_FUTURE) {
		current->mm->def_flags |= VM_LOCKED;

		if (flags & MCL_ONFAULT)
			current->mm->def_flags |= VM_LOCKONFAULT;

		if (!(flags & MCL_CURRENT))
			goto out;
	}

	if (flags & MCL_CURRENT) {
		to_add |= VM_LOCKED;
		if (flags & MCL_ONFAULT)
			to_add |= VM_LOCKONFAULT;
	}

	for_each_vma(vmi, vma) {
		vm_flags_t newflags;

		newflags = vma->vm_flags & ~VM_LOCKED_MASK;
		newflags |= to_add;

		/* Ignore errors */
		mlock_fixup(&vmi, vma, &prev, vma->vm_start, vma->vm_end,
			    newflags);
		cond_resched();
	}
out:
	return 0;
}

SYSCALL_DEFINE1(mlockall, int, flags)
{
	unsigned long lock_limit;
	int ret;

	if (!flags || (flags & ~(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) ||
	    flags == MCL_ONFAULT)
		return -EINVAL;

	if (!can_do_mlock())
		return -EPERM;

	lock_limit = rlimit(RLIMIT_MEMLOCK);
	lock_limit >>= PAGE_SHIFT;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;

	ret = -ENOMEM;
	if (!(flags & MCL_CURRENT) || (current->mm->total_vm <= lock_limit) ||
	    capable(CAP_IPC_LOCK))
		ret = apply_mlockall_flags(flags);
	mmap_write_unlock(current->mm);
	if (!ret && (flags & MCL_CURRENT))
		mm_populate(0, TASK_SIZE);

	return ret;
}

SYSCALL_DEFINE0(munlockall)
{
	int ret;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;
	ret = apply_mlockall_flags(0);
	mmap_write_unlock(current->mm);
	return ret;
}

/*
 * Objects with different lifetime than processes (SHM_LOCK and SHM_HUGETLB
 * shm segments) get accounted against the user_struct instead.
 */
static DEFINE_SPINLOCK(shmlock_user_lock);

int user_shm_lock(size_t size, struct ucounts *ucounts)
{
	unsigned long lock_limit, locked;
	long memlock;
	int allowed = 0;

	locked = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	lock_limit = rlimit(RLIMIT_MEMLOCK);
	if (lock_limit != RLIM_INFINITY)
		lock_limit >>= PAGE_SHIFT;
	spin_lock(&shmlock_user_lock);
	memlock = inc_rlimit_ucounts(ucounts, UCOUNT_RLIMIT_MEMLOCK, locked);

	if ((memlock == LONG_MAX || memlock > lock_limit) && !capable(CAP_IPC_LOCK)) {
		dec_rlimit_ucounts(ucounts, UCOUNT_RLIMIT_MEMLOCK, locked);
		goto out;
	}
	if (!get_ucounts(ucounts)) {
		dec_rlimit_ucounts(ucounts, UCOUNT_RLIMIT_MEMLOCK, locked);
		allowed = 0;
		goto out;
	}
	allowed = 1;
out:
	spin_unlock(&shmlock_user_lock);
	return allowed;
}

void user_shm_unlock(size_t size, struct ucounts *ucounts)
{
	spin_lock(&shmlock_user_lock);
	dec_rlimit_ucounts(ucounts, UCOUNT_RLIMIT_MEMLOCK, (size + PAGE_SIZE - 1) >> PAGE_SHIFT);
	spin_unlock(&shmlock_user_lock);
	put_ucounts(ucounts);
}
