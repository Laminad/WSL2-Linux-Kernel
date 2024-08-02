// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/page_reporting.h>
#include <linux/gfp.h>
#include <linux/export.h>
<<<<<<< HEAD
#include <linux/module.h>
=======
>>>>>>> master
#include <linux/delay.h>
#include <linux/scatterlist.h>

#include "page_reporting.h"
#include "internal.h"

<<<<<<< HEAD
/* Initialize to an unsupported value */
unsigned int page_reporting_order = -1;

static int page_order_update_notify(const char *val, const struct kernel_param *kp)
{
	/*
	 * If param is set beyond this limit, order is set to default
	 * pageblock_order value
	 */
	return  param_set_uint_minmax(val, kp, 0, MAX_ORDER);
}

static const struct kernel_param_ops page_reporting_param_ops = {
	.set = &page_order_update_notify,
	/*
	 * For the get op, use param_get_int instead of param_get_uint.
	 * This is to make sure that when unset the initialized value of
	 * -1 is shown correctly
	 */
	.get = &param_get_int,
};

module_param_cb(page_reporting_order, &page_reporting_param_ops,
			&page_reporting_order, 0644);
MODULE_PARM_DESC(page_reporting_order, "Set page reporting order");

/*
 * This symbol is also a kernel parameter. Export the page_reporting_order
 * symbol so that other drivers can access it to control order values without
 * having to introduce another configurable parameter. Only one driver can
 * register with the page_reporting driver for the service, so we have just
 * one control parameter for the use case(which can be accessed in both
 * drivers)
 */
EXPORT_SYMBOL_GPL(page_reporting_order);

#define PAGE_REPORTING_DELAY	(2 * HZ)
static struct page_reporting_dev_info __rcu *pr_dev_info __read_mostly;

enum {
	PAGE_REPORTING_IDLE = 0,
	PAGE_REPORTING_REQUESTED,
	PAGE_REPORTING_ACTIVE
};

/* request page reporting */
static void
__page_reporting_request(struct page_reporting_dev_info *prdev)
{
	unsigned int state;

	/* Check to see if we are in desired state */
	state = atomic_read(&prdev->state);
	if (state == PAGE_REPORTING_REQUESTED)
		return;

	/*
	 * If reporting is already active there is nothing we need to do.
	 * Test against 0 as that represents PAGE_REPORTING_IDLE.
	 */
	state = atomic_xchg(&prdev->state, PAGE_REPORTING_REQUESTED);
	if (state != PAGE_REPORTING_IDLE)
		return;

	/*
	 * Delay the start of work to allow a sizable queue to build. For
	 * now we are limiting this to running no more than once every
	 * couple of seconds.
	 */
	schedule_delayed_work(&prdev->work, PAGE_REPORTING_DELAY);
}

/* notify prdev of free page reporting request */
void __page_reporting_notify(void)
{
	struct page_reporting_dev_info *prdev;

	/*
	 * We use RCU to protect the pr_dev_info pointer. In almost all
	 * cases this should be present, however in the unlikely case of
	 * a shutdown this will be NULL and we should exit.
	 */
	rcu_read_lock();
	prdev = rcu_dereference(pr_dev_info);
	if (likely(prdev))
		__page_reporting_request(prdev);

	rcu_read_unlock();
}

static void
page_reporting_drain(struct page_reporting_dev_info *prdev,
		     struct scatterlist *sgl, unsigned int nents, bool reported)
{
	struct scatterlist *sg = sgl;
=======
static struct page_reporting_dev_info __rcu *ph_dev_info __read_mostly;
struct list_head **reported_boundary __read_mostly;

#define for_each_reporting_migratetype_order(_order, _type) \
	for (_order = MAX_ORDER; _order-- != PAGE_REPORTING_MIN_ORDER;) \
		for (_type = MIGRATE_TYPES; _type--;) \
			if (!is_migrate_isolate(_type))

static void page_reporting_populate_metadata(struct zone *zone)
{
	size_t size;
	int node;

	/*
	 * We need to make sure we have somewhere to store the tracking
	 * data for how many reported pages are in the zone. To do that
	 * we need to make certain zone->reported_pages is populated.
	 */
	if (zone->reported_pages)
		return;

	node = zone_to_nid(zone);
	size = (MAX_ORDER - PAGE_REPORTING_MIN_ORDER) * sizeof(unsigned long);
	zone->reported_pages = kzalloc_node(size, GFP_KERNEL, node);
}

static void page_reporting_reset_all_boundaries(struct zone *zone)
{
	unsigned int order, mt;

	/* Update boundary data to reflect the zone we are currently working */
	for_each_reporting_migratetype_order(order, mt)
		page_reporting_reset_boundary(zone, order, mt);
}

static struct page *
get_unreported_page(struct zone *zone, unsigned int order, int mt)
{
	struct list_head *list = &zone->free_area[order].free_list[mt];
	struct list_head *tail = get_unreported_tail(zone, order, mt);
	unsigned long index = get_reporting_index(order, mt);
	struct page *page;

	/* Find a page of the appropriate size in the preferred list */
	page = list_last_entry(tail, struct page, lru);
	list_for_each_entry_from_reverse(page, list, lru) {
		/* If we entered this loop then the "raw" list isn't empty */

		/*
		 * We are going to skip over the reported pages. Make
		 * certain that the index of those pages are correct
		 * as we will later be moving the boundary into place
		 * above them.
		 */
		if (PageReported(page)) {
			page->index = index;
			tail = &page->lru;
			continue;
		}

		/* Drop reference to page if isolate fails */
		if (__isolate_free_page(page, order))
			goto out;

		break;
	}

	page = NULL;
out:
	/* Update the boundary */
	reported_boundary[index] = tail;

	return page;
}

static void
__page_reporting_cancel(struct zone *zone,
			struct page_reporting_dev_info *phdev)
{
	/* processing of the zone is complete, we can disable boundaries */
	page_reporting_disable_boundaries(zone);

	/*
	 * If there are no longer enough free pages to fully populate
	 * the scatterlist, then we can just shut it down for this zone.
	 */
	__clear_bit(ZONE_PAGE_REPORTING_REQUESTED, &zone->flags);
	atomic_dec(&phdev->refcnt);
}

static unsigned int
page_reporting_fill(struct zone *zone, struct page_reporting_dev_info *phdev)
{
	struct scatterlist *sg = phdev->sg;
	unsigned int order, mt, count = 0;

	sg_init_table(phdev->sg, phdev->capacity);

	/* Make sure the boundaries are enabled */
	if (!__test_and_set_bit(ZONE_PAGE_REPORTING_ACTIVE, &zone->flags))
		page_reporting_reset_all_boundaries(zone);

	for_each_reporting_migratetype_order(order, mt) {
		struct page *page;

		/*
		 * Pull pages from free list until we have drained
		 * it or we have reached capacity.
		 */
		while ((page = get_unreported_page(zone, order, mt))) {
			sg_set_page(&sg[count], page, PAGE_SIZE << order, 0);

			if (++count == phdev->capacity)
				return phdev->capacity;
		}
	}

	/* mark end of scatterlist due to underflow */
	if (count)
		sg_mark_end(&sg[count - 1]);

	/* We ran out of pages so we can stop now */
	__page_reporting_cancel(zone, phdev);

	return count;
}

static void page_reporting_drain(struct page_reporting_dev_info *phdev)
{
	struct scatterlist *sg = phdev->sg;
>>>>>>> master

	/*
	 * Drain the now reported pages back into their respective
	 * free lists/areas. We assume at least one page is populated.
	 */
	do {
<<<<<<< HEAD
		struct page *page = sg_page(sg);
		int mt = get_pageblock_migratetype(page);
		unsigned int order = get_order(sg->length);

		__putback_isolated_page(page, order, mt);

		/* If the pages were not reported due to error skip flagging */
		if (!reported)
			continue;

		/*
		 * If page was not comingled with another page we can
		 * consider the result to be "reported" since the page
		 * hasn't been modified, otherwise we will need to
		 * report on the new larger page when we make our way
		 * up to that higher order.
		 */
		if (PageBuddy(page) && buddy_order(page) == order)
			__SetPageReported(page);
	} while ((sg = sg_next(sg)));

	/* reinitialize scatterlist now that it is empty */
	sg_init_table(sgl, nents);
=======
		free_reported_page(sg_page(sg), get_order(sg->length));
	} while (!sg_is_last(sg++));
>>>>>>> master
}

/*
 * The page reporting cycle consists of 4 stages, fill, report, drain, and
<<<<<<< HEAD
 * idle. We will cycle through the first 3 stages until we cannot obtain a
 * full scatterlist of pages, in that case we will switch to idle.
 */
static int
page_reporting_cycle(struct page_reporting_dev_info *prdev, struct zone *zone,
		     unsigned int order, unsigned int mt,
		     struct scatterlist *sgl, unsigned int *offset)
{
	struct free_area *area = &zone->free_area[order];
	struct list_head *list = &area->free_list[mt];
	unsigned int page_len = PAGE_SIZE << order;
	struct page *page, *next;
	long budget;
	int err = 0;

	/*
	 * Perform early check, if free area is empty there is
	 * nothing to process so we can skip this free_list.
	 */
	if (list_empty(list))
		return err;

	spin_lock_irq(&zone->lock);

	/*
	 * Limit how many calls we will be making to the page reporting
	 * device for this list. By doing this we avoid processing any
	 * given list for too long.
	 *
	 * The current value used allows us enough calls to process over a
	 * sixteenth of the current list plus one additional call to handle
	 * any pages that may have already been present from the previous
	 * list processed. This should result in us reporting all pages on
	 * an idle system in about 30 seconds.
	 *
	 * The division here should be cheap since PAGE_REPORTING_CAPACITY
	 * should always be a power of 2.
	 */
	budget = DIV_ROUND_UP(area->nr_free, PAGE_REPORTING_CAPACITY * 16);

	/* loop through free list adding unreported pages to sg list */
	list_for_each_entry_safe(page, next, list, lru) {
		/* We are going to skip over the reported pages. */
		if (PageReported(page))
			continue;

		/*
		 * If we fully consumed our budget then update our
		 * state to indicate that we are requesting additional
		 * processing and exit this list.
		 */
		if (budget < 0) {
			atomic_set(&prdev->state, PAGE_REPORTING_REQUESTED);
			next = page;
			break;
		}

		/* Attempt to pull page from list and place in scatterlist */
		if (*offset) {
			if (!__isolate_free_page(page, order)) {
				next = page;
				break;
			}

			/* Add page to scatter list */
			--(*offset);
			sg_set_page(&sgl[*offset], page, page_len, 0);

			continue;
		}

		/*
		 * Make the first non-reported page in the free list
		 * the new head of the free list before we release the
		 * zone lock.
		 */
		if (!list_is_first(&page->lru, list))
			list_rotate_to_front(&page->lru, list);

		/* release lock before waiting on report processing */
		spin_unlock_irq(&zone->lock);

		/* begin processing pages in local list */
		err = prdev->report(prdev, sgl, PAGE_REPORTING_CAPACITY);

		/* reset offset since the full list was reported */
		*offset = PAGE_REPORTING_CAPACITY;

		/* update budget to reflect call to report function */
		budget--;

		/* reacquire zone lock and resume processing */
		spin_lock_irq(&zone->lock);

		/* flush reported pages from the sg list */
		page_reporting_drain(prdev, sgl, PAGE_REPORTING_CAPACITY, !err);

		/*
		 * Reset next to first entry, the old next isn't valid
		 * since we dropped the lock to report the pages
		 */
		next = list_first_entry(list, struct page, lru);

		/* exit on error */
		if (err)
			break;
	}

	/* Rotate any leftover pages to the head of the freelist */
	if (!list_entry_is_head(next, list, lru) && !list_is_first(&next->lru, list))
		list_rotate_to_front(&next->lru, list);

	spin_unlock_irq(&zone->lock);

	return err;
}

static int
page_reporting_process_zone(struct page_reporting_dev_info *prdev,
			    struct scatterlist *sgl, struct zone *zone)
{
	unsigned int order, mt, leftover, offset = PAGE_REPORTING_CAPACITY;
	unsigned long watermark;
	int err = 0;

	/* Generate minimum watermark to be able to guarantee progress */
	watermark = low_wmark_pages(zone) +
		    (PAGE_REPORTING_CAPACITY << page_reporting_order);

	/*
	 * Cancel request if insufficient free memory or if we failed
	 * to allocate page reporting statistics for the zone.
	 */
	if (!zone_watermark_ok(zone, 0, watermark, 0, ALLOC_CMA))
		return err;

	/* Process each free list starting from lowest order/mt */
	for (order = page_reporting_order; order < NR_PAGE_ORDERS; order++) {
		for (mt = 0; mt < MIGRATE_TYPES; mt++) {
			/* We do not pull pages from the isolate free list */
			if (is_migrate_isolate(mt))
				continue;

			err = page_reporting_cycle(prdev, zone, order, mt,
						   sgl, &offset);
			if (err)
				return err;
		}
	}

	/* report the leftover pages before going idle */
	leftover = PAGE_REPORTING_CAPACITY - offset;
	if (leftover) {
		sgl = &sgl[offset];
		err = prdev->report(prdev, sgl, leftover);

		/* flush any remaining pages out from the last report */
		spin_lock_irq(&zone->lock);
		page_reporting_drain(prdev, sgl, leftover, !err);
		spin_unlock_irq(&zone->lock);
	}

	return err;
=======
 * idle. We will cycle through the first 3 stages until we fail to obtain any
 * pages, in that case we will switch to idle.
 */
static void
page_reporting_cycle(struct zone *zone, struct page_reporting_dev_info *phdev)
{
	/*
	 * Guarantee boundaries and stats are populated before we
	 * start placing reported pages in the zone.
	 */
	page_reporting_populate_metadata(zone);

	spin_lock_irq(&zone->lock);

	/* Cancel the request if we failed to populate zone metadata */
	if (!zone->reported_pages) {
		__page_reporting_cancel(zone, phdev);
		goto zone_not_ready;
	}

	do {
		/* Pull pages out of allocator into a scaterlist */
		unsigned int nents = page_reporting_fill(zone, phdev);

		/* no pages were acquired, give up */
		if (!nents)
			break;

		spin_unlock_irq(&zone->lock);

		/* begin processing pages in local list */
		phdev->report(phdev, nents);

		spin_lock_irq(&zone->lock);

		/*
		 * We should have a scatterlist of pages that have been
		 * processed. Return them to their original free lists.
		 */
		page_reporting_drain(phdev);

		/* keep pulling pages till there are none to pull */
	} while (test_bit(ZONE_PAGE_REPORTING_REQUESTED, &zone->flags));
zone_not_ready:
	spin_unlock_irq(&zone->lock);
>>>>>>> master
}

static void page_reporting_process(struct work_struct *work)
{
	struct delayed_work *d_work = to_delayed_work(work);
<<<<<<< HEAD
	struct page_reporting_dev_info *prdev =
		container_of(d_work, struct page_reporting_dev_info, work);
	int err = 0, state = PAGE_REPORTING_ACTIVE;
	struct scatterlist *sgl;
	struct zone *zone;

	/*
	 * Change the state to "Active" so that we can track if there is
	 * anyone requests page reporting after we complete our pass. If
	 * the state is not altered by the end of the pass we will switch
	 * to idle and quit scheduling reporting runs.
	 */
	atomic_set(&prdev->state, state);

	/* allocate scatterlist to store pages being reported on */
	sgl = kmalloc_array(PAGE_REPORTING_CAPACITY, sizeof(*sgl), GFP_KERNEL);
	if (!sgl)
		goto err_out;

	sg_init_table(sgl, PAGE_REPORTING_CAPACITY);

	for_each_zone(zone) {
		err = page_reporting_process_zone(prdev, sgl, zone);
		if (err)
			break;
	}

	kfree(sgl);
err_out:
	/*
	 * If the state has reverted back to requested then there may be
	 * additional pages to be processed. We will defer for 2s to allow
	 * more pages to accumulate.
	 */
	state = atomic_cmpxchg(&prdev->state, state, PAGE_REPORTING_IDLE);
	if (state == PAGE_REPORTING_REQUESTED)
		schedule_delayed_work(&prdev->work, PAGE_REPORTING_DELAY);
}

static DEFINE_MUTEX(page_reporting_mutex);
DEFINE_STATIC_KEY_FALSE(page_reporting_enabled);

int page_reporting_register(struct page_reporting_dev_info *prdev)
{
	int err = 0;

	mutex_lock(&page_reporting_mutex);

	/* nothing to do if already in use */
	if (rcu_dereference_protected(pr_dev_info,
				lockdep_is_held(&page_reporting_mutex))) {
=======
	struct page_reporting_dev_info *phdev =
		container_of(d_work, struct page_reporting_dev_info, work);
	struct zone *zone = first_online_pgdat()->node_zones;

	do {
		if (test_bit(ZONE_PAGE_REPORTING_REQUESTED, &zone->flags))
			page_reporting_cycle(zone, phdev);

		/* Move to next zone, if at end of list start over */
		zone = next_zone(zone) ? : first_online_pgdat()->node_zones;

		/*
		 * As long as refcnt has not reached zero there are still
		 * zones to be processed.
		 */
	} while (atomic_read(&phdev->refcnt));
}

/* request page reporting on this zone */
void __page_reporting_request(struct zone *zone)
{
	struct page_reporting_dev_info *phdev;

	rcu_read_lock();

	/*
	 * We use RCU to protect the ph_dev_info pointer. In almost all
	 * cases this should be present, however in the unlikely case of
	 * a shutdown this will be NULL and we should exit.
	 */
	phdev = rcu_dereference(ph_dev_info);
	if (unlikely(!phdev))
		goto out;

	/*
	 * We can use separate test and set operations here as there
	 * is nothing else that can set or clear this bit while we are
	 * holding the zone lock. The advantage to doing it this way is
	 * that we don't have to dirty the cacheline unless we are
	 * changing the value.
	 */
	__set_bit(ZONE_PAGE_REPORTING_REQUESTED, &zone->flags);

	/*
	 * Delay the start of work to allow a sizable queue to
	 * build. For now we are limiting this to running no more
	 * than 10 times per second.
	 */
	if (!atomic_fetch_inc(&phdev->refcnt))
		schedule_delayed_work(&phdev->work, HZ / 10);
out:
	rcu_read_unlock();
}

static DEFINE_MUTEX(page_reporting_mutex);
DEFINE_STATIC_KEY_FALSE(page_reporting_notify_enabled);

void page_reporting_unregister(struct page_reporting_dev_info *phdev)
{
	mutex_lock(&page_reporting_mutex);

	if (rcu_access_pointer(ph_dev_info) == phdev) {
		/* Disable page reporting notification */
		static_branch_disable(&page_reporting_notify_enabled);
		RCU_INIT_POINTER(ph_dev_info, NULL);
		synchronize_rcu();

		/* Flush any existing work, and lock it out */
		cancel_delayed_work_sync(&phdev->work);

		/* Free scatterlist */
		kfree(phdev->sg);
		phdev->sg = NULL;

		/* Free boundaries */
		kfree(reported_boundary);
		reported_boundary = NULL;
	}

	mutex_unlock(&page_reporting_mutex);
}
EXPORT_SYMBOL_GPL(page_reporting_unregister);

int page_reporting_register(struct page_reporting_dev_info *phdev)
{
	struct zone *zone;
	int err = 0;

	/* No point in enabling this if it cannot handle any pages */
	if (WARN_ON(!phdev->capacity))
		return -EINVAL;

	mutex_lock(&page_reporting_mutex);

	/* nothing to do if already in use */
	if (rcu_access_pointer(ph_dev_info)) {
>>>>>>> master
		err = -EBUSY;
		goto err_out;
	}

	/*
<<<<<<< HEAD
	 * If the page_reporting_order value is not set, we check if
	 * an order is provided from the driver that is performing the
	 * registration. If that is not provided either, we default to
	 * pageblock_order.
	 */

	if (page_reporting_order == -1) {
		if (prdev->order > 0 && prdev->order <= MAX_ORDER)
			page_reporting_order = prdev->order;
		else
			page_reporting_order = pageblock_order;
	}

	/* initialize state and work structures */
	atomic_set(&prdev->state, PAGE_REPORTING_IDLE);
	INIT_DELAYED_WORK(&prdev->work, &page_reporting_process);

	/* Begin initial flush of zones */
	__page_reporting_request(prdev);

	/* Assign device to allow notifications */
	rcu_assign_pointer(pr_dev_info, prdev);

	/* enable page reporting notification */
	if (!static_key_enabled(&page_reporting_enabled)) {
		static_branch_enable(&page_reporting_enabled);
		pr_info("Free page reporting enabled\n");
	}
=======
	 * Allocate space to store the boundaries for the zone we are
	 * actively reporting on. We will need to store one boundary
	 * pointer per migratetype, and then we need to have one of these
	 * arrays per order for orders greater than or equal to
	 * PAGE_REPORTING_MIN_ORDER.
	 */
	reported_boundary = kcalloc(get_reporting_index(MAX_ORDER, 0),
				    sizeof(struct list_head *), GFP_KERNEL);
	if (!reported_boundary) {
		err = -ENOMEM;
		goto err_out;
	}

	/* allocate scatterlist to store pages being reported on */
	phdev->sg = kcalloc(phdev->capacity, sizeof(*phdev->sg), GFP_KERNEL);
	if (!phdev->sg) {
		err = -ENOMEM;

		kfree(reported_boundary);
		reported_boundary = NULL;

		goto err_out;
	}


	/* initialize refcnt and work structures */
	atomic_set(&phdev->refcnt, 0);
	INIT_DELAYED_WORK(&phdev->work, &page_reporting_process);

	/* assign device, and begin initial flush of populated zones */
	rcu_assign_pointer(ph_dev_info, phdev);
	for_each_populated_zone(zone) {
		spin_lock_irq(&zone->lock);
		__page_reporting_request(zone);
		spin_unlock_irq(&zone->lock);
	}

	/* enable page reporting notification */
	static_branch_enable(&page_reporting_notify_enabled);
>>>>>>> master
err_out:
	mutex_unlock(&page_reporting_mutex);

	return err;
}
EXPORT_SYMBOL_GPL(page_reporting_register);
<<<<<<< HEAD

void page_reporting_unregister(struct page_reporting_dev_info *prdev)
{
	mutex_lock(&page_reporting_mutex);

	if (prdev == rcu_dereference_protected(pr_dev_info,
				lockdep_is_held(&page_reporting_mutex))) {
		/* Disable page reporting notification */
		RCU_INIT_POINTER(pr_dev_info, NULL);
		synchronize_rcu();

		/* Flush any existing work, and lock it out */
		cancel_delayed_work_sync(&prdev->work);
	}

	mutex_unlock(&page_reporting_mutex);
}
EXPORT_SYMBOL_GPL(page_reporting_unregister);
=======
>>>>>>> master
