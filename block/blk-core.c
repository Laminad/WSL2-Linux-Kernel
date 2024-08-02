// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1991, 1992 Linus Torvalds
 * Copyright (C) 1994,      Karl Keyte: Added support for disk statistics
 * Elevator latency, (C) 2000  Andrea Arcangeli <andrea@suse.de> SuSE
 * Queue request tables / lock, selectable elevator, Jens Axboe <axboe@suse.de>
 * kernel-doc documentation started by NeilBrown <neilb@cse.unsw.edu.au>
 *	-  July2000
 * bio rewrite, highmem i/o, etc, Jens Axboe <axboe@suse.de> - may 2001
 */

/*
 * This handles all read/write requests to block devices
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-pm.h>
#include <linux/blk-integrity.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/kernel_stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/fault-inject.h>
#include <linux/list_sort.h>
#include <linux/delay.h>
#include <linux/ratelimit.h>
#include <linux/pm_runtime.h>
#include <linux/t10-pi.h>
#include <linux/debugfs.h>
#include <linux/bpf.h>
#include <linux/part_stat.h>
#include <linux/sched/sysctl.h>
#include <linux/blk-crypto.h>

#define CREATE_TRACE_POINTS
#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-pm.h"
#include "blk-cgroup.h"
#include "blk-throttle.h"

struct dentry *blk_debugfs_root;

EXPORT_TRACEPOINT_SYMBOL_GPL(block_bio_remap);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_rq_remap);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_bio_complete);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_split);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_unplug);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_rq_insert);

static DEFINE_IDA(blk_queue_ida);

/*
 * For queue allocation
 */
static struct kmem_cache *blk_requestq_cachep;

/*
 * Controlling structure to kblockd
 */
static struct workqueue_struct *kblockd_workqueue;

/**
 * blk_queue_flag_set - atomically set a queue flag
 * @flag: flag to be set
 * @q: request queue
 */
void blk_queue_flag_set(unsigned int flag, struct request_queue *q)
{
	set_bit(flag, &q->queue_flags);
}
EXPORT_SYMBOL(blk_queue_flag_set);

/**
 * blk_queue_flag_clear - atomically clear a queue flag
 * @flag: flag to be cleared
 * @q: request queue
 */
void blk_queue_flag_clear(unsigned int flag, struct request_queue *q)
{
	clear_bit(flag, &q->queue_flags);
}
EXPORT_SYMBOL(blk_queue_flag_clear);

/**
 * blk_queue_flag_test_and_set - atomically test and set a queue flag
 * @flag: flag to be set
 * @q: request queue
 *
 * Returns the previous value of @flag - 0 if the flag was not set and 1 if
 * the flag was already set.
 */
bool blk_queue_flag_test_and_set(unsigned int flag, struct request_queue *q)
{
	return test_and_set_bit(flag, &q->queue_flags);
}
EXPORT_SYMBOL_GPL(blk_queue_flag_test_and_set);

#define REQ_OP_NAME(name) [REQ_OP_##name] = #name
static const char *const blk_op_name[] = {
	REQ_OP_NAME(READ),
	REQ_OP_NAME(WRITE),
	REQ_OP_NAME(FLUSH),
	REQ_OP_NAME(DISCARD),
	REQ_OP_NAME(SECURE_ERASE),
	REQ_OP_NAME(ZONE_RESET),
	REQ_OP_NAME(ZONE_RESET_ALL),
	REQ_OP_NAME(ZONE_OPEN),
	REQ_OP_NAME(ZONE_CLOSE),
	REQ_OP_NAME(ZONE_FINISH),
	REQ_OP_NAME(ZONE_APPEND),
	REQ_OP_NAME(WRITE_ZEROES),
	REQ_OP_NAME(DRV_IN),
	REQ_OP_NAME(DRV_OUT),
};
#undef REQ_OP_NAME

/**
 * blk_op_str - Return string XXX in the REQ_OP_XXX.
 * @op: REQ_OP_XXX.
 *
 * Description: Centralize block layer function to convert REQ_OP_XXX into
 * string format. Useful in the debugging and tracing bio or request. For
 * invalid REQ_OP_XXX it returns string "UNKNOWN".
 */
inline const char *blk_op_str(enum req_op op)
{
	const char *op_str = "UNKNOWN";

	if (op < ARRAY_SIZE(blk_op_name) && blk_op_name[op])
		op_str = blk_op_name[op];

	return op_str;
}
<<<<<<< HEAD
EXPORT_SYMBOL_GPL(blk_op_str);
=======
EXPORT_SYMBOL_GPL(blk_queue_flag_test_and_clear);

static void blk_clear_congested(struct request_list *rl, int sync)
{
#ifdef CONFIG_CGROUP_WRITEBACK
	clear_wb_congested(rl->blkg->wb_congested, sync);
#else
	/*
	 * If !CGROUP_WRITEBACK, all blkg's map to bdi->wb and we shouldn't
	 * flip its congestion state for events on other blkcgs.
	 */
	if (rl == &rl->q->root_rl)
		clear_wb_congested(rl->q->backing_dev_info->wb.congested, sync);
#endif
}

static void blk_set_congested(struct request_list *rl, int sync)
{
#ifdef CONFIG_CGROUP_WRITEBACK
	set_wb_congested(rl->blkg->wb_congested, sync);
#else
	/* see blk_clear_congested() */
	if (rl == &rl->q->root_rl)
		set_wb_congested(rl->q->backing_dev_info->wb.congested, sync);
#endif
}

void blk_queue_congestion_threshold(struct request_queue *q)
{
	int nr;

	nr = q->nr_requests - (q->nr_requests / 8) + 1;
	if (nr > q->nr_requests)
		nr = q->nr_requests;
	q->nr_congestion_on = nr;

	nr = q->nr_requests - (q->nr_requests / 8) - (q->nr_requests / 16) - 1;
	if (nr < 1)
		nr = 1;
	q->nr_congestion_off = nr;
}

void blk_rq_init(struct request_queue *q, struct request *rq)
{
	memset(rq, 0, sizeof(*rq));

	INIT_LIST_HEAD(&rq->queuelist);
	INIT_LIST_HEAD(&rq->timeout_list);
	rq->cpu = -1;
	rq->q = q;
	rq->__sector = (sector_t) -1;
	INIT_HLIST_NODE(&rq->hash);
	RB_CLEAR_NODE(&rq->rb_node);
	rq->tag = -1;
	rq->internal_tag = -1;
	rq->start_time_ns = ktime_get_ns();
	rq->part = NULL;
	refcount_set(&rq->ref, 1);
}
EXPORT_SYMBOL(blk_rq_init);
>>>>>>> master

static const struct {
	int		errno;
	const char	*name;
} blk_errors[] = {
	[BLK_STS_OK]		= { 0,		"" },
	[BLK_STS_NOTSUPP]	= { -EOPNOTSUPP, "operation not supported" },
	[BLK_STS_TIMEOUT]	= { -ETIMEDOUT,	"timeout" },
	[BLK_STS_NOSPC]		= { -ENOSPC,	"critical space allocation" },
	[BLK_STS_TRANSPORT]	= { -ENOLINK,	"recoverable transport" },
	[BLK_STS_TARGET]	= { -EREMOTEIO,	"critical target" },
	[BLK_STS_RESV_CONFLICT]	= { -EBADE,	"reservation conflict" },
	[BLK_STS_MEDIUM]	= { -ENODATA,	"critical medium" },
	[BLK_STS_PROTECTION]	= { -EILSEQ,	"protection" },
	[BLK_STS_RESOURCE]	= { -ENOMEM,	"kernel resource" },
	[BLK_STS_DEV_RESOURCE]	= { -EBUSY,	"device resource" },
	[BLK_STS_AGAIN]		= { -EAGAIN,	"nonblocking retry" },
	[BLK_STS_OFFLINE]	= { -ENODEV,	"device offline" },

	/* device mapper special case, should not leak out: */
	[BLK_STS_DM_REQUEUE]	= { -EREMCHG, "dm internal retry" },

	/* zone device specific errors */
	[BLK_STS_ZONE_OPEN_RESOURCE]	= { -ETOOMANYREFS, "open zones exceeded" },
	[BLK_STS_ZONE_ACTIVE_RESOURCE]	= { -EOVERFLOW, "active zones exceeded" },

	/* Command duration limit device-side timeout */
	[BLK_STS_DURATION_LIMIT]	= { -ETIME, "duration limit exceeded" },

	/* everything else not covered above: */
	[BLK_STS_IOERR]		= { -EIO,	"I/O" },
};

blk_status_t errno_to_blk_status(int errno)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(blk_errors); i++) {
		if (blk_errors[i].errno == errno)
			return (__force blk_status_t)i;
	}

	return BLK_STS_IOERR;
}
EXPORT_SYMBOL_GPL(errno_to_blk_status);

int blk_status_to_errno(blk_status_t status)
{
	int idx = (__force int)status;

	if (WARN_ON_ONCE(idx >= ARRAY_SIZE(blk_errors)))
		return -EIO;
	return blk_errors[idx].errno;
}
EXPORT_SYMBOL_GPL(blk_status_to_errno);

const char *blk_status_to_str(blk_status_t status)
{
	int idx = (__force int)status;

	if (WARN_ON_ONCE(idx >= ARRAY_SIZE(blk_errors)))
		return "<null>";
	return blk_errors[idx].name;
}
EXPORT_SYMBOL_GPL(blk_status_to_str);

/**
 * blk_sync_queue - cancel any pending callbacks on a queue
 * @q: the queue
 *
 * Description:
 *     The block layer may perform asynchronous callback activity
 *     on a queue, such as calling the unplug function after a timeout.
 *     A block device may call blk_sync_queue to ensure that any
 *     such activity is cancelled, thus allowing it to release resources
 *     that the callbacks might use. The caller must already have made sure
 *     that its ->submit_bio will not re-add plugging prior to calling
 *     this function.
 *
 *     This function does not cancel any asynchronous activity arising
 *     out of elevator or throttling code. That would require elevator_exit()
 *     and blkcg_exit_queue() to be called with queue lock initialized.
 *
 */
void blk_sync_queue(struct request_queue *q)
{
	del_timer_sync(&q->timeout);
	cancel_work_sync(&q->timeout_work);
<<<<<<< HEAD
=======

	if (q->mq_ops) {
		struct blk_mq_hw_ctx *hctx;
		int i;

		queue_for_each_hw_ctx(q, hctx, i)
			cancel_delayed_work_sync(&hctx->run_work);
	} else {
		cancel_delayed_work_sync(&q->delay_work);
	}
>>>>>>> master
}
EXPORT_SYMBOL(blk_sync_queue);

/**
 * blk_set_pm_only - increment pm_only counter
 * @q: request queue pointer
 */
void blk_set_pm_only(struct request_queue *q)
{
	atomic_inc(&q->pm_only);
}
EXPORT_SYMBOL_GPL(blk_set_pm_only);

void blk_clear_pm_only(struct request_queue *q)
{
	int pm_only;

	pm_only = atomic_dec_return(&q->pm_only);
	WARN_ON_ONCE(pm_only < 0);
	if (pm_only == 0)
		wake_up_all(&q->mq_freeze_wq);
<<<<<<< HEAD
}
EXPORT_SYMBOL_GPL(blk_clear_pm_only);

static void blk_free_queue_rcu(struct rcu_head *rcu_head)
{
	struct request_queue *q = container_of(rcu_head,
			struct request_queue, rcu_head);

	percpu_ref_exit(&q->q_usage_counter);
	kmem_cache_free(blk_requestq_cachep, q);
}

static void blk_free_queue(struct request_queue *q)
{
	blk_free_queue_stats(q->stats);
	if (queue_is_mq(q))
		blk_mq_release(q);

	ida_free(&blk_queue_ida, q->id);
	call_rcu(&q->rcu_head, blk_free_queue_rcu);
}
=======
}
EXPORT_SYMBOL_GPL(blk_clear_pm_only);
>>>>>>> master

/**
 * blk_put_queue - decrement the request_queue refcount
 * @q: the request_queue structure to decrement the refcount for
 *
 * Decrements the refcount of the request_queue and free it when the refcount
 * reaches 0.
 */
void blk_put_queue(struct request_queue *q)
{
	if (refcount_dec_and_test(&q->refs))
		blk_free_queue(q);
}
EXPORT_SYMBOL(blk_put_queue);

void blk_queue_start_drain(struct request_queue *q)
{
	/*
	 * When queue DYING flag is set, we need to block new req
	 * entering queue, so we call blk_freeze_queue_start() to
	 * prevent I/O from crossing blk_queue_enter().
	 */
	blk_freeze_queue_start(q);
	if (queue_is_mq(q))
		blk_mq_wake_waiters(q);
	/* Make blk_queue_enter() reexamine the DYING flag. */
	wake_up_all(&q->mq_freeze_wq);
}
<<<<<<< HEAD
=======
EXPORT_SYMBOL_GPL(blk_set_queue_dying);

/* Unconfigure the I/O scheduler and dissociate from the cgroup controller. */
void blk_exit_queue(struct request_queue *q)
{
	/*
	 * Since the I/O scheduler exit code may access cgroup information,
	 * perform I/O scheduler exit before disassociating from the block
	 * cgroup controller.
	 */
	if (q->elevator) {
		ioc_clear_queue(q);
		elevator_exit(q, q->elevator);
		q->elevator = NULL;
	}

	/*
	 * Remove all references to @q from the block cgroup controller before
	 * restoring @q->queue_lock to avoid that restoring this pointer causes
	 * e.g. blkcg_print_blkgs() to crash.
	 */
	blkcg_exit_queue(q);

	/*
	 * Since the cgroup code may dereference the @q->backing_dev_info
	 * pointer, only decrease its reference count after having removed the
	 * association with the block cgroup controller.
	 */
	bdi_put(q->backing_dev_info);
}

/**
 * blk_cleanup_queue - shutdown a request queue
 * @q: request queue to shutdown
 *
 * Mark @q DYING, drain all pending requests, mark @q DEAD, destroy and
 * put it.  All future requests will be failed immediately with -ENODEV.
 */
void blk_cleanup_queue(struct request_queue *q)
{
	spinlock_t *lock = q->queue_lock;

	/* mark @q DYING, no new request or merges will be allowed afterwards */
	mutex_lock(&q->sysfs_lock);
	blk_set_queue_dying(q);
	spin_lock_irq(lock);

	/*
	 * A dying queue is permanently in bypass mode till released.  Note
	 * that, unlike blk_queue_bypass_start(), we aren't performing
	 * synchronize_rcu() after entering bypass mode to avoid the delay
	 * as some drivers create and destroy a lot of queues while
	 * probing.  This is still safe because blk_release_queue() will be
	 * called only after the queue refcnt drops to zero and nothing,
	 * RCU or not, would be traversing the queue by then.
	 */
	q->bypass_depth++;
	queue_flag_set(QUEUE_FLAG_BYPASS, q);

	queue_flag_set(QUEUE_FLAG_NOMERGES, q);
	queue_flag_set(QUEUE_FLAG_NOXMERGES, q);
	queue_flag_set(QUEUE_FLAG_DYING, q);
	spin_unlock_irq(lock);
	mutex_unlock(&q->sysfs_lock);

	/*
	 * Drain all requests queued before DYING marking. Set DEAD flag to
	 * prevent that q->request_fn() gets invoked after draining finished.
	 */
	blk_freeze_queue(q);
	spin_lock_irq(lock);
	queue_flag_set(QUEUE_FLAG_DEAD, q);
	spin_unlock_irq(lock);

	/*
	 * make sure all in-progress dispatch are completed because
	 * blk_freeze_queue() can only complete all requests, and
	 * dispatch may still be in-progress since we dispatch requests
	 * from more than one contexts.
	 *
	 * We rely on driver to deal with the race in case that queue
	 * initialization isn't done.
	 */
	if (q->mq_ops && blk_queue_init_done(q))
		blk_mq_quiesce_queue(q);

	/* for synchronous bio-based driver finish in-flight integrity i/o */
	blk_flush_integrity();

	/* @q won't process any more request, flush async actions */
	del_timer_sync(&q->backing_dev_info->laptop_mode_wb_timer);
	blk_sync_queue(q);

	/*
	 * I/O scheduler exit is only safe after the sysfs scheduler attribute
	 * has been removed.
	 */
	WARN_ON_ONCE(q->kobj.state_in_sysfs);

	blk_exit_queue(q);

	if (q->mq_ops)
		blk_mq_exit_queue(q);

	percpu_ref_exit(&q->q_usage_counter);

	spin_lock_irq(lock);
	if (q->queue_lock != &q->__queue_lock)
		q->queue_lock = &q->__queue_lock;
	spin_unlock_irq(lock);

	/* @q is and will stay empty, shutdown and put */
	blk_put_queue(q);
}
EXPORT_SYMBOL(blk_cleanup_queue);

/* Allocate memory local to the request queue */
static void *alloc_request_simple(gfp_t gfp_mask, void *data)
{
	struct request_queue *q = data;

	return kmem_cache_alloc_node(request_cachep, gfp_mask, q->node);
}

static void free_request_simple(void *element, void *data)
{
	kmem_cache_free(request_cachep, element);
}

static void *alloc_request_size(gfp_t gfp_mask, void *data)
{
	struct request_queue *q = data;
	struct request *rq;

	rq = kmalloc_node(sizeof(struct request) + q->cmd_size, gfp_mask,
			q->node);
	if (rq && q->init_rq_fn && q->init_rq_fn(q, rq, gfp_mask) < 0) {
		kfree(rq);
		rq = NULL;
	}
	return rq;
}

static void free_request_size(void *element, void *data)
{
	struct request_queue *q = data;

	if (q->exit_rq_fn)
		q->exit_rq_fn(q, element);
	kfree(element);
}

int blk_init_rl(struct request_list *rl, struct request_queue *q,
		gfp_t gfp_mask)
{
	if (unlikely(rl->rq_pool) || q->mq_ops)
		return 0;

	rl->q = q;
	rl->count[BLK_RW_SYNC] = rl->count[BLK_RW_ASYNC] = 0;
	rl->starved[BLK_RW_SYNC] = rl->starved[BLK_RW_ASYNC] = 0;
	init_waitqueue_head(&rl->wait[BLK_RW_SYNC]);
	init_waitqueue_head(&rl->wait[BLK_RW_ASYNC]);

	if (q->cmd_size) {
		rl->rq_pool = mempool_create_node(BLKDEV_MIN_RQ,
				alloc_request_size, free_request_size,
				q, gfp_mask, q->node);
	} else {
		rl->rq_pool = mempool_create_node(BLKDEV_MIN_RQ,
				alloc_request_simple, free_request_simple,
				q, gfp_mask, q->node);
	}
	if (!rl->rq_pool)
		return -ENOMEM;

	if (rl != &q->root_rl)
		WARN_ON_ONCE(!blk_get_queue(q));

	return 0;
}

void blk_exit_rl(struct request_queue *q, struct request_list *rl)
{
	if (rl->rq_pool) {
		mempool_destroy(rl->rq_pool);
		if (rl != &q->root_rl)
			blk_put_queue(q);
	}
}

struct request_queue *blk_alloc_queue(gfp_t gfp_mask)
{
	return blk_alloc_queue_node(gfp_mask, NUMA_NO_NODE, NULL);
}
EXPORT_SYMBOL(blk_alloc_queue);
>>>>>>> master

/**
 * blk_queue_enter() - try to increase q->q_usage_counter
 * @q: request queue pointer
 * @flags: BLK_MQ_REQ_NOWAIT and/or BLK_MQ_REQ_PM
 */
int blk_queue_enter(struct request_queue *q, blk_mq_req_flags_t flags)
{
<<<<<<< HEAD
	const bool pm = flags & BLK_MQ_REQ_PM;
=======
	const bool pm = flags & BLK_MQ_REQ_PREEMPT;

	while (true) {
		bool success = false;

		rcu_read_lock();
		if (percpu_ref_tryget_live(&q->q_usage_counter)) {
			/*
			 * The code that increments the pm_only counter is
			 * responsible for ensuring that that counter is
			 * globally visible before the queue is unfrozen.
			 */
			if (pm || !blk_queue_pm_only(q)) {
				success = true;
			} else {
				percpu_ref_put(&q->q_usage_counter);
			}
		}
		rcu_read_unlock();

		if (success)
			return 0;
>>>>>>> master

	while (!blk_try_enter_queue(q, pm)) {
		if (flags & BLK_MQ_REQ_NOWAIT)
			return -EAGAIN;

		/*
		 * read pair of barrier in blk_freeze_queue_start(), we need to
		 * order reading __PERCPU_REF_DEAD flag of .q_usage_counter and
		 * reading .mq_freeze_depth or queue dying flag, otherwise the
		 * following wait may never return if the two reads are
		 * reordered.
		 */
		smp_rmb();
		wait_event(q->mq_freeze_wq,
<<<<<<< HEAD
			   (!q->mq_freeze_depth &&
			    blk_pm_resume_queue(pm, q)) ||
=======
			   (atomic_read(&q->mq_freeze_depth) == 0 &&
			    (pm || !blk_queue_pm_only(q))) ||
>>>>>>> master
			   blk_queue_dying(q));
		if (blk_queue_dying(q))
			return -ENODEV;
	}

	return 0;
}

int __bio_queue_enter(struct request_queue *q, struct bio *bio)
{
	while (!blk_try_enter_queue(q, false)) {
		struct gendisk *disk = bio->bi_bdev->bd_disk;

		if (bio->bi_opf & REQ_NOWAIT) {
			if (test_bit(GD_DEAD, &disk->state))
				goto dead;
			bio_wouldblock_error(bio);
			return -EAGAIN;
		}

		/*
		 * read pair of barrier in blk_freeze_queue_start(), we need to
		 * order reading __PERCPU_REF_DEAD flag of .q_usage_counter and
		 * reading .mq_freeze_depth or queue dying flag, otherwise the
		 * following wait may never return if the two reads are
		 * reordered.
		 */
		smp_rmb();
		wait_event(q->mq_freeze_wq,
			   (!q->mq_freeze_depth &&
			    blk_pm_resume_queue(false, q)) ||
			   test_bit(GD_DEAD, &disk->state));
		if (test_bit(GD_DEAD, &disk->state))
			goto dead;
	}

	return 0;
dead:
	bio_io_error(bio);
	return -ENODEV;
}

void blk_queue_exit(struct request_queue *q)
{
	percpu_ref_put(&q->q_usage_counter);
}

static void blk_queue_usage_counter_release(struct percpu_ref *ref)
{
	struct request_queue *q =
		container_of(ref, struct request_queue, q_usage_counter);

	wake_up_all(&q->mq_freeze_wq);
}

static void blk_rq_timed_out_timer(struct timer_list *t)
{
	struct request_queue *q = from_timer(q, t, timeout);

	kblockd_schedule_work(&q->timeout_work);
}

<<<<<<< HEAD
static void blk_timeout_work(struct work_struct *work)
{
}

struct request_queue *blk_alloc_queue(int node_id)
=======
static void blk_timeout_work_dummy(struct work_struct *work)
{
}

/**
 * blk_alloc_queue_node - allocate a request queue
 * @gfp_mask: memory allocation flags
 * @node_id: NUMA node to allocate memory from
 * @lock: For legacy queues, pointer to a spinlock that will be used to e.g.
 *        serialize calls to the legacy .request_fn() callback. Ignored for
 *	  blk-mq request queues.
 *
 * Note: pass the queue lock as the third argument to this function instead of
 * setting the queue lock pointer explicitly to avoid triggering a sporadic
 * crash in the blkcg code. This function namely calls blkcg_init_queue() and
 * the queue lock pointer must be set before blkcg_init_queue() is called.
 */
struct request_queue *blk_alloc_queue_node(gfp_t gfp_mask, int node_id,
					   spinlock_t *lock)
>>>>>>> master
{
	struct request_queue *q;

	q = kmem_cache_alloc_node(blk_requestq_cachep, GFP_KERNEL | __GFP_ZERO,
				  node_id);
	if (!q)
		return NULL;

	q->last_merge = NULL;

	q->id = ida_alloc(&blk_queue_ida, GFP_KERNEL);
	if (q->id < 0)
		goto fail_q;

	q->stats = blk_alloc_queue_stats();
	if (!q->stats)
		goto fail_id;

	q->node = node_id;

	atomic_set(&q->nr_active_requests_shared_tags, 0);

	timer_setup(&q->timeout, blk_rq_timed_out_timer, 0);
<<<<<<< HEAD
	INIT_WORK(&q->timeout_work, blk_timeout_work);
=======
	INIT_WORK(&q->timeout_work, blk_timeout_work_dummy);
	INIT_LIST_HEAD(&q->timeout_list);
>>>>>>> master
	INIT_LIST_HEAD(&q->icq_list);

	refcount_set(&q->refs, 1);
	mutex_init(&q->debugfs_mutex);
	mutex_init(&q->sysfs_lock);
	mutex_init(&q->sysfs_dir_lock);
	mutex_init(&q->rq_qos_mutex);
	spin_lock_init(&q->queue_lock);

	init_waitqueue_head(&q->mq_freeze_wq);
	mutex_init(&q->mq_freeze_lock);

	blkg_init_queue(q);

	/*
	 * Init percpu_ref in atomic mode so that it's faster to shutdown.
	 * See blk_register_queue() for details.
	 */
	if (percpu_ref_init(&q->q_usage_counter,
				blk_queue_usage_counter_release,
				PERCPU_REF_INIT_ATOMIC, GFP_KERNEL))
		goto fail_stats;

	blk_set_default_limits(&q->limits);
	q->nr_requests = BLKDEV_DEFAULT_RQ;

	return q;

fail_stats:
	blk_free_queue_stats(q->stats);
fail_id:
	ida_free(&blk_queue_ida, q->id);
fail_q:
	kmem_cache_free(blk_requestq_cachep, q);
	return NULL;
}

/**
 * blk_get_queue - increment the request_queue refcount
 * @q: the request_queue structure to increment the refcount for
 *
 * Increment the refcount of the request_queue kobject.
 *
<<<<<<< HEAD
 * Context: Any context.
 */
=======
 *    @rfn is not required, or even expected, to remove all requests off the
 *    queue, but only as many as it can handle at a time.  If it does leave
 *    requests on the queue, it is responsible for arranging that the requests
 *    get dealt with eventually.
 *
 *    The queue spin lock must be held while manipulating the requests on the
 *    request queue; this lock will be taken also from interrupt context, so irq
 *    disabling is needed for it.
 *
 *    Function returns a pointer to the initialized request queue, or %NULL if
 *    it didn't succeed.
 *
 * Note:
 *    blk_init_queue() must be paired with a blk_cleanup_queue() call
 *    when the block device is deactivated (such as at module unload).
 **/

struct request_queue *blk_init_queue(request_fn_proc *rfn, spinlock_t *lock)
{
	return blk_init_queue_node(rfn, lock, NUMA_NO_NODE);
}
EXPORT_SYMBOL(blk_init_queue);

struct request_queue *
blk_init_queue_node(request_fn_proc *rfn, spinlock_t *lock, int node_id)
{
	struct request_queue *q;

	q = blk_alloc_queue_node(GFP_KERNEL, node_id, lock);
	if (!q)
		return NULL;

	q->request_fn = rfn;
	if (blk_init_allocated_queue(q) < 0) {
		blk_cleanup_queue(q);
		return NULL;
	}

	return q;
}
EXPORT_SYMBOL(blk_init_queue_node);

static blk_qc_t blk_queue_bio(struct request_queue *q, struct bio *bio);


int blk_init_allocated_queue(struct request_queue *q)
{
	WARN_ON_ONCE(q->mq_ops);

	q->fq = blk_alloc_flush_queue(q, NUMA_NO_NODE, q->cmd_size, GFP_KERNEL);
	if (!q->fq)
		return -ENOMEM;

	if (q->init_rq_fn && q->init_rq_fn(q, q->fq->flush_rq, GFP_KERNEL))
		goto out_free_flush_queue;

	if (blk_init_rl(&q->root_rl, q, GFP_KERNEL))
		goto out_exit_flush_rq;

	INIT_WORK(&q->timeout_work, blk_timeout_work);
	q->queue_flags		|= QUEUE_FLAG_DEFAULT;

	/*
	 * This also sets hw/phys segments, boundary and size
	 */
	blk_queue_make_request(q, blk_queue_bio);

	q->sg_reserved_size = INT_MAX;

	if (elevator_init(q))
		goto out_exit_flush_rq;
	return 0;

out_exit_flush_rq:
	if (q->exit_rq_fn)
		q->exit_rq_fn(q, q->fq->flush_rq);
out_free_flush_queue:
	blk_free_flush_queue(q->fq);
	q->fq = NULL;
	return -ENOMEM;
}
EXPORT_SYMBOL(blk_init_allocated_queue);

>>>>>>> master
bool blk_get_queue(struct request_queue *q)
{
	if (unlikely(blk_queue_dying(q)))
		return false;
	refcount_inc(&q->refs);
	return true;
}
EXPORT_SYMBOL(blk_get_queue);

#ifdef CONFIG_FAIL_MAKE_REQUEST

static DECLARE_FAULT_ATTR(fail_make_request);

static int __init setup_fail_make_request(char *str)
{
	return setup_fault_attr(&fail_make_request, str);
}
__setup("fail_make_request=", setup_fail_make_request);

bool should_fail_request(struct block_device *part, unsigned int bytes)
{
	return part->bd_make_it_fail && should_fail(&fail_make_request, bytes);
}

static int __init fail_make_request_debugfs(void)
{
	struct dentry *dir = fault_create_debugfs_attr("fail_make_request",
						NULL, &fail_make_request);

	return PTR_ERR_OR_ZERO(dir);
}

late_initcall(fail_make_request_debugfs);
#endif /* CONFIG_FAIL_MAKE_REQUEST */

static inline void bio_check_ro(struct bio *bio)
{
	if (op_is_write(bio_op(bio)) && bdev_read_only(bio->bi_bdev)) {
		if (op_is_flush(bio->bi_opf) && !bio_sectors(bio))
			return;

		if (bio->bi_bdev->bd_ro_warned)
			return;

		bio->bi_bdev->bd_ro_warned = true;
		/*
		 * Use ioctl to set underlying disk of raid/dm to read-only
		 * will trigger this.
		 */
		pr_warn("Trying to write to read-only block-device %pg\n",
			bio->bi_bdev);
	}
}

static noinline int should_fail_bio(struct bio *bio)
{
	if (should_fail_request(bdev_whole(bio->bi_bdev), bio->bi_iter.bi_size))
		return -EIO;
	return 0;
}
ALLOW_ERROR_INJECTION(should_fail_bio, ERRNO);

/*
 * Check whether this bio extends beyond the end of the device or partition.
 * This may well happen - the kernel calls bread() without checking the size of
 * the device, e.g., when mounting a file system.
 */
static inline int bio_check_eod(struct bio *bio)
{
	sector_t maxsector = bdev_nr_sectors(bio->bi_bdev);
	unsigned int nr_sectors = bio_sectors(bio);

	if (nr_sectors &&
	    (nr_sectors > maxsector ||
	     bio->bi_iter.bi_sector > maxsector - nr_sectors)) {
		pr_info_ratelimited("%s: attempt to access beyond end of device\n"
				    "%pg: rw=%d, sector=%llu, nr_sectors = %u limit=%llu\n",
				    current->comm, bio->bi_bdev, bio->bi_opf,
				    bio->bi_iter.bi_sector, nr_sectors, maxsector);
		return -EIO;
	}
	return 0;
}

/*
 * Remap block n of partition p to block n+start(p) of the disk.
 */
static int blk_partition_remap(struct bio *bio)
{
	struct block_device *p = bio->bi_bdev;

	if (unlikely(should_fail_request(p, bio->bi_iter.bi_size)))
		return -EIO;
	if (bio_sectors(bio)) {
		bio->bi_iter.bi_sector += p->bd_start_sect;
		trace_block_bio_remap(bio, p->bd_dev,
				      bio->bi_iter.bi_sector -
				      p->bd_start_sect);
	}
	bio_set_flag(bio, BIO_REMAPPED);
	return 0;
}

/*
 * Check write append to a zoned block device.
 */
static inline blk_status_t blk_check_zone_append(struct request_queue *q,
						 struct bio *bio)
{
	int nr_sectors = bio_sectors(bio);

	/* Only applicable to zoned block devices */
	if (!bdev_is_zoned(bio->bi_bdev))
		return BLK_STS_NOTSUPP;

	/* The bio sector must point to the start of a sequential zone */
	if (!bdev_is_zone_start(bio->bi_bdev, bio->bi_iter.bi_sector) ||
	    !bio_zone_is_seq(bio))
		return BLK_STS_IOERR;

	/*
	 * Not allowed to cross zone boundaries. Otherwise, the BIO will be
	 * split and could result in non-contiguous sectors being written in
	 * different zones.
	 */
	if (nr_sectors > q->limits.chunk_sectors)
		return BLK_STS_IOERR;

	/* Make sure the BIO is small enough and will not get split */
	if (nr_sectors > q->limits.max_zone_append_sectors)
		return BLK_STS_IOERR;

	bio->bi_opf |= REQ_NOMERGE;

	return BLK_STS_OK;
}

static void __submit_bio(struct bio *bio)
{
	if (unlikely(!blk_crypto_bio_prep(&bio)))
		return;

	if (!bio->bi_bdev->bd_has_submit_bio) {
		blk_mq_submit_bio(bio);
	} else if (likely(bio_queue_enter(bio) == 0)) {
		struct gendisk *disk = bio->bi_bdev->bd_disk;

		disk->fops->submit_bio(bio);
		blk_queue_exit(disk->queue);
	}
}

/*
 * The loop in this function may be a bit non-obvious, and so deserves some
 * explanation:
 *
 *  - Before entering the loop, bio->bi_next is NULL (as all callers ensure
 *    that), so we have a list with a single bio.
 *  - We pretend that we have just taken it off a longer list, so we assign
 *    bio_list to a pointer to the bio_list_on_stack, thus initialising the
 *    bio_list of new bios to be added.  ->submit_bio() may indeed add some more
 *    bios through a recursive call to submit_bio_noacct.  If it did, we find a
 *    non-NULL value in bio_list and re-enter the loop from the top.
 *  - In this case we really did just take the bio of the top of the list (no
 *    pretending) and so remove it from bio_list, and call into ->submit_bio()
 *    again.
 *
 * bio_list_on_stack[0] contains bios submitted by the current ->submit_bio.
 * bio_list_on_stack[1] contains bios that were submitted before the current
 *	->submit_bio, but that haven't been processed yet.
 */
static void __submit_bio_noacct(struct bio *bio)
{
	struct bio_list bio_list_on_stack[2];

	BUG_ON(bio->bi_next);

	bio_list_init(&bio_list_on_stack[0]);
	current->bio_list = bio_list_on_stack;

	do {
		struct request_queue *q = bdev_get_queue(bio->bi_bdev);
		struct bio_list lower, same;

		/*
		 * Create a fresh bio_list for all subordinate requests.
		 */
		bio_list_on_stack[1] = bio_list_on_stack[0];
		bio_list_init(&bio_list_on_stack[0]);

		__submit_bio(bio);

		/*
		 * Sort new bios into those for a lower level and those for the
		 * same level.
		 */
		bio_list_init(&lower);
		bio_list_init(&same);
		while ((bio = bio_list_pop(&bio_list_on_stack[0])) != NULL)
			if (q == bdev_get_queue(bio->bi_bdev))
				bio_list_add(&same, bio);
			else
				bio_list_add(&lower, bio);

		/*
		 * Now assemble so we handle the lowest level first.
		 */
		bio_list_merge(&bio_list_on_stack[0], &lower);
		bio_list_merge(&bio_list_on_stack[0], &same);
		bio_list_merge(&bio_list_on_stack[0], &bio_list_on_stack[1]);
	} while ((bio = bio_list_pop(&bio_list_on_stack[0])));

	current->bio_list = NULL;
}

static void __submit_bio_noacct_mq(struct bio *bio)
{
	struct bio_list bio_list[2] = { };

	current->bio_list = bio_list;

	do {
		__submit_bio(bio);
	} while ((bio = bio_list_pop(&bio_list[0])));

	current->bio_list = NULL;
}

void submit_bio_noacct_nocheck(struct bio *bio)
{
	blk_cgroup_bio_start(bio);
	blkcg_bio_issue_init(bio);

	if (!bio_flagged(bio, BIO_TRACE_COMPLETION)) {
		trace_block_bio_queue(bio);
		/*
		 * Now that enqueuing has been traced, we need to trace
		 * completion as well.
		 */
		bio_set_flag(bio, BIO_TRACE_COMPLETION);
	}

	/*
	 * We only want one ->submit_bio to be active at a time, else stack
	 * usage with stacked devices could be a problem.  Use current->bio_list
	 * to collect a list of requests submited by a ->submit_bio method while
	 * it is active, and then process them after it returned.
	 */
	if (current->bio_list)
		bio_list_add(&current->bio_list[0], bio);
	else if (!bio->bi_bdev->bd_has_submit_bio)
		__submit_bio_noacct_mq(bio);
	else
		__submit_bio_noacct(bio);
}

/**
 * submit_bio_noacct - re-submit a bio to the block device layer for I/O
 * @bio:  The bio describing the location in memory and on the device.
 *
 * This is a version of submit_bio() that shall only be used for I/O that is
 * resubmitted to lower level drivers by stacking block drivers.  All file
 * systems and other upper level users of the block layer should use
 * submit_bio() instead.
 */
void submit_bio_noacct(struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct request_queue *q = bdev_get_queue(bdev);
	blk_status_t status = BLK_STS_IOERR;

	might_sleep();

	/*
	 * For a REQ_NOWAIT based request, return -EOPNOTSUPP
	 * if queue does not support NOWAIT.
	 */
	if ((bio->bi_opf & REQ_NOWAIT) && !bdev_nowait(bdev))
		goto not_supported;

	if (should_fail_bio(bio))
		goto end_io;
	bio_check_ro(bio);
	if (!bio_flagged(bio, BIO_REMAPPED)) {
		if (unlikely(bio_check_eod(bio)))
			goto end_io;
		if (bdev->bd_partno && unlikely(blk_partition_remap(bio)))
			goto end_io;
	}

	/*
	 * Filter flush bio's early so that bio based drivers without flush
	 * support don't have to worry about them.
	 */
	if (op_is_flush(bio->bi_opf)) {
		if (WARN_ON_ONCE(bio_op(bio) != REQ_OP_WRITE &&
				 bio_op(bio) != REQ_OP_ZONE_APPEND))
			goto end_io;
		if (!test_bit(QUEUE_FLAG_WC, &q->queue_flags)) {
			bio->bi_opf &= ~(REQ_PREFLUSH | REQ_FUA);
			if (!bio_sectors(bio)) {
				status = BLK_STS_OK;
				goto end_io;
			}
		}
	}

	if (!test_bit(QUEUE_FLAG_POLL, &q->queue_flags))
		bio_clear_polled(bio);

	switch (bio_op(bio)) {
	case REQ_OP_DISCARD:
		if (!bdev_max_discard_sectors(bdev))
			goto not_supported;
		break;
	case REQ_OP_SECURE_ERASE:
		if (!bdev_max_secure_erase_sectors(bdev))
			goto not_supported;
		break;
	case REQ_OP_ZONE_APPEND:
		status = blk_check_zone_append(q, bio);
		if (status != BLK_STS_OK)
			goto end_io;
		break;
	case REQ_OP_ZONE_RESET:
	case REQ_OP_ZONE_OPEN:
	case REQ_OP_ZONE_CLOSE:
	case REQ_OP_ZONE_FINISH:
		if (!bdev_is_zoned(bio->bi_bdev))
			goto not_supported;
		break;
	case REQ_OP_ZONE_RESET_ALL:
		if (!bdev_is_zoned(bio->bi_bdev) || !blk_queue_zone_resetall(q))
			goto not_supported;
		break;
	case REQ_OP_WRITE_ZEROES:
		if (!q->limits.max_write_zeroes_sectors)
			goto not_supported;
		break;
	default:
		break;
	}

	if (blk_throtl_bio(bio))
		return;
	submit_bio_noacct_nocheck(bio);
	return;

not_supported:
	status = BLK_STS_NOTSUPP;
end_io:
	bio->bi_status = status;
	bio_endio(bio);
}
<<<<<<< HEAD
EXPORT_SYMBOL(submit_bio_noacct);
=======

/**
 * generic_make_request - hand a buffer to its device driver for I/O
 * @bio:  The bio describing the location in memory and on the device.
 *
 * generic_make_request() is used to make I/O requests of block
 * devices. It is passed a &struct bio, which describes the I/O that needs
 * to be done.
 *
 * generic_make_request() does not return any status.  The
 * success/failure status of the request, along with notification of
 * completion, is delivered asynchronously through the bio->bi_end_io
 * function described (one day) else where.
 *
 * The caller of generic_make_request must make sure that bi_io_vec
 * are set to describe the memory buffer, and that bi_dev and bi_sector are
 * set to describe the device address, and the
 * bi_end_io and optionally bi_private are set to describe how
 * completion notification should be signaled.
 *
 * generic_make_request and the drivers it calls may use bi_next if this
 * bio happens to be merged with someone else, and may resubmit the bio to
 * a lower device by calling into generic_make_request recursively, which
 * means the bio should NOT be touched after the call to ->make_request_fn.
 */
blk_qc_t generic_make_request(struct bio *bio)
{
	/*
	 * bio_list_on_stack[0] contains bios submitted by the current
	 * make_request_fn.
	 * bio_list_on_stack[1] contains bios that were submitted before
	 * the current make_request_fn, but that haven't been processed
	 * yet.
	 */
	struct bio_list bio_list_on_stack[2];
	blk_mq_req_flags_t flags = 0;
	struct request_queue *q = bio->bi_disk->queue;
	blk_qc_t ret = BLK_QC_T_NONE;

	if (bio->bi_opf & REQ_NOWAIT)
		flags = BLK_MQ_REQ_NOWAIT;
	if (bio_flagged(bio, BIO_QUEUE_ENTERED))
		blk_queue_enter_live(q);
	else if (blk_queue_enter(q, flags) < 0) {
		if (!blk_queue_dying(q) && (bio->bi_opf & REQ_NOWAIT))
			bio_wouldblock_error(bio);
		else
			bio_io_error(bio);
		return ret;
	}

	if (!generic_make_request_checks(bio))
		goto out;

	/*
	 * We only want one ->make_request_fn to be active at a time, else
	 * stack usage with stacked devices could be a problem.  So use
	 * current->bio_list to keep a list of requests submited by a
	 * make_request_fn function.  current->bio_list is also used as a
	 * flag to say if generic_make_request is currently active in this
	 * task or not.  If it is NULL, then no make_request is active.  If
	 * it is non-NULL, then a make_request is active, and new requests
	 * should be added at the tail
	 */
	if (current->bio_list) {
		bio_list_add(&current->bio_list[0], bio);
		goto out;
	}

	/* following loop may be a bit non-obvious, and so deserves some
	 * explanation.
	 * Before entering the loop, bio->bi_next is NULL (as all callers
	 * ensure that) so we have a list with a single bio.
	 * We pretend that we have just taken it off a longer list, so
	 * we assign bio_list to a pointer to the bio_list_on_stack,
	 * thus initialising the bio_list of new bios to be
	 * added.  ->make_request() may indeed add some more bios
	 * through a recursive call to generic_make_request.  If it
	 * did, we find a non-NULL value in bio_list and re-enter the loop
	 * from the top.  In this case we really did just take the bio
	 * of the top of the list (no pretending) and so remove it from
	 * bio_list, and call into ->make_request() again.
	 */
	BUG_ON(bio->bi_next);
	bio_list_init(&bio_list_on_stack[0]);
	current->bio_list = bio_list_on_stack;
	do {
		bool enter_succeeded = true;

		if (unlikely(q != bio->bi_disk->queue)) {
			if (q)
				blk_queue_exit(q);
			q = bio->bi_disk->queue;
			flags = 0;
			if (bio->bi_opf & REQ_NOWAIT)
				flags = BLK_MQ_REQ_NOWAIT;
			if (blk_queue_enter(q, flags) < 0)
				enter_succeeded = false;
		}

		if (enter_succeeded) {
			struct bio_list lower, same;

			/* Create a fresh bio_list for all subordinate requests */
			bio_list_on_stack[1] = bio_list_on_stack[0];
			bio_list_init(&bio_list_on_stack[0]);
			ret = q->make_request_fn(q, bio);

			/* sort new bios into those for a lower level
			 * and those for the same level
			 */
			bio_list_init(&lower);
			bio_list_init(&same);
			while ((bio = bio_list_pop(&bio_list_on_stack[0])) != NULL)
				if (q == bio->bi_disk->queue)
					bio_list_add(&same, bio);
				else
					bio_list_add(&lower, bio);
			/* now assemble so we handle the lowest level first */
			bio_list_merge(&bio_list_on_stack[0], &lower);
			bio_list_merge(&bio_list_on_stack[0], &same);
			bio_list_merge(&bio_list_on_stack[0], &bio_list_on_stack[1]);
		} else {
			if (unlikely(!blk_queue_dying(q) &&
					(bio->bi_opf & REQ_NOWAIT)))
				bio_wouldblock_error(bio);
			else
				bio_io_error(bio);
			q = NULL;
		}
		bio = bio_list_pop(&bio_list_on_stack[0]);
	} while (bio);
	current->bio_list = NULL; /* deactivate */

out:
	if (q)
		blk_queue_exit(q);
	return ret;
}
EXPORT_SYMBOL(generic_make_request);

/**
 * direct_make_request - hand a buffer directly to its device driver for I/O
 * @bio:  The bio describing the location in memory and on the device.
 *
 * This function behaves like generic_make_request(), but does not protect
 * against recursion.  Must only be used if the called driver is known
 * to not call generic_make_request (or direct_make_request) again from
 * its make_request function.  (Calling direct_make_request again from
 * a workqueue is perfectly fine as that doesn't recurse).
 */
blk_qc_t direct_make_request(struct bio *bio)
{
	struct request_queue *q = bio->bi_disk->queue;
	bool nowait = bio->bi_opf & REQ_NOWAIT;
	blk_qc_t ret;

	if (!generic_make_request_checks(bio))
		return BLK_QC_T_NONE;

	if (unlikely(blk_queue_enter(q, nowait ? BLK_MQ_REQ_NOWAIT : 0))) {
		if (nowait && !blk_queue_dying(q))
			bio->bi_status = BLK_STS_AGAIN;
		else
			bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	ret = q->make_request_fn(q, bio);
	blk_queue_exit(q);
	return ret;
}
EXPORT_SYMBOL_GPL(direct_make_request);
>>>>>>> master

/**
 * submit_bio - submit a bio to the block device layer for I/O
 * @bio: The &struct bio which describes the I/O
 *
 * submit_bio() is used to submit I/O requests to block devices.  It is passed a
 * fully set up &struct bio that describes the I/O that needs to be done.  The
 * bio will be send to the device described by the bi_bdev field.
 *
 * The success/failure status of the request, along with notification of
 * completion, is delivered asynchronously through the ->bi_end_io() callback
 * in @bio.  The bio must NOT be touched by the caller until ->bi_end_io() has
 * been called.
 */
void submit_bio(struct bio *bio)
{
	if (bio_op(bio) == REQ_OP_READ) {
		task_io_account_read(bio->bi_iter.bi_size);
		count_vm_events(PGPGIN, bio_sectors(bio));
	} else if (bio_op(bio) == REQ_OP_WRITE) {
		count_vm_events(PGPGOUT, bio_sectors(bio));
	}

	submit_bio_noacct(bio);
}
EXPORT_SYMBOL(submit_bio);

/**
 * bio_poll - poll for BIO completions
 * @bio: bio to poll for
 * @iob: batches of IO
 * @flags: BLK_POLL_* flags that control the behavior
 *
 * Poll for completions on queue associated with the bio. Returns number of
 * completed entries found.
 *
 * Note: the caller must either be the context that submitted @bio, or
 * be in a RCU critical section to prevent freeing of @bio.
 */
int bio_poll(struct bio *bio, struct io_comp_batch *iob, unsigned int flags)
{
	blk_qc_t cookie = READ_ONCE(bio->bi_cookie);
	struct block_device *bdev;
	struct request_queue *q;
	int ret = 0;

	bdev = READ_ONCE(bio->bi_bdev);
	if (!bdev)
		return 0;

	q = bdev_get_queue(bdev);
	if (cookie == BLK_QC_T_NONE ||
	    !test_bit(QUEUE_FLAG_POLL, &q->queue_flags))
		return 0;

	/*
	 * As the requests that require a zone lock are not plugged in the
	 * first place, directly accessing the plug instead of using
	 * blk_mq_plug() should not have any consequences during flushing for
	 * zoned devices.
	 */
	blk_flush_plug(current->plug, false);

	/*
	 * We need to be able to enter a frozen queue, similar to how
	 * timeouts also need to do that. If that is blocked, then we can
	 * have pending IO when a queue freeze is started, and then the
	 * wait for the freeze to finish will wait for polled requests to
	 * timeout as the poller is preventer from entering the queue and
	 * completing them. As long as we prevent new IO from being queued,
	 * that should be all that matters.
	 */
	if (!percpu_ref_tryget(&q->q_usage_counter))
		return 0;
	if (queue_is_mq(q)) {
		ret = blk_mq_poll(q, cookie, iob, flags);
	} else {
		struct gendisk *disk = q->disk;

		if (disk && disk->fops->poll_bio)
			ret = disk->fops->poll_bio(bio, iob, flags);
	}
	blk_queue_exit(q);
	return ret;
}
EXPORT_SYMBOL_GPL(bio_poll);

/*
 * Helper to implement file_operations.iopoll.  Requires the bio to be stored
 * in iocb->private, and cleared before freeing the bio.
 */
int iocb_bio_iopoll(struct kiocb *kiocb, struct io_comp_batch *iob,
		    unsigned int flags)
{
	struct bio *bio;
	int ret = 0;

	/*
	 * Note: the bio cache only uses SLAB_TYPESAFE_BY_RCU, so bio can
	 * point to a freshly allocated bio at this point.  If that happens
	 * we have a few cases to consider:
	 *
	 *  1) the bio is beeing initialized and bi_bdev is NULL.  We can just
	 *     simply nothing in this case
	 *  2) the bio points to a not poll enabled device.  bio_poll will catch
	 *     this and return 0
	 *  3) the bio points to a poll capable device, including but not
	 *     limited to the one that the original bio pointed to.  In this
	 *     case we will call into the actual poll method and poll for I/O,
	 *     even if we don't need to, but it won't cause harm either.
	 *
	 * For cases 2) and 3) above the RCU grace period ensures that bi_bdev
	 * is still allocated. Because partitions hold a reference to the whole
	 * device bdev and thus disk, the disk is also still valid.  Grabbing
	 * a reference to the queue in bio_poll() ensures the hctxs and requests
	 * are still valid as well.
	 */
	rcu_read_lock();
	bio = READ_ONCE(kiocb->private);
	if (bio)
		ret = bio_poll(bio, iob, flags);
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(iocb_bio_iopoll);

void update_io_ticks(struct block_device *part, unsigned long now, bool end)
{
	unsigned long stamp;
again:
	stamp = READ_ONCE(part->bd_stamp);
	if (unlikely(time_after(now, stamp)) &&
	    likely(try_cmpxchg(&part->bd_stamp, &stamp, now)) &&
	    (end || part_in_flight(part)))
		__part_stat_add(part, io_ticks, now - stamp);

	if (part->bd_partno) {
		part = bdev_whole(part);
		goto again;
	}
}

unsigned long bdev_start_io_acct(struct block_device *bdev, enum req_op op,
				 unsigned long start_time)
{
	part_stat_lock();
	update_io_ticks(bdev, start_time, false);
	part_stat_local_inc(bdev, in_flight[op_is_write(op)]);
	part_stat_unlock();

	return start_time;
}
EXPORT_SYMBOL(bdev_start_io_acct);

/**
 * bio_start_io_acct - start I/O accounting for bio based drivers
 * @bio:	bio to start account for
 *
 * Returns the start time that should be passed back to bio_end_io_acct().
 */
unsigned long bio_start_io_acct(struct bio *bio)
{
	return bdev_start_io_acct(bio->bi_bdev, bio_op(bio), jiffies);
}
EXPORT_SYMBOL_GPL(bio_start_io_acct);

void bdev_end_io_acct(struct block_device *bdev, enum req_op op,
		      unsigned int sectors, unsigned long start_time)
{
	const int sgrp = op_stat_group(op);
	unsigned long now = READ_ONCE(jiffies);
	unsigned long duration = now - start_time;

	part_stat_lock();
	update_io_ticks(bdev, now, true);
	part_stat_inc(bdev, ios[sgrp]);
	part_stat_add(bdev, sectors[sgrp], sectors);
	part_stat_add(bdev, nsecs[sgrp], jiffies_to_nsecs(duration));
	part_stat_local_dec(bdev, in_flight[op_is_write(op)]);
	part_stat_unlock();
}
EXPORT_SYMBOL(bdev_end_io_acct);

void bio_end_io_acct_remapped(struct bio *bio, unsigned long start_time,
			      struct block_device *orig_bdev)
{
	bdev_end_io_acct(orig_bdev, bio_op(bio), bio_sectors(bio), start_time);
}
EXPORT_SYMBOL_GPL(bio_end_io_acct_remapped);

/**
 * blk_lld_busy - Check if underlying low-level drivers of a device are busy
 * @q : the queue of the device being checked
 *
 * Description:
 *    Check if underlying low-level drivers of a device are busy.
 *    If the drivers want to export their busy state, they must set own
 *    exporting function using blk_queue_lld_busy() first.
 *
 *    Basically, this function is used only by request stacking drivers
 *    to stop dispatching requests to underlying devices when underlying
 *    devices are busy.  This behavior helps more I/O merging on the queue
 *    of the request stacking driver and prevents I/O throughput regression
 *    on burst I/O load.
 *
 * Return:
 *    0 - Not busy (The request stacking driver should dispatch request)
 *    1 - Busy (The request stacking driver should stop dispatching request)
 */
int blk_lld_busy(struct request_queue *q)
{
	if (queue_is_mq(q) && q->mq_ops->busy)
		return q->mq_ops->busy(q);

	return 0;
}
EXPORT_SYMBOL_GPL(blk_lld_busy);

int kblockd_schedule_work(struct work_struct *work)
{
	return queue_work(kblockd_workqueue, work);
}
EXPORT_SYMBOL(kblockd_schedule_work);

int kblockd_mod_delayed_work_on(int cpu, struct delayed_work *dwork,
				unsigned long delay)
{
	return mod_delayed_work_on(cpu, kblockd_workqueue, dwork, delay);
}
EXPORT_SYMBOL(kblockd_mod_delayed_work_on);

void blk_start_plug_nr_ios(struct blk_plug *plug, unsigned short nr_ios)
{
	struct task_struct *tsk = current;

	/*
	 * If this is a nested plug, don't actually assign it.
	 */
	if (tsk->plug)
		return;

	plug->mq_list = NULL;
	plug->cached_rq = NULL;
	plug->nr_ios = min_t(unsigned short, nr_ios, BLK_MAX_REQUEST_COUNT);
	plug->rq_count = 0;
	plug->multiple_queues = false;
	plug->has_elevator = false;
	INIT_LIST_HEAD(&plug->cb_list);

	/*
	 * Store ordering should not be needed here, since a potential
	 * preempt will imply a full memory barrier
	 */
	tsk->plug = plug;
}

/**
 * blk_start_plug - initialize blk_plug and track it inside the task_struct
 * @plug:	The &struct blk_plug that needs to be initialized
 *
 * Description:
 *   blk_start_plug() indicates to the block layer an intent by the caller
 *   to submit multiple I/O requests in a batch.  The block layer may use
 *   this hint to defer submitting I/Os from the caller until blk_finish_plug()
 *   is called.  However, the block layer may choose to submit requests
 *   before a call to blk_finish_plug() if the number of queued I/Os
 *   exceeds %BLK_MAX_REQUEST_COUNT, or if the size of the I/O is larger than
 *   %BLK_PLUG_FLUSH_SIZE.  The queued I/Os may also be submitted early if
 *   the task schedules (see below).
 *
 *   Tracking blk_plug inside the task_struct will help with auto-flushing the
 *   pending I/O should the task end up blocking between blk_start_plug() and
 *   blk_finish_plug(). This is important from a performance perspective, but
 *   also ensures that we don't deadlock. For instance, if the task is blocking
 *   for a memory allocation, memory reclaim could end up wanting to free a
 *   page belonging to that request that is currently residing in our private
 *   plug. By flushing the pending I/O when the process goes to sleep, we avoid
 *   this kind of deadlock.
 */
void blk_start_plug(struct blk_plug *plug)
{
	blk_start_plug_nr_ios(plug, 1);
}
EXPORT_SYMBOL(blk_start_plug);

static void flush_plug_callbacks(struct blk_plug *plug, bool from_schedule)
{
	LIST_HEAD(callbacks);

	while (!list_empty(&plug->cb_list)) {
		list_splice_init(&plug->cb_list, &callbacks);

		while (!list_empty(&callbacks)) {
			struct blk_plug_cb *cb = list_first_entry(&callbacks,
							  struct blk_plug_cb,
							  list);
			list_del(&cb->list);
			cb->callback(cb, from_schedule);
		}
	}
}

struct blk_plug_cb *blk_check_plugged(blk_plug_cb_fn unplug, void *data,
				      int size)
{
	struct blk_plug *plug = current->plug;
	struct blk_plug_cb *cb;

	if (!plug)
		return NULL;

	list_for_each_entry(cb, &plug->cb_list, list)
		if (cb->callback == unplug && cb->data == data)
			return cb;

	/* Not currently on the callback list */
	BUG_ON(size < sizeof(*cb));
	cb = kzalloc(size, GFP_ATOMIC);
	if (cb) {
		cb->data = data;
		cb->callback = unplug;
		list_add(&cb->list, &plug->cb_list);
	}
	return cb;
}
EXPORT_SYMBOL(blk_check_plugged);

void __blk_flush_plug(struct blk_plug *plug, bool from_schedule)
{
	if (!list_empty(&plug->cb_list))
		flush_plug_callbacks(plug, from_schedule);
	blk_mq_flush_plug_list(plug, from_schedule);
	/*
	 * Unconditionally flush out cached requests, even if the unplug
	 * event came from schedule. Since we know hold references to the
	 * queue for cached requests, we don't want a blocked task holding
	 * up a queue freeze/quiesce event.
	 */
	if (unlikely(!rq_list_empty(plug->cached_rq)))
		blk_mq_free_plug_rqs(plug);
}

/**
 * blk_finish_plug - mark the end of a batch of submitted I/O
 * @plug:	The &struct blk_plug passed to blk_start_plug()
 *
 * Description:
 * Indicate that a batch of I/O submissions is complete.  This function
 * must be paired with an initial call to blk_start_plug().  The intent
 * is to allow the block layer to optimize I/O submission.  See the
 * documentation for blk_start_plug() for more information.
 */
void blk_finish_plug(struct blk_plug *plug)
{
	if (plug == current->plug) {
		__blk_flush_plug(plug, false);
		current->plug = NULL;
	}
}
EXPORT_SYMBOL(blk_finish_plug);

void blk_io_schedule(void)
{
	/* Prevent hang_check timer from firing at us during very long I/O */
	unsigned long timeout = sysctl_hung_task_timeout_secs * HZ / 2;

	if (timeout)
		io_schedule_timeout(timeout);
	else
		io_schedule();
}
EXPORT_SYMBOL_GPL(blk_io_schedule);

int __init blk_dev_init(void)
{
	BUILD_BUG_ON((__force u32)REQ_OP_LAST >= (1 << REQ_OP_BITS));
	BUILD_BUG_ON(REQ_OP_BITS + REQ_FLAG_BITS > 8 *
			sizeof_field(struct request, cmd_flags));
	BUILD_BUG_ON(REQ_OP_BITS + REQ_FLAG_BITS > 8 *
			sizeof_field(struct bio, bi_opf));

	/* used for unplugging and affects IO latency/throughput - HIGHPRI */
	kblockd_workqueue = alloc_workqueue("kblockd",
					    WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!kblockd_workqueue)
		panic("Failed to create kblockd\n");

	blk_requestq_cachep = kmem_cache_create("request_queue",
			sizeof(struct request_queue), 0, SLAB_PANIC, NULL);

	blk_debugfs_root = debugfs_create_dir("block", NULL);

	return 0;
}
