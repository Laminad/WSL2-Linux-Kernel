/* SPDX-License-Identifier: GPL-2.0-or-later */
/* General filesystem caching backing cache interface
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * NOTE!!! See:
 *
 *	Documentation/filesystems/caching/backend-api.rst
 *
 * for a description of the cache backend interface declared here.
 */

#ifndef _LINUX_FSCACHE_CACHE_H
#define _LINUX_FSCACHE_CACHE_H

#include <linux/fscache.h>

enum fscache_cache_trace;
enum fscache_cookie_trace;
enum fscache_access_trace;

enum fscache_cache_state {
	FSCACHE_CACHE_IS_NOT_PRESENT,	/* No cache is present for this name */
	FSCACHE_CACHE_IS_PREPARING,	/* A cache is preparing to come live */
	FSCACHE_CACHE_IS_ACTIVE,	/* Attached cache is active and can be used */
	FSCACHE_CACHE_GOT_IOERROR,	/* Attached cache stopped on I/O error */
	FSCACHE_CACHE_IS_WITHDRAWN,	/* Attached cache is being withdrawn */
#define NR__FSCACHE_CACHE_STATE (FSCACHE_CACHE_IS_WITHDRAWN + 1)
};

/*
 * Cache cookie.
 */
struct fscache_cache {
	const struct fscache_cache_ops *ops;
	struct list_head	cache_link;	/* Link in cache list */
	void			*cache_priv;	/* Private cache data (or NULL) */
	refcount_t		ref;
	atomic_t		n_volumes;	/* Number of active volumes; */
	atomic_t		n_accesses;	/* Number of in-progress accesses on the cache */
	atomic_t		object_count;	/* no. of live objects in this cache */
<<<<<<< HEAD
	unsigned int		debug_id;
	enum fscache_cache_state state;
	char			*name;
=======
	struct fscache_object	*fsdef;		/* object for the fsdef index */
	unsigned long		flags;
#define FSCACHE_IOERROR		0	/* cache stopped on I/O error */
#define FSCACHE_CACHE_WITHDRAWN	1	/* cache has been withdrawn */
};

extern wait_queue_head_t fscache_cache_cleared_wq;

/*
 * operation to be applied to a cache object
 * - retrieval initiation operations are done in the context of the process
 *   that issued them, and not in an async thread pool
 */
typedef void (*fscache_operation_release_t)(struct fscache_operation *op);
typedef void (*fscache_operation_processor_t)(struct fscache_operation *op);
typedef void (*fscache_operation_cancel_t)(struct fscache_operation *op);

enum fscache_operation_state {
	FSCACHE_OP_ST_BLANK,		/* Op is not yet submitted */
	FSCACHE_OP_ST_INITIALISED,	/* Op is initialised */
	FSCACHE_OP_ST_PENDING,		/* Op is blocked from running */
	FSCACHE_OP_ST_IN_PROGRESS,	/* Op is in progress */
	FSCACHE_OP_ST_COMPLETE,		/* Op is complete */
	FSCACHE_OP_ST_CANCELLED,	/* Op has been cancelled */
	FSCACHE_OP_ST_DEAD		/* Op is now dead */
};

struct fscache_operation {
	struct work_struct	work;		/* record for async ops */
	struct list_head	pend_link;	/* link in object->pending_ops */
	struct fscache_object	*object;	/* object to be operated upon */

	unsigned long		flags;
#define FSCACHE_OP_TYPE		0x000f	/* operation type */
#define FSCACHE_OP_ASYNC	0x0001	/* - async op, processor may sleep for disk */
#define FSCACHE_OP_MYTHREAD	0x0002	/* - processing is done be issuing thread, not pool */
#define FSCACHE_OP_WAITING	4	/* cleared when op is woken */
#define FSCACHE_OP_EXCLUSIVE	5	/* exclusive op, other ops must wait */
#define FSCACHE_OP_DEC_READ_CNT	6	/* decrement object->n_reads on destruction */
#define FSCACHE_OP_UNUSE_COOKIE	7	/* call fscache_unuse_cookie() on completion */
#define FSCACHE_OP_KEEP_FLAGS	0x00f0	/* flags to keep when repurposing an op */

	enum fscache_operation_state state;
	atomic_t		usage;
	unsigned		debug_id;	/* debugging ID */

	/* operation processor callback
	 * - can be NULL if FSCACHE_OP_WAITING is going to be used to perform
	 *   the op in a non-pool thread */
	fscache_operation_processor_t processor;

	/* Operation cancellation cleanup (optional) */
	fscache_operation_cancel_t cancel;

	/* operation releaser */
	fscache_operation_release_t release;
};

extern atomic_t fscache_op_debug_id;
extern void fscache_op_work_func(struct work_struct *work);

extern void fscache_enqueue_operation(struct fscache_operation *);
extern void fscache_op_complete(struct fscache_operation *, bool);
extern void fscache_put_operation(struct fscache_operation *);
extern void fscache_operation_init(struct fscache_cookie *,
				   struct fscache_operation *,
				   fscache_operation_processor_t,
				   fscache_operation_cancel_t,
				   fscache_operation_release_t);

/*
 * data read operation
 */
struct fscache_retrieval {
	struct fscache_operation op;
	struct fscache_cookie	*cookie;	/* The netfs cookie */
	struct address_space	*mapping;	/* netfs pages */
	fscache_rw_complete_t	end_io_func;	/* function to call on I/O completion */
	void			*context;	/* netfs read context (pinned) */
	struct list_head	to_do;		/* list of things to be done by the backend */
	unsigned long		start_time;	/* time at which retrieval started */
	atomic_t		n_pages;	/* number of pages to be retrieved */
};

typedef int (*fscache_page_retrieval_func_t)(struct fscache_retrieval *op,
					     struct page *page,
					     gfp_t gfp);

typedef int (*fscache_pages_retrieval_func_t)(struct fscache_retrieval *op,
					      struct list_head *pages,
					      unsigned *nr_pages,
					      gfp_t gfp);

/**
 * fscache_get_retrieval - Get an extra reference on a retrieval operation
 * @op: The retrieval operation to get a reference on
 *
 * Get an extra reference on a retrieval operation.
 */
static inline
struct fscache_retrieval *fscache_get_retrieval(struct fscache_retrieval *op)
{
	atomic_inc(&op->op.usage);
	return op;
}

/**
 * fscache_enqueue_retrieval - Enqueue a retrieval operation for processing
 * @op: The retrieval operation affected
 *
 * Enqueue a retrieval operation for processing by the FS-Cache thread pool.
 */
static inline void fscache_enqueue_retrieval(struct fscache_retrieval *op)
{
	fscache_enqueue_operation(&op->op);
}

/**
 * fscache_retrieval_complete - Record (partial) completion of a retrieval
 * @op: The retrieval operation affected
 * @n_pages: The number of pages to account for
 */
static inline void fscache_retrieval_complete(struct fscache_retrieval *op,
					      int n_pages)
{
	if (atomic_sub_return_relaxed(n_pages, &op->n_pages) <= 0)
		fscache_op_complete(&op->op, false);
}

/**
 * fscache_put_retrieval - Drop a reference to a retrieval operation
 * @op: The retrieval operation affected
 *
 * Drop a reference to a retrieval operation.
 */
static inline void fscache_put_retrieval(struct fscache_retrieval *op)
{
	fscache_put_operation(&op->op);
}

/*
 * cached page storage work item
 * - used to do three things:
 *   - batch writes to the cache
 *   - do cache writes asynchronously
 *   - defer writes until cache object lookup completion
 */
struct fscache_storage {
	struct fscache_operation op;
	pgoff_t			store_limit;	/* don't write more than this */
>>>>>>> master
};

/*
 * cache operations
 */
struct fscache_cache_ops {
	/* name of cache provider */
	const char *name;

	/* Acquire a volume */
	void (*acquire_volume)(struct fscache_volume *volume);

	/* Free the cache's data attached to a volume */
	void (*free_volume)(struct fscache_volume *volume);

	/* Look up a cookie in the cache */
	bool (*lookup_cookie)(struct fscache_cookie *cookie);

	/* Withdraw an object without any cookie access counts held */
	void (*withdraw_cookie)(struct fscache_cookie *cookie);

	/* Change the size of a data object */
	void (*resize_cookie)(struct netfs_cache_resources *cres,
			      loff_t new_size);

	/* Invalidate an object */
	bool (*invalidate_cookie)(struct fscache_cookie *cookie);

	/* Begin an operation for the netfs lib */
	bool (*begin_operation)(struct netfs_cache_resources *cres,
				enum fscache_want_state want_state);

	/* Prepare to write to a live cache object */
	void (*prepare_to_write)(struct fscache_cookie *cookie);
};

extern struct workqueue_struct *fscache_wq;
extern wait_queue_head_t fscache_clearance_waiters;

/*
 * out-of-line cache backend functions
 */
extern struct rw_semaphore fscache_addremove_sem;
extern struct fscache_cache *fscache_acquire_cache(const char *name);
extern void fscache_relinquish_cache(struct fscache_cache *cache);
extern int fscache_add_cache(struct fscache_cache *cache,
			     const struct fscache_cache_ops *ops,
			     void *cache_priv);
extern void fscache_withdraw_cache(struct fscache_cache *cache);
extern void fscache_withdraw_volume(struct fscache_volume *volume);
extern void fscache_withdraw_cookie(struct fscache_cookie *cookie);

extern void fscache_io_error(struct fscache_cache *cache);

extern void fscache_end_volume_access(struct fscache_volume *volume,
				      struct fscache_cookie *cookie,
				      enum fscache_access_trace why);

extern struct fscache_cookie *fscache_get_cookie(struct fscache_cookie *cookie,
						 enum fscache_cookie_trace where);
extern void fscache_put_cookie(struct fscache_cookie *cookie,
			       enum fscache_cookie_trace where);
extern void fscache_end_cookie_access(struct fscache_cookie *cookie,
				      enum fscache_access_trace why);
extern void fscache_cookie_lookup_negative(struct fscache_cookie *cookie);
extern void fscache_resume_after_invalidation(struct fscache_cookie *cookie);
extern void fscache_caching_failed(struct fscache_cookie *cookie);
extern bool fscache_wait_for_operation(struct netfs_cache_resources *cred,
				       enum fscache_want_state state);

/**
 * fscache_cookie_state - Read the state of a cookie
 * @cookie: The cookie to query
 *
 * Get the state of a cookie, imposing an ordering between the cookie contents
 * and the state value.  Paired with fscache_set_cookie_state().
 */
static inline
enum fscache_cookie_state fscache_cookie_state(struct fscache_cookie *cookie)
{
	return smp_load_acquire(&cookie->state);
}

/**
 * fscache_get_key - Get a pointer to the cookie key
 * @cookie: The cookie to query
 *
 * Return a pointer to the where a cookie's key is stored.
 */
static inline void *fscache_get_key(struct fscache_cookie *cookie)
{
	if (cookie->key_len <= sizeof(cookie->inline_key))
		return cookie->inline_key;
	else
		return cookie->key;
}

static inline struct fscache_cookie *fscache_cres_cookie(struct netfs_cache_resources *cres)
{
	return cres->cache_priv;
}

/**
 * fscache_count_object - Tell fscache that an object has been added
 * @cache: The cache to account to
 *
 * Tell fscache that an object has been added to the cache.  This prevents the
 * cache from tearing down the cache structure until the object is uncounted.
 */
static inline void fscache_count_object(struct fscache_cache *cache)
{
	atomic_inc(&cache->object_count);
}

/**
 * fscache_uncount_object - Tell fscache that an object has been removed
 * @cache: The cache to account to
 *
 * Tell fscache that an object has been removed from the cache and will no
 * longer be accessed.  After this point, the cache cookie may be destroyed.
 */
static inline void fscache_uncount_object(struct fscache_cache *cache)
{
	if (atomic_dec_and_test(&cache->object_count))
		wake_up_all(&fscache_clearance_waiters);
}

/**
 * fscache_wait_for_objects - Wait for all objects to be withdrawn
 * @cache: The cache to query
 *
 * Wait for all extant objects in a cache to finish being withdrawn
 * and go away.
 */
static inline void fscache_wait_for_objects(struct fscache_cache *cache)
{
	wait_event(fscache_clearance_waiters,
		   atomic_read(&cache->object_count) == 0);
}

#ifdef CONFIG_FSCACHE_STATS
extern atomic_t fscache_n_read;
extern atomic_t fscache_n_write;
extern atomic_t fscache_n_no_write_space;
extern atomic_t fscache_n_no_create_space;
extern atomic_t fscache_n_culled;
#define fscache_count_read() atomic_inc(&fscache_n_read)
#define fscache_count_write() atomic_inc(&fscache_n_write)
#define fscache_count_no_write_space() atomic_inc(&fscache_n_no_write_space)
#define fscache_count_no_create_space() atomic_inc(&fscache_n_no_create_space)
#define fscache_count_culled() atomic_inc(&fscache_n_culled)
#else
#define fscache_count_read() do {} while(0)
#define fscache_count_write() do {} while(0)
#define fscache_count_no_write_space() do {} while(0)
#define fscache_count_no_create_space() do {} while(0)
#define fscache_count_culled() do {} while(0)
#endif

#endif /* _LINUX_FSCACHE_CACHE_H */
