/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 */

#ifndef BTRFS_CTREE_H
#define BTRFS_CTREE_H

#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/backing-dev.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <trace/events/btrfs.h>
#include <asm/unaligned.h>
#include <linux/pagemap.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/sizes.h>
#include <linux/dynamic_debug.h>
#include <linux/refcount.h>
#include <linux/crc32c.h>
#include <linux/iomap.h>
#include <linux/fscrypt.h>
#include "extent-io-tree.h"
#include "extent_io.h"
#include "extent_map.h"
#include "async-thread.h"
#include "block-rsv.h"
#include "locking.h"
#include "misc.h"
#include "fs.h"

struct btrfs_trans_handle;
struct btrfs_transaction;
struct btrfs_pending_snapshot;
<<<<<<< HEAD
struct btrfs_delayed_ref_root;
struct btrfs_space_info;
struct btrfs_block_group;
=======
extern struct kmem_cache *btrfs_trans_handle_cachep;
extern struct kmem_cache *btrfs_bit_radix_cachep;
extern struct kmem_cache *btrfs_path_cachep;
extern struct kmem_cache *btrfs_free_space_cachep;
extern struct kmem_cache *btrfs_free_space_bitmap_cachep;
>>>>>>> master
struct btrfs_ordered_sum;
struct btrfs_ref;
struct btrfs_bio;
struct btrfs_ioctl_encoded_io_args;
struct btrfs_device;
struct btrfs_fs_devices;
struct btrfs_balance_control;
struct btrfs_delayed_root;
struct reloc_control;

/* Read ahead values for struct btrfs_path.reada */
enum {
	READA_NONE,
	READA_BACK,
	READA_FORWARD,
	/*
	 * Similar to READA_FORWARD but unlike it:
	 *
	 * 1) It will trigger readahead even for leaves that are not close to
	 *    each other on disk;
	 * 2) It also triggers readahead for nodes;
	 * 3) During a search, even when a node or leaf is already in memory, it
	 *    will still trigger readahead for other nodes and leaves that follow
	 *    it.
	 *
	 * This is meant to be used only when we know we are iterating over the
	 * entire tree or a very large part of it.
	 */
	READA_FORWARD_ALWAYS,
};

/*
 * btrfs_paths remember the path taken from the root down to the leaf.
 * level 0 is always the leaf, and nodes[1...BTRFS_MAX_LEVEL] will point
 * to any other levels that are present.
 *
 * The slots array records the index of the item or block pointer
 * used while walking the tree.
 */
struct btrfs_path {
	struct extent_buffer *nodes[BTRFS_MAX_LEVEL];
	int slots[BTRFS_MAX_LEVEL];
	/* if there is real range locking, this locks field will change */
	u8 locks[BTRFS_MAX_LEVEL];
	u8 reada;
	/* keep some upper locks as we walk down */
	u8 lowest_level;

	/*
	 * set by btrfs_split_item, tells search_slot to keep all locks
	 * and to force calls to keep space in the nodes
	 */
	unsigned int search_for_split:1;
	unsigned int keep_locks:1;
	unsigned int skip_locking:1;
	unsigned int search_commit_root:1;
	unsigned int need_commit_sem:1;
	unsigned int skip_release_on_error:1;
	/*
	 * Indicate that new item (btrfs_search_slot) is extending already
	 * existing item and ins_len contains only the data size and not item
	 * header (ie. sizeof(struct btrfs_item) is not included).
	 */
	unsigned int search_for_extension:1;
	/* Stop search if any locks need to be taken (for read) */
	unsigned int nowait:1;
};

/*
 * The state of btrfs root
 */
enum {
	/*
	 * btrfs_record_root_in_trans is a multi-step process, and it can race
	 * with the balancing code.   But the race is very small, and only the
	 * first time the root is added to each transaction.  So IN_TRANS_SETUP
	 * is used to tell us when more checks are required
	 */
	BTRFS_ROOT_IN_TRANS_SETUP,

	/*
	 * Set if tree blocks of this root can be shared by other roots.
	 * Only subvolume trees and their reloc trees have this bit set.
	 * Conflicts with TRACK_DIRTY bit.
	 *
	 * This affects two things:
	 *
	 * - How balance works
	 *   For shareable roots, we need to use reloc tree and do path
	 *   replacement for balance, and need various pre/post hooks for
	 *   snapshot creation to handle them.
	 *
	 *   While for non-shareable trees, we just simply do a tree search
	 *   with COW.
	 *
	 * - How dirty roots are tracked
	 *   For shareable roots, btrfs_record_root_in_trans() is needed to
	 *   track them, while non-subvolume roots have TRACK_DIRTY bit, they
	 *   don't need to set this manually.
	 */
	BTRFS_ROOT_SHAREABLE,
	BTRFS_ROOT_TRACK_DIRTY,
	BTRFS_ROOT_IN_RADIX,
	BTRFS_ROOT_ORPHAN_ITEM_INSERTED,
	BTRFS_ROOT_DEFRAG_RUNNING,
	BTRFS_ROOT_FORCE_COW,
	BTRFS_ROOT_MULTI_LOG_TASKS,
	BTRFS_ROOT_DIRTY,
	BTRFS_ROOT_DELETING,

	/*
	 * Reloc tree is orphan, only kept here for qgroup delayed subtree scan
	 *
	 * Set for the subvolume tree owning the reloc tree.
	 */
	BTRFS_ROOT_DEAD_RELOC_TREE,
	/* Mark dead root stored on device whose cleanup needs to be resumed */
	BTRFS_ROOT_DEAD_TREE,
	/* The root has a log tree. Used for subvolume roots and the tree root. */
	BTRFS_ROOT_HAS_LOG_TREE,
	/* Qgroup flushing is in progress */
	BTRFS_ROOT_QGROUP_FLUSHING,
	/* We started the orphan cleanup for this root. */
	BTRFS_ROOT_ORPHAN_CLEANUP,
	/* This root has a drop operation that was started previously. */
	BTRFS_ROOT_UNFINISHED_DROP,
	/* This reloc root needs to have its buffers lockdep class reset. */
	BTRFS_ROOT_RESET_LOCKDEP_CLASS,
};

/*
 * Record swapped tree blocks of a subvolume tree for delayed subtree trace
 * code. For detail check comment in fs/btrfs/qgroup.c.
 */
struct btrfs_qgroup_swapped_blocks {
	spinlock_t lock;
	/* RM_EMPTY_ROOT() of above blocks[] */
	bool swapped;
	struct rb_root blocks[BTRFS_MAX_LEVEL];
};

/*
 * in ram representation of the tree.  extent_root is used for all allocations
 * and for the extent tree extent_root root.
 */
struct btrfs_root {
	struct rb_node rb_node;

	struct extent_buffer *node;

	struct extent_buffer *commit_root;
	struct btrfs_root *log_root;
	struct btrfs_root *reloc_root;

	unsigned long state;
	struct btrfs_root_item root_item;
	struct btrfs_key root_key;
	struct btrfs_fs_info *fs_info;
	struct extent_io_tree dirty_log_pages;

	struct mutex objectid_mutex;

	spinlock_t accounting_lock;
	struct btrfs_block_rsv *block_rsv;

	struct mutex log_mutex;
	wait_queue_head_t log_writer_wait;
	wait_queue_head_t log_commit_wait[2];
	struct list_head log_ctxs[2];
	/* Used only for log trees of subvolumes, not for the log root tree */
	atomic_t log_writers;
	atomic_t log_commit[2];
	/* Used only for log trees of subvolumes, not for the log root tree */
	atomic_t log_batch;
	int log_transid;
	/* No matter the commit succeeds or not*/
	int log_transid_committed;
	/* Just be updated when the commit succeeds. */
	int last_log_commit;
	pid_t log_start_pid;

	u64 last_trans;

	u32 type;

	u64 free_objectid;

	struct btrfs_key defrag_progress;
	struct btrfs_key defrag_max;

	/* The dirty list is only used by non-shareable roots */
	struct list_head dirty_list;

	struct list_head root_list;

	spinlock_t log_extents_lock[2];
	struct list_head logged_list[2];

	spinlock_t inode_lock;
	/* red-black tree that keeps track of in-memory inodes */
	struct rb_root inode_tree;

	/*
	 * radix tree that keeps track of delayed nodes of every inode,
	 * protected by inode_lock
	 */
	struct radix_tree_root delayed_nodes_tree;
	/*
	 * right now this just gets used so that a root has its own devid
	 * for stat.  It may be used for more later
	 */
	dev_t anon_dev;

	spinlock_t root_item_lock;
	refcount_t refs;

	struct mutex delalloc_mutex;
	spinlock_t delalloc_lock;
	/*
	 * all of the inodes that have delalloc bytes.  It is possible for
	 * this list to be empty even when there is still dirty data=ordered
	 * extents waiting to finish IO.
	 */
	struct list_head delalloc_inodes;
	struct list_head delalloc_root;
	u64 nr_delalloc_inodes;

	struct mutex ordered_extent_mutex;
	/*
	 * this is used by the balancing code to wait for all the pending
	 * ordered extents
	 */
	spinlock_t ordered_extent_lock;

	/*
	 * all of the data=ordered extents pending writeback
	 * these can span multiple transactions and basically include
	 * every dirty data page that isn't from nodatacow
	 */
	struct list_head ordered_extents;
	struct list_head ordered_root;
	u64 nr_ordered_extents;

	/*
	 * Not empty if this subvolume root has gone through tree block swap
	 * (relocation)
	 *
	 * Will be used by reloc_control::dirty_subvol_roots.
	 */
	struct list_head reloc_dirty_list;

	/*
	 * Number of currently running SEND ioctls to prevent
	 * manipulation with the read-only status via SUBVOL_SETFLAGS
	 */
	int send_in_progress;
	/*
	 * Number of currently running deduplication operations that have a
	 * destination inode belonging to this root. Protected by the lock
	 * root_item_lock.
	 */
	int dedupe_in_progress;
	/* For exclusion of snapshot creation and nocow writes */
	struct btrfs_drew_lock snapshot_lock;

	atomic_t snapshot_force_cow;

	/* For qgroup metadata reserved space */
	spinlock_t qgroup_meta_rsv_lock;
	u64 qgroup_meta_rsv_pertrans;
	u64 qgroup_meta_rsv_prealloc;
	wait_queue_head_t qgroup_flush_wait;

	/* Number of active swapfiles */
	atomic_t nr_swapfiles;

	/* Record pairs of swapped blocks for qgroup */
	struct btrfs_qgroup_swapped_blocks swapped_blocks;

	/* Used only by log trees, when logging csum items */
	struct extent_io_tree log_csum_range;

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
	u64 alloc_bytenr;
#endif

#ifdef CONFIG_BTRFS_DEBUG
	struct list_head leak_list;
#endif
};

static inline bool btrfs_root_readonly(const struct btrfs_root *root)
{
	/* Byte-swap the constant at compile time, root_item::flags is LE */
	return (root->root_item.flags & cpu_to_le64(BTRFS_ROOT_SUBVOL_RDONLY)) != 0;
}

static inline bool btrfs_root_dead(const struct btrfs_root *root)
{
	/* Byte-swap the constant at compile time, root_item::flags is LE */
	return (root->root_item.flags & cpu_to_le64(BTRFS_ROOT_SUBVOL_DEAD)) != 0;
}

static inline u64 btrfs_root_id(const struct btrfs_root *root)
{
	return root->root_key.objectid;
}

/*
 * Structure that conveys information about an extent that is going to replace
 * all the extents in a file range.
 */
struct btrfs_replace_extent_info {
	u64 disk_offset;
	u64 disk_len;
	u64 data_offset;
	u64 data_len;
	u64 file_offset;
	/* Pointer to a file extent item of type regular or prealloc. */
	char *extent_buf;
	/*
	 * Set to true when attempting to replace a file range with a new extent
	 * described by this structure, set to false when attempting to clone an
	 * existing extent into a file range.
	 */
	bool is_new_extent;
	/* Indicate if we should update the inode's mtime and ctime. */
	bool update_times;
	/* Meaningful only if is_new_extent is true. */
	int qgroup_reserved;
	/*
	 * Meaningful only if is_new_extent is true.
	 * Used to track how many extent items we have already inserted in a
	 * subvolume tree that refer to the extent described by this structure,
	 * so that we know when to create a new delayed ref or update an existing
	 * one.
	 */
	int insertions;
};

/* Arguments for btrfs_drop_extents() */
struct btrfs_drop_extents_args {
	/* Input parameters */

	/*
	 * If NULL, btrfs_drop_extents() will allocate and free its own path.
	 * If 'replace_extent' is true, this must not be NULL. Also the path
	 * is always released except if 'replace_extent' is true and
	 * btrfs_drop_extents() sets 'extent_inserted' to true, in which case
	 * the path is kept locked.
	 */
	struct btrfs_path *path;
	/* Start offset of the range to drop extents from */
	u64 start;
	/* End (exclusive, last byte + 1) of the range to drop extents from */
	u64 end;
	/* If true drop all the extent maps in the range */
	bool drop_cache;
	/*
	 * If true it means we want to insert a new extent after dropping all
	 * the extents in the range. If this is true, the 'extent_item_size'
	 * parameter must be set as well and the 'extent_inserted' field will
	 * be set to true by btrfs_drop_extents() if it could insert the new
	 * extent.
	 * Note: when this is set to true the path must not be NULL.
	 */
	bool replace_extent;
	/*
	 * Used if 'replace_extent' is true. Size of the file extent item to
	 * insert after dropping all existing extents in the range
	 */
	u32 extent_item_size;

	/* Output parameters */

	/*
	 * Set to the minimum between the input parameter 'end' and the end
	 * (exclusive, last byte + 1) of the last dropped extent. This is always
	 * set even if btrfs_drop_extents() returns an error.
	 */
	u64 drop_end;
	/*
	 * The number of allocated bytes found in the range. This can be smaller
	 * than the range's length when there are holes in the range.
	 */
	u64 bytes_found;
	/*
	 * Only set if 'replace_extent' is true. Set to true if we were able
	 * to insert a replacement extent after dropping all extents in the
	 * range, otherwise set to false by btrfs_drop_extents().
	 * Also, if btrfs_drop_extents() has set this to true it means it
	 * returned with the path locked, otherwise if it has set this to
	 * false it has returned with the path released.
	 */
	bool extent_inserted;
};

struct btrfs_file_private {
	void *filldir_buf;
	u64 last_index;
	struct extent_state *llseek_cached_state;
};

static inline u32 BTRFS_LEAF_DATA_SIZE(const struct btrfs_fs_info *info)
{
	return info->nodesize - sizeof(struct btrfs_header);
}

static inline u32 BTRFS_MAX_ITEM_SIZE(const struct btrfs_fs_info *info)
{
	return BTRFS_LEAF_DATA_SIZE(info) - sizeof(struct btrfs_item);
}

static inline u32 BTRFS_NODEPTRS_PER_BLOCK(const struct btrfs_fs_info *info)
{
	return BTRFS_LEAF_DATA_SIZE(info) / sizeof(struct btrfs_key_ptr);
}

static inline u32 BTRFS_MAX_XATTR_SIZE(const struct btrfs_fs_info *info)
{
	return BTRFS_MAX_ITEM_SIZE(info) - sizeof(struct btrfs_dir_item);
}

#define BTRFS_BYTES_TO_BLKS(fs_info, bytes) \
				((bytes) >> (fs_info)->sectorsize_bits)

static inline u32 btrfs_crc32c(u32 crc, const void *address, unsigned length)
{
	return crc32c(crc, address, length);
}

static inline void btrfs_crc32c_final(u32 crc, u8 *result)
{
	put_unaligned_le32(~crc, result);
}

static inline u64 btrfs_name_hash(const char *name, int len)
{
       return crc32c((u32)~1, name, len);
}

/*
 * Figure the key offset of an extended inode ref
 */
static inline u64 btrfs_extref_hash(u64 parent_objectid, const char *name,
                                   int len)
{
       return (u64) crc32c(parent_objectid, name, len);
}

static inline gfp_t btrfs_alloc_write_mask(struct address_space *mapping)
{
	return mapping_gfp_constraint(mapping, ~__GFP_FS);
}

<<<<<<< HEAD
=======
/* extent-tree.c */

enum btrfs_inline_ref_type {
	BTRFS_REF_TYPE_INVALID =	 0,
	BTRFS_REF_TYPE_BLOCK =		 1,
	BTRFS_REF_TYPE_DATA =		 2,
	BTRFS_REF_TYPE_ANY =		 3,
};

int btrfs_get_extent_inline_ref_type(const struct extent_buffer *eb,
				     struct btrfs_extent_inline_ref *iref,
				     enum btrfs_inline_ref_type is_data);

u64 btrfs_csum_bytes_to_leaves(struct btrfs_fs_info *fs_info, u64 csum_bytes);

static inline u64 btrfs_calc_trans_metadata_size(struct btrfs_fs_info *fs_info,
						 unsigned num_items)
{
	return (u64)fs_info->nodesize * BTRFS_MAX_LEVEL * 2 * num_items;
}

/*
 * Doing a truncate won't result in new nodes or leaves, just what we need for
 * COW.
 */
static inline u64 btrfs_calc_trunc_metadata_size(struct btrfs_fs_info *fs_info,
						 unsigned num_items)
{
	return (u64)fs_info->nodesize * BTRFS_MAX_LEVEL * num_items;
}

int btrfs_should_throttle_delayed_refs(struct btrfs_trans_handle *trans,
				       struct btrfs_fs_info *fs_info);
int btrfs_check_space_for_delayed_refs(struct btrfs_trans_handle *trans,
				       struct btrfs_fs_info *fs_info);
void btrfs_dec_block_group_reservations(struct btrfs_fs_info *fs_info,
					 const u64 start);
void btrfs_wait_block_group_reservations(struct btrfs_block_group_cache *bg);
bool btrfs_inc_nocow_writers(struct btrfs_fs_info *fs_info, u64 bytenr);
void btrfs_dec_nocow_writers(struct btrfs_fs_info *fs_info, u64 bytenr);
void btrfs_wait_nocow_writers(struct btrfs_block_group_cache *bg);
void btrfs_put_block_group(struct btrfs_block_group_cache *cache);
int btrfs_run_delayed_refs(struct btrfs_trans_handle *trans,
			   unsigned long count);
int btrfs_async_run_delayed_refs(struct btrfs_fs_info *fs_info,
				 unsigned long count, u64 transid, int wait);
int btrfs_lookup_data_extent(struct btrfs_fs_info *fs_info, u64 start, u64 len);
int btrfs_lookup_extent_info(struct btrfs_trans_handle *trans,
			     struct btrfs_fs_info *fs_info, u64 bytenr,
			     u64 offset, int metadata, u64 *refs, u64 *flags);
int btrfs_pin_extent(struct btrfs_fs_info *fs_info,
		     u64 bytenr, u64 num, int reserved);
int btrfs_pin_extent_for_log_replay(struct btrfs_fs_info *fs_info,
				    u64 bytenr, u64 num_bytes);
int btrfs_exclude_logged_extents(struct btrfs_fs_info *fs_info,
				 struct extent_buffer *eb);
int btrfs_cross_ref_exist(struct btrfs_root *root,
			  u64 objectid, u64 offset, u64 bytenr);
struct btrfs_block_group_cache *btrfs_lookup_block_group(
						 struct btrfs_fs_info *info,
						 u64 bytenr);
void btrfs_get_block_group(struct btrfs_block_group_cache *cache);
void btrfs_put_block_group(struct btrfs_block_group_cache *cache);
struct extent_buffer *btrfs_alloc_tree_block(struct btrfs_trans_handle *trans,
					     struct btrfs_root *root,
					     u64 parent, u64 root_objectid,
					     const struct btrfs_disk_key *key,
					     int level, u64 hint,
					     u64 empty_size);
void btrfs_free_tree_block(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   struct extent_buffer *buf,
			   u64 parent, int last_ref);
int btrfs_alloc_reserved_file_extent(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root, u64 owner,
				     u64 offset, u64 ram_bytes,
				     struct btrfs_key *ins);
int btrfs_alloc_logged_file_extent(struct btrfs_trans_handle *trans,
				   u64 root_objectid, u64 owner, u64 offset,
				   struct btrfs_key *ins);
int btrfs_reserve_extent(struct btrfs_root *root, u64 ram_bytes, u64 num_bytes,
			 u64 min_alloc_size, u64 empty_size, u64 hint_byte,
			 struct btrfs_key *ins, int is_data, int delalloc);
int btrfs_inc_ref(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		  struct extent_buffer *buf, int full_backref);
int btrfs_dec_ref(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		  struct extent_buffer *buf, int full_backref);
int btrfs_set_disk_extent_flags(struct btrfs_trans_handle *trans,
				struct btrfs_fs_info *fs_info,
				u64 bytenr, u64 num_bytes, u64 flags,
				int level, int is_data);
int btrfs_free_extent(struct btrfs_trans_handle *trans,
		      struct btrfs_root *root,
		      u64 bytenr, u64 num_bytes, u64 parent, u64 root_objectid,
		      u64 owner, u64 offset);

int btrfs_free_reserved_extent(struct btrfs_fs_info *fs_info,
			       u64 start, u64 len, int delalloc);
int btrfs_free_and_pin_reserved_extent(struct btrfs_fs_info *fs_info,
				       u64 start, u64 len);
void btrfs_prepare_extent_commit(struct btrfs_fs_info *fs_info);
int btrfs_finish_extent_commit(struct btrfs_trans_handle *trans);
int btrfs_inc_extent_ref(struct btrfs_trans_handle *trans,
			 struct btrfs_root *root,
			 u64 bytenr, u64 num_bytes, u64 parent,
			 u64 root_objectid, u64 owner, u64 offset);

int btrfs_start_dirty_block_groups(struct btrfs_trans_handle *trans);
int btrfs_write_dirty_block_groups(struct btrfs_trans_handle *trans,
				   struct btrfs_fs_info *fs_info);
int btrfs_setup_space_cache(struct btrfs_trans_handle *trans,
			    struct btrfs_fs_info *fs_info);
int btrfs_extent_readonly(struct btrfs_fs_info *fs_info, u64 bytenr);
int btrfs_free_block_groups(struct btrfs_fs_info *info);
int btrfs_read_block_groups(struct btrfs_fs_info *info);
int btrfs_can_relocate(struct btrfs_fs_info *fs_info, u64 bytenr);
int btrfs_make_block_group(struct btrfs_trans_handle *trans,
			   u64 bytes_used, u64 type, u64 chunk_offset,
			   u64 size);
void btrfs_add_raid_kobjects(struct btrfs_fs_info *fs_info);
struct btrfs_trans_handle *btrfs_start_trans_remove_block_group(
				struct btrfs_fs_info *fs_info,
				const u64 chunk_offset);
int btrfs_remove_block_group(struct btrfs_trans_handle *trans,
			     u64 group_start, struct extent_map *em);
void btrfs_delete_unused_bgs(struct btrfs_fs_info *fs_info);
void btrfs_get_block_group_trimming(struct btrfs_block_group_cache *cache);
void btrfs_put_block_group_trimming(struct btrfs_block_group_cache *cache);
void btrfs_create_pending_block_groups(struct btrfs_trans_handle *trans);
u64 btrfs_data_alloc_profile(struct btrfs_fs_info *fs_info);
u64 btrfs_metadata_alloc_profile(struct btrfs_fs_info *fs_info);
u64 btrfs_system_alloc_profile(struct btrfs_fs_info *fs_info);
void btrfs_clear_space_info_full(struct btrfs_fs_info *info);

enum btrfs_reserve_flush_enum {
	/* If we are in the transaction, we can't flush anything.*/
	BTRFS_RESERVE_NO_FLUSH,
	/*
	 * Flushing delalloc may cause deadlock somewhere, in this
	 * case, use FLUSH LIMIT
	 */
	BTRFS_RESERVE_FLUSH_LIMIT,
	BTRFS_RESERVE_FLUSH_ALL,
};

enum btrfs_flush_state {
	FLUSH_DELAYED_ITEMS_NR	=	1,
	FLUSH_DELAYED_ITEMS	=	2,
	FLUSH_DELALLOC		=	3,
	FLUSH_DELALLOC_WAIT	=	4,
	ALLOC_CHUNK		=	5,
	COMMIT_TRANS		=	6,
};

int btrfs_alloc_data_chunk_ondemand(struct btrfs_inode *inode, u64 bytes);
int btrfs_check_data_free_space(struct inode *inode,
			struct extent_changeset **reserved, u64 start, u64 len);
void btrfs_free_reserved_data_space(struct inode *inode,
			struct extent_changeset *reserved, u64 start, u64 len);
void btrfs_delalloc_release_space(struct inode *inode,
				  struct extent_changeset *reserved,
				  u64 start, u64 len, bool qgroup_free);
void btrfs_free_reserved_data_space_noquota(struct inode *inode, u64 start,
					    u64 len);
void btrfs_trans_release_chunk_metadata(struct btrfs_trans_handle *trans);
int btrfs_subvolume_reserve_metadata(struct btrfs_root *root,
				     struct btrfs_block_rsv *rsv,
				     int nitems, bool use_global_rsv);
void btrfs_subvolume_release_metadata(struct btrfs_fs_info *fs_info,
				      struct btrfs_block_rsv *rsv);
void btrfs_delalloc_release_extents(struct btrfs_inode *inode, u64 num_bytes);

int btrfs_delalloc_reserve_metadata(struct btrfs_inode *inode, u64 num_bytes);
void btrfs_delalloc_release_metadata(struct btrfs_inode *inode, u64 num_bytes,
				     bool qgroup_free);
int btrfs_delalloc_reserve_space(struct inode *inode,
			struct extent_changeset **reserved, u64 start, u64 len);
void btrfs_init_block_rsv(struct btrfs_block_rsv *rsv, unsigned short type);
struct btrfs_block_rsv *btrfs_alloc_block_rsv(struct btrfs_fs_info *fs_info,
					      unsigned short type);
void btrfs_init_metadata_block_rsv(struct btrfs_fs_info *fs_info,
				   struct btrfs_block_rsv *rsv,
				   unsigned short type);
void btrfs_free_block_rsv(struct btrfs_fs_info *fs_info,
			  struct btrfs_block_rsv *rsv);
int btrfs_block_rsv_add(struct btrfs_root *root,
			struct btrfs_block_rsv *block_rsv, u64 num_bytes,
			enum btrfs_reserve_flush_enum flush);
int btrfs_block_rsv_check(struct btrfs_block_rsv *block_rsv, int min_factor);
int btrfs_block_rsv_refill(struct btrfs_root *root,
			   struct btrfs_block_rsv *block_rsv, u64 min_reserved,
			   enum btrfs_reserve_flush_enum flush);
int btrfs_block_rsv_migrate(struct btrfs_block_rsv *src_rsv,
			    struct btrfs_block_rsv *dst_rsv, u64 num_bytes,
			    int update_size);
int btrfs_cond_migrate_bytes(struct btrfs_fs_info *fs_info,
			     struct btrfs_block_rsv *dest, u64 num_bytes,
			     int min_factor);
void btrfs_block_rsv_release(struct btrfs_fs_info *fs_info,
			     struct btrfs_block_rsv *block_rsv,
			     u64 num_bytes);
int btrfs_inc_block_group_ro(struct btrfs_block_group_cache *cache);
void btrfs_dec_block_group_ro(struct btrfs_block_group_cache *cache);
void btrfs_put_block_group_cache(struct btrfs_fs_info *info);
u64 btrfs_account_ro_block_groups_free_space(struct btrfs_space_info *sinfo);
>>>>>>> master
int btrfs_error_unpin_extent_range(struct btrfs_fs_info *fs_info,
				   u64 start, u64 end);
int btrfs_discard_extent(struct btrfs_fs_info *fs_info, u64 bytenr,
			 u64 num_bytes, u64 *actual_bytes);
int btrfs_trim_fs(struct btrfs_fs_info *fs_info, struct fstrim_range *range);

/* ctree.c */
int __init btrfs_ctree_init(void);
void __cold btrfs_ctree_exit(void);

int btrfs_bin_search(struct extent_buffer *eb, int first_slot,
		     const struct btrfs_key *key, int *slot);

int __pure btrfs_comp_cpu_keys(const struct btrfs_key *k1, const struct btrfs_key *k2);
int btrfs_previous_item(struct btrfs_root *root,
			struct btrfs_path *path, u64 min_objectid,
			int type);
int btrfs_previous_extent_item(struct btrfs_root *root,
			struct btrfs_path *path, u64 min_objectid);
void btrfs_set_item_key_safe(struct btrfs_trans_handle *trans,
			     struct btrfs_path *path,
			     const struct btrfs_key *new_key);
struct extent_buffer *btrfs_root_node(struct btrfs_root *root);
int btrfs_find_next_key(struct btrfs_root *root, struct btrfs_path *path,
			struct btrfs_key *key, int lowest_level,
			u64 min_trans);
int btrfs_search_forward(struct btrfs_root *root, struct btrfs_key *min_key,
			 struct btrfs_path *path,
			 u64 min_trans);
struct extent_buffer *btrfs_read_node_slot(struct extent_buffer *parent,
					   int slot);

int btrfs_cow_block(struct btrfs_trans_handle *trans,
		    struct btrfs_root *root, struct extent_buffer *buf,
		    struct extent_buffer *parent, int parent_slot,
		    struct extent_buffer **cow_ret,
		    enum btrfs_lock_nesting nest);
int btrfs_copy_root(struct btrfs_trans_handle *trans,
		      struct btrfs_root *root,
		      struct extent_buffer *buf,
		      struct extent_buffer **cow_ret, u64 new_root_objectid);
int btrfs_block_can_be_shared(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root,
			      struct extent_buffer *buf);
int btrfs_del_ptr(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		  struct btrfs_path *path, int level, int slot);
void btrfs_extend_item(struct btrfs_trans_handle *trans,
		       struct btrfs_path *path, u32 data_size);
void btrfs_truncate_item(struct btrfs_trans_handle *trans,
			 struct btrfs_path *path, u32 new_size, int from_end);
int btrfs_split_item(struct btrfs_trans_handle *trans,
		     struct btrfs_root *root,
		     struct btrfs_path *path,
		     const struct btrfs_key *new_key,
		     unsigned long split_offset);
int btrfs_duplicate_item(struct btrfs_trans_handle *trans,
			 struct btrfs_root *root,
			 struct btrfs_path *path,
			 const struct btrfs_key *new_key);
int btrfs_find_item(struct btrfs_root *fs_root, struct btrfs_path *path,
		u64 inum, u64 ioff, u8 key_type, struct btrfs_key *found_key);
int btrfs_search_slot(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		      const struct btrfs_key *key, struct btrfs_path *p,
		      int ins_len, int cow);
int btrfs_search_old_slot(struct btrfs_root *root, const struct btrfs_key *key,
			  struct btrfs_path *p, u64 time_seq);
int btrfs_search_slot_for_read(struct btrfs_root *root,
			       const struct btrfs_key *key,
			       struct btrfs_path *p, int find_higher,
			       int return_any);
int btrfs_realloc_node(struct btrfs_trans_handle *trans,
		       struct btrfs_root *root, struct extent_buffer *parent,
		       int start_slot, u64 *last_ret,
		       struct btrfs_key *progress);
void btrfs_release_path(struct btrfs_path *p);
struct btrfs_path *btrfs_alloc_path(void);
void btrfs_free_path(struct btrfs_path *p);

int btrfs_del_items(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		   struct btrfs_path *path, int slot, int nr);
static inline int btrfs_del_item(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path)
{
	return btrfs_del_items(trans, root, path, path->slots[0], 1);
}

/*
 * Describes a batch of items to insert in a btree. This is used by
 * btrfs_insert_empty_items().
 */
struct btrfs_item_batch {
	/*
	 * Pointer to an array containing the keys of the items to insert (in
	 * sorted order).
	 */
	const struct btrfs_key *keys;
	/* Pointer to an array containing the data size for each item to insert. */
	const u32 *data_sizes;
	/*
	 * The sum of data sizes for all items. The caller can compute this while
	 * setting up the data_sizes array, so it ends up being more efficient
	 * than having btrfs_insert_empty_items() or setup_item_for_insert()
	 * doing it, as it would avoid an extra loop over a potentially large
	 * array, and in the case of setup_item_for_insert(), we would be doing
	 * it while holding a write lock on a leaf and often on upper level nodes
	 * too, unnecessarily increasing the size of a critical section.
	 */
	u32 total_data_size;
	/* Size of the keys and data_sizes arrays (number of items in the batch). */
	int nr;
};

void btrfs_setup_item_for_insert(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 const struct btrfs_key *key,
				 u32 data_size);
int btrfs_insert_item(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		      const struct btrfs_key *key, void *data, u32 data_size);
int btrfs_insert_empty_items(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     struct btrfs_path *path,
			     const struct btrfs_item_batch *batch);

static inline int btrfs_insert_empty_item(struct btrfs_trans_handle *trans,
					  struct btrfs_root *root,
					  struct btrfs_path *path,
					  const struct btrfs_key *key,
					  u32 data_size)
{
	struct btrfs_item_batch batch;

	batch.keys = key;
	batch.data_sizes = &data_size;
	batch.total_data_size = data_size;
	batch.nr = 1;

	return btrfs_insert_empty_items(trans, root, path, &batch);
}

int btrfs_next_old_leaf(struct btrfs_root *root, struct btrfs_path *path,
			u64 time_seq);

int btrfs_search_backwards(struct btrfs_root *root, struct btrfs_key *key,
			   struct btrfs_path *path);

int btrfs_get_next_valid_item(struct btrfs_root *root, struct btrfs_key *key,
			      struct btrfs_path *path);

/*
 * Search in @root for a given @key, and store the slot found in @found_key.
 *
 * @root:	The root node of the tree.
 * @key:	The key we are looking for.
 * @found_key:	Will hold the found item.
 * @path:	Holds the current slot/leaf.
 * @iter_ret:	Contains the value returned from btrfs_search_slot or
 * 		btrfs_get_next_valid_item, whichever was executed last.
 *
 * The @iter_ret is an output variable that will contain the return value of
 * btrfs_search_slot, if it encountered an error, or the value returned from
 * btrfs_get_next_valid_item otherwise. That return value can be 0, if a valid
 * slot was found, 1 if there were no more leaves, and <0 if there was an error.
 *
 * It's recommended to use a separate variable for iter_ret and then use it to
 * set the function return value so there's no confusion of the 0/1/errno
 * values stemming from btrfs_search_slot.
 */
#define btrfs_for_each_slot(root, key, found_key, path, iter_ret)		\
	for (iter_ret = btrfs_search_slot(NULL, (root), (key), (path), 0, 0);	\
		(iter_ret) >= 0 &&						\
		(iter_ret = btrfs_get_next_valid_item((root), (found_key), (path))) == 0; \
		(path)->slots[0]++						\
	)

int btrfs_next_old_item(struct btrfs_root *root, struct btrfs_path *path, u64 time_seq);

/*
 * Search the tree again to find a leaf with greater keys.
 *
 * Returns 0 if it found something or 1 if there are no greater leaves.
 * Returns < 0 on error.
 */
static inline int btrfs_next_leaf(struct btrfs_root *root, struct btrfs_path *path)
{
	return btrfs_next_old_leaf(root, path, 0);
}

static inline int btrfs_next_item(struct btrfs_root *root, struct btrfs_path *p)
{
	return btrfs_next_old_item(root, p, 0);
}
<<<<<<< HEAD
int btrfs_leaf_free_space(const struct extent_buffer *leaf);
=======
int btrfs_leaf_free_space(struct btrfs_fs_info *fs_info,
			  struct extent_buffer *leaf);
int __must_check btrfs_drop_snapshot(struct btrfs_root *root,
				     struct btrfs_block_rsv *block_rsv,
				     int update_ref, int for_reloc);
int btrfs_drop_subtree(struct btrfs_trans_handle *trans,
			struct btrfs_root *root,
			struct extent_buffer *node,
			struct extent_buffer *parent);
static inline int btrfs_fs_closing(struct btrfs_fs_info *fs_info)
{
	/*
	 * Do it this way so we only ever do one test_bit in the normal case.
	 */
	if (test_bit(BTRFS_FS_CLOSING_START, &fs_info->flags)) {
		if (test_bit(BTRFS_FS_CLOSING_DONE, &fs_info->flags))
			return 2;
		return 1;
	}
	return 0;
}

/*
 * If we remount the fs to be R/O or umount the fs, the cleaner needn't do
 * anything except sleeping. This function is used to check the status of
 * the fs.
 */
static inline int btrfs_need_cleaner_sleep(struct btrfs_fs_info *fs_info)
{
	return fs_info->sb->s_flags & SB_RDONLY || btrfs_fs_closing(fs_info);
}

static inline void free_fs_info(struct btrfs_fs_info *fs_info)
{
	kfree(fs_info->balance_ctl);
	kfree(fs_info->delayed_root);
	kfree(fs_info->extent_root);
	kfree(fs_info->tree_root);
	kfree(fs_info->chunk_root);
	kfree(fs_info->dev_root);
	kfree(fs_info->csum_root);
	kfree(fs_info->quota_root);
	kfree(fs_info->uuid_root);
	kfree(fs_info->free_space_root);
	kfree(fs_info->super_copy);
	kfree(fs_info->super_for_commit);
	security_free_mnt_opts(&fs_info->security_opts);
	kvfree(fs_info);
}

/* tree mod log functions from ctree.c */
u64 btrfs_get_tree_mod_seq(struct btrfs_fs_info *fs_info,
			   struct seq_list *elem);
void btrfs_put_tree_mod_seq(struct btrfs_fs_info *fs_info,
			    struct seq_list *elem);
int btrfs_old_root_level(struct btrfs_root *root, u64 time_seq);

/* root-item.c */
int btrfs_add_root_ref(struct btrfs_trans_handle *trans, u64 root_id,
		       u64 ref_id, u64 dirid, u64 sequence, const char *name,
		       int name_len);
int btrfs_del_root_ref(struct btrfs_trans_handle *trans, u64 root_id,
		       u64 ref_id, u64 dirid, u64 *sequence, const char *name,
		       int name_len);
int btrfs_del_root(struct btrfs_trans_handle *trans,
		   const struct btrfs_key *key);
int btrfs_insert_root(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		      const struct btrfs_key *key,
		      struct btrfs_root_item *item);
int __must_check btrfs_update_root(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   struct btrfs_key *key,
				   struct btrfs_root_item *item);
int btrfs_find_root(struct btrfs_root *root, const struct btrfs_key *search_key,
		    struct btrfs_path *path, struct btrfs_root_item *root_item,
		    struct btrfs_key *root_key);
int btrfs_find_orphan_roots(struct btrfs_fs_info *fs_info);
void btrfs_set_root_node(struct btrfs_root_item *item,
			 struct extent_buffer *node);
void btrfs_check_and_init_root_item(struct btrfs_root_item *item);
void btrfs_update_root_times(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root);

/* uuid-tree.c */
int btrfs_uuid_tree_add(struct btrfs_trans_handle *trans, u8 *uuid, u8 type,
			u64 subid);
int btrfs_uuid_tree_remove(struct btrfs_trans_handle *trans, u8 *uuid, u8 type,
			u64 subid);
int btrfs_uuid_tree_iterate(struct btrfs_fs_info *fs_info,
			    int (*check_func)(struct btrfs_fs_info *, u8 *, u8,
					      u64));

/* dir-item.c */
int btrfs_check_dir_item_collision(struct btrfs_root *root, u64 dir,
			  const char *name, int name_len);
int btrfs_insert_dir_item(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, const char *name,
			  int name_len, struct btrfs_inode *dir,
			  struct btrfs_key *location, u8 type, u64 index);
struct btrfs_dir_item *btrfs_lookup_dir_item(struct btrfs_trans_handle *trans,
					     struct btrfs_root *root,
					     struct btrfs_path *path, u64 dir,
					     const char *name, int name_len,
					     int mod);
struct btrfs_dir_item *
btrfs_lookup_dir_index_item(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root,
			    struct btrfs_path *path, u64 dir,
			    u64 objectid, const char *name, int name_len,
			    int mod);
struct btrfs_dir_item *
btrfs_search_dir_index_item(struct btrfs_root *root,
			    struct btrfs_path *path, u64 dirid,
			    const char *name, int name_len);
int btrfs_delete_one_dir_name(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root,
			      struct btrfs_path *path,
			      struct btrfs_dir_item *di);
int btrfs_insert_xattr_item(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root,
			    struct btrfs_path *path, u64 objectid,
			    const char *name, u16 name_len,
			    const void *data, u16 data_len);
struct btrfs_dir_item *btrfs_lookup_xattr(struct btrfs_trans_handle *trans,
					  struct btrfs_root *root,
					  struct btrfs_path *path, u64 dir,
					  const char *name, u16 name_len,
					  int mod);
struct btrfs_dir_item *btrfs_match_dir_item_name(struct btrfs_fs_info *fs_info,
						 struct btrfs_path *path,
						 const char *name,
						 int name_len);

/* orphan.c */
int btrfs_insert_orphan_item(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root, u64 offset);
int btrfs_del_orphan_item(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, u64 offset);
int btrfs_find_orphan_item(struct btrfs_root *root, u64 offset);

/* inode-item.c */
int btrfs_insert_inode_ref(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   const char *name, int name_len,
			   u64 inode_objectid, u64 ref_objectid, u64 index);
int btrfs_del_inode_ref(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   const char *name, int name_len,
			   u64 inode_objectid, u64 ref_objectid, u64 *index);
int btrfs_insert_empty_inode(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     struct btrfs_path *path, u64 objectid);
int btrfs_lookup_inode(struct btrfs_trans_handle *trans, struct btrfs_root
		       *root, struct btrfs_path *path,
		       struct btrfs_key *location, int mod);

struct btrfs_inode_extref *
btrfs_lookup_inode_extref(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root,
			  struct btrfs_path *path,
			  const char *name, int name_len,
			  u64 inode_objectid, u64 ref_objectid, int ins_len,
			  int cow);

int btrfs_find_name_in_backref(struct extent_buffer *leaf, int slot,
			       const char *name,
			       int name_len, struct btrfs_inode_ref **ref_ret);
int btrfs_find_name_in_ext_backref(struct extent_buffer *leaf, int slot,
				   u64 ref_objectid, const char *name,
				   int name_len,
				   struct btrfs_inode_extref **extref_ret);

/* file-item.c */
struct btrfs_dio_private;
int btrfs_del_csums(struct btrfs_trans_handle *trans,
		    struct btrfs_fs_info *fs_info, u64 bytenr, u64 len);
blk_status_t btrfs_lookup_bio_sums(struct inode *inode, struct bio *bio, u32 *dst);
blk_status_t btrfs_lookup_bio_sums_dio(struct inode *inode, struct bio *bio,
			      u64 logical_offset);
int btrfs_insert_file_extent(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     u64 objectid, u64 pos,
			     u64 disk_offset, u64 disk_num_bytes,
			     u64 num_bytes, u64 offset, u64 ram_bytes,
			     u8 compression, u8 encryption, u16 other_encoding);
int btrfs_lookup_file_extent(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     struct btrfs_path *path, u64 objectid,
			     u64 bytenr, int mod);
int btrfs_csum_file_blocks(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   struct btrfs_ordered_sum *sums);
blk_status_t btrfs_csum_one_bio(struct inode *inode, struct bio *bio,
		       u64 file_start, int contig);
int btrfs_lookup_csums_range(struct btrfs_root *root, u64 start, u64 end,
			     struct list_head *list, int search_commit);
void btrfs_extent_item_to_extent_map(struct btrfs_inode *inode,
				     const struct btrfs_path *path,
				     struct btrfs_file_extent_item *fi,
				     const bool new_inline,
				     struct extent_map *em);

/* inode.c */
struct extent_map *btrfs_get_extent_fiemap(struct btrfs_inode *inode,
		struct page *page, size_t pg_offset, u64 start,
		u64 len, int create);
noinline int can_nocow_extent(struct inode *inode, u64 offset, u64 *len,
			      u64 *orig_start, u64 *orig_block_len,
			      u64 *ram_bytes);

void __btrfs_del_delalloc_inode(struct btrfs_root *root,
				struct btrfs_inode *inode);
struct inode *btrfs_lookup_dentry(struct inode *dir, struct dentry *dentry);
int btrfs_set_inode_index(struct btrfs_inode *dir, u64 *index);
int btrfs_unlink_inode(struct btrfs_trans_handle *trans,
		       struct btrfs_root *root,
		       struct btrfs_inode *dir, struct btrfs_inode *inode,
		       const char *name, int name_len);
int btrfs_add_link(struct btrfs_trans_handle *trans,
		   struct btrfs_inode *parent_inode, struct btrfs_inode *inode,
		   const char *name, int name_len, int add_backref, u64 index);
int btrfs_delete_subvolume(struct inode *dir, struct dentry *dentry);
int btrfs_truncate_block(struct inode *inode, loff_t from, loff_t len,
			int front);
int btrfs_truncate_inode_items(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root,
			       struct inode *inode, u64 new_size,
			       u32 min_type);

int btrfs_start_delalloc_snapshot(struct btrfs_root *root);
int btrfs_start_delalloc_roots(struct btrfs_fs_info *fs_info, int nr);
int btrfs_set_extent_delalloc(struct inode *inode, u64 start, u64 end,
			      unsigned int extra_bits,
			      struct extent_state **cached_state, int dedupe);
int btrfs_create_subvol_root(struct btrfs_trans_handle *trans,
			     struct btrfs_root *new_root,
			     struct btrfs_root *parent_root,
			     u64 new_dirid);
int btrfs_merge_bio_hook(struct page *page, unsigned long offset,
			 size_t size, struct bio *bio,
			 unsigned long bio_flags);
void btrfs_set_range_writeback(struct extent_io_tree *tree, u64 start, u64 end);
vm_fault_t btrfs_page_mkwrite(struct vm_fault *vmf);
int btrfs_readpage(struct file *file, struct page *page);
void btrfs_evict_inode(struct inode *inode);
int btrfs_write_inode(struct inode *inode, struct writeback_control *wbc);
struct inode *btrfs_alloc_inode(struct super_block *sb);
void btrfs_destroy_inode(struct inode *inode);
int btrfs_drop_inode(struct inode *inode);
int __init btrfs_init_cachep(void);
void __cold btrfs_destroy_cachep(void);
struct inode *btrfs_iget_path(struct super_block *s, struct btrfs_key *location,
			      struct btrfs_root *root, int *new,
			      struct btrfs_path *path);
struct inode *btrfs_iget(struct super_block *s, struct btrfs_key *location,
			 struct btrfs_root *root, int *was_new);
struct extent_map *btrfs_get_extent(struct btrfs_inode *inode,
		struct page *page, size_t pg_offset,
		u64 start, u64 end, int create);
int btrfs_update_inode(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root,
			      struct inode *inode);
int btrfs_update_inode_fallback(struct btrfs_trans_handle *trans,
				struct btrfs_root *root, struct inode *inode);
int btrfs_orphan_add(struct btrfs_trans_handle *trans,
		struct btrfs_inode *inode);
int btrfs_orphan_cleanup(struct btrfs_root *root);
int btrfs_cont_expand(struct inode *inode, loff_t oldsize, loff_t size);
void btrfs_add_delayed_iput(struct inode *inode);
void btrfs_run_delayed_iputs(struct btrfs_fs_info *fs_info);
int btrfs_prealloc_file_range(struct inode *inode, int mode,
			      u64 start, u64 num_bytes, u64 min_size,
			      loff_t actual_len, u64 *alloc_hint);
int btrfs_prealloc_file_range_trans(struct inode *inode,
				    struct btrfs_trans_handle *trans, int mode,
				    u64 start, u64 num_bytes, u64 min_size,
				    loff_t actual_len, u64 *alloc_hint);
int btrfs_run_delalloc_range(void *private_data, struct page *locked_page,
		u64 start, u64 end, int *page_started, unsigned long *nr_written,
		struct writeback_control *wbc);
extern const struct dentry_operations btrfs_dentry_operations;
#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
void btrfs_test_inode_set_ops(struct inode *inode);
#endif

/* ioctl.c */
long btrfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
long btrfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int btrfs_ioctl_get_supported_features(void __user *arg);
void btrfs_sync_inode_flags_to_i_flags(struct inode *inode);
int btrfs_is_empty_uuid(u8 *uuid);
int btrfs_defrag_file(struct inode *inode, struct file *file,
		      struct btrfs_ioctl_defrag_range_args *range,
		      u64 newer_than, unsigned long max_pages);
void btrfs_get_block_group_info(struct list_head *groups_list,
				struct btrfs_ioctl_space_info *space);
void btrfs_update_ioctl_balance_args(struct btrfs_fs_info *fs_info,
			       struct btrfs_ioctl_balance_args *bargs);
int btrfs_dedupe_file_range(struct file *src_file, loff_t src_loff,
			    struct file *dst_file, loff_t dst_loff,
			    u64 olen);

/* file.c */
int __init btrfs_auto_defrag_init(void);
void __cold btrfs_auto_defrag_exit(void);
int btrfs_add_inode_defrag(struct btrfs_trans_handle *trans,
			   struct btrfs_inode *inode);
int btrfs_run_defrag_inodes(struct btrfs_fs_info *fs_info);
void btrfs_cleanup_defrag_inodes(struct btrfs_fs_info *fs_info);
int btrfs_sync_file(struct file *file, loff_t start, loff_t end, int datasync);
void btrfs_drop_extent_cache(struct btrfs_inode *inode, u64 start, u64 end,
			     int skip_pinned);
extern const struct file_operations btrfs_file_operations;
int __btrfs_drop_extents(struct btrfs_trans_handle *trans,
			 struct btrfs_root *root, struct inode *inode,
			 struct btrfs_path *path, u64 start, u64 end,
			 u64 *drop_end, int drop_cache,
			 int replace_extent,
			 u32 extent_item_size,
			 int *key_inserted);
int btrfs_drop_extents(struct btrfs_trans_handle *trans,
		       struct btrfs_root *root, struct inode *inode, u64 start,
		       u64 end, int drop_cache);
int btrfs_mark_extent_written(struct btrfs_trans_handle *trans,
			      struct btrfs_inode *inode, u64 start, u64 end);
int btrfs_release_file(struct inode *inode, struct file *file);
int btrfs_dirty_pages(struct inode *inode, struct page **pages,
		      size_t num_pages, loff_t pos, size_t write_bytes,
		      struct extent_state **cached);
int btrfs_fdatawrite_range(struct inode *inode, loff_t start, loff_t end);
int btrfs_clone_file_range(struct file *file_in, loff_t pos_in,
			   struct file *file_out, loff_t pos_out, u64 len);

/* tree-defrag.c */
int btrfs_defrag_leaves(struct btrfs_trans_handle *trans,
			struct btrfs_root *root);

/* sysfs.c */
int __init btrfs_init_sysfs(void);
void __cold btrfs_exit_sysfs(void);
int btrfs_sysfs_add_mounted(struct btrfs_fs_info *fs_info);
void btrfs_sysfs_remove_mounted(struct btrfs_fs_info *fs_info);

/* super.c */
int btrfs_parse_options(struct btrfs_fs_info *info, char *options,
			unsigned long new_flags);
int btrfs_sync_fs(struct super_block *sb, int wait);

static inline __printf(2, 3) __cold
void btrfs_no_printk(const struct btrfs_fs_info *fs_info, const char *fmt, ...)
{
}

#ifdef CONFIG_PRINTK
__printf(2, 3)
__cold
void btrfs_printk(const struct btrfs_fs_info *fs_info, const char *fmt, ...);
#else
#define btrfs_printk(fs_info, fmt, args...) \
	btrfs_no_printk(fs_info, fmt, ##args)
#endif

#define btrfs_emerg(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_EMERG fmt, ##args)
#define btrfs_alert(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_ALERT fmt, ##args)
#define btrfs_crit(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_CRIT fmt, ##args)
#define btrfs_err(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_ERR fmt, ##args)
#define btrfs_warn(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_WARNING fmt, ##args)
#define btrfs_notice(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_NOTICE fmt, ##args)
#define btrfs_info(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_INFO fmt, ##args)

/*
 * Wrappers that use printk_in_rcu
 */
#define btrfs_emerg_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_EMERG fmt, ##args)
#define btrfs_alert_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_ALERT fmt, ##args)
#define btrfs_crit_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_CRIT fmt, ##args)
#define btrfs_err_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_ERR fmt, ##args)
#define btrfs_warn_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_WARNING fmt, ##args)
#define btrfs_notice_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_NOTICE fmt, ##args)
#define btrfs_info_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_INFO fmt, ##args)

/*
 * Wrappers that use a ratelimited printk_in_rcu
 */
#define btrfs_emerg_rl_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_rl_in_rcu(fs_info, KERN_EMERG fmt, ##args)
#define btrfs_alert_rl_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_rl_in_rcu(fs_info, KERN_ALERT fmt, ##args)
#define btrfs_crit_rl_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_rl_in_rcu(fs_info, KERN_CRIT fmt, ##args)
#define btrfs_err_rl_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_rl_in_rcu(fs_info, KERN_ERR fmt, ##args)
#define btrfs_warn_rl_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_rl_in_rcu(fs_info, KERN_WARNING fmt, ##args)
#define btrfs_notice_rl_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_rl_in_rcu(fs_info, KERN_NOTICE fmt, ##args)
#define btrfs_info_rl_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_rl_in_rcu(fs_info, KERN_INFO fmt, ##args)

/*
 * Wrappers that use a ratelimited printk
 */
#define btrfs_emerg_rl(fs_info, fmt, args...) \
	btrfs_printk_ratelimited(fs_info, KERN_EMERG fmt, ##args)
#define btrfs_alert_rl(fs_info, fmt, args...) \
	btrfs_printk_ratelimited(fs_info, KERN_ALERT fmt, ##args)
#define btrfs_crit_rl(fs_info, fmt, args...) \
	btrfs_printk_ratelimited(fs_info, KERN_CRIT fmt, ##args)
#define btrfs_err_rl(fs_info, fmt, args...) \
	btrfs_printk_ratelimited(fs_info, KERN_ERR fmt, ##args)
#define btrfs_warn_rl(fs_info, fmt, args...) \
	btrfs_printk_ratelimited(fs_info, KERN_WARNING fmt, ##args)
#define btrfs_notice_rl(fs_info, fmt, args...) \
	btrfs_printk_ratelimited(fs_info, KERN_NOTICE fmt, ##args)
#define btrfs_info_rl(fs_info, fmt, args...) \
	btrfs_printk_ratelimited(fs_info, KERN_INFO fmt, ##args)

#if defined(CONFIG_DYNAMIC_DEBUG)
#define btrfs_debug(fs_info, fmt, args...)				\
do {									\
        DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);         	\
        if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT))  	\
		btrfs_printk(fs_info, KERN_DEBUG fmt, ##args);		\
} while (0)
#define btrfs_debug_in_rcu(fs_info, fmt, args...) 			\
do {									\
        DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt); 	        \
        if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT)) 		\
		btrfs_printk_in_rcu(fs_info, KERN_DEBUG fmt, ##args);	\
} while (0)
#define btrfs_debug_rl_in_rcu(fs_info, fmt, args...)			\
do {									\
        DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);         	\
        if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT))  	\
		btrfs_printk_rl_in_rcu(fs_info, KERN_DEBUG fmt,		\
				       ##args);\
} while (0)
#define btrfs_debug_rl(fs_info, fmt, args...) 				\
do {									\
        DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);         	\
        if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT))  	\
		btrfs_printk_ratelimited(fs_info, KERN_DEBUG fmt,	\
					 ##args);			\
} while (0)
#elif defined(DEBUG)
#define btrfs_debug(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_DEBUG fmt, ##args)
#define btrfs_debug_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_DEBUG fmt, ##args)
#define btrfs_debug_rl_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_rl_in_rcu(fs_info, KERN_DEBUG fmt, ##args)
#define btrfs_debug_rl(fs_info, fmt, args...) \
	btrfs_printk_ratelimited(fs_info, KERN_DEBUG fmt, ##args)
#else
#define btrfs_debug(fs_info, fmt, args...) \
	btrfs_no_printk(fs_info, KERN_DEBUG fmt, ##args)
#define btrfs_debug_in_rcu(fs_info, fmt, args...) \
	btrfs_no_printk_in_rcu(fs_info, KERN_DEBUG fmt, ##args)
#define btrfs_debug_rl_in_rcu(fs_info, fmt, args...) \
	btrfs_no_printk_in_rcu(fs_info, KERN_DEBUG fmt, ##args)
#define btrfs_debug_rl(fs_info, fmt, args...) \
	btrfs_no_printk(fs_info, KERN_DEBUG fmt, ##args)
#endif

#define btrfs_printk_in_rcu(fs_info, fmt, args...)	\
do {							\
	rcu_read_lock();				\
	btrfs_printk(fs_info, fmt, ##args);		\
	rcu_read_unlock();				\
} while (0)

#define btrfs_no_printk_in_rcu(fs_info, fmt, args...)	\
do {							\
	rcu_read_lock();				\
	btrfs_no_printk(fs_info, fmt, ##args);		\
	rcu_read_unlock();				\
} while (0)

#define btrfs_printk_ratelimited(fs_info, fmt, args...)		\
do {								\
	static DEFINE_RATELIMIT_STATE(_rs,			\
		DEFAULT_RATELIMIT_INTERVAL,			\
		DEFAULT_RATELIMIT_BURST);       		\
	if (__ratelimit(&_rs))					\
		btrfs_printk(fs_info, fmt, ##args);		\
} while (0)

#define btrfs_printk_rl_in_rcu(fs_info, fmt, args...)		\
do {								\
	rcu_read_lock();					\
	btrfs_printk_ratelimited(fs_info, fmt, ##args);		\
	rcu_read_unlock();					\
} while (0)

#ifdef CONFIG_BTRFS_ASSERT

__cold
static inline void assfail(const char *expr, const char *file, int line)
{
	pr_err("assertion failed: %s, file: %s, line: %d\n",
	       expr, file, line);
	BUG();
}

#define ASSERT(expr)	\
	(likely(expr) ? (void)0 : assfail(#expr, __FILE__, __LINE__))
#else
#define ASSERT(expr)	((void)0)
#endif

__cold
static inline void btrfs_print_v0_err(struct btrfs_fs_info *fs_info)
{
	btrfs_err(fs_info,
"Unsupported V0 extent filesystem detected. Aborting. Please re-create your filesystem with a newer kernel");
}

__printf(5, 6)
__cold
void __btrfs_handle_fs_error(struct btrfs_fs_info *fs_info, const char *function,
		     unsigned int line, int errno, const char *fmt, ...);

const char *btrfs_decode_error(int errno);

__cold
void __btrfs_abort_transaction(struct btrfs_trans_handle *trans,
			       const char *function,
			       unsigned int line, int errno);

/*
 * Call btrfs_abort_transaction as early as possible when an error condition is
 * detected, that way the exact line number is reported.
 */
#define btrfs_abort_transaction(trans, errno)		\
do {								\
	/* Report first abort since mount */			\
	if (!test_and_set_bit(BTRFS_FS_STATE_TRANS_ABORTED,	\
			&((trans)->fs_info->fs_state))) {	\
		if ((errno) != -EIO) {				\
			WARN(1, KERN_DEBUG				\
			"BTRFS: Transaction aborted (error %d)\n",	\
			(errno));					\
		} else {						\
			btrfs_debug((trans)->fs_info,			\
				    "Transaction aborted (error %d)", \
				  (errno));			\
		}						\
	}							\
	__btrfs_abort_transaction((trans), __func__,		\
				  __LINE__, (errno));		\
} while (0)

#define btrfs_handle_fs_error(fs_info, errno, fmt, args...)		\
do {								\
	__btrfs_handle_fs_error((fs_info), __func__, __LINE__,	\
			  (errno), fmt, ##args);		\
} while (0)

__printf(5, 6)
__cold
void __btrfs_panic(struct btrfs_fs_info *fs_info, const char *function,
		   unsigned int line, int errno, const char *fmt, ...);
/*
 * If BTRFS_MOUNT_PANIC_ON_FATAL_ERROR is in mount_opt, __btrfs_panic
 * will panic().  Otherwise we BUG() here.
 */
#define btrfs_panic(fs_info, errno, fmt, args...)			\
do {									\
	__btrfs_panic(fs_info, __func__, __LINE__, errno, fmt, ##args);	\
	BUG();								\
} while (0)


/* compatibility and incompatibility defines */

#define btrfs_set_fs_incompat(__fs_info, opt) \
	__btrfs_set_fs_incompat((__fs_info), BTRFS_FEATURE_INCOMPAT_##opt)

static inline void __btrfs_set_fs_incompat(struct btrfs_fs_info *fs_info,
					   u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info, "setting %llu feature flag",
					 flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_clear_fs_incompat(__fs_info, opt) \
	__btrfs_clear_fs_incompat((__fs_info), BTRFS_FEATURE_INCOMPAT_##opt)

static inline void __btrfs_clear_fs_incompat(struct btrfs_fs_info *fs_info,
					     u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info, "clearing %llu feature flag",
					 flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_fs_incompat(fs_info, opt) \
	__btrfs_fs_incompat((fs_info), BTRFS_FEATURE_INCOMPAT_##opt)

static inline bool __btrfs_fs_incompat(struct btrfs_fs_info *fs_info, u64 flag)
{
	struct btrfs_super_block *disk_super;
	disk_super = fs_info->super_copy;
	return !!(btrfs_super_incompat_flags(disk_super) & flag);
}

#define btrfs_set_fs_compat_ro(__fs_info, opt) \
	__btrfs_set_fs_compat_ro((__fs_info), BTRFS_FEATURE_COMPAT_RO_##opt)

static inline void __btrfs_set_fs_compat_ro(struct btrfs_fs_info *fs_info,
					    u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info, "setting %llu ro feature flag",
				   flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_clear_fs_compat_ro(__fs_info, opt) \
	__btrfs_clear_fs_compat_ro((__fs_info), BTRFS_FEATURE_COMPAT_RO_##opt)

static inline void __btrfs_clear_fs_compat_ro(struct btrfs_fs_info *fs_info,
					      u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info, "clearing %llu ro feature flag",
				   flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_fs_compat_ro(fs_info, opt) \
	__btrfs_fs_compat_ro((fs_info), BTRFS_FEATURE_COMPAT_RO_##opt)

static inline int __btrfs_fs_compat_ro(struct btrfs_fs_info *fs_info, u64 flag)
{
	struct btrfs_super_block *disk_super;
	disk_super = fs_info->super_copy;
	return !!(btrfs_super_compat_ro_flags(disk_super) & flag);
}

/* acl.c */
#ifdef CONFIG_BTRFS_FS_POSIX_ACL
struct posix_acl *btrfs_get_acl(struct inode *inode, int type);
int btrfs_set_acl(struct inode *inode, struct posix_acl *acl, int type);
int btrfs_init_acl(struct btrfs_trans_handle *trans,
		   struct inode *inode, struct inode *dir);
#else
#define btrfs_get_acl NULL
#define btrfs_set_acl NULL
static inline int btrfs_init_acl(struct btrfs_trans_handle *trans,
				 struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif

/* relocation.c */
int btrfs_relocate_block_group(struct btrfs_fs_info *fs_info, u64 group_start);
int btrfs_init_reloc_root(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root);
int btrfs_update_reloc_root(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root);
int btrfs_recover_relocation(struct btrfs_root *root);
int btrfs_reloc_clone_csums(struct inode *inode, u64 file_pos, u64 len);
int btrfs_reloc_cow_block(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, struct extent_buffer *buf,
			  struct extent_buffer *cow);
void btrfs_reloc_pre_snapshot(struct btrfs_pending_snapshot *pending,
			      u64 *bytes_to_reserve);
int btrfs_reloc_post_snapshot(struct btrfs_trans_handle *trans,
			      struct btrfs_pending_snapshot *pending);

/* scrub.c */
int btrfs_scrub_dev(struct btrfs_fs_info *fs_info, u64 devid, u64 start,
		    u64 end, struct btrfs_scrub_progress *progress,
		    int readonly, int is_dev_replace);
void btrfs_scrub_pause(struct btrfs_fs_info *fs_info);
void btrfs_scrub_continue(struct btrfs_fs_info *fs_info);
int btrfs_scrub_cancel(struct btrfs_fs_info *info);
int btrfs_scrub_cancel_dev(struct btrfs_fs_info *info,
			   struct btrfs_device *dev);
int btrfs_scrub_progress(struct btrfs_fs_info *fs_info, u64 devid,
			 struct btrfs_scrub_progress *progress);
static inline void btrfs_init_full_stripe_locks_tree(
			struct btrfs_full_stripe_locks_tree *locks_root)
{
	locks_root->root = RB_ROOT;
	mutex_init(&locks_root->lock);
}

/* dev-replace.c */
void btrfs_bio_counter_inc_blocked(struct btrfs_fs_info *fs_info);
void btrfs_bio_counter_inc_noblocked(struct btrfs_fs_info *fs_info);
void btrfs_bio_counter_sub(struct btrfs_fs_info *fs_info, s64 amount);

static inline void btrfs_bio_counter_dec(struct btrfs_fs_info *fs_info)
{
	btrfs_bio_counter_sub(fs_info, 1);
}

/* reada.c */
struct reada_control {
	struct btrfs_fs_info	*fs_info;		/* tree to prefetch */
	struct btrfs_key	key_start;
	struct btrfs_key	key_end;	/* exclusive */
	atomic_t		elems;
	struct kref		refcnt;
	wait_queue_head_t	wait;
};
struct reada_control *btrfs_reada_add(struct btrfs_root *root,
			      struct btrfs_key *start, struct btrfs_key *end);
int btrfs_reada_wait(void *handle);
void btrfs_reada_detach(void *handle);
int btree_readahead_hook(struct extent_buffer *eb, int err);
>>>>>>> master

static inline int is_fstree(u64 rootid)
{
	if (rootid == BTRFS_FS_TREE_OBJECTID ||
	    ((s64)rootid >= (s64)BTRFS_FIRST_FREE_OBJECTID &&
	      !btrfs_qgroup_level(rootid)))
		return 1;
	return 0;
}

static inline bool btrfs_is_data_reloc_root(const struct btrfs_root *root)
{
	return root->root_key.objectid == BTRFS_DATA_RELOC_TREE_OBJECTID;
}

u16 btrfs_csum_type_size(u16 type);
int btrfs_super_csum_size(const struct btrfs_super_block *s);
const char *btrfs_super_csum_name(u16 csum_type);
const char *btrfs_super_csum_driver(u16 csum_type);
size_t __attribute_const__ btrfs_get_num_csums(void);

/*
 * We use page status Private2 to indicate there is an ordered extent with
 * unfinished IO.
 *
 * Rename the Private2 accessors to Ordered, to improve readability.
 */
#define PageOrdered(page)		PagePrivate2(page)
#define SetPageOrdered(page)		SetPagePrivate2(page)
#define ClearPageOrdered(page)		ClearPagePrivate2(page)
#define folio_test_ordered(folio)	folio_test_private_2(folio)
#define folio_set_ordered(folio)	folio_set_private_2(folio)
#define folio_clear_ordered(folio)	folio_clear_private_2(folio)

#endif
