// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/writeback.h>
#include <linux/compat.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/uuid.h>
#include <linux/btrfs.h>
#include <linux/uaccess.h>
#include <linux/iversion.h>
#include <linux/fileattr.h>
#include <linux/fsverity.h>
#include <linux/sched/xacct.h>
#include "ctree.h"
#include "disk-io.h"
#include "export.h"
#include "transaction.h"
#include "btrfs_inode.h"
#include "print-tree.h"
#include "volumes.h"
#include "locking.h"
#include "backref.h"
#include "rcu-string.h"
#include "send.h"
#include "dev-replace.h"
#include "props.h"
#include "sysfs.h"
#include "qgroup.h"
#include "tree-log.h"
#include "compression.h"
#include "space-info.h"
#include "delalloc-space.h"
#include "block-group.h"
#include "subpage.h"
#include "fs.h"
#include "accessors.h"
#include "extent-tree.h"
#include "root-tree.h"
#include "defrag.h"
#include "dir-item.h"
#include "uuid-tree.h"
#include "ioctl.h"
#include "file.h"
#include "scrub.h"
#include "super.h"

#ifdef CONFIG_64BIT
/* If we have a 32-bit userspace and 64-bit kernel, then the UAPI
 * structures are incorrect, as the timespec structure from userspace
 * is 4 bytes too small. We define these alternatives here to teach
 * the kernel about the 32-bit struct packing.
 */
struct btrfs_ioctl_timespec_32 {
	__u64 sec;
	__u32 nsec;
} __attribute__ ((__packed__));

struct btrfs_ioctl_received_subvol_args_32 {
	char	uuid[BTRFS_UUID_SIZE];	/* in */
	__u64	stransid;		/* in */
	__u64	rtransid;		/* out */
	struct btrfs_ioctl_timespec_32 stime; /* in */
	struct btrfs_ioctl_timespec_32 rtime; /* out */
	__u64	flags;			/* in */
	__u64	reserved[16];		/* in */
} __attribute__ ((__packed__));

#define BTRFS_IOC_SET_RECEIVED_SUBVOL_32 _IOWR(BTRFS_IOCTL_MAGIC, 37, \
				struct btrfs_ioctl_received_subvol_args_32)
#endif

#if defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
struct btrfs_ioctl_send_args_32 {
	__s64 send_fd;			/* in */
	__u64 clone_sources_count;	/* in */
	compat_uptr_t clone_sources;	/* in */
	__u64 parent_root;		/* in */
	__u64 flags;			/* in */
	__u32 version;			/* in */
	__u8  reserved[28];		/* in */
} __attribute__ ((__packed__));

#define BTRFS_IOC_SEND_32 _IOW(BTRFS_IOCTL_MAGIC, 38, \
			       struct btrfs_ioctl_send_args_32)

struct btrfs_ioctl_encoded_io_args_32 {
	compat_uptr_t iov;
	compat_ulong_t iovcnt;
	__s64 offset;
	__u64 flags;
	__u64 len;
	__u64 unencoded_len;
	__u64 unencoded_offset;
	__u32 compression;
	__u32 encryption;
	__u8 reserved[64];
};

#define BTRFS_IOC_ENCODED_READ_32 _IOR(BTRFS_IOCTL_MAGIC, 64, \
				       struct btrfs_ioctl_encoded_io_args_32)
#define BTRFS_IOC_ENCODED_WRITE_32 _IOW(BTRFS_IOCTL_MAGIC, 64, \
					struct btrfs_ioctl_encoded_io_args_32)
#endif

/* Mask out flags that are inappropriate for the given type of inode. */
static unsigned int btrfs_mask_fsflags_for_type(struct inode *inode,
		unsigned int flags)
{
	if (S_ISDIR(inode->i_mode))
		return flags;
	else if (S_ISREG(inode->i_mode))
		return flags & ~FS_DIRSYNC_FL;
	else
		return flags & (FS_NODUMP_FL | FS_NOATIME_FL);
}

/*
 * Export internal inode flags to the format expected by the FS_IOC_GETFLAGS
 * ioctl.
 */
static unsigned int btrfs_inode_flags_to_fsflags(struct btrfs_inode *binode)
{
	unsigned int iflags = 0;
	u32 flags = binode->flags;
	u32 ro_flags = binode->ro_flags;

	if (flags & BTRFS_INODE_SYNC)
		iflags |= FS_SYNC_FL;
	if (flags & BTRFS_INODE_IMMUTABLE)
		iflags |= FS_IMMUTABLE_FL;
	if (flags & BTRFS_INODE_APPEND)
		iflags |= FS_APPEND_FL;
	if (flags & BTRFS_INODE_NODUMP)
		iflags |= FS_NODUMP_FL;
	if (flags & BTRFS_INODE_NOATIME)
		iflags |= FS_NOATIME_FL;
	if (flags & BTRFS_INODE_DIRSYNC)
		iflags |= FS_DIRSYNC_FL;
	if (flags & BTRFS_INODE_NODATACOW)
		iflags |= FS_NOCOW_FL;
	if (ro_flags & BTRFS_INODE_RO_VERITY)
		iflags |= FS_VERITY_FL;

	if (flags & BTRFS_INODE_NOCOMPRESS)
		iflags |= FS_NOCOMP_FL;
	else if (flags & BTRFS_INODE_COMPRESS)
		iflags |= FS_COMPR_FL;

	return iflags;
}

/*
 * Update inode->i_flags based on the btrfs internal flags.
 */
void btrfs_sync_inode_flags_to_i_flags(struct inode *inode)
{
	struct btrfs_inode *binode = BTRFS_I(inode);
	unsigned int new_fl = 0;

	if (binode->flags & BTRFS_INODE_SYNC)
		new_fl |= S_SYNC;
	if (binode->flags & BTRFS_INODE_IMMUTABLE)
		new_fl |= S_IMMUTABLE;
	if (binode->flags & BTRFS_INODE_APPEND)
		new_fl |= S_APPEND;
	if (binode->flags & BTRFS_INODE_NOATIME)
		new_fl |= S_NOATIME;
	if (binode->flags & BTRFS_INODE_DIRSYNC)
		new_fl |= S_DIRSYNC;
	if (binode->ro_flags & BTRFS_INODE_RO_VERITY)
		new_fl |= S_VERITY;

	set_mask_bits(&inode->i_flags,
		      S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC |
		      S_VERITY, new_fl);
}

/*
 * Check if @flags are a supported and valid set of FS_*_FL flags and that
 * the old and new flags are not conflicting
 */
static int check_fsflags(unsigned int old_flags, unsigned int flags)
{
	if (flags & ~(FS_IMMUTABLE_FL | FS_APPEND_FL | \
		      FS_NOATIME_FL | FS_NODUMP_FL | \
		      FS_SYNC_FL | FS_DIRSYNC_FL | \
		      FS_NOCOMP_FL | FS_COMPR_FL |
		      FS_NOCOW_FL))
		return -EOPNOTSUPP;

	/* COMPR and NOCOMP on new/old are valid */
	if ((flags & FS_NOCOMP_FL) && (flags & FS_COMPR_FL))
		return -EINVAL;

	if ((flags & FS_COMPR_FL) && (flags & FS_NOCOW_FL))
		return -EINVAL;

	/* NOCOW and compression options are mutually exclusive */
	if ((old_flags & FS_NOCOW_FL) && (flags & (FS_COMPR_FL | FS_NOCOMP_FL)))
		return -EINVAL;
	if ((flags & FS_NOCOW_FL) && (old_flags & (FS_COMPR_FL | FS_NOCOMP_FL)))
		return -EINVAL;

	return 0;
}

static int check_fsflags_compatible(struct btrfs_fs_info *fs_info,
				    unsigned int flags)
{
	if (btrfs_is_zoned(fs_info) && (flags & FS_NOCOW_FL))
		return -EPERM;

	return 0;
}

/*
 * Set flags/xflags from the internal inode flags. The remaining items of
 * fsxattr are zeroed.
 */
int btrfs_fileattr_get(struct dentry *dentry, struct fileattr *fa)
{
	struct btrfs_inode *binode = BTRFS_I(d_inode(dentry));

	fileattr_fill_flags(fa, btrfs_inode_flags_to_fsflags(binode));
	return 0;
}

int btrfs_fileattr_set(struct mnt_idmap *idmap,
		       struct dentry *dentry, struct fileattr *fa)
{
	struct inode *inode = d_inode(dentry);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_inode *binode = BTRFS_I(inode);
	struct btrfs_root *root = binode->root;
	struct btrfs_trans_handle *trans;
	unsigned int fsflags, old_fsflags;
	int ret;
	const char *comp = NULL;
	u32 binode_flags;

	if (btrfs_root_readonly(root))
		return -EROFS;

	if (fileattr_has_fsx(fa))
		return -EOPNOTSUPP;

	fsflags = btrfs_mask_fsflags_for_type(inode, fa->flags);
	old_fsflags = btrfs_inode_flags_to_fsflags(binode);
	ret = check_fsflags(old_fsflags, fsflags);
	if (ret)
		return ret;

	ret = check_fsflags_compatible(fs_info, fsflags);
	if (ret)
		return ret;

	binode_flags = binode->flags;
	if (fsflags & FS_SYNC_FL)
		binode_flags |= BTRFS_INODE_SYNC;
	else
		binode_flags &= ~BTRFS_INODE_SYNC;
	if (fsflags & FS_IMMUTABLE_FL)
		binode_flags |= BTRFS_INODE_IMMUTABLE;
	else
		binode_flags &= ~BTRFS_INODE_IMMUTABLE;
	if (fsflags & FS_APPEND_FL)
		binode_flags |= BTRFS_INODE_APPEND;
	else
		binode_flags &= ~BTRFS_INODE_APPEND;
	if (fsflags & FS_NODUMP_FL)
		binode_flags |= BTRFS_INODE_NODUMP;
	else
		binode_flags &= ~BTRFS_INODE_NODUMP;
	if (fsflags & FS_NOATIME_FL)
		binode_flags |= BTRFS_INODE_NOATIME;
	else
		binode_flags &= ~BTRFS_INODE_NOATIME;

	/* If coming from FS_IOC_FSSETXATTR then skip unconverted flags */
	if (!fa->flags_valid) {
		/* 1 item for the inode */
		trans = btrfs_start_transaction(root, 1);
		if (IS_ERR(trans))
			return PTR_ERR(trans);
		goto update_flags;
	}

	if (fsflags & FS_DIRSYNC_FL)
		binode_flags |= BTRFS_INODE_DIRSYNC;
	else
		binode_flags &= ~BTRFS_INODE_DIRSYNC;
	if (fsflags & FS_NOCOW_FL) {
		if (S_ISREG(inode->i_mode)) {
			/*
			 * It's safe to turn csums off here, no extents exist.
			 * Otherwise we want the flag to reflect the real COW
			 * status of the file and will not set it.
			 */
			if (inode->i_size == 0)
				binode_flags |= BTRFS_INODE_NODATACOW |
						BTRFS_INODE_NODATASUM;
		} else {
			binode_flags |= BTRFS_INODE_NODATACOW;
		}
	} else {
		/*
		 * Revert back under same assumptions as above
		 */
		if (S_ISREG(inode->i_mode)) {
			if (inode->i_size == 0)
				binode_flags &= ~(BTRFS_INODE_NODATACOW |
						  BTRFS_INODE_NODATASUM);
		} else {
			binode_flags &= ~BTRFS_INODE_NODATACOW;
		}
	}

	/*
	 * The COMPRESS flag can only be changed by users, while the NOCOMPRESS
	 * flag may be changed automatically if compression code won't make
	 * things smaller.
	 */
	if (fsflags & FS_NOCOMP_FL) {
		binode_flags &= ~BTRFS_INODE_COMPRESS;
		binode_flags |= BTRFS_INODE_NOCOMPRESS;
	} else if (fsflags & FS_COMPR_FL) {

		if (IS_SWAPFILE(inode))
			return -ETXTBSY;

		binode_flags |= BTRFS_INODE_COMPRESS;
		binode_flags &= ~BTRFS_INODE_NOCOMPRESS;

		comp = btrfs_compress_type2str(fs_info->compress_type);
		if (!comp || comp[0] == 0)
			comp = btrfs_compress_type2str(BTRFS_COMPRESS_ZLIB);
	} else {
		binode_flags &= ~(BTRFS_INODE_COMPRESS | BTRFS_INODE_NOCOMPRESS);
	}

	/*
	 * 1 for inode item
	 * 2 for properties
	 */
	trans = btrfs_start_transaction(root, 3);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	if (comp) {
		ret = btrfs_set_prop(trans, inode, "btrfs.compression", comp,
				     strlen(comp), 0);
		if (ret) {
			btrfs_abort_transaction(trans, ret);
			goto out_end_trans;
		}
	} else {
		ret = btrfs_set_prop(trans, inode, "btrfs.compression", NULL,
				     0, 0);
		if (ret && ret != -ENODATA) {
			btrfs_abort_transaction(trans, ret);
			goto out_end_trans;
		}
	}

update_flags:
	binode->flags = binode_flags;
	btrfs_sync_inode_flags_to_i_flags(inode);
	inode_inc_iversion(inode);
	inode_set_ctime_current(inode);
	ret = btrfs_update_inode(trans, root, BTRFS_I(inode));

 out_end_trans:
	btrfs_end_transaction(trans);
	return ret;
}

/*
 * Start exclusive operation @type, return true on success
 */
bool btrfs_exclop_start(struct btrfs_fs_info *fs_info,
			enum btrfs_exclusive_operation type)
{
	bool ret = false;

	spin_lock(&fs_info->super_lock);
	if (fs_info->exclusive_operation == BTRFS_EXCLOP_NONE) {
		fs_info->exclusive_operation = type;
		ret = true;
	}
	spin_unlock(&fs_info->super_lock);

	return ret;
}

/*
 * Conditionally allow to enter the exclusive operation in case it's compatible
 * with the running one.  This must be paired with btrfs_exclop_start_unlock and
 * btrfs_exclop_finish.
 *
 * Compatibility:
 * - the same type is already running
 * - when trying to add a device and balance has been paused
 * - not BTRFS_EXCLOP_NONE - this is intentionally incompatible and the caller
 *   must check the condition first that would allow none -> @type
 */
bool btrfs_exclop_start_try_lock(struct btrfs_fs_info *fs_info,
				 enum btrfs_exclusive_operation type)
{
	spin_lock(&fs_info->super_lock);
	if (fs_info->exclusive_operation == type ||
	    (fs_info->exclusive_operation == BTRFS_EXCLOP_BALANCE_PAUSED &&
	     type == BTRFS_EXCLOP_DEV_ADD))
		return true;

	spin_unlock(&fs_info->super_lock);
	return false;
}

void btrfs_exclop_start_unlock(struct btrfs_fs_info *fs_info)
{
	spin_unlock(&fs_info->super_lock);
}

void btrfs_exclop_finish(struct btrfs_fs_info *fs_info)
{
	spin_lock(&fs_info->super_lock);
	WRITE_ONCE(fs_info->exclusive_operation, BTRFS_EXCLOP_NONE);
	spin_unlock(&fs_info->super_lock);
	sysfs_notify(&fs_info->fs_devices->fsid_kobj, NULL, "exclusive_operation");
}

void btrfs_exclop_balance(struct btrfs_fs_info *fs_info,
			  enum btrfs_exclusive_operation op)
{
	switch (op) {
	case BTRFS_EXCLOP_BALANCE_PAUSED:
		spin_lock(&fs_info->super_lock);
		ASSERT(fs_info->exclusive_operation == BTRFS_EXCLOP_BALANCE ||
		       fs_info->exclusive_operation == BTRFS_EXCLOP_DEV_ADD ||
		       fs_info->exclusive_operation == BTRFS_EXCLOP_NONE ||
		       fs_info->exclusive_operation == BTRFS_EXCLOP_BALANCE_PAUSED);
		fs_info->exclusive_operation = BTRFS_EXCLOP_BALANCE_PAUSED;
		spin_unlock(&fs_info->super_lock);
		break;
	case BTRFS_EXCLOP_BALANCE:
		spin_lock(&fs_info->super_lock);
		ASSERT(fs_info->exclusive_operation == BTRFS_EXCLOP_BALANCE_PAUSED);
		fs_info->exclusive_operation = BTRFS_EXCLOP_BALANCE;
		spin_unlock(&fs_info->super_lock);
		break;
	default:
		btrfs_warn(fs_info,
			"invalid exclop balance operation %d requested", op);
	}
}

static int btrfs_ioctl_getversion(struct inode *inode, int __user *arg)
{
	return put_user(inode->i_generation, arg);
}

static noinline int btrfs_ioctl_fitrim(struct btrfs_fs_info *fs_info,
					void __user *arg)
{
	struct btrfs_device *device;
	struct fstrim_range range;
	u64 minlen = ULLONG_MAX;
	u64 num_devices = 0;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/*
<<<<<<< HEAD
	 * btrfs_trim_block_group() depends on space cache, which is not
	 * available in zoned filesystem. So, disallow fitrim on a zoned
	 * filesystem for now.
	 */
	if (btrfs_is_zoned(fs_info))
		return -EOPNOTSUPP;

	/*
=======
>>>>>>> master
	 * If the fs is mounted with nologreplay, which requires it to be
	 * mounted in RO mode as well, we can not allow discard on free space
	 * inside block groups, because log trees refer to extents that are not
	 * pinned in a block group's free space cache (pinning the extents is
	 * precisely the first phase of replaying a log tree).
	 */
	if (btrfs_test_opt(fs_info, NOLOGREPLAY))
		return -EROFS;

	rcu_read_lock();
	list_for_each_entry_rcu(device, &fs_info->fs_devices->devices,
				dev_list) {
		if (!device->bdev || !bdev_max_discard_sectors(device->bdev))
			continue;
		num_devices++;
		minlen = min_t(u64, bdev_discard_granularity(device->bdev),
				    minlen);
	}
	rcu_read_unlock();

	if (!num_devices)
		return -EOPNOTSUPP;
	if (copy_from_user(&range, arg, sizeof(range)))
		return -EFAULT;

	/*
	 * NOTE: Don't truncate the range using super->total_bytes.  Bytenr of
	 * block group is in the logical address space, which can be any
	 * sectorsize aligned bytenr in  the range [0, U64_MAX].
	 */
	if (range.len < fs_info->sb->s_blocksize)
		return -EINVAL;

	range.minlen = max(range.minlen, minlen);
	ret = btrfs_trim_fs(fs_info, &range);
	if (ret < 0)
		return ret;

	if (copy_to_user(arg, &range, sizeof(range)))
		return -EFAULT;

	return 0;
}

int __pure btrfs_is_empty_uuid(u8 *uuid)
{
	int i;

	for (i = 0; i < BTRFS_UUID_SIZE; i++) {
		if (uuid[i])
			return 0;
	}
	return 1;
}

/*
 * Calculate the number of transaction items to reserve for creating a subvolume
 * or snapshot, not including the inode, directory entries, or parent directory.
 */
static unsigned int create_subvol_num_items(struct btrfs_qgroup_inherit *inherit)
{
	/*
	 * 1 to add root block
	 * 1 to add root item
	 * 1 to add root ref
	 * 1 to add root backref
	 * 1 to add UUID item
	 * 1 to add qgroup info
	 * 1 to add qgroup limit
	 *
	 * Ideally the last two would only be accounted if qgroups are enabled,
	 * but that can change between now and the time we would insert them.
	 */
	unsigned int num_items = 7;

	if (inherit) {
		/* 2 to add qgroup relations for each inherited qgroup */
		num_items += 2 * inherit->num_qgroups;
	}
	return num_items;
}

static noinline int create_subvol(struct mnt_idmap *idmap,
				  struct inode *dir, struct dentry *dentry,
				  struct btrfs_qgroup_inherit *inherit)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(dir->i_sb);
	struct btrfs_trans_handle *trans;
	struct btrfs_key key;
	struct btrfs_root_item *root_item;
	struct btrfs_inode_item *inode_item;
	struct extent_buffer *leaf;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_root *new_root;
	struct btrfs_block_rsv block_rsv;
	struct timespec64 cur_time = current_time(dir);
	struct btrfs_new_inode_args new_inode_args = {
		.dir = dir,
		.dentry = dentry,
		.subvol = true,
	};
	unsigned int trans_num_items;
	int ret;
	dev_t anon_dev;
	u64 objectid;
	u64 qgroup_reserved = 0;

	root_item = kzalloc(sizeof(*root_item), GFP_KERNEL);
	if (!root_item)
		return -ENOMEM;

	ret = btrfs_get_free_objectid(fs_info->tree_root, &objectid);
	if (ret)
		goto out_root_item;

	/*
	 * Don't create subvolume whose level is not zero. Or qgroup will be
	 * screwed up since it assumes subvolume qgroup's level to be 0.
	 */
	if (btrfs_qgroup_level(objectid)) {
		ret = -ENOSPC;
		goto out_root_item;
	}

	ret = get_anon_bdev(&anon_dev);
	if (ret < 0)
		goto out_root_item;

	new_inode_args.inode = btrfs_new_subvol_inode(idmap, dir);
	if (!new_inode_args.inode) {
		ret = -ENOMEM;
		goto out_anon_dev;
	}
	ret = btrfs_new_inode_prepare(&new_inode_args, &trans_num_items);
	if (ret)
		goto out_inode;
	trans_num_items += create_subvol_num_items(inherit);

	btrfs_init_block_rsv(&block_rsv, BTRFS_BLOCK_RSV_TEMP);
	ret = btrfs_subvolume_reserve_metadata(root, &block_rsv,
					       trans_num_items, false);
	if (ret)
		goto out_new_inode_args;
	qgroup_reserved = block_rsv.qgroup_rsv_reserved;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_release_rsv;
	}
	ret = btrfs_record_root_in_trans(trans, BTRFS_I(dir)->root);
	if (ret)
		goto out;
	btrfs_qgroup_convert_reserved_meta(root, qgroup_reserved);
	qgroup_reserved = 0;
	trans->block_rsv = &block_rsv;
	trans->bytes_reserved = block_rsv.size;
	/* Tree log can't currently deal with an inode which is a new root. */
	btrfs_set_log_full_commit(trans);

	ret = btrfs_qgroup_inherit(trans, 0, objectid, inherit);
	if (ret)
		goto out;

	leaf = btrfs_alloc_tree_block(trans, root, 0, objectid, NULL, 0, 0, 0,
				      BTRFS_NESTING_NORMAL);
	if (IS_ERR(leaf)) {
		ret = PTR_ERR(leaf);
		goto out;
	}

	btrfs_mark_buffer_dirty(trans, leaf);

	inode_item = &root_item->inode;
	btrfs_set_stack_inode_generation(inode_item, 1);
	btrfs_set_stack_inode_size(inode_item, 3);
	btrfs_set_stack_inode_nlink(inode_item, 1);
	btrfs_set_stack_inode_nbytes(inode_item,
				     fs_info->nodesize);
	btrfs_set_stack_inode_mode(inode_item, S_IFDIR | 0755);

	btrfs_set_root_flags(root_item, 0);
	btrfs_set_root_limit(root_item, 0);
	btrfs_set_stack_inode_flags(inode_item, BTRFS_INODE_ROOT_ITEM_INIT);

	btrfs_set_root_bytenr(root_item, leaf->start);
	btrfs_set_root_generation(root_item, trans->transid);
	btrfs_set_root_level(root_item, 0);
	btrfs_set_root_refs(root_item, 1);
	btrfs_set_root_used(root_item, leaf->len);
	btrfs_set_root_last_snapshot(root_item, 0);

	btrfs_set_root_generation_v2(root_item,
			btrfs_root_generation(root_item));
	generate_random_guid(root_item->uuid);
	btrfs_set_stack_timespec_sec(&root_item->otime, cur_time.tv_sec);
	btrfs_set_stack_timespec_nsec(&root_item->otime, cur_time.tv_nsec);
	root_item->ctime = root_item->otime;
	btrfs_set_root_ctransid(root_item, trans->transid);
	btrfs_set_root_otransid(root_item, trans->transid);

	btrfs_tree_unlock(leaf);

	btrfs_set_root_dirid(root_item, BTRFS_FIRST_FREE_OBJECTID);

	key.objectid = objectid;
	key.offset = 0;
	key.type = BTRFS_ROOT_ITEM_KEY;
	ret = btrfs_insert_root(trans, fs_info->tree_root, &key,
				root_item);
	if (ret) {
		/*
		 * Since we don't abort the transaction in this case, free the
		 * tree block so that we don't leak space and leave the
		 * filesystem in an inconsistent state (an extent item in the
		 * extent tree with a backreference for a root that does not
		 * exists).
		 */
		btrfs_tree_lock(leaf);
		btrfs_clear_buffer_dirty(trans, leaf);
		btrfs_tree_unlock(leaf);
		btrfs_free_tree_block(trans, objectid, leaf, 0, 1);
		free_extent_buffer(leaf);
		goto out;
	}

	free_extent_buffer(leaf);
	leaf = NULL;

	new_root = btrfs_get_new_fs_root(fs_info, objectid, &anon_dev);
	if (IS_ERR(new_root)) {
		ret = PTR_ERR(new_root);
		btrfs_abort_transaction(trans, ret);
		goto out;
	}
	/* anon_dev is owned by new_root now. */
	anon_dev = 0;
	BTRFS_I(new_inode_args.inode)->root = new_root;
	/* ... and new_root is owned by new_inode_args.inode now. */

	ret = btrfs_record_root_in_trans(trans, new_root);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto out;
	}

	ret = btrfs_uuid_tree_add(trans, root_item->uuid,
				  BTRFS_UUID_KEY_SUBVOL, objectid);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto out;
	}

	ret = btrfs_create_new_inode(trans, &new_inode_args);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto out;
	}

	d_instantiate_new(dentry, new_inode_args.inode);
	new_inode_args.inode = NULL;

out:
	trans->block_rsv = NULL;
	trans->bytes_reserved = 0;
	btrfs_end_transaction(trans);
out_release_rsv:
	btrfs_block_rsv_release(fs_info, &block_rsv, (u64)-1, NULL);
	if (qgroup_reserved)
		btrfs_qgroup_free_meta_prealloc(root, qgroup_reserved);
out_new_inode_args:
	btrfs_new_inode_args_destroy(&new_inode_args);
out_inode:
	iput(new_inode_args.inode);
out_anon_dev:
	if (anon_dev)
		free_anon_bdev(anon_dev);
out_root_item:
	kfree(root_item);
	return ret;
}

static int create_snapshot(struct btrfs_root *root, struct inode *dir,
			   struct dentry *dentry, bool readonly,
			   struct btrfs_qgroup_inherit *inherit)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(dir->i_sb);
	struct inode *inode;
	struct btrfs_pending_snapshot *pending_snapshot;
	unsigned int trans_num_items;
	struct btrfs_trans_handle *trans;
	struct btrfs_block_rsv *block_rsv;
	u64 qgroup_reserved = 0;
	int ret;

	/* We do not support snapshotting right now. */
	if (btrfs_fs_incompat(fs_info, EXTENT_TREE_V2)) {
		btrfs_warn(fs_info,
			   "extent tree v2 doesn't support snapshotting yet");
		return -EOPNOTSUPP;
	}

	if (btrfs_root_refs(&root->root_item) == 0)
		return -ENOENT;

	if (!test_bit(BTRFS_ROOT_SHAREABLE, &root->state))
		return -EINVAL;

	if (atomic_read(&root->nr_swapfiles)) {
		btrfs_warn(fs_info,
			   "cannot snapshot subvolume with active swapfile");
		return -ETXTBSY;
	}

	pending_snapshot = kzalloc(sizeof(*pending_snapshot), GFP_KERNEL);
	if (!pending_snapshot)
		return -ENOMEM;

	ret = get_anon_bdev(&pending_snapshot->anon_dev);
	if (ret < 0)
		goto free_pending;
	pending_snapshot->root_item = kzalloc(sizeof(struct btrfs_root_item),
			GFP_KERNEL);
	pending_snapshot->path = btrfs_alloc_path();
	if (!pending_snapshot->root_item || !pending_snapshot->path) {
		ret = -ENOMEM;
		goto free_pending;
	}

	block_rsv = &pending_snapshot->block_rsv;
	btrfs_init_block_rsv(block_rsv, BTRFS_BLOCK_RSV_TEMP);
	/*
	 * 1 to add dir item
	 * 1 to add dir index
	 * 1 to update parent inode item
	 */
<<<<<<< HEAD
	trans_num_items = create_subvol_num_items(inherit) + 3;
	ret = btrfs_subvolume_reserve_metadata(BTRFS_I(dir)->root, block_rsv,
					       trans_num_items, false);
=======
	atomic_inc(&root->will_be_snapshotted);
	smp_mb__after_atomic();
	/* wait for no snapshot writes */
	wait_event(root->subv_writers->wait,
		   percpu_counter_sum(&root->subv_writers->counter) == 0);

	ret = btrfs_start_delalloc_snapshot(root);
>>>>>>> master
	if (ret)
		goto free_pending;
	qgroup_reserved = block_rsv->qgroup_rsv_reserved;

	pending_snapshot->dentry = dentry;
	pending_snapshot->root = root;
	pending_snapshot->readonly = readonly;
	pending_snapshot->dir = dir;
	pending_snapshot->inherit = inherit;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto fail;
	}
	ret = btrfs_record_root_in_trans(trans, BTRFS_I(dir)->root);
	if (ret) {
		btrfs_end_transaction(trans);
		goto fail;
	}
	btrfs_qgroup_convert_reserved_meta(root, qgroup_reserved);
	qgroup_reserved = 0;

	trans->pending_snapshot = pending_snapshot;

	ret = btrfs_commit_transaction(trans);
	if (ret)
		goto fail;

	ret = pending_snapshot->error;
	if (ret)
		goto fail;

	ret = btrfs_orphan_cleanup(pending_snapshot->snap);
	if (ret)
		goto fail;

	inode = btrfs_lookup_dentry(d_inode(dentry->d_parent), dentry);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto fail;
	}

	d_instantiate(dentry, inode);
	ret = 0;
	pending_snapshot->anon_dev = 0;
fail:
	/* Prevent double freeing of anon_dev */
	if (ret && pending_snapshot->snap)
		pending_snapshot->snap->anon_dev = 0;
	btrfs_put_root(pending_snapshot->snap);
	btrfs_block_rsv_release(fs_info, block_rsv, (u64)-1, NULL);
	if (qgroup_reserved)
		btrfs_qgroup_free_meta_prealloc(root, qgroup_reserved);
free_pending:
	if (pending_snapshot->anon_dev)
		free_anon_bdev(pending_snapshot->anon_dev);
	kfree(pending_snapshot->root_item);
	btrfs_free_path(pending_snapshot->path);
	kfree(pending_snapshot);

	return ret;
}

/*  copy of may_delete in fs/namei.c()
 *	Check whether we can remove a link victim from directory dir, check
 *  whether the type of victim is right.
 *  1. We can't do it if dir is read-only (done in permission())
 *  2. We should have write and exec permissions on dir
 *  3. We can't remove anything from append-only dir
 *  4. We can't do anything with immutable dir (done in permission())
 *  5. If the sticky bit on dir is set we should either
 *	a. be owner of dir, or
 *	b. be owner of victim, or
 *	c. have CAP_FOWNER capability
 *  6. If the victim is append-only or immutable we can't do anything with
 *     links pointing to it.
 *  7. If we were asked to remove a directory and victim isn't one - ENOTDIR.
 *  8. If we were asked to remove a non-directory and victim isn't one - EISDIR.
 *  9. We can't remove a root or mountpoint.
 * 10. We don't allow removal of NFS sillyrenamed files; it's handled by
 *     nfs_async_unlink().
 */

static int btrfs_may_delete(struct mnt_idmap *idmap,
			    struct inode *dir, struct dentry *victim, int isdir)
{
	int error;

	if (d_really_is_negative(victim))
		return -ENOENT;

	BUG_ON(d_inode(victim->d_parent) != dir);
	audit_inode_child(dir, victim, AUDIT_TYPE_CHILD_DELETE);

	error = inode_permission(idmap, dir, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;
	if (check_sticky(idmap, dir, d_inode(victim)) ||
	    IS_APPEND(d_inode(victim)) || IS_IMMUTABLE(d_inode(victim)) ||
	    IS_SWAPFILE(d_inode(victim)))
		return -EPERM;
	if (isdir) {
		if (!d_is_dir(victim))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (d_is_dir(victim))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}

/* copy of may_create in fs/namei.c() */
static inline int btrfs_may_create(struct mnt_idmap *idmap,
				   struct inode *dir, struct dentry *child)
{
	if (d_really_is_positive(child))
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (!fsuidgid_has_mapping(dir->i_sb, idmap))
		return -EOVERFLOW;
	return inode_permission(idmap, dir, MAY_WRITE | MAY_EXEC);
}

/*
 * Create a new subvolume below @parent.  This is largely modeled after
 * sys_mkdirat and vfs_mkdir, but we only do a single component lookup
 * inside this filesystem so it's quite a bit simpler.
 */
static noinline int btrfs_mksubvol(const struct path *parent,
				   struct mnt_idmap *idmap,
				   const char *name, int namelen,
				   struct btrfs_root *snap_src,
				   bool readonly,
				   struct btrfs_qgroup_inherit *inherit)
{
	struct inode *dir = d_inode(parent->dentry);
	struct btrfs_fs_info *fs_info = btrfs_sb(dir->i_sb);
	struct dentry *dentry;
	struct fscrypt_str name_str = FSTR_INIT((char *)name, namelen);
	int error;

	error = down_write_killable_nested(&dir->i_rwsem, I_MUTEX_PARENT);
	if (error == -EINTR)
		return error;

	dentry = lookup_one(idmap, name, parent->dentry, namelen);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_unlock;

	error = btrfs_may_create(idmap, dir, dentry);
	if (error)
		goto out_dput;

	/*
	 * even if this name doesn't exist, we may get hash collisions.
	 * check for them now when we can safely fail
	 */
	error = btrfs_check_dir_item_collision(BTRFS_I(dir)->root,
					       dir->i_ino, &name_str);
	if (error)
		goto out_dput;

	down_read(&fs_info->subvol_sem);

	if (btrfs_root_refs(&BTRFS_I(dir)->root->root_item) == 0)
		goto out_up_read;

	if (snap_src)
		error = create_snapshot(snap_src, dir, dentry, readonly, inherit);
	else
		error = create_subvol(idmap, dir, dentry, inherit);

	if (!error)
		fsnotify_mkdir(dir, dentry);
out_up_read:
	up_read(&fs_info->subvol_sem);
out_dput:
	dput(dentry);
out_unlock:
	btrfs_inode_unlock(BTRFS_I(dir), 0);
	return error;
}

static noinline int btrfs_mksnapshot(const struct path *parent,
				   struct mnt_idmap *idmap,
				   const char *name, int namelen,
				   struct btrfs_root *root,
				   bool readonly,
				   struct btrfs_qgroup_inherit *inherit)
{
	int ret;
	bool snapshot_force_cow = false;

	/*
	 * Force new buffered writes to reserve space even when NOCOW is
	 * possible. This is to avoid later writeback (running dealloc) to
	 * fallback to COW mode and unexpectedly fail with ENOSPC.
	 */
	btrfs_drew_read_lock(&root->snapshot_lock);

	ret = btrfs_start_delalloc_snapshot(root, false);
	if (ret)
		goto out;

	/*
	 * All previous writes have started writeback in NOCOW mode, so now
	 * we force future writes to fallback to COW mode during snapshot
	 * creation.
	 */
	atomic_inc(&root->snapshot_force_cow);
	snapshot_force_cow = true;

	btrfs_wait_ordered_extents(root, U64_MAX, 0, (u64)-1);

<<<<<<< HEAD
	ret = btrfs_mksubvol(parent, idmap, name, namelen,
			     root, readonly, inherit);
out:
	if (snapshot_force_cow)
		atomic_dec(&root->snapshot_force_cow);
	btrfs_drew_read_unlock(&root->snapshot_lock);
=======
	lock_extent_bits(&BTRFS_I(inode)->io_tree,
			 page_start, page_end - 1, &cached_state);
	clear_extent_bit(&BTRFS_I(inode)->io_tree, page_start,
			  page_end - 1, EXTENT_DIRTY | EXTENT_DELALLOC |
			  EXTENT_DO_ACCOUNTING | EXTENT_DEFRAG, 0, 0,
			  &cached_state);

	if (i_done != page_cnt) {
		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->outstanding_extents++;
		spin_unlock(&BTRFS_I(inode)->lock);
		btrfs_delalloc_release_space(inode, data_reserved,
				start_index << PAGE_SHIFT,
				(page_cnt - i_done) << PAGE_SHIFT, true);
	}


	set_extent_defrag(&BTRFS_I(inode)->io_tree, page_start, page_end - 1,
			  &cached_state);

	unlock_extent_cached(&BTRFS_I(inode)->io_tree,
			     page_start, page_end - 1, &cached_state);

	for (i = 0; i < i_done; i++) {
		clear_page_dirty_for_io(pages[i]);
		ClearPageChecked(pages[i]);
		set_page_extent_mapped(pages[i]);
		set_page_dirty(pages[i]);
		unlock_page(pages[i]);
		put_page(pages[i]);
	}
	btrfs_delalloc_release_extents(BTRFS_I(inode), page_cnt << PAGE_SHIFT);
	extent_changeset_free(data_reserved);
	return i_done;
out:
	for (i = 0; i < i_done; i++) {
		unlock_page(pages[i]);
		put_page(pages[i]);
	}
	btrfs_delalloc_release_space(inode, data_reserved,
			start_index << PAGE_SHIFT,
			page_cnt << PAGE_SHIFT, true);
	btrfs_delalloc_release_extents(BTRFS_I(inode), page_cnt << PAGE_SHIFT);
	extent_changeset_free(data_reserved);
>>>>>>> master
	return ret;
}

/*
 * Try to start exclusive operation @type or cancel it if it's running.
 *
 * Return:
 *   0        - normal mode, newly claimed op started
 *  >0        - normal mode, something else is running,
 *              return BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS to user space
 * ECANCELED  - cancel mode, successful cancel
 * ENOTCONN   - cancel mode, operation not running anymore
 */
static int exclop_start_or_cancel_reloc(struct btrfs_fs_info *fs_info,
			enum btrfs_exclusive_operation type, bool cancel)
{
	if (!cancel) {
		/* Start normal op */
		if (!btrfs_exclop_start(fs_info, type))
			return BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;
		/* Exclusive operation is now claimed */
		return 0;
	}

	/* Cancel running op */
	if (btrfs_exclop_start_try_lock(fs_info, type)) {
		/*
		 * This blocks any exclop finish from setting it to NONE, so we
		 * request cancellation. Either it runs and we will wait for it,
		 * or it has finished and no waiting will happen.
		 */
		atomic_inc(&fs_info->reloc_cancel_req);
		btrfs_exclop_start_unlock(fs_info);

		if (test_bit(BTRFS_FS_RELOC_RUNNING, &fs_info->flags))
			wait_on_bit(&fs_info->flags, BTRFS_FS_RELOC_RUNNING,
				    TASK_INTERRUPTIBLE);

		return -ECANCELED;
	}

	/* Something else is running or none */
	return -ENOTCONN;
}

static noinline int btrfs_ioctl_resize(struct file *file,
					void __user *arg)
{
	BTRFS_DEV_LOOKUP_ARGS(args);
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	u64 new_size;
	u64 old_size;
	u64 devid = 1;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ioctl_vol_args *vol_args;
	struct btrfs_trans_handle *trans;
	struct btrfs_device *device = NULL;
	char *sizestr;
	char *retptr;
	char *devstr = NULL;
	int ret = 0;
	int mod = 0;
	bool cancel;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	/*
	 * Read the arguments before checking exclusivity to be able to
	 * distinguish regular resize and cancel
	 */
	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args)) {
		ret = PTR_ERR(vol_args);
		goto out_drop;
	}
	vol_args->name[BTRFS_PATH_NAME_MAX] = '\0';
	sizestr = vol_args->name;
	cancel = (strcmp("cancel", sizestr) == 0);
	ret = exclop_start_or_cancel_reloc(fs_info, BTRFS_EXCLOP_RESIZE, cancel);
	if (ret)
		goto out_free;
	/* Exclusive operation is now claimed */

	devstr = strchr(sizestr, ':');
	if (devstr) {
		sizestr = devstr + 1;
		*devstr = '\0';
		devstr = vol_args->name;
		ret = kstrtoull(devstr, 10, &devid);
		if (ret)
			goto out_finish;
		if (!devid) {
			ret = -EINVAL;
			goto out_finish;
		}
		btrfs_info(fs_info, "resizing devid %llu", devid);
	}

	args.devid = devid;
	device = btrfs_find_device(fs_info->fs_devices, &args);
	if (!device) {
		btrfs_info(fs_info, "resizer unable to find device %llu",
			   devid);
		ret = -ENODEV;
		goto out_finish;
	}

	if (!test_bit(BTRFS_DEV_STATE_WRITEABLE, &device->dev_state)) {
		btrfs_info(fs_info,
			   "resizer unable to apply on readonly device %llu",
		       devid);
		ret = -EPERM;
		goto out_finish;
	}

	if (!strcmp(sizestr, "max"))
		new_size = bdev_nr_bytes(device->bdev);
	else {
		if (sizestr[0] == '-') {
			mod = -1;
			sizestr++;
		} else if (sizestr[0] == '+') {
			mod = 1;
			sizestr++;
		}
		new_size = memparse(sizestr, &retptr);
		if (*retptr != '\0' || new_size == 0) {
			ret = -EINVAL;
			goto out_finish;
		}
	}

	if (test_bit(BTRFS_DEV_STATE_REPLACE_TGT, &device->dev_state)) {
		ret = -EPERM;
		goto out_finish;
	}

	old_size = btrfs_device_get_total_bytes(device);

	if (mod < 0) {
		if (new_size > old_size) {
			ret = -EINVAL;
			goto out_finish;
		}
		new_size = old_size - new_size;
	} else if (mod > 0) {
		if (new_size > ULLONG_MAX - old_size) {
			ret = -ERANGE;
			goto out_finish;
		}
		new_size = old_size + new_size;
	}

	if (new_size < SZ_256M) {
		ret = -EINVAL;
		goto out_finish;
	}
	if (new_size > bdev_nr_bytes(device->bdev)) {
		ret = -EFBIG;
		goto out_finish;
	}

	new_size = round_down(new_size, fs_info->sectorsize);

	if (new_size > old_size) {
		trans = btrfs_start_transaction(root, 0);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			goto out_finish;
		}
		ret = btrfs_grow_device(trans, device, new_size);
		btrfs_commit_transaction(trans);
	} else if (new_size < old_size) {
		ret = btrfs_shrink_device(device, new_size);
	} /* equal, nothing need to do */

	if (ret == 0 && new_size != old_size)
		btrfs_info_in_rcu(fs_info,
			"resize device %s (devid %llu) from %llu to %llu",
			btrfs_dev_name(device), device->devid,
			old_size, new_size);
out_finish:
	btrfs_exclop_finish(fs_info);
out_free:
	kfree(vol_args);
out_drop:
	mnt_drop_write_file(file);
	return ret;
}

static noinline int __btrfs_ioctl_snap_create(struct file *file,
				struct mnt_idmap *idmap,
				const char *name, unsigned long fd, int subvol,
				bool readonly,
				struct btrfs_qgroup_inherit *inherit)
{
	int namelen;
	int ret = 0;

	if (!S_ISDIR(file_inode(file)->i_mode))
		return -ENOTDIR;

	ret = mnt_want_write_file(file);
	if (ret)
		goto out;

	namelen = strlen(name);
	if (strchr(name, '/')) {
		ret = -EINVAL;
		goto out_drop_write;
	}

	if (name[0] == '.' &&
	   (namelen == 1 || (name[1] == '.' && namelen == 2))) {
		ret = -EEXIST;
		goto out_drop_write;
	}

	if (subvol) {
		ret = btrfs_mksubvol(&file->f_path, idmap, name,
				     namelen, NULL, readonly, inherit);
	} else {
		struct fd src = fdget(fd);
		struct inode *src_inode;
		if (!src.file) {
			ret = -EINVAL;
			goto out_drop_write;
		}

		src_inode = file_inode(src.file);
		if (src_inode->i_sb != file_inode(file)->i_sb) {
			btrfs_info(BTRFS_I(file_inode(file))->root->fs_info,
				   "Snapshot src from another FS");
			ret = -EXDEV;
		} else if (!inode_owner_or_capable(idmap, src_inode)) {
			/*
			 * Subvolume creation is not restricted, but snapshots
			 * are limited to own subvolumes only
			 */
			ret = -EPERM;
		} else if (btrfs_ino(BTRFS_I(src_inode)) != BTRFS_FIRST_FREE_OBJECTID) {
			/*
			 * Snapshots must be made with the src_inode referring
			 * to the subvolume inode, otherwise the permission
			 * checking above is useless because we may have
			 * permission on a lower directory but not the subvol
			 * itself.
			 */
			ret = -EINVAL;
		} else {
			ret = btrfs_mksnapshot(&file->f_path, idmap,
					       name, namelen,
					       BTRFS_I(src_inode)->root,
					       readonly, inherit);
		}
		fdput(src);
	}
out_drop_write:
	mnt_drop_write_file(file);
out:
	return ret;
}

static noinline int btrfs_ioctl_snap_create(struct file *file,
					    void __user *arg, int subvol)
{
	struct btrfs_ioctl_vol_args *vol_args;
	int ret;

	if (!S_ISDIR(file_inode(file)->i_mode))
		return -ENOTDIR;

	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args))
		return PTR_ERR(vol_args);
	vol_args->name[BTRFS_PATH_NAME_MAX] = '\0';

	ret = __btrfs_ioctl_snap_create(file, file_mnt_idmap(file),
					vol_args->name, vol_args->fd, subvol,
					false, NULL);

	kfree(vol_args);
	return ret;
}

static noinline int btrfs_ioctl_snap_create_v2(struct file *file,
					       void __user *arg, int subvol)
{
	struct btrfs_ioctl_vol_args_v2 *vol_args;
	int ret;
	bool readonly = false;
	struct btrfs_qgroup_inherit *inherit = NULL;

	if (!S_ISDIR(file_inode(file)->i_mode))
		return -ENOTDIR;

	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args))
		return PTR_ERR(vol_args);
	vol_args->name[BTRFS_SUBVOL_NAME_MAX] = '\0';

	if (vol_args->flags & ~BTRFS_SUBVOL_CREATE_ARGS_MASK) {
		ret = -EOPNOTSUPP;
		goto free_args;
	}

	if (vol_args->flags & BTRFS_SUBVOL_RDONLY)
		readonly = true;
	if (vol_args->flags & BTRFS_SUBVOL_QGROUP_INHERIT) {
		u64 nums;

		if (vol_args->size < sizeof(*inherit) ||
		    vol_args->size > PAGE_SIZE) {
			ret = -EINVAL;
			goto free_args;
		}
		inherit = memdup_user(vol_args->qgroup_inherit, vol_args->size);
		if (IS_ERR(inherit)) {
			ret = PTR_ERR(inherit);
			goto free_args;
		}

		if (inherit->num_qgroups > PAGE_SIZE ||
		    inherit->num_ref_copies > PAGE_SIZE ||
		    inherit->num_excl_copies > PAGE_SIZE) {
			ret = -EINVAL;
			goto free_inherit;
		}

		nums = inherit->num_qgroups + 2 * inherit->num_ref_copies +
		       2 * inherit->num_excl_copies;
		if (vol_args->size != struct_size(inherit, qgroups, nums)) {
			ret = -EINVAL;
			goto free_inherit;
		}
	}

	ret = __btrfs_ioctl_snap_create(file, file_mnt_idmap(file),
					vol_args->name, vol_args->fd, subvol,
					readonly, inherit);
	if (ret)
		goto free_inherit;
free_inherit:
	kfree(inherit);
free_args:
	kfree(vol_args);
	return ret;
}

static noinline int btrfs_ioctl_subvol_getflags(struct inode *inode,
						void __user *arg)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret = 0;
	u64 flags = 0;

	if (btrfs_ino(BTRFS_I(inode)) != BTRFS_FIRST_FREE_OBJECTID)
		return -EINVAL;

	down_read(&fs_info->subvol_sem);
	if (btrfs_root_readonly(root))
		flags |= BTRFS_SUBVOL_RDONLY;
	up_read(&fs_info->subvol_sem);

	if (copy_to_user(arg, &flags, sizeof(flags)))
		ret = -EFAULT;

	return ret;
}

static noinline int btrfs_ioctl_subvol_setflags(struct file *file,
					      void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	u64 root_flags;
	u64 flags;
	int ret = 0;

	if (!inode_owner_or_capable(file_mnt_idmap(file), inode))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		goto out;

	if (btrfs_ino(BTRFS_I(inode)) != BTRFS_FIRST_FREE_OBJECTID) {
		ret = -EINVAL;
		goto out_drop_write;
	}

	if (copy_from_user(&flags, arg, sizeof(flags))) {
		ret = -EFAULT;
		goto out_drop_write;
	}

	if (flags & ~BTRFS_SUBVOL_RDONLY) {
		ret = -EOPNOTSUPP;
		goto out_drop_write;
	}

	down_write(&fs_info->subvol_sem);

	/* nothing to do */
	if (!!(flags & BTRFS_SUBVOL_RDONLY) == btrfs_root_readonly(root))
		goto out_drop_sem;

	root_flags = btrfs_root_flags(&root->root_item);
	if (flags & BTRFS_SUBVOL_RDONLY) {
		btrfs_set_root_flags(&root->root_item,
				     root_flags | BTRFS_ROOT_SUBVOL_RDONLY);
	} else {
		/*
		 * Block RO -> RW transition if this subvolume is involved in
		 * send
		 */
		spin_lock(&root->root_item_lock);
		if (root->send_in_progress == 0) {
			btrfs_set_root_flags(&root->root_item,
				     root_flags & ~BTRFS_ROOT_SUBVOL_RDONLY);
			spin_unlock(&root->root_item_lock);
		} else {
			spin_unlock(&root->root_item_lock);
			btrfs_warn(fs_info,
				   "Attempt to set subvolume %llu read-write during send",
				   root->root_key.objectid);
			ret = -EPERM;
			goto out_drop_sem;
		}
	}

	trans = btrfs_start_transaction(root, 1);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_reset;
	}

	ret = btrfs_update_root(trans, fs_info->tree_root,
				&root->root_key, &root->root_item);
	if (ret < 0) {
		btrfs_end_transaction(trans);
		goto out_reset;
	}

	ret = btrfs_commit_transaction(trans);

out_reset:
	if (ret)
		btrfs_set_root_flags(&root->root_item, root_flags);
out_drop_sem:
	up_write(&fs_info->subvol_sem);
out_drop_write:
	mnt_drop_write_file(file);
out:
	return ret;
}

static noinline int key_in_sk(struct btrfs_key *key,
			      struct btrfs_ioctl_search_key *sk)
{
	struct btrfs_key test;
	int ret;

	test.objectid = sk->min_objectid;
	test.type = sk->min_type;
	test.offset = sk->min_offset;

	ret = btrfs_comp_cpu_keys(key, &test);
	if (ret < 0)
		return 0;

	test.objectid = sk->max_objectid;
	test.type = sk->max_type;
	test.offset = sk->max_offset;

	ret = btrfs_comp_cpu_keys(key, &test);
	if (ret > 0)
		return 0;
	return 1;
}

static noinline int copy_to_sk(struct btrfs_path *path,
			       struct btrfs_key *key,
			       struct btrfs_ioctl_search_key *sk,
			       u64 *buf_size,
			       char __user *ubuf,
			       unsigned long *sk_offset,
			       int *num_found)
{
	u64 found_transid;
	struct extent_buffer *leaf;
	struct btrfs_ioctl_search_header sh;
	struct btrfs_key test;
	unsigned long item_off;
	unsigned long item_len;
	int nritems;
	int i;
	int slot;
	int ret = 0;

	leaf = path->nodes[0];
	slot = path->slots[0];
	nritems = btrfs_header_nritems(leaf);

	if (btrfs_header_generation(leaf) > sk->max_transid) {
		i = nritems;
		goto advance_key;
	}
	found_transid = btrfs_header_generation(leaf);

	for (i = slot; i < nritems; i++) {
		item_off = btrfs_item_ptr_offset(leaf, i);
		item_len = btrfs_item_size(leaf, i);

		btrfs_item_key_to_cpu(leaf, key, i);
		if (!key_in_sk(key, sk))
			continue;

		if (sizeof(sh) + item_len > *buf_size) {
			if (*num_found) {
				ret = 1;
				goto out;
			}

			/*
			 * return one empty item back for v1, which does not
			 * handle -EOVERFLOW
			 */

			*buf_size = sizeof(sh) + item_len;
			item_len = 0;
			ret = -EOVERFLOW;
		}

		if (sizeof(sh) + item_len + *sk_offset > *buf_size) {
			ret = 1;
			goto out;
		}

		sh.objectid = key->objectid;
		sh.offset = key->offset;
		sh.type = key->type;
		sh.len = item_len;
		sh.transid = found_transid;

		/*
		 * Copy search result header. If we fault then loop again so we
		 * can fault in the pages and -EFAULT there if there's a
		 * problem. Otherwise we'll fault and then copy the buffer in
		 * properly this next time through
		 */
		if (copy_to_user_nofault(ubuf + *sk_offset, &sh, sizeof(sh))) {
			ret = 0;
			goto out;
		}

		*sk_offset += sizeof(sh);

		if (item_len) {
			char __user *up = ubuf + *sk_offset;
			/*
			 * Copy the item, same behavior as above, but reset the
			 * * sk_offset so we copy the full thing again.
			 */
			if (read_extent_buffer_to_user_nofault(leaf, up,
						item_off, item_len)) {
				ret = 0;
				*sk_offset -= sizeof(sh);
				goto out;
			}

			*sk_offset += item_len;
		}
		(*num_found)++;

		if (ret) /* -EOVERFLOW from above */
			goto out;

		if (*num_found >= sk->nr_items) {
			ret = 1;
			goto out;
		}
	}
advance_key:
	ret = 0;
	test.objectid = sk->max_objectid;
	test.type = sk->max_type;
	test.offset = sk->max_offset;
	if (btrfs_comp_cpu_keys(key, &test) >= 0)
		ret = 1;
	else if (key->offset < (u64)-1)
		key->offset++;
	else if (key->type < (u8)-1) {
		key->offset = 0;
		key->type++;
	} else if (key->objectid < (u64)-1) {
		key->offset = 0;
		key->type = 0;
		key->objectid++;
	} else
		ret = 1;
out:
	/*
	 *  0: all items from this leaf copied, continue with next
	 *  1: * more items can be copied, but unused buffer is too small
	 *     * all items were found
	 *     Either way, it will stops the loop which iterates to the next
	 *     leaf
	 *  -EOVERFLOW: item was to large for buffer
	 *  -EFAULT: could not copy extent buffer back to userspace
	 */
	return ret;
}

static noinline int search_ioctl(struct inode *inode,
				 struct btrfs_ioctl_search_key *sk,
				 u64 *buf_size,
				 char __user *ubuf)
{
	struct btrfs_fs_info *info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root;
	struct btrfs_key key;
	struct btrfs_path *path;
	int ret;
	int num_found = 0;
	unsigned long sk_offset = 0;

	if (*buf_size < sizeof(struct btrfs_ioctl_search_header)) {
		*buf_size = sizeof(struct btrfs_ioctl_search_header);
		return -EOVERFLOW;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	if (sk->tree_id == 0) {
		/* search the root of the inode that was passed */
		root = btrfs_grab_root(BTRFS_I(inode)->root);
	} else {
		root = btrfs_get_fs_root(info, sk->tree_id, true);
		if (IS_ERR(root)) {
			btrfs_free_path(path);
			return PTR_ERR(root);
		}
	}

	key.objectid = sk->min_objectid;
	key.type = sk->min_type;
	key.offset = sk->min_offset;

	while (1) {
		ret = -EFAULT;
		/*
		 * Ensure that the whole user buffer is faulted in at sub-page
		 * granularity, otherwise the loop may live-lock.
		 */
		if (fault_in_subpage_writeable(ubuf + sk_offset,
					       *buf_size - sk_offset))
			break;

		ret = btrfs_search_forward(root, &key, path, sk->min_transid);
		if (ret != 0) {
			if (ret > 0)
				ret = 0;
			goto err;
		}
		ret = copy_to_sk(path, &key, sk, buf_size, ubuf,
				 &sk_offset, &num_found);
		btrfs_release_path(path);
		if (ret)
			break;

	}
	if (ret > 0)
		ret = 0;
err:
	sk->nr_items = num_found;
	btrfs_put_root(root);
	btrfs_free_path(path);
	return ret;
}

static noinline int btrfs_ioctl_tree_search(struct inode *inode,
					    void __user *argp)
{
	struct btrfs_ioctl_search_args __user *uargs = argp;
	struct btrfs_ioctl_search_key sk;
	int ret;
	u64 buf_size;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&sk, &uargs->key, sizeof(sk)))
		return -EFAULT;

	buf_size = sizeof(uargs->buf);

	ret = search_ioctl(inode, &sk, &buf_size, uargs->buf);

	/*
	 * In the origin implementation an overflow is handled by returning a
	 * search header with a len of zero, so reset ret.
	 */
	if (ret == -EOVERFLOW)
		ret = 0;

	if (ret == 0 && copy_to_user(&uargs->key, &sk, sizeof(sk)))
		ret = -EFAULT;
	return ret;
}

static noinline int btrfs_ioctl_tree_search_v2(struct inode *inode,
					       void __user *argp)
{
	struct btrfs_ioctl_search_args_v2 __user *uarg = argp;
	struct btrfs_ioctl_search_args_v2 args;
	int ret;
	u64 buf_size;
	const u64 buf_limit = SZ_16M;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* copy search header and buffer size */
	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	buf_size = args.buf_size;

	/* limit result size to 16MB */
	if (buf_size > buf_limit)
		buf_size = buf_limit;

	ret = search_ioctl(inode, &args.key, &buf_size,
			   (char __user *)(&uarg->buf[0]));
	if (ret == 0 && copy_to_user(&uarg->key, &args.key, sizeof(args.key)))
		ret = -EFAULT;
	else if (ret == -EOVERFLOW &&
		copy_to_user(&uarg->buf_size, &buf_size, sizeof(buf_size)))
		ret = -EFAULT;

	return ret;
}

/*
 * Search INODE_REFs to identify path name of 'dirid' directory
 * in a 'tree_id' tree. and sets path name to 'name'.
 */
static noinline int btrfs_search_path_in_tree(struct btrfs_fs_info *info,
				u64 tree_id, u64 dirid, char *name)
{
	struct btrfs_root *root;
	struct btrfs_key key;
	char *ptr;
	int ret = -1;
	int slot;
	int len;
	int total_len = 0;
	struct btrfs_inode_ref *iref;
	struct extent_buffer *l;
	struct btrfs_path *path;

	if (dirid == BTRFS_FIRST_FREE_OBJECTID) {
		name[0]='\0';
		return 0;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ptr = &name[BTRFS_INO_LOOKUP_PATH_MAX - 1];

	root = btrfs_get_fs_root(info, tree_id, true);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		root = NULL;
		goto out;
	}

	key.objectid = dirid;
	key.type = BTRFS_INODE_REF_KEY;
	key.offset = (u64)-1;

	while (1) {
		ret = btrfs_search_backwards(root, &key, path);
		if (ret < 0)
			goto out;
		else if (ret > 0) {
			ret = -ENOENT;
			goto out;
		}

		l = path->nodes[0];
		slot = path->slots[0];

		iref = btrfs_item_ptr(l, slot, struct btrfs_inode_ref);
		len = btrfs_inode_ref_name_len(l, iref);
		ptr -= len + 1;
		total_len += len + 1;
		if (ptr < name) {
			ret = -ENAMETOOLONG;
			goto out;
		}

		*(ptr + len) = '/';
		read_extent_buffer(l, ptr, (unsigned long)(iref + 1), len);

		if (key.offset == BTRFS_FIRST_FREE_OBJECTID)
			break;

		btrfs_release_path(path);
		key.objectid = key.offset;
		key.offset = (u64)-1;
		dirid = key.objectid;
	}
	memmove(name, ptr, total_len);
	name[total_len] = '\0';
	ret = 0;
out:
	btrfs_put_root(root);
	btrfs_free_path(path);
	return ret;
}

static int btrfs_search_path_in_tree_user(struct mnt_idmap *idmap,
				struct inode *inode,
				struct btrfs_ioctl_ino_lookup_user_args *args)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
	struct super_block *sb = inode->i_sb;
	struct btrfs_key upper_limit = BTRFS_I(inode)->location;
	u64 treeid = BTRFS_I(inode)->root->root_key.objectid;
	u64 dirid = args->dirid;
	unsigned long item_off;
	unsigned long item_len;
	struct btrfs_inode_ref *iref;
	struct btrfs_root_ref *rref;
	struct btrfs_root *root = NULL;
	struct btrfs_path *path;
	struct btrfs_key key, key2;
	struct extent_buffer *leaf;
	struct inode *temp_inode;
	char *ptr;
	int slot;
	int len;
	int total_len = 0;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	/*
	 * If the bottom subvolume does not exist directly under upper_limit,
	 * construct the path in from the bottom up.
	 */
	if (dirid != upper_limit.objectid) {
		ptr = &args->path[BTRFS_INO_LOOKUP_USER_PATH_MAX - 1];

		root = btrfs_get_fs_root(fs_info, treeid, true);
		if (IS_ERR(root)) {
			ret = PTR_ERR(root);
			goto out;
		}

		key.objectid = dirid;
		key.type = BTRFS_INODE_REF_KEY;
		key.offset = (u64)-1;
		while (1) {
			ret = btrfs_search_backwards(root, &key, path);
			if (ret < 0)
				goto out_put;
			else if (ret > 0) {
				ret = -ENOENT;
				goto out_put;
			}

			leaf = path->nodes[0];
			slot = path->slots[0];

			iref = btrfs_item_ptr(leaf, slot, struct btrfs_inode_ref);
			len = btrfs_inode_ref_name_len(leaf, iref);
			ptr -= len + 1;
			total_len += len + 1;
			if (ptr < args->path) {
				ret = -ENAMETOOLONG;
				goto out_put;
			}

			*(ptr + len) = '/';
			read_extent_buffer(leaf, ptr,
					(unsigned long)(iref + 1), len);

			/* Check the read+exec permission of this directory */
			ret = btrfs_previous_item(root, path, dirid,
						  BTRFS_INODE_ITEM_KEY);
			if (ret < 0) {
				goto out_put;
			} else if (ret > 0) {
				ret = -ENOENT;
				goto out_put;
			}

			leaf = path->nodes[0];
			slot = path->slots[0];
			btrfs_item_key_to_cpu(leaf, &key2, slot);
			if (key2.objectid != dirid) {
				ret = -ENOENT;
				goto out_put;
			}

			/*
			 * We don't need the path anymore, so release it and
			 * avoid deadlocks and lockdep warnings in case
			 * btrfs_iget() needs to lookup the inode from its root
			 * btree and lock the same leaf.
			 */
			btrfs_release_path(path);
			temp_inode = btrfs_iget(sb, key2.objectid, root);
			if (IS_ERR(temp_inode)) {
				ret = PTR_ERR(temp_inode);
				goto out_put;
			}
			ret = inode_permission(idmap, temp_inode,
					       MAY_READ | MAY_EXEC);
			iput(temp_inode);
			if (ret) {
				ret = -EACCES;
				goto out_put;
			}

			if (key.offset == upper_limit.objectid)
				break;
			if (key.objectid == BTRFS_FIRST_FREE_OBJECTID) {
				ret = -EACCES;
				goto out_put;
			}

			key.objectid = key.offset;
			key.offset = (u64)-1;
			dirid = key.objectid;
		}

		memmove(args->path, ptr, total_len);
		args->path[total_len] = '\0';
		btrfs_put_root(root);
		root = NULL;
		btrfs_release_path(path);
	}

	/* Get the bottom subvolume's name from ROOT_REF */
	key.objectid = treeid;
	key.type = BTRFS_ROOT_REF_KEY;
	key.offset = args->treeid;
	ret = btrfs_search_slot(NULL, fs_info->tree_root, &key, path, 0, 0);
	if (ret < 0) {
		goto out;
	} else if (ret > 0) {
		ret = -ENOENT;
		goto out;
	}

	leaf = path->nodes[0];
	slot = path->slots[0];
	btrfs_item_key_to_cpu(leaf, &key, slot);

	item_off = btrfs_item_ptr_offset(leaf, slot);
	item_len = btrfs_item_size(leaf, slot);
	/* Check if dirid in ROOT_REF corresponds to passed dirid */
	rref = btrfs_item_ptr(leaf, slot, struct btrfs_root_ref);
	if (args->dirid != btrfs_root_ref_dirid(leaf, rref)) {
		ret = -EINVAL;
		goto out;
	}

	/* Copy subvolume's name */
	item_off += sizeof(struct btrfs_root_ref);
	item_len -= sizeof(struct btrfs_root_ref);
	read_extent_buffer(leaf, args->name, item_off, item_len);
	args->name[item_len] = 0;

out_put:
	btrfs_put_root(root);
out:
	btrfs_free_path(path);
	return ret;
}

static noinline int btrfs_ioctl_ino_lookup(struct btrfs_root *root,
					   void __user *argp)
{
	struct btrfs_ioctl_ino_lookup_args *args;
	int ret = 0;

	args = memdup_user(argp, sizeof(*args));
	if (IS_ERR(args))
		return PTR_ERR(args);

	/*
	 * Unprivileged query to obtain the containing subvolume root id. The
	 * path is reset so it's consistent with btrfs_search_path_in_tree.
	 */
	if (args->treeid == 0)
		args->treeid = root->root_key.objectid;

	if (args->objectid == BTRFS_FIRST_FREE_OBJECTID) {
		args->name[0] = 0;
		goto out;
	}

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	ret = btrfs_search_path_in_tree(root->fs_info,
					args->treeid, args->objectid,
					args->name);

out:
	if (ret == 0 && copy_to_user(argp, args, sizeof(*args)))
		ret = -EFAULT;

	kfree(args);
	return ret;
}

/*
 * Version of ino_lookup ioctl (unprivileged)
 *
 * The main differences from ino_lookup ioctl are:
 *
 *   1. Read + Exec permission will be checked using inode_permission() during
 *      path construction. -EACCES will be returned in case of failure.
 *   2. Path construction will be stopped at the inode number which corresponds
 *      to the fd with which this ioctl is called. If constructed path does not
 *      exist under fd's inode, -EACCES will be returned.
 *   3. The name of bottom subvolume is also searched and filled.
 */
static int btrfs_ioctl_ino_lookup_user(struct file *file, void __user *argp)
{
	struct btrfs_ioctl_ino_lookup_user_args *args;
	struct inode *inode;
	int ret;

	args = memdup_user(argp, sizeof(*args));
	if (IS_ERR(args))
		return PTR_ERR(args);

	inode = file_inode(file);

	if (args->dirid == BTRFS_FIRST_FREE_OBJECTID &&
	    BTRFS_I(inode)->location.objectid != BTRFS_FIRST_FREE_OBJECTID) {
		/*
		 * The subvolume does not exist under fd with which this is
		 * called
		 */
		kfree(args);
		return -EACCES;
	}

	ret = btrfs_search_path_in_tree_user(file_mnt_idmap(file), inode, args);

	if (ret == 0 && copy_to_user(argp, args, sizeof(*args)))
		ret = -EFAULT;

	kfree(args);
	return ret;
}

/* Get the subvolume information in BTRFS_ROOT_ITEM and BTRFS_ROOT_BACKREF */
static int btrfs_ioctl_get_subvol_info(struct inode *inode, void __user *argp)
{
	struct btrfs_ioctl_get_subvol_info_args *subvol_info;
	struct btrfs_fs_info *fs_info;
	struct btrfs_root *root;
	struct btrfs_path *path;
	struct btrfs_key key;
	struct btrfs_root_item *root_item;
	struct btrfs_root_ref *rref;
	struct extent_buffer *leaf;
	unsigned long item_off;
	unsigned long item_len;
	int slot;
	int ret = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	subvol_info = kzalloc(sizeof(*subvol_info), GFP_KERNEL);
	if (!subvol_info) {
		btrfs_free_path(path);
		return -ENOMEM;
	}

	fs_info = BTRFS_I(inode)->root->fs_info;

	/* Get root_item of inode's subvolume */
	key.objectid = BTRFS_I(inode)->root->root_key.objectid;
	root = btrfs_get_fs_root(fs_info, key.objectid, true);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto out_free;
	}
	root_item = &root->root_item;

	subvol_info->treeid = key.objectid;

	subvol_info->generation = btrfs_root_generation(root_item);
	subvol_info->flags = btrfs_root_flags(root_item);

	memcpy(subvol_info->uuid, root_item->uuid, BTRFS_UUID_SIZE);
	memcpy(subvol_info->parent_uuid, root_item->parent_uuid,
						    BTRFS_UUID_SIZE);
	memcpy(subvol_info->received_uuid, root_item->received_uuid,
						    BTRFS_UUID_SIZE);

	subvol_info->ctransid = btrfs_root_ctransid(root_item);
	subvol_info->ctime.sec = btrfs_stack_timespec_sec(&root_item->ctime);
	subvol_info->ctime.nsec = btrfs_stack_timespec_nsec(&root_item->ctime);

	subvol_info->otransid = btrfs_root_otransid(root_item);
	subvol_info->otime.sec = btrfs_stack_timespec_sec(&root_item->otime);
	subvol_info->otime.nsec = btrfs_stack_timespec_nsec(&root_item->otime);

	subvol_info->stransid = btrfs_root_stransid(root_item);
	subvol_info->stime.sec = btrfs_stack_timespec_sec(&root_item->stime);
	subvol_info->stime.nsec = btrfs_stack_timespec_nsec(&root_item->stime);

	subvol_info->rtransid = btrfs_root_rtransid(root_item);
	subvol_info->rtime.sec = btrfs_stack_timespec_sec(&root_item->rtime);
	subvol_info->rtime.nsec = btrfs_stack_timespec_nsec(&root_item->rtime);

	if (key.objectid != BTRFS_FS_TREE_OBJECTID) {
		/* Search root tree for ROOT_BACKREF of this subvolume */
		key.type = BTRFS_ROOT_BACKREF_KEY;
		key.offset = 0;
		ret = btrfs_search_slot(NULL, fs_info->tree_root, &key, path, 0, 0);
		if (ret < 0) {
			goto out;
		} else if (path->slots[0] >=
			   btrfs_header_nritems(path->nodes[0])) {
			ret = btrfs_next_leaf(fs_info->tree_root, path);
			if (ret < 0) {
				goto out;
			} else if (ret > 0) {
				ret = -EUCLEAN;
				goto out;
			}
		}

		leaf = path->nodes[0];
		slot = path->slots[0];
		btrfs_item_key_to_cpu(leaf, &key, slot);
		if (key.objectid == subvol_info->treeid &&
		    key.type == BTRFS_ROOT_BACKREF_KEY) {
			subvol_info->parent_id = key.offset;

			rref = btrfs_item_ptr(leaf, slot, struct btrfs_root_ref);
			subvol_info->dirid = btrfs_root_ref_dirid(leaf, rref);

			item_off = btrfs_item_ptr_offset(leaf, slot)
					+ sizeof(struct btrfs_root_ref);
			item_len = btrfs_item_size(leaf, slot)
					- sizeof(struct btrfs_root_ref);
			read_extent_buffer(leaf, subvol_info->name,
					   item_off, item_len);
		} else {
			ret = -ENOENT;
			goto out;
		}
	}

	btrfs_free_path(path);
	path = NULL;
	if (copy_to_user(argp, subvol_info, sizeof(*subvol_info)))
		ret = -EFAULT;

out:
	btrfs_put_root(root);
out_free:
	btrfs_free_path(path);
	kfree(subvol_info);
	return ret;
}

/*
 * Return ROOT_REF information of the subvolume containing this inode
 * except the subvolume name.
 */
static int btrfs_ioctl_get_subvol_rootref(struct btrfs_root *root,
					  void __user *argp)
{
	struct btrfs_ioctl_get_subvol_rootref_args *rootrefs;
	struct btrfs_root_ref *rref;
	struct btrfs_path *path;
	struct btrfs_key key;
	struct extent_buffer *leaf;
	u64 objectid;
	int slot;
	int ret;
	u8 found;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	rootrefs = memdup_user(argp, sizeof(*rootrefs));
	if (IS_ERR(rootrefs)) {
		btrfs_free_path(path);
		return PTR_ERR(rootrefs);
	}

	objectid = root->root_key.objectid;
	key.objectid = objectid;
	key.type = BTRFS_ROOT_REF_KEY;
	key.offset = rootrefs->min_treeid;
	found = 0;

	root = root->fs_info->tree_root;
	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0) {
		goto out;
	} else if (path->slots[0] >=
		   btrfs_header_nritems(path->nodes[0])) {
		ret = btrfs_next_leaf(root, path);
		if (ret < 0) {
			goto out;
		} else if (ret > 0) {
			ret = -EUCLEAN;
			goto out;
		}
	}
	while (1) {
		leaf = path->nodes[0];
		slot = path->slots[0];

		btrfs_item_key_to_cpu(leaf, &key, slot);
		if (key.objectid != objectid || key.type != BTRFS_ROOT_REF_KEY) {
			ret = 0;
			goto out;
		}

		if (found == BTRFS_MAX_ROOTREF_BUFFER_NUM) {
			ret = -EOVERFLOW;
			goto out;
		}

		rref = btrfs_item_ptr(leaf, slot, struct btrfs_root_ref);
		rootrefs->rootref[found].treeid = key.offset;
		rootrefs->rootref[found].dirid =
				  btrfs_root_ref_dirid(leaf, rref);
		found++;

		ret = btrfs_next_item(root, path);
		if (ret < 0) {
			goto out;
		} else if (ret > 0) {
			ret = -EUCLEAN;
			goto out;
		}
	}

out:
	btrfs_free_path(path);

	if (!ret || ret == -EOVERFLOW) {
		rootrefs->num_items = found;
		/* update min_treeid for next search */
		if (found)
			rootrefs->min_treeid =
				rootrefs->rootref[found - 1].treeid + 1;
		if (copy_to_user(argp, rootrefs, sizeof(*rootrefs)))
			ret = -EFAULT;
	}

	kfree(rootrefs);

	return ret;
}

static noinline int btrfs_ioctl_snap_destroy(struct file *file,
					     void __user *arg,
					     bool destroy_v2)
{
	struct dentry *parent = file->f_path.dentry;
	struct btrfs_fs_info *fs_info = btrfs_sb(parent->d_sb);
	struct dentry *dentry;
	struct inode *dir = d_inode(parent);
	struct inode *inode;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_root *dest = NULL;
	struct btrfs_ioctl_vol_args *vol_args = NULL;
	struct btrfs_ioctl_vol_args_v2 *vol_args2 = NULL;
	struct mnt_idmap *idmap = file_mnt_idmap(file);
	char *subvol_name, *subvol_name_ptr = NULL;
	int subvol_namelen;
	int err = 0;
	bool destroy_parent = false;

	/* We don't support snapshots with extent tree v2 yet. */
	if (btrfs_fs_incompat(fs_info, EXTENT_TREE_V2)) {
		btrfs_err(fs_info,
			  "extent tree v2 doesn't support snapshot deletion yet");
		return -EOPNOTSUPP;
	}

	if (destroy_v2) {
		vol_args2 = memdup_user(arg, sizeof(*vol_args2));
		if (IS_ERR(vol_args2))
			return PTR_ERR(vol_args2);

		if (vol_args2->flags & ~BTRFS_SUBVOL_DELETE_ARGS_MASK) {
			err = -EOPNOTSUPP;
			goto out;
		}

		/*
		 * If SPEC_BY_ID is not set, we are looking for the subvolume by
		 * name, same as v1 currently does.
		 */
		if (!(vol_args2->flags & BTRFS_SUBVOL_SPEC_BY_ID)) {
			vol_args2->name[BTRFS_SUBVOL_NAME_MAX] = 0;
			subvol_name = vol_args2->name;

			err = mnt_want_write_file(file);
			if (err)
				goto out;
		} else {
			struct inode *old_dir;

			if (vol_args2->subvolid < BTRFS_FIRST_FREE_OBJECTID) {
				err = -EINVAL;
				goto out;
			}

			err = mnt_want_write_file(file);
			if (err)
				goto out;

			dentry = btrfs_get_dentry(fs_info->sb,
					BTRFS_FIRST_FREE_OBJECTID,
					vol_args2->subvolid, 0);
			if (IS_ERR(dentry)) {
				err = PTR_ERR(dentry);
				goto out_drop_write;
			}

			/*
			 * Change the default parent since the subvolume being
			 * deleted can be outside of the current mount point.
			 */
			parent = btrfs_get_parent(dentry);

			/*
			 * At this point dentry->d_name can point to '/' if the
			 * subvolume we want to destroy is outsite of the
			 * current mount point, so we need to release the
			 * current dentry and execute the lookup to return a new
			 * one with ->d_name pointing to the
			 * <mount point>/subvol_name.
			 */
			dput(dentry);
			if (IS_ERR(parent)) {
				err = PTR_ERR(parent);
				goto out_drop_write;
			}
			old_dir = dir;
			dir = d_inode(parent);

			/*
			 * If v2 was used with SPEC_BY_ID, a new parent was
			 * allocated since the subvolume can be outside of the
			 * current mount point. Later on we need to release this
			 * new parent dentry.
			 */
			destroy_parent = true;

			/*
			 * On idmapped mounts, deletion via subvolid is
			 * restricted to subvolumes that are immediate
			 * ancestors of the inode referenced by the file
			 * descriptor in the ioctl. Otherwise the idmapping
			 * could potentially be abused to delete subvolumes
			 * anywhere in the filesystem the user wouldn't be able
			 * to delete without an idmapped mount.
			 */
			if (old_dir != dir && idmap != &nop_mnt_idmap) {
				err = -EOPNOTSUPP;
				goto free_parent;
			}

			subvol_name_ptr = btrfs_get_subvol_name_from_objectid(
						fs_info, vol_args2->subvolid);
			if (IS_ERR(subvol_name_ptr)) {
				err = PTR_ERR(subvol_name_ptr);
				goto free_parent;
			}
			/* subvol_name_ptr is already nul terminated */
			subvol_name = (char *)kbasename(subvol_name_ptr);
		}
	} else {
		vol_args = memdup_user(arg, sizeof(*vol_args));
		if (IS_ERR(vol_args))
			return PTR_ERR(vol_args);

		vol_args->name[BTRFS_PATH_NAME_MAX] = 0;
		subvol_name = vol_args->name;

		err = mnt_want_write_file(file);
		if (err)
			goto out;
	}

	subvol_namelen = strlen(subvol_name);

	if (strchr(subvol_name, '/') ||
	    strncmp(subvol_name, "..", subvol_namelen) == 0) {
		err = -EINVAL;
		goto free_subvol_name;
	}

	if (!S_ISDIR(dir->i_mode)) {
		err = -ENOTDIR;
		goto free_subvol_name;
	}

	err = down_write_killable_nested(&dir->i_rwsem, I_MUTEX_PARENT);
	if (err == -EINTR)
		goto free_subvol_name;
	dentry = lookup_one(idmap, subvol_name, parent, subvol_namelen);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		goto out_unlock_dir;
	}

	if (d_really_is_negative(dentry)) {
		err = -ENOENT;
		goto out_dput;
	}

	inode = d_inode(dentry);
	dest = BTRFS_I(inode)->root;
	if (!capable(CAP_SYS_ADMIN)) {
		/*
		 * Regular user.  Only allow this with a special mount
		 * option, when the user has write+exec access to the
		 * subvol root, and when rmdir(2) would have been
		 * allowed.
		 *
		 * Note that this is _not_ check that the subvol is
		 * empty or doesn't contain data that we wouldn't
		 * otherwise be able to delete.
		 *
		 * Users who want to delete empty subvols should try
		 * rmdir(2).
		 */
		err = -EPERM;
		if (!btrfs_test_opt(fs_info, USER_SUBVOL_RM_ALLOWED))
			goto out_dput;

		/*
		 * Do not allow deletion if the parent dir is the same
		 * as the dir to be deleted.  That means the ioctl
		 * must be called on the dentry referencing the root
		 * of the subvol, not a random directory contained
		 * within it.
		 */
		err = -EINVAL;
		if (root == dest)
			goto out_dput;

		err = inode_permission(idmap, inode, MAY_WRITE | MAY_EXEC);
		if (err)
			goto out_dput;
	}

	/* check if subvolume may be deleted by a user */
	err = btrfs_may_delete(idmap, dir, dentry, 1);
	if (err)
		goto out_dput;

	if (btrfs_ino(BTRFS_I(inode)) != BTRFS_FIRST_FREE_OBJECTID) {
		err = -EINVAL;
		goto out_dput;
	}

	btrfs_inode_lock(BTRFS_I(inode), 0);
	err = btrfs_delete_subvolume(BTRFS_I(dir), dentry);
	btrfs_inode_unlock(BTRFS_I(inode), 0);
	if (!err)
		d_delete_notify(dir, dentry);

out_dput:
	dput(dentry);
out_unlock_dir:
	btrfs_inode_unlock(BTRFS_I(dir), 0);
free_subvol_name:
	kfree(subvol_name_ptr);
free_parent:
	if (destroy_parent)
		dput(parent);
out_drop_write:
	mnt_drop_write_file(file);
out:
	kfree(vol_args2);
	kfree(vol_args);
	return err;
}

static int btrfs_ioctl_defrag(struct file *file, void __user *argp)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ioctl_defrag_range_args range = {0};
	int ret;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	if (btrfs_root_readonly(root)) {
		ret = -EROFS;
		goto out;
	}

	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		if (!capable(CAP_SYS_ADMIN)) {
			ret = -EPERM;
			goto out;
		}
		ret = btrfs_defrag_root(root);
		break;
	case S_IFREG:
		/*
		 * Note that this does not check the file descriptor for write
		 * access. This prevents defragmenting executables that are
		 * running and allows defrag on files open in read-only mode.
		 */
		if (!capable(CAP_SYS_ADMIN) &&
		    inode_permission(&nop_mnt_idmap, inode, MAY_WRITE)) {
			ret = -EPERM;
			goto out;
		}

		if (argp) {
			if (copy_from_user(&range, argp, sizeof(range))) {
				ret = -EFAULT;
				goto out;
			}
			if (range.flags & ~BTRFS_DEFRAG_RANGE_FLAGS_SUPP) {
				ret = -EOPNOTSUPP;
				goto out;
			}
			/* compression requires us to start the IO */
			if ((range.flags & BTRFS_DEFRAG_RANGE_COMPRESS)) {
				range.flags |= BTRFS_DEFRAG_RANGE_START_IO;
				range.extent_thresh = (u32)-1;
			}
		} else {
			/* the rest are all set to zero by kzalloc */
			range.len = (u64)-1;
		}
		ret = btrfs_defrag_file(file_inode(file), &file->f_ra,
					&range, BTRFS_OLDEST_GENERATION, 0);
		if (ret > 0)
			ret = 0;
		break;
	default:
		ret = -EINVAL;
	}
out:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_add_dev(struct btrfs_fs_info *fs_info, void __user *arg)
{
	struct btrfs_ioctl_vol_args *vol_args;
	bool restore_op = false;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (btrfs_fs_incompat(fs_info, EXTENT_TREE_V2)) {
		btrfs_err(fs_info, "device add not supported on extent tree v2 yet");
		return -EINVAL;
	}

	if (!btrfs_exclop_start(fs_info, BTRFS_EXCLOP_DEV_ADD)) {
		if (!btrfs_exclop_start_try_lock(fs_info, BTRFS_EXCLOP_DEV_ADD))
			return BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;

		/*
		 * We can do the device add because we have a paused balanced,
		 * change the exclusive op type and remember we should bring
		 * back the paused balance
		 */
		fs_info->exclusive_operation = BTRFS_EXCLOP_DEV_ADD;
		btrfs_exclop_start_unlock(fs_info);
		restore_op = true;
	}

	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args)) {
		ret = PTR_ERR(vol_args);
		goto out;
	}

	vol_args->name[BTRFS_PATH_NAME_MAX] = '\0';
	ret = btrfs_init_new_device(fs_info, vol_args->name);

	if (!ret)
		btrfs_info(fs_info, "disk added %s", vol_args->name);

	kfree(vol_args);
out:
	if (restore_op)
		btrfs_exclop_balance(fs_info, BTRFS_EXCLOP_BALANCE_PAUSED);
	else
		btrfs_exclop_finish(fs_info);
	return ret;
}

static long btrfs_ioctl_rm_dev_v2(struct file *file, void __user *arg)
{
	BTRFS_DEV_LOOKUP_ARGS(args);
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_ioctl_vol_args_v2 *vol_args;
	struct block_device *bdev = NULL;
	void *holder;
	int ret;
	bool cancel = false;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args))
		return PTR_ERR(vol_args);

	if (vol_args->flags & ~BTRFS_DEVICE_REMOVE_ARGS_MASK) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	vol_args->name[BTRFS_SUBVOL_NAME_MAX] = '\0';
	if (vol_args->flags & BTRFS_DEVICE_SPEC_BY_ID) {
		args.devid = vol_args->devid;
	} else if (!strcmp("cancel", vol_args->name)) {
		cancel = true;
	} else {
		ret = btrfs_get_dev_args_from_path(fs_info, &args, vol_args->name);
		if (ret)
			goto out;
	}

	ret = mnt_want_write_file(file);
	if (ret)
		goto out;

	ret = exclop_start_or_cancel_reloc(fs_info, BTRFS_EXCLOP_DEV_REMOVE,
					   cancel);
	if (ret)
		goto err_drop;

	/* Exclusive operation is now claimed */
	ret = btrfs_rm_device(fs_info, &args, &bdev, &holder);

	btrfs_exclop_finish(fs_info);

	if (!ret) {
		if (vol_args->flags & BTRFS_DEVICE_SPEC_BY_ID)
			btrfs_info(fs_info, "device deleted: id %llu",
					vol_args->devid);
		else
			btrfs_info(fs_info, "device deleted: %s",
					vol_args->name);
	}
err_drop:
	mnt_drop_write_file(file);
	if (bdev)
		blkdev_put(bdev, holder);
out:
	btrfs_put_dev_args_from_path(&args);
	kfree(vol_args);
	return ret;
}

static long btrfs_ioctl_rm_dev(struct file *file, void __user *arg)
{
	BTRFS_DEV_LOOKUP_ARGS(args);
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_ioctl_vol_args *vol_args;
	struct block_device *bdev = NULL;
	void *holder;
	int ret;
	bool cancel = false;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args))
		return PTR_ERR(vol_args);

	vol_args->name[BTRFS_PATH_NAME_MAX] = '\0';
	if (!strcmp("cancel", vol_args->name)) {
		cancel = true;
	} else {
		ret = btrfs_get_dev_args_from_path(fs_info, &args, vol_args->name);
		if (ret)
			goto out;
	}

	ret = mnt_want_write_file(file);
	if (ret)
		goto out;

	ret = exclop_start_or_cancel_reloc(fs_info, BTRFS_EXCLOP_DEV_REMOVE,
					   cancel);
	if (ret == 0) {
		ret = btrfs_rm_device(fs_info, &args, &bdev, &holder);
		if (!ret)
			btrfs_info(fs_info, "disk deleted %s", vol_args->name);
		btrfs_exclop_finish(fs_info);
	}

	mnt_drop_write_file(file);
	if (bdev)
		blkdev_put(bdev, holder);
out:
	btrfs_put_dev_args_from_path(&args);
	kfree(vol_args);
	return ret;
}

static long btrfs_ioctl_fs_info(struct btrfs_fs_info *fs_info,
				void __user *arg)
{
	struct btrfs_ioctl_fs_info_args *fi_args;
	struct btrfs_device *device;
	struct btrfs_fs_devices *fs_devices = fs_info->fs_devices;
	u64 flags_in;
	int ret = 0;

	fi_args = memdup_user(arg, sizeof(*fi_args));
	if (IS_ERR(fi_args))
		return PTR_ERR(fi_args);

	flags_in = fi_args->flags;
	memset(fi_args, 0, sizeof(*fi_args));

	rcu_read_lock();
	fi_args->num_devices = fs_devices->num_devices;

	list_for_each_entry_rcu(device, &fs_devices->devices, dev_list) {
		if (device->devid > fi_args->max_id)
			fi_args->max_id = device->devid;
	}
	rcu_read_unlock();

	memcpy(&fi_args->fsid, fs_devices->fsid, sizeof(fi_args->fsid));
	fi_args->nodesize = fs_info->nodesize;
	fi_args->sectorsize = fs_info->sectorsize;
	fi_args->clone_alignment = fs_info->sectorsize;

	if (flags_in & BTRFS_FS_INFO_FLAG_CSUM_INFO) {
		fi_args->csum_type = btrfs_super_csum_type(fs_info->super_copy);
		fi_args->csum_size = btrfs_super_csum_size(fs_info->super_copy);
		fi_args->flags |= BTRFS_FS_INFO_FLAG_CSUM_INFO;
	}

	if (flags_in & BTRFS_FS_INFO_FLAG_GENERATION) {
		fi_args->generation = fs_info->generation;
		fi_args->flags |= BTRFS_FS_INFO_FLAG_GENERATION;
	}

	if (flags_in & BTRFS_FS_INFO_FLAG_METADATA_UUID) {
		memcpy(&fi_args->metadata_uuid, fs_devices->metadata_uuid,
		       sizeof(fi_args->metadata_uuid));
		fi_args->flags |= BTRFS_FS_INFO_FLAG_METADATA_UUID;
	}

	if (copy_to_user(arg, fi_args, sizeof(*fi_args)))
		ret = -EFAULT;

	kfree(fi_args);
	return ret;
}

static long btrfs_ioctl_dev_info(struct btrfs_fs_info *fs_info,
				 void __user *arg)
{
	BTRFS_DEV_LOOKUP_ARGS(args);
	struct btrfs_ioctl_dev_info_args *di_args;
	struct btrfs_device *dev;
	int ret = 0;

	di_args = memdup_user(arg, sizeof(*di_args));
	if (IS_ERR(di_args))
		return PTR_ERR(di_args);

	args.devid = di_args->devid;
	if (!btrfs_is_empty_uuid(di_args->uuid))
		args.uuid = di_args->uuid;

	rcu_read_lock();
	dev = btrfs_find_device(fs_info->fs_devices, &args);
	if (!dev) {
		ret = -ENODEV;
		goto out;
	}

	di_args->devid = dev->devid;
	di_args->bytes_used = btrfs_device_get_bytes_used(dev);
	di_args->total_bytes = btrfs_device_get_total_bytes(dev);
	memcpy(di_args->uuid, dev->uuid, sizeof(di_args->uuid));
	memcpy(di_args->fsid, dev->fs_devices->fsid, BTRFS_UUID_SIZE);
	if (dev->name)
		strscpy(di_args->path, btrfs_dev_name(dev), sizeof(di_args->path));
	else
		di_args->path[0] = '\0';

out:
	rcu_read_unlock();
	if (ret == 0 && copy_to_user(arg, di_args, sizeof(*di_args)))
		ret = -EFAULT;

	kfree(di_args);
	return ret;
}

<<<<<<< HEAD
=======
static struct page *extent_same_get_page(struct inode *inode, pgoff_t index)
{
	struct page *page;

	page = grab_cache_page(inode->i_mapping, index);
	if (!page)
		return ERR_PTR(-ENOMEM);

	if (!PageUptodate(page)) {
		int ret;

		ret = btrfs_readpage(NULL, page);
		if (ret)
			return ERR_PTR(ret);
		lock_page(page);
		if (!PageUptodate(page)) {
			unlock_page(page);
			put_page(page);
			return ERR_PTR(-EIO);
		}
		if (page->mapping != inode->i_mapping) {
			unlock_page(page);
			put_page(page);
			return ERR_PTR(-EAGAIN);
		}
	}

	return page;
}

static int gather_extent_pages(struct inode *inode, struct page **pages,
			       int num_pages, u64 off)
{
	int i;
	pgoff_t index = off >> PAGE_SHIFT;

	for (i = 0; i < num_pages; i++) {
again:
		pages[i] = extent_same_get_page(inode, index + i);
		if (IS_ERR(pages[i])) {
			int err = PTR_ERR(pages[i]);

			if (err == -EAGAIN)
				goto again;
			pages[i] = NULL;
			return err;
		}
	}
	return 0;
}

static int lock_extent_range(struct inode *inode, u64 off, u64 len,
			     bool retry_range_locking)
{
	/*
	 * Do any pending delalloc/csum calculations on inode, one way or
	 * another, and lock file content.
	 * The locking order is:
	 *
	 *   1) pages
	 *   2) range in the inode's io tree
	 */
	while (1) {
		struct btrfs_ordered_extent *ordered;
		lock_extent(&BTRFS_I(inode)->io_tree, off, off + len - 1);
		ordered = btrfs_lookup_first_ordered_extent(inode,
							    off + len - 1);
		if ((!ordered ||
		     ordered->file_offset + ordered->len <= off ||
		     ordered->file_offset >= off + len) &&
		    !test_range_bit(&BTRFS_I(inode)->io_tree, off,
				    off + len - 1, EXTENT_DELALLOC, 0, NULL)) {
			if (ordered)
				btrfs_put_ordered_extent(ordered);
			break;
		}
		unlock_extent(&BTRFS_I(inode)->io_tree, off, off + len - 1);
		if (ordered)
			btrfs_put_ordered_extent(ordered);
		if (!retry_range_locking)
			return -EAGAIN;
		btrfs_wait_ordered_range(inode, off, len);
	}
	return 0;
}

static void btrfs_double_inode_unlock(struct inode *inode1, struct inode *inode2)
{
	inode_unlock(inode1);
	inode_unlock(inode2);
}

static void btrfs_double_inode_lock(struct inode *inode1, struct inode *inode2)
{
	if (inode1 < inode2)
		swap(inode1, inode2);

	inode_lock_nested(inode1, I_MUTEX_PARENT);
	inode_lock_nested(inode2, I_MUTEX_CHILD);
}

static void btrfs_double_extent_unlock(struct inode *inode1, u64 loff1,
				      struct inode *inode2, u64 loff2, u64 len)
{
	unlock_extent(&BTRFS_I(inode1)->io_tree, loff1, loff1 + len - 1);
	unlock_extent(&BTRFS_I(inode2)->io_tree, loff2, loff2 + len - 1);
}

static int btrfs_double_extent_lock(struct inode *inode1, u64 loff1,
				    struct inode *inode2, u64 loff2, u64 len,
				    bool retry_range_locking)
{
	int ret;

	if (inode1 < inode2) {
		swap(inode1, inode2);
		swap(loff1, loff2);
	}
	ret = lock_extent_range(inode1, loff1, len, retry_range_locking);
	if (ret)
		return ret;
	ret = lock_extent_range(inode2, loff2, len, retry_range_locking);
	if (ret)
		unlock_extent(&BTRFS_I(inode1)->io_tree, loff1,
			      loff1 + len - 1);
	return ret;
}

struct cmp_pages {
	int		num_pages;
	struct page	**src_pages;
	struct page	**dst_pages;
};

static void btrfs_cmp_data_free(struct cmp_pages *cmp)
{
	int i;
	struct page *pg;

	for (i = 0; i < cmp->num_pages; i++) {
		pg = cmp->src_pages[i];
		if (pg) {
			unlock_page(pg);
			put_page(pg);
			cmp->src_pages[i] = NULL;
		}
		pg = cmp->dst_pages[i];
		if (pg) {
			unlock_page(pg);
			put_page(pg);
			cmp->dst_pages[i] = NULL;
		}
	}
}

static int btrfs_cmp_data_prepare(struct inode *src, u64 loff,
				  struct inode *dst, u64 dst_loff,
				  u64 len, struct cmp_pages *cmp)
{
	int ret;
	int num_pages = PAGE_ALIGN(len) >> PAGE_SHIFT;

	cmp->num_pages = num_pages;

	ret = gather_extent_pages(src, cmp->src_pages, num_pages, loff);
	if (ret)
		goto out;

	ret = gather_extent_pages(dst, cmp->dst_pages, num_pages, dst_loff);

out:
	if (ret)
		btrfs_cmp_data_free(cmp);
	return ret;
}

static int btrfs_cmp_data(u64 len, struct cmp_pages *cmp)
{
	int ret = 0;
	int i;
	struct page *src_page, *dst_page;
	unsigned int cmp_len = PAGE_SIZE;
	void *addr, *dst_addr;

	i = 0;
	while (len) {
		if (len < PAGE_SIZE)
			cmp_len = len;

		BUG_ON(i >= cmp->num_pages);

		src_page = cmp->src_pages[i];
		dst_page = cmp->dst_pages[i];
		ASSERT(PageLocked(src_page));
		ASSERT(PageLocked(dst_page));

		addr = kmap_atomic(src_page);
		dst_addr = kmap_atomic(dst_page);

		flush_dcache_page(src_page);
		flush_dcache_page(dst_page);

		if (memcmp(addr, dst_addr, cmp_len))
			ret = -EBADE;

		kunmap_atomic(addr);
		kunmap_atomic(dst_addr);

		if (ret)
			break;

		len -= cmp_len;
		i++;
	}

	return ret;
}

static int extent_same_check_offsets(struct inode *inode, u64 off, u64 *plen,
				     u64 olen)
{
	u64 len = *plen;
	u64 bs = BTRFS_I(inode)->root->fs_info->sb->s_blocksize;

	if (off + olen > inode->i_size || off + olen < off)
		return -EINVAL;

	/* if we extend to eof, continue to block boundary */
	if (off + len == inode->i_size)
		*plen = len = ALIGN(inode->i_size, bs) - off;

	/* Check that we are block aligned - btrfs_clone() requires this */
	if (!IS_ALIGNED(off, bs) || !IS_ALIGNED(off + len, bs))
		return -EINVAL;

	return 0;
}

static int btrfs_extent_same_range(struct inode *src, u64 loff, u64 olen,
				   struct inode *dst, u64 dst_loff,
				   struct cmp_pages *cmp)
{
	int ret;
	u64 len = olen;
	bool same_inode = (src == dst);
	u64 same_lock_start = 0;
	u64 same_lock_len = 0;

	ret = extent_same_check_offsets(src, loff, &len, olen);
	if (ret)
		return ret;

	ret = extent_same_check_offsets(dst, dst_loff, &len, olen);
	if (ret)
		return ret;

	if (same_inode) {
		/*
		 * Single inode case wants the same checks, except we
		 * don't want our length pushed out past i_size as
		 * comparing that data range makes no sense.
		 *
		 * extent_same_check_offsets() will do this for an
		 * unaligned length at i_size, so catch it here and
		 * reject the request.
		 *
		 * This effectively means we require aligned extents
		 * for the single-inode case, whereas the other cases
		 * allow an unaligned length so long as it ends at
		 * i_size.
		 */
		if (len != olen)
			return -EINVAL;

		/* Check for overlapping ranges */
		if (dst_loff + len > loff && dst_loff < loff + len)
			return -EINVAL;

		same_lock_start = min_t(u64, loff, dst_loff);
		same_lock_len = max_t(u64, loff, dst_loff) + len - same_lock_start;
	} else {
		/*
		 * If the source and destination inodes are different, the
		 * source's range end offset matches the source's i_size, that
		 * i_size is not a multiple of the sector size, and the
		 * destination range does not go past the destination's i_size,
		 * we must round down the length to the nearest sector size
		 * multiple. If we don't do this adjustment we end replacing
		 * with zeroes the bytes in the range that starts at the
		 * deduplication range's end offset and ends at the next sector
		 * size multiple.
		 */
		if (loff + olen == i_size_read(src) &&
		    dst_loff + len < i_size_read(dst)) {
			const u64 sz = BTRFS_I(src)->root->fs_info->sectorsize;

			len = round_down(i_size_read(src), sz) - loff;
			if (len == 0)
				return 0;
			olen = len;
		}
	}

again:
	ret = btrfs_cmp_data_prepare(src, loff, dst, dst_loff, olen, cmp);
	if (ret)
		return ret;

	if (same_inode)
		ret = lock_extent_range(src, same_lock_start, same_lock_len,
					false);
	else
		ret = btrfs_double_extent_lock(src, loff, dst, dst_loff, len,
					       false);
	/*
	 * If one of the inodes has dirty pages in the respective range or
	 * ordered extents, we need to flush dellaloc and wait for all ordered
	 * extents in the range. We must unlock the pages and the ranges in the
	 * io trees to avoid deadlocks when flushing delalloc (requires locking
	 * pages) and when waiting for ordered extents to complete (they require
	 * range locking).
	 */
	if (ret == -EAGAIN) {
		/*
		 * Ranges in the io trees already unlocked. Now unlock all
		 * pages before waiting for all IO to complete.
		 */
		btrfs_cmp_data_free(cmp);
		if (same_inode) {
			btrfs_wait_ordered_range(src, same_lock_start,
						 same_lock_len);
		} else {
			btrfs_wait_ordered_range(src, loff, len);
			btrfs_wait_ordered_range(dst, dst_loff, len);
		}
		goto again;
	}
	ASSERT(ret == 0);
	if (WARN_ON(ret)) {
		/* ranges in the io trees already unlocked */
		btrfs_cmp_data_free(cmp);
		return ret;
	}

	/* pass original length for comparison so we stay within i_size */
	ret = btrfs_cmp_data(olen, cmp);
	if (ret == 0)
		ret = btrfs_clone(src, dst, loff, olen, len, dst_loff, 1);

	if (same_inode)
		unlock_extent(&BTRFS_I(src)->io_tree, same_lock_start,
			      same_lock_start + same_lock_len - 1);
	else
		btrfs_double_extent_unlock(src, loff, dst, dst_loff, len);

	btrfs_cmp_data_free(cmp);

	return ret;
}

#define BTRFS_MAX_DEDUPE_LEN	SZ_16M

static int btrfs_extent_same(struct inode *src, u64 loff, u64 olen,
			     struct inode *dst, u64 dst_loff)
{
	int ret;
	struct cmp_pages cmp;
	int num_pages = PAGE_ALIGN(BTRFS_MAX_DEDUPE_LEN) >> PAGE_SHIFT;
	bool same_inode = (src == dst);
	u64 i, tail_len, chunk_count;

	if (olen == 0)
		return 0;

	if (same_inode)
		inode_lock(src);
	else
		btrfs_double_inode_lock(src, dst);

	/* don't make the dst file partly checksummed */
	if ((BTRFS_I(src)->flags & BTRFS_INODE_NODATASUM) !=
	    (BTRFS_I(dst)->flags & BTRFS_INODE_NODATASUM)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	tail_len = olen % BTRFS_MAX_DEDUPE_LEN;
	chunk_count = div_u64(olen, BTRFS_MAX_DEDUPE_LEN);
	if (chunk_count == 0)
		num_pages = PAGE_ALIGN(tail_len) >> PAGE_SHIFT;

	/*
	 * If deduping ranges in the same inode, locking rules make it
	 * mandatory to always lock pages in ascending order to avoid deadlocks
	 * with concurrent tasks (such as starting writeback/delalloc).
	 */
	if (same_inode && dst_loff < loff)
		swap(loff, dst_loff);

	/*
	 * We must gather up all the pages before we initiate our extent
	 * locking. We use an array for the page pointers. Size of the array is
	 * bounded by len, which is in turn bounded by BTRFS_MAX_DEDUPE_LEN.
	 */
	cmp.src_pages = kvmalloc_array(num_pages, sizeof(struct page *),
				       GFP_KERNEL | __GFP_ZERO);
	cmp.dst_pages = kvmalloc_array(num_pages, sizeof(struct page *),
				       GFP_KERNEL | __GFP_ZERO);
	if (!cmp.src_pages || !cmp.dst_pages) {
		ret = -ENOMEM;
		goto out_free;
	}

	for (i = 0; i < chunk_count; i++) {
		ret = btrfs_extent_same_range(src, loff, BTRFS_MAX_DEDUPE_LEN,
					      dst, dst_loff, &cmp);
		if (ret)
			goto out_free;

		loff += BTRFS_MAX_DEDUPE_LEN;
		dst_loff += BTRFS_MAX_DEDUPE_LEN;
	}

	if (tail_len > 0)
		ret = btrfs_extent_same_range(src, loff, tail_len, dst,
					      dst_loff, &cmp);

out_free:
	kvfree(cmp.src_pages);
	kvfree(cmp.dst_pages);

out_unlock:
	if (same_inode)
		inode_unlock(src);
	else
		btrfs_double_inode_unlock(src, dst);

	return ret;
}

int btrfs_dedupe_file_range(struct file *src_file, loff_t src_loff,
			    struct file *dst_file, loff_t dst_loff,
			    u64 olen)
{
	struct inode *src = file_inode(src_file);
	struct inode *dst = file_inode(dst_file);
	u64 bs = BTRFS_I(src)->root->fs_info->sb->s_blocksize;

	if (WARN_ON_ONCE(bs < PAGE_SIZE)) {
		/*
		 * Btrfs does not support blocksize < page_size. As a
		 * result, btrfs_cmp_data() won't correctly handle
		 * this situation without an update.
		 */
		return -EINVAL;
	}

	return btrfs_extent_same(src, src_loff, olen, dst, dst_loff);
}

static int clone_finish_inode_update(struct btrfs_trans_handle *trans,
				     struct inode *inode,
				     u64 endoff,
				     const u64 destoff,
				     const u64 olen,
				     int no_time_update)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	inode_inc_iversion(inode);
	if (!no_time_update)
		inode->i_mtime = inode->i_ctime = current_time(inode);
	/*
	 * We round up to the block size at eof when determining which
	 * extents to clone above, but shouldn't round up the file size.
	 */
	if (endoff > destoff + olen)
		endoff = destoff + olen;
	if (endoff > inode->i_size)
		btrfs_i_size_write(BTRFS_I(inode), endoff);

	ret = btrfs_update_inode(trans, root, inode);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		btrfs_end_transaction(trans);
		goto out;
	}
	ret = btrfs_end_transaction(trans);
out:
	return ret;
}

static void clone_update_extent_map(struct btrfs_inode *inode,
				    const struct btrfs_trans_handle *trans,
				    const struct btrfs_path *path,
				    const u64 hole_offset,
				    const u64 hole_len)
{
	struct extent_map_tree *em_tree = &inode->extent_tree;
	struct extent_map *em;
	int ret;

	em = alloc_extent_map();
	if (!em) {
		set_bit(BTRFS_INODE_NEEDS_FULL_SYNC, &inode->runtime_flags);
		return;
	}

	if (path) {
		struct btrfs_file_extent_item *fi;

		fi = btrfs_item_ptr(path->nodes[0], path->slots[0],
				    struct btrfs_file_extent_item);
		btrfs_extent_item_to_extent_map(inode, path, fi, false, em);
		em->generation = -1;
		if (btrfs_file_extent_type(path->nodes[0], fi) ==
		    BTRFS_FILE_EXTENT_INLINE)
			set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
					&inode->runtime_flags);
	} else {
		em->start = hole_offset;
		em->len = hole_len;
		em->ram_bytes = em->len;
		em->orig_start = hole_offset;
		em->block_start = EXTENT_MAP_HOLE;
		em->block_len = 0;
		em->orig_block_len = 0;
		em->compress_type = BTRFS_COMPRESS_NONE;
		em->generation = trans->transid;
	}

	while (1) {
		write_lock(&em_tree->lock);
		ret = add_extent_mapping(em_tree, em, 1);
		write_unlock(&em_tree->lock);
		if (ret != -EEXIST) {
			free_extent_map(em);
			break;
		}
		btrfs_drop_extent_cache(inode, em->start,
					em->start + em->len - 1, 0);
	}

	if (ret)
		set_bit(BTRFS_INODE_NEEDS_FULL_SYNC, &inode->runtime_flags);
}

/*
 * Make sure we do not end up inserting an inline extent into a file that has
 * already other (non-inline) extents. If a file has an inline extent it can
 * not have any other extents and the (single) inline extent must start at the
 * file offset 0. Failing to respect these rules will lead to file corruption,
 * resulting in EIO errors on read/write operations, hitting BUG_ON's in mm, etc
 *
 * We can have extents that have been already written to disk or we can have
 * dirty ranges still in delalloc, in which case the extent maps and items are
 * created only when we run delalloc, and the delalloc ranges might fall outside
 * the range we are currently locking in the inode's io tree. So we check the
 * inode's i_size because of that (i_size updates are done while holding the
 * i_mutex, which we are holding here).
 * We also check to see if the inode has a size not greater than "datal" but has
 * extents beyond it, due to an fallocate with FALLOC_FL_KEEP_SIZE (and we are
 * protected against such concurrent fallocate calls by the i_mutex).
 *
 * If the file has no extents but a size greater than datal, do not allow the
 * copy because we would need turn the inline extent into a non-inline one (even
 * with NO_HOLES enabled). If we find our destination inode only has one inline
 * extent, just overwrite it with the source inline extent if its size is less
 * than the source extent's size, or we could copy the source inline extent's
 * data into the destination inode's inline extent if the later is greater then
 * the former.
 */
static int clone_copy_inline_extent(struct inode *dst,
				    struct btrfs_trans_handle *trans,
				    struct btrfs_path *path,
				    struct btrfs_key *new_key,
				    const u64 drop_start,
				    const u64 datal,
				    const u64 skip,
				    const u64 size,
				    char *inline_data)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(dst->i_sb);
	struct btrfs_root *root = BTRFS_I(dst)->root;
	const u64 aligned_end = ALIGN(new_key->offset + datal,
				      fs_info->sectorsize);
	int ret;
	struct btrfs_key key;

	if (new_key->offset > 0)
		return -EOPNOTSUPP;

	key.objectid = btrfs_ino(BTRFS_I(dst));
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = 0;
	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0) {
		return ret;
	} else if (ret > 0) {
		if (path->slots[0] >= btrfs_header_nritems(path->nodes[0])) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				return ret;
			else if (ret > 0)
				goto copy_inline_extent;
		}
		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
		if (key.objectid == btrfs_ino(BTRFS_I(dst)) &&
		    key.type == BTRFS_EXTENT_DATA_KEY) {
			ASSERT(key.offset > 0);
			return -EOPNOTSUPP;
		}
	} else if (i_size_read(dst) <= datal) {
		struct btrfs_file_extent_item *ei;
		u64 ext_len;

		/*
		 * If the file size is <= datal, make sure there are no other
		 * extents following (can happen do to an fallocate call with
		 * the flag FALLOC_FL_KEEP_SIZE).
		 */
		ei = btrfs_item_ptr(path->nodes[0], path->slots[0],
				    struct btrfs_file_extent_item);
		/*
		 * If it's an inline extent, it can not have other extents
		 * following it.
		 */
		if (btrfs_file_extent_type(path->nodes[0], ei) ==
		    BTRFS_FILE_EXTENT_INLINE)
			goto copy_inline_extent;

		ext_len = btrfs_file_extent_num_bytes(path->nodes[0], ei);
		if (ext_len > aligned_end)
			return -EOPNOTSUPP;

		ret = btrfs_next_item(root, path);
		if (ret < 0) {
			return ret;
		} else if (ret == 0) {
			btrfs_item_key_to_cpu(path->nodes[0], &key,
					      path->slots[0]);
			if (key.objectid == btrfs_ino(BTRFS_I(dst)) &&
			    key.type == BTRFS_EXTENT_DATA_KEY)
				return -EOPNOTSUPP;
		}
	}

copy_inline_extent:
	/*
	 * We have no extent items, or we have an extent at offset 0 which may
	 * or may not be inlined. All these cases are dealt the same way.
	 */
	if (i_size_read(dst) > datal) {
		/*
		 * If the destination inode has an inline extent...
		 * This would require copying the data from the source inline
		 * extent into the beginning of the destination's inline extent.
		 * But this is really complex, both extents can be compressed
		 * or just one of them, which would require decompressing and
		 * re-compressing data (which could increase the new compressed
		 * size, not allowing the compressed data to fit anymore in an
		 * inline extent).
		 * So just don't support this case for now (it should be rare,
		 * we are not really saving space when cloning inline extents).
		 */
		return -EOPNOTSUPP;
	}

	btrfs_release_path(path);
	ret = btrfs_drop_extents(trans, root, dst, drop_start, aligned_end, 1);
	if (ret)
		return ret;
	ret = btrfs_insert_empty_item(trans, root, path, new_key, size);
	if (ret)
		return ret;

	if (skip) {
		const u32 start = btrfs_file_extent_calc_inline_size(0);

		memmove(inline_data + start, inline_data + start + skip, datal);
	}

	write_extent_buffer(path->nodes[0], inline_data,
			    btrfs_item_ptr_offset(path->nodes[0],
						  path->slots[0]),
			    size);
	inode_add_bytes(dst, datal);

	return 0;
}

/**
 * btrfs_clone() - clone a range from inode file to another
 *
 * @src: Inode to clone from
 * @inode: Inode to clone to
 * @off: Offset within source to start clone from
 * @olen: Original length, passed by user, of range to clone
 * @olen_aligned: Block-aligned value of olen
 * @destoff: Offset within @inode to start clone
 * @no_time_update: Whether to update mtime/ctime on the target inode
 */
static int btrfs_clone(struct inode *src, struct inode *inode,
		       const u64 off, const u64 olen, const u64 olen_aligned,
		       const u64 destoff, int no_time_update)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_path *path = NULL;
	struct extent_buffer *leaf;
	struct btrfs_trans_handle *trans;
	char *buf = NULL;
	struct btrfs_key key;
	u32 nritems;
	int slot;
	int ret;
	const u64 len = olen_aligned;
	u64 last_dest_end = destoff;

	ret = -ENOMEM;
	buf = kvmalloc(fs_info->nodesize, GFP_KERNEL);
	if (!buf)
		return ret;

	path = btrfs_alloc_path();
	if (!path) {
		kvfree(buf);
		return ret;
	}

	path->reada = READA_FORWARD;
	/* clone data */
	key.objectid = btrfs_ino(BTRFS_I(src));
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = off;

	while (1) {
		u64 next_key_min_offset = key.offset + 1;

		/*
		 * note the key will change type as we walk through the
		 * tree.
		 */
		path->leave_spinning = 1;
		ret = btrfs_search_slot(NULL, BTRFS_I(src)->root, &key, path,
				0, 0);
		if (ret < 0)
			goto out;
		/*
		 * First search, if no extent item that starts at offset off was
		 * found but the previous item is an extent item, it's possible
		 * it might overlap our target range, therefore process it.
		 */
		if (key.offset == off && ret > 0 && path->slots[0] > 0) {
			btrfs_item_key_to_cpu(path->nodes[0], &key,
					      path->slots[0] - 1);
			if (key.type == BTRFS_EXTENT_DATA_KEY)
				path->slots[0]--;
		}

		nritems = btrfs_header_nritems(path->nodes[0]);
process_slot:
		if (path->slots[0] >= nritems) {
			ret = btrfs_next_leaf(BTRFS_I(src)->root, path);
			if (ret < 0)
				goto out;
			if (ret > 0)
				break;
			nritems = btrfs_header_nritems(path->nodes[0]);
		}
		leaf = path->nodes[0];
		slot = path->slots[0];

		btrfs_item_key_to_cpu(leaf, &key, slot);
		if (key.type > BTRFS_EXTENT_DATA_KEY ||
		    key.objectid != btrfs_ino(BTRFS_I(src)))
			break;

		if (key.type == BTRFS_EXTENT_DATA_KEY) {
			struct btrfs_file_extent_item *extent;
			int type;
			u32 size;
			struct btrfs_key new_key;
			u64 disko = 0, diskl = 0;
			u64 datao = 0, datal = 0;
			u8 comp;
			u64 drop_start;

			extent = btrfs_item_ptr(leaf, slot,
						struct btrfs_file_extent_item);
			comp = btrfs_file_extent_compression(leaf, extent);
			type = btrfs_file_extent_type(leaf, extent);
			if (type == BTRFS_FILE_EXTENT_REG ||
			    type == BTRFS_FILE_EXTENT_PREALLOC) {
				disko = btrfs_file_extent_disk_bytenr(leaf,
								      extent);
				diskl = btrfs_file_extent_disk_num_bytes(leaf,
								 extent);
				datao = btrfs_file_extent_offset(leaf, extent);
				datal = btrfs_file_extent_num_bytes(leaf,
								    extent);
			} else if (type == BTRFS_FILE_EXTENT_INLINE) {
				/* take upper bound, may be compressed */
				datal = btrfs_file_extent_ram_bytes(leaf,
								    extent);
			}

			/*
			 * The first search might have left us at an extent
			 * item that ends before our target range's start, can
			 * happen if we have holes and NO_HOLES feature enabled.
			 */
			if (key.offset + datal <= off) {
				path->slots[0]++;
				goto process_slot;
			} else if (key.offset >= off + len) {
				break;
			}
			next_key_min_offset = key.offset + datal;
			size = btrfs_item_size_nr(leaf, slot);
			read_extent_buffer(leaf, buf,
					   btrfs_item_ptr_offset(leaf, slot),
					   size);

			btrfs_release_path(path);
			path->leave_spinning = 0;

			memcpy(&new_key, &key, sizeof(new_key));
			new_key.objectid = btrfs_ino(BTRFS_I(inode));
			if (off <= key.offset)
				new_key.offset = key.offset + destoff - off;
			else
				new_key.offset = destoff;

			/*
			 * Deal with a hole that doesn't have an extent item
			 * that represents it (NO_HOLES feature enabled).
			 * This hole is either in the middle of the cloning
			 * range or at the beginning (fully overlaps it or
			 * partially overlaps it).
			 */
			if (new_key.offset != last_dest_end)
				drop_start = last_dest_end;
			else
				drop_start = new_key.offset;

			/*
			 * 1 - adjusting old extent (we may have to split it)
			 * 1 - add new extent
			 * 1 - inode update
			 */
			trans = btrfs_start_transaction(root, 3);
			if (IS_ERR(trans)) {
				ret = PTR_ERR(trans);
				goto out;
			}

			if (type == BTRFS_FILE_EXTENT_REG ||
			    type == BTRFS_FILE_EXTENT_PREALLOC) {
				/*
				 *    a  | --- range to clone ---|  b
				 * | ------------- extent ------------- |
				 */

				/* subtract range b */
				if (key.offset + datal > off + len)
					datal = off + len - key.offset;

				/* subtract range a */
				if (off > key.offset) {
					datao += off - key.offset;
					datal -= off - key.offset;
				}

				ret = btrfs_drop_extents(trans, root, inode,
							 drop_start,
							 new_key.offset + datal,
							 1);
				if (ret) {
					if (ret != -EOPNOTSUPP)
						btrfs_abort_transaction(trans,
									ret);
					btrfs_end_transaction(trans);
					goto out;
				}

				ret = btrfs_insert_empty_item(trans, root, path,
							      &new_key, size);
				if (ret) {
					btrfs_abort_transaction(trans, ret);
					btrfs_end_transaction(trans);
					goto out;
				}

				leaf = path->nodes[0];
				slot = path->slots[0];
				write_extent_buffer(leaf, buf,
					    btrfs_item_ptr_offset(leaf, slot),
					    size);

				extent = btrfs_item_ptr(leaf, slot,
						struct btrfs_file_extent_item);

				/* disko == 0 means it's a hole */
				if (!disko)
					datao = 0;

				btrfs_set_file_extent_offset(leaf, extent,
							     datao);
				btrfs_set_file_extent_num_bytes(leaf, extent,
								datal);

				if (disko) {
					inode_add_bytes(inode, datal);
					ret = btrfs_inc_extent_ref(trans,
							root,
							disko, diskl, 0,
							root->root_key.objectid,
							btrfs_ino(BTRFS_I(inode)),
							new_key.offset - datao);
					if (ret) {
						btrfs_abort_transaction(trans,
									ret);
						btrfs_end_transaction(trans);
						goto out;

					}
				}
			} else if (type == BTRFS_FILE_EXTENT_INLINE) {
				u64 skip = 0;
				u64 trim = 0;

				if (off > key.offset) {
					skip = off - key.offset;
					new_key.offset += skip;
				}

				if (key.offset + datal > off + len)
					trim = key.offset + datal - (off + len);

				if (comp && (skip || trim)) {
					ret = -EINVAL;
					btrfs_end_transaction(trans);
					goto out;
				}
				size -= skip + trim;
				datal -= skip + trim;

				ret = clone_copy_inline_extent(inode,
							       trans, path,
							       &new_key,
							       drop_start,
							       datal,
							       skip, size, buf);
				if (ret) {
					if (ret != -EOPNOTSUPP)
						btrfs_abort_transaction(trans,
									ret);
					btrfs_end_transaction(trans);
					goto out;
				}
				leaf = path->nodes[0];
				slot = path->slots[0];
			}

			/* If we have an implicit hole (NO_HOLES feature). */
			if (drop_start < new_key.offset)
				clone_update_extent_map(BTRFS_I(inode), trans,
						NULL, drop_start,
						new_key.offset - drop_start);

			clone_update_extent_map(BTRFS_I(inode), trans,
					path, 0, 0);

			btrfs_mark_buffer_dirty(leaf);
			btrfs_release_path(path);

			last_dest_end = ALIGN(new_key.offset + datal,
					      fs_info->sectorsize);
			ret = clone_finish_inode_update(trans, inode,
							last_dest_end,
							destoff, olen,
							no_time_update);
			if (ret)
				goto out;
			if (new_key.offset + datal >= destoff + len)
				break;
		}
		btrfs_release_path(path);
		key.offset = next_key_min_offset;

		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto out;
		}
	}
	ret = 0;

	if (last_dest_end < destoff + len) {
		/*
		 * We have an implicit hole (NO_HOLES feature is enabled) that
		 * fully or partially overlaps our cloning range at its end.
		 */
		btrfs_release_path(path);

		/*
		 * 1 - remove extent(s)
		 * 1 - inode update
		 */
		trans = btrfs_start_transaction(root, 2);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			goto out;
		}
		ret = btrfs_drop_extents(trans, root, inode,
					 last_dest_end, destoff + len, 1);
		if (ret) {
			if (ret != -EOPNOTSUPP)
				btrfs_abort_transaction(trans, ret);
			btrfs_end_transaction(trans);
			goto out;
		}
		clone_update_extent_map(BTRFS_I(inode), trans, NULL,
				last_dest_end,
				destoff + len - last_dest_end);
		ret = clone_finish_inode_update(trans, inode, destoff + len,
						destoff, olen, no_time_update);
	}

out:
	btrfs_free_path(path);
	kvfree(buf);
	return ret;
}

static noinline int btrfs_clone_files(struct file *file, struct file *file_src,
					u64 off, u64 olen, u64 destoff)
{
	struct inode *inode = file_inode(file);
	struct inode *src = file_inode(file_src);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;
	u64 len = olen;
	u64 bs = fs_info->sb->s_blocksize;
	int same_inode = src == inode;

	/*
	 * TODO:
	 * - split compressed inline extents.  annoying: we need to
	 *   decompress into destination's address_space (the file offset
	 *   may change, so source mapping won't do), then recompress (or
	 *   otherwise reinsert) a subrange.
	 *
	 * - split destination inode's inline extents.  The inline extents can
	 *   be either compressed or non-compressed.
	 */

	if (btrfs_root_readonly(root))
		return -EROFS;

	if (file_src->f_path.mnt != file->f_path.mnt ||
	    src->i_sb != inode->i_sb)
		return -EXDEV;

	if (S_ISDIR(src->i_mode) || S_ISDIR(inode->i_mode))
		return -EISDIR;

	if (!same_inode) {
		btrfs_double_inode_lock(src, inode);
	} else {
		inode_lock(src);
	}

	/* don't make the dst file partly checksummed */
	if ((BTRFS_I(src)->flags & BTRFS_INODE_NODATASUM) !=
	    (BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* determine range to clone */
	ret = -EINVAL;
	if (off + len > src->i_size || off + len < off)
		goto out_unlock;
	if (len == 0)
		olen = len = src->i_size - off;
	/*
	 * If we extend to eof, continue to block boundary if and only if the
	 * destination end offset matches the destination file's size, otherwise
	 * we would be corrupting data by placing the eof block into the middle
	 * of a file.
	 */
	if (off + len == src->i_size) {
		if (!IS_ALIGNED(len, bs) && destoff + len < inode->i_size)
			goto out_unlock;
		len = ALIGN(src->i_size, bs) - off;
	}

	if (len == 0) {
		ret = 0;
		goto out_unlock;
	}

	/* verify the end result is block aligned */
	if (!IS_ALIGNED(off, bs) || !IS_ALIGNED(off + len, bs) ||
	    !IS_ALIGNED(destoff, bs))
		goto out_unlock;

	/* verify if ranges are overlapped within the same file */
	if (same_inode) {
		if (destoff + len > off && destoff < off + len)
			goto out_unlock;
	}

	if (destoff > inode->i_size) {
		ret = btrfs_cont_expand(inode, inode->i_size, destoff);
		if (ret)
			goto out_unlock;
	}

	/*
	 * Lock the target range too. Right after we replace the file extent
	 * items in the fs tree (which now point to the cloned data), we might
	 * have a worker replace them with extent items relative to a write
	 * operation that was issued before this clone operation (i.e. confront
	 * with inode.c:btrfs_finish_ordered_io).
	 */
	if (same_inode) {
		u64 lock_start = min_t(u64, off, destoff);
		u64 lock_len = max_t(u64, off, destoff) + len - lock_start;

		ret = lock_extent_range(src, lock_start, lock_len, true);
	} else {
		ret = btrfs_double_extent_lock(src, off, inode, destoff, len,
					       true);
	}
	ASSERT(ret == 0);
	if (WARN_ON(ret)) {
		/* ranges in the io trees already unlocked */
		goto out_unlock;
	}

	ret = btrfs_clone(src, inode, off, olen, len, destoff, 0);

	if (same_inode) {
		u64 lock_start = min_t(u64, off, destoff);
		u64 lock_end = max_t(u64, off, destoff) + len - 1;

		unlock_extent(&BTRFS_I(src)->io_tree, lock_start, lock_end);
	} else {
		btrfs_double_extent_unlock(src, off, inode, destoff, len);
	}
	/*
	 * Truncate page cache pages so that future reads will see the cloned
	 * data immediately and not the previous data.
	 */
	truncate_inode_pages_range(&inode->i_data,
				round_down(destoff, PAGE_SIZE),
				round_up(destoff + len, PAGE_SIZE) - 1);
out_unlock:
	if (!same_inode)
		btrfs_double_inode_unlock(src, inode);
	else
		inode_unlock(src);
	return ret;
}

int btrfs_clone_file_range(struct file *src_file, loff_t off,
		struct file *dst_file, loff_t destoff, u64 len)
{
	return btrfs_clone_files(dst_file, src_file, off, len, destoff);
}

>>>>>>> master
static long btrfs_ioctl_default_subvol(struct file *file, void __user *argp)
{
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_root *new_root;
	struct btrfs_dir_item *di;
	struct btrfs_trans_handle *trans;
	struct btrfs_path *path = NULL;
	struct btrfs_disk_key disk_key;
	struct fscrypt_str name = FSTR_INIT("default", 7);
	u64 objectid = 0;
	u64 dir_id;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	if (copy_from_user(&objectid, argp, sizeof(objectid))) {
		ret = -EFAULT;
		goto out;
	}

	if (!objectid)
		objectid = BTRFS_FS_TREE_OBJECTID;

	new_root = btrfs_get_fs_root(fs_info, objectid, true);
	if (IS_ERR(new_root)) {
		ret = PTR_ERR(new_root);
		goto out;
	}
	if (!is_fstree(new_root->root_key.objectid)) {
		ret = -ENOENT;
		goto out_free;
	}

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out_free;
	}

	trans = btrfs_start_transaction(root, 1);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_free;
	}

	dir_id = btrfs_super_root_dir(fs_info->super_copy);
	di = btrfs_lookup_dir_item(trans, fs_info->tree_root, path,
				   dir_id, &name, 1);
	if (IS_ERR_OR_NULL(di)) {
		btrfs_release_path(path);
		btrfs_end_transaction(trans);
		btrfs_err(fs_info,
			  "Umm, you don't have the default diritem, this isn't going to work");
		ret = -ENOENT;
		goto out_free;
	}

	btrfs_cpu_key_to_disk(&disk_key, &new_root->root_key);
	btrfs_set_dir_item_key(path->nodes[0], di, &disk_key);
	btrfs_mark_buffer_dirty(trans, path->nodes[0]);
	btrfs_release_path(path);

	btrfs_set_fs_incompat(fs_info, DEFAULT_SUBVOL);
	btrfs_end_transaction(trans);
out_free:
	btrfs_put_root(new_root);
	btrfs_free_path(path);
out:
	mnt_drop_write_file(file);
	return ret;
}

static void get_block_group_info(struct list_head *groups_list,
				 struct btrfs_ioctl_space_info *space)
{
	struct btrfs_block_group *block_group;

	space->total_bytes = 0;
	space->used_bytes = 0;
	space->flags = 0;
	list_for_each_entry(block_group, groups_list, list) {
		space->flags = block_group->flags;
		space->total_bytes += block_group->length;
		space->used_bytes += block_group->used;
	}
}

static long btrfs_ioctl_space_info(struct btrfs_fs_info *fs_info,
				   void __user *arg)
{
	struct btrfs_ioctl_space_args space_args = { 0 };
	struct btrfs_ioctl_space_info space;
	struct btrfs_ioctl_space_info *dest;
	struct btrfs_ioctl_space_info *dest_orig;
	struct btrfs_ioctl_space_info __user *user_dest;
	struct btrfs_space_info *info;
	static const u64 types[] = {
		BTRFS_BLOCK_GROUP_DATA,
		BTRFS_BLOCK_GROUP_SYSTEM,
		BTRFS_BLOCK_GROUP_METADATA,
		BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA
	};
	int num_types = 4;
	int alloc_size;
	int ret = 0;
	u64 slot_count = 0;
	int i, c;

	if (copy_from_user(&space_args,
			   (struct btrfs_ioctl_space_args __user *)arg,
			   sizeof(space_args)))
		return -EFAULT;

	for (i = 0; i < num_types; i++) {
		struct btrfs_space_info *tmp;

		info = NULL;
		list_for_each_entry(tmp, &fs_info->space_info, list) {
			if (tmp->flags == types[i]) {
				info = tmp;
				break;
			}
		}

		if (!info)
			continue;

		down_read(&info->groups_sem);
		for (c = 0; c < BTRFS_NR_RAID_TYPES; c++) {
			if (!list_empty(&info->block_groups[c]))
				slot_count++;
		}
		up_read(&info->groups_sem);
	}

	/*
	 * Global block reserve, exported as a space_info
	 */
	slot_count++;

	/* space_slots == 0 means they are asking for a count */
	if (space_args.space_slots == 0) {
		space_args.total_spaces = slot_count;
		goto out;
	}

	slot_count = min_t(u64, space_args.space_slots, slot_count);

	alloc_size = sizeof(*dest) * slot_count;

	/* we generally have at most 6 or so space infos, one for each raid
	 * level.  So, a whole page should be more than enough for everyone
	 */
	if (alloc_size > PAGE_SIZE)
		return -ENOMEM;

	space_args.total_spaces = 0;
	dest = kmalloc(alloc_size, GFP_KERNEL);
	if (!dest)
		return -ENOMEM;
	dest_orig = dest;

	/* now we have a buffer to copy into */
	for (i = 0; i < num_types; i++) {
		struct btrfs_space_info *tmp;

		if (!slot_count)
			break;

		info = NULL;
		list_for_each_entry(tmp, &fs_info->space_info, list) {
			if (tmp->flags == types[i]) {
				info = tmp;
				break;
			}
		}

		if (!info)
			continue;
		down_read(&info->groups_sem);
		for (c = 0; c < BTRFS_NR_RAID_TYPES; c++) {
			if (!list_empty(&info->block_groups[c])) {
				get_block_group_info(&info->block_groups[c],
						     &space);
				memcpy(dest, &space, sizeof(space));
				dest++;
				space_args.total_spaces++;
				slot_count--;
			}
			if (!slot_count)
				break;
		}
		up_read(&info->groups_sem);
	}

	/*
	 * Add global block reserve
	 */
	if (slot_count) {
		struct btrfs_block_rsv *block_rsv = &fs_info->global_block_rsv;

		spin_lock(&block_rsv->lock);
		space.total_bytes = block_rsv->size;
		space.used_bytes = block_rsv->size - block_rsv->reserved;
		spin_unlock(&block_rsv->lock);
		space.flags = BTRFS_SPACE_INFO_GLOBAL_RSV;
		memcpy(dest, &space, sizeof(space));
		space_args.total_spaces++;
	}

	user_dest = (struct btrfs_ioctl_space_info __user *)
		(arg + sizeof(struct btrfs_ioctl_space_args));

	if (copy_to_user(user_dest, dest_orig, alloc_size))
		ret = -EFAULT;

	kfree(dest_orig);
out:
	if (ret == 0 && copy_to_user(arg, &space_args, sizeof(space_args)))
		ret = -EFAULT;

	return ret;
}

static noinline long btrfs_ioctl_start_sync(struct btrfs_root *root,
					    void __user *argp)
{
	struct btrfs_trans_handle *trans;
	u64 transid;

	/*
	 * Start orphan cleanup here for the given root in case it hasn't been
	 * started already by other means. Errors are handled in the other
	 * functions during transaction commit.
	 */
	btrfs_orphan_cleanup(root);

	trans = btrfs_attach_transaction_barrier(root);
	if (IS_ERR(trans)) {
		if (PTR_ERR(trans) != -ENOENT)
			return PTR_ERR(trans);

		/* No running transaction, don't bother */
		transid = root->fs_info->last_trans_committed;
		goto out;
	}
	transid = trans->transid;
	btrfs_commit_transaction_async(trans);
out:
	if (argp)
		if (copy_to_user(argp, &transid, sizeof(transid)))
			return -EFAULT;
	return 0;
}

static noinline long btrfs_ioctl_wait_sync(struct btrfs_fs_info *fs_info,
					   void __user *argp)
{
	/* By default wait for the current transaction. */
	u64 transid = 0;

	if (argp)
		if (copy_from_user(&transid, argp, sizeof(transid)))
			return -EFAULT;

	return btrfs_wait_for_commit(fs_info, transid);
}

static long btrfs_ioctl_scrub(struct file *file, void __user *arg)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(file_inode(file)->i_sb);
	struct btrfs_ioctl_scrub_args *sa;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (btrfs_fs_incompat(fs_info, EXTENT_TREE_V2)) {
		btrfs_err(fs_info, "scrub is not supported on extent tree v2 yet");
		return -EINVAL;
	}

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa))
		return PTR_ERR(sa);

	if (sa->flags & ~BTRFS_SCRUB_SUPPORTED_FLAGS) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (!(sa->flags & BTRFS_SCRUB_READONLY)) {
		ret = mnt_want_write_file(file);
		if (ret)
			goto out;
	}

	ret = btrfs_scrub_dev(fs_info, sa->devid, sa->start, sa->end,
			      &sa->progress, sa->flags & BTRFS_SCRUB_READONLY,
			      0);

	/*
	 * Copy scrub args to user space even if btrfs_scrub_dev() returned an
	 * error. This is important as it allows user space to know how much
	 * progress scrub has done. For example, if scrub is canceled we get
	 * -ECANCELED from btrfs_scrub_dev() and return that error back to user
	 * space. Later user space can inspect the progress from the structure
	 * btrfs_ioctl_scrub_args and resume scrub from where it left off
	 * previously (btrfs-progs does this).
	 * If we fail to copy the btrfs_ioctl_scrub_args structure to user space
	 * then return -EFAULT to signal the structure was not copied or it may
	 * be corrupt and unreliable due to a partial copy.
	 */
	if (copy_to_user(arg, sa, sizeof(*sa)))
		ret = -EFAULT;

	if (!(sa->flags & BTRFS_SCRUB_READONLY))
		mnt_drop_write_file(file);
out:
	kfree(sa);
	return ret;
}

static long btrfs_ioctl_scrub_cancel(struct btrfs_fs_info *fs_info)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return btrfs_scrub_cancel(fs_info);
}

static long btrfs_ioctl_scrub_progress(struct btrfs_fs_info *fs_info,
				       void __user *arg)
{
	struct btrfs_ioctl_scrub_args *sa;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa))
		return PTR_ERR(sa);

	ret = btrfs_scrub_progress(fs_info, sa->devid, &sa->progress);

	if (ret == 0 && copy_to_user(arg, sa, sizeof(*sa)))
		ret = -EFAULT;

	kfree(sa);
	return ret;
}

static long btrfs_ioctl_get_dev_stats(struct btrfs_fs_info *fs_info,
				      void __user *arg)
{
	struct btrfs_ioctl_get_dev_stats *sa;
	int ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa))
		return PTR_ERR(sa);

	if ((sa->flags & BTRFS_DEV_STATS_RESET) && !capable(CAP_SYS_ADMIN)) {
		kfree(sa);
		return -EPERM;
	}

	ret = btrfs_get_dev_stats(fs_info, sa);

	if (ret == 0 && copy_to_user(arg, sa, sizeof(*sa)))
		ret = -EFAULT;

	kfree(sa);
	return ret;
}

static long btrfs_ioctl_dev_replace(struct btrfs_fs_info *fs_info,
				    void __user *arg)
{
	struct btrfs_ioctl_dev_replace_args *p;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (btrfs_fs_incompat(fs_info, EXTENT_TREE_V2)) {
		btrfs_err(fs_info, "device replace not supported on extent tree v2 yet");
		return -EINVAL;
	}

	p = memdup_user(arg, sizeof(*p));
	if (IS_ERR(p))
		return PTR_ERR(p);

	switch (p->cmd) {
	case BTRFS_IOCTL_DEV_REPLACE_CMD_START:
		if (sb_rdonly(fs_info->sb)) {
			ret = -EROFS;
			goto out;
		}
		if (!btrfs_exclop_start(fs_info, BTRFS_EXCLOP_DEV_REPLACE)) {
			ret = BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;
		} else {
			ret = btrfs_dev_replace_by_ioctl(fs_info, p);
			btrfs_exclop_finish(fs_info);
		}
		break;
	case BTRFS_IOCTL_DEV_REPLACE_CMD_STATUS:
		btrfs_dev_replace_status(fs_info, p);
		ret = 0;
		break;
	case BTRFS_IOCTL_DEV_REPLACE_CMD_CANCEL:
		p->result = btrfs_dev_replace_cancel(fs_info);
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if ((ret == 0 || ret == -ECANCELED) && copy_to_user(arg, p, sizeof(*p)))
		ret = -EFAULT;
out:
	kfree(p);
	return ret;
}

static long btrfs_ioctl_ino_to_path(struct btrfs_root *root, void __user *arg)
{
	int ret = 0;
	int i;
	u64 rel_ptr;
	int size;
	struct btrfs_ioctl_ino_path_args *ipa = NULL;
	struct inode_fs_paths *ipath = NULL;
	struct btrfs_path *path;

	if (!capable(CAP_DAC_READ_SEARCH))
		return -EPERM;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	ipa = memdup_user(arg, sizeof(*ipa));
	if (IS_ERR(ipa)) {
		ret = PTR_ERR(ipa);
		ipa = NULL;
		goto out;
	}

	size = min_t(u32, ipa->size, 4096);
	ipath = init_ipath(size, root, path);
	if (IS_ERR(ipath)) {
		ret = PTR_ERR(ipath);
		ipath = NULL;
		goto out;
	}

	ret = paths_from_inode(ipa->inum, ipath);
	if (ret < 0)
		goto out;

	for (i = 0; i < ipath->fspath->elem_cnt; ++i) {
		rel_ptr = ipath->fspath->val[i] -
			  (u64)(unsigned long)ipath->fspath->val;
		ipath->fspath->val[i] = rel_ptr;
	}

	btrfs_free_path(path);
	path = NULL;
	ret = copy_to_user((void __user *)(unsigned long)ipa->fspath,
			   ipath->fspath, size);
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

out:
	btrfs_free_path(path);
	free_ipath(ipath);
	kfree(ipa);

	return ret;
}

static long btrfs_ioctl_logical_to_ino(struct btrfs_fs_info *fs_info,
					void __user *arg, int version)
{
	int ret = 0;
	int size;
	struct btrfs_ioctl_logical_ino_args *loi;
	struct btrfs_data_container *inodes = NULL;
	struct btrfs_path *path = NULL;
	bool ignore_offset;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	loi = memdup_user(arg, sizeof(*loi));
	if (IS_ERR(loi))
		return PTR_ERR(loi);

	if (version == 1) {
		ignore_offset = false;
		size = min_t(u32, loi->size, SZ_64K);
	} else {
		/* All reserved bits must be 0 for now */
		if (memchr_inv(loi->reserved, 0, sizeof(loi->reserved))) {
			ret = -EINVAL;
			goto out_loi;
		}
		/* Only accept flags we have defined so far */
		if (loi->flags & ~(BTRFS_LOGICAL_INO_ARGS_IGNORE_OFFSET)) {
			ret = -EINVAL;
			goto out_loi;
		}
		ignore_offset = loi->flags & BTRFS_LOGICAL_INO_ARGS_IGNORE_OFFSET;
		size = min_t(u32, loi->size, SZ_16M);
	}

	inodes = init_data_container(size);
	if (IS_ERR(inodes)) {
		ret = PTR_ERR(inodes);
		goto out_loi;
	}

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}
	ret = iterate_inodes_from_logical(loi->logical, fs_info, path,
					  inodes, ignore_offset);
	btrfs_free_path(path);
	if (ret == -EINVAL)
		ret = -ENOENT;
	if (ret < 0)
		goto out;

	ret = copy_to_user((void __user *)(unsigned long)loi->inodes, inodes,
			   size);
	if (ret)
		ret = -EFAULT;

out:
	kvfree(inodes);
out_loi:
	kfree(loi);

	return ret;
}

void btrfs_update_ioctl_balance_args(struct btrfs_fs_info *fs_info,
			       struct btrfs_ioctl_balance_args *bargs)
{
	struct btrfs_balance_control *bctl = fs_info->balance_ctl;

	bargs->flags = bctl->flags;

	if (test_bit(BTRFS_FS_BALANCE_RUNNING, &fs_info->flags))
		bargs->state |= BTRFS_BALANCE_STATE_RUNNING;
	if (atomic_read(&fs_info->balance_pause_req))
		bargs->state |= BTRFS_BALANCE_STATE_PAUSE_REQ;
	if (atomic_read(&fs_info->balance_cancel_req))
		bargs->state |= BTRFS_BALANCE_STATE_CANCEL_REQ;

	memcpy(&bargs->data, &bctl->data, sizeof(bargs->data));
	memcpy(&bargs->meta, &bctl->meta, sizeof(bargs->meta));
	memcpy(&bargs->sys, &bctl->sys, sizeof(bargs->sys));

	spin_lock(&fs_info->balance_lock);
	memcpy(&bargs->stat, &bctl->stat, sizeof(bargs->stat));
	spin_unlock(&fs_info->balance_lock);
}

/*
 * Try to acquire fs_info::balance_mutex as well as set BTRFS_EXLCOP_BALANCE as
 * required.
 *
 * @fs_info:       the filesystem
 * @excl_acquired: ptr to boolean value which is set to false in case balance
 *                 is being resumed
 *
 * Return 0 on success in which case both fs_info::balance is acquired as well
 * as exclusive ops are blocked. In case of failure return an error code.
 */
static int btrfs_try_lock_balance(struct btrfs_fs_info *fs_info, bool *excl_acquired)
{
	int ret;

	/*
	 * Exclusive operation is locked. Three possibilities:
	 *   (1) some other op is running
	 *   (2) balance is running
	 *   (3) balance is paused -- special case (think resume)
	 */
	while (1) {
		if (btrfs_exclop_start(fs_info, BTRFS_EXCLOP_BALANCE)) {
			*excl_acquired = true;
			mutex_lock(&fs_info->balance_mutex);
			return 0;
		}

		mutex_lock(&fs_info->balance_mutex);
		if (fs_info->balance_ctl) {
			/* This is either (2) or (3) */
			if (test_bit(BTRFS_FS_BALANCE_RUNNING, &fs_info->flags)) {
				/* This is (2) */
				ret = -EINPROGRESS;
				goto out_failure;

			} else {
				mutex_unlock(&fs_info->balance_mutex);
				/*
				 * Lock released to allow other waiters to
				 * continue, we'll reexamine the status again.
				 */
				mutex_lock(&fs_info->balance_mutex);

				if (fs_info->balance_ctl &&
				    !test_bit(BTRFS_FS_BALANCE_RUNNING, &fs_info->flags)) {
					/* This is (3) */
					*excl_acquired = false;
					return 0;
				}
			}
		} else {
			/* This is (1) */
			ret = BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;
			goto out_failure;
		}

		mutex_unlock(&fs_info->balance_mutex);
	}

out_failure:
	mutex_unlock(&fs_info->balance_mutex);
	*excl_acquired = false;
	return ret;
}

static long btrfs_ioctl_balance(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_ioctl_balance_args *bargs;
	struct btrfs_balance_control *bctl;
	bool need_unlock = true;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	bargs = memdup_user(arg, sizeof(*bargs));
	if (IS_ERR(bargs)) {
		ret = PTR_ERR(bargs);
		bargs = NULL;
		goto out;
	}

	ret = btrfs_try_lock_balance(fs_info, &need_unlock);
	if (ret)
		goto out;

	lockdep_assert_held(&fs_info->balance_mutex);

	if (bargs->flags & BTRFS_BALANCE_RESUME) {
		if (!fs_info->balance_ctl) {
			ret = -ENOTCONN;
			goto out_unlock;
		}

		bctl = fs_info->balance_ctl;
		spin_lock(&fs_info->balance_lock);
		bctl->flags |= BTRFS_BALANCE_RESUME;
		spin_unlock(&fs_info->balance_lock);
		btrfs_exclop_balance(fs_info, BTRFS_EXCLOP_BALANCE);

		goto do_balance;
	}

	if (bargs->flags & ~(BTRFS_BALANCE_ARGS_MASK | BTRFS_BALANCE_TYPE_MASK)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (fs_info->balance_ctl) {
		ret = -EINPROGRESS;
		goto out_unlock;
	}

	bctl = kzalloc(sizeof(*bctl), GFP_KERNEL);
	if (!bctl) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	memcpy(&bctl->data, &bargs->data, sizeof(bctl->data));
	memcpy(&bctl->meta, &bargs->meta, sizeof(bctl->meta));
	memcpy(&bctl->sys, &bargs->sys, sizeof(bctl->sys));

	bctl->flags = bargs->flags;
do_balance:
	/*
	 * Ownership of bctl and exclusive operation goes to btrfs_balance.
	 * bctl is freed in reset_balance_state, or, if restriper was paused
	 * all the way until unmount, in free_fs_info.  The flag should be
	 * cleared after reset_balance_state.
	 */
	need_unlock = false;

	ret = btrfs_balance(fs_info, bctl, bargs);
	bctl = NULL;

	if (ret == 0 || ret == -ECANCELED) {
		if (copy_to_user(arg, bargs, sizeof(*bargs)))
			ret = -EFAULT;
	}

	kfree(bctl);
out_unlock:
	mutex_unlock(&fs_info->balance_mutex);
	if (need_unlock)
		btrfs_exclop_finish(fs_info);
out:
	mnt_drop_write_file(file);
	kfree(bargs);
	return ret;
}

static long btrfs_ioctl_balance_ctl(struct btrfs_fs_info *fs_info, int cmd)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	switch (cmd) {
	case BTRFS_BALANCE_CTL_PAUSE:
		return btrfs_pause_balance(fs_info);
	case BTRFS_BALANCE_CTL_CANCEL:
		return btrfs_cancel_balance(fs_info);
	}

	return -EINVAL;
}

static long btrfs_ioctl_balance_progress(struct btrfs_fs_info *fs_info,
					 void __user *arg)
{
	struct btrfs_ioctl_balance_args *bargs;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&fs_info->balance_mutex);
	if (!fs_info->balance_ctl) {
		ret = -ENOTCONN;
		goto out;
	}

	bargs = kzalloc(sizeof(*bargs), GFP_KERNEL);
	if (!bargs) {
		ret = -ENOMEM;
		goto out;
	}

	btrfs_update_ioctl_balance_args(fs_info, bargs);

	if (copy_to_user(arg, bargs, sizeof(*bargs)))
		ret = -EFAULT;

	kfree(bargs);
out:
	mutex_unlock(&fs_info->balance_mutex);
	return ret;
}

static long btrfs_ioctl_quota_ctl(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_ioctl_quota_ctl_args *sa;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa)) {
		ret = PTR_ERR(sa);
		goto drop_write;
	}

	down_write(&fs_info->subvol_sem);

	switch (sa->cmd) {
	case BTRFS_QUOTA_CTL_ENABLE:
		ret = btrfs_quota_enable(fs_info);
		break;
	case BTRFS_QUOTA_CTL_DISABLE:
		ret = btrfs_quota_disable(fs_info);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	kfree(sa);
	up_write(&fs_info->subvol_sem);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_qgroup_assign(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ioctl_qgroup_assign_args *sa;
	struct btrfs_trans_handle *trans;
	int ret;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa)) {
		ret = PTR_ERR(sa);
		goto drop_write;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	if (sa->assign) {
		ret = btrfs_add_qgroup_relation(trans, sa->src, sa->dst);
	} else {
		ret = btrfs_del_qgroup_relation(trans, sa->src, sa->dst);
	}

	/* update qgroup status and info */
	mutex_lock(&fs_info->qgroup_ioctl_lock);
	err = btrfs_run_qgroups(trans);
	mutex_unlock(&fs_info->qgroup_ioctl_lock);
	if (err < 0)
		btrfs_handle_fs_error(fs_info, err,
				      "failed to update qgroup status and info");
	err = btrfs_end_transaction(trans);
	if (err && !ret)
		ret = err;

out:
	kfree(sa);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_qgroup_create(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ioctl_qgroup_create_args *sa;
	struct btrfs_trans_handle *trans;
	int ret;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa)) {
		ret = PTR_ERR(sa);
		goto drop_write;
	}

	if (!sa->qgroupid) {
		ret = -EINVAL;
		goto out;
	}

	if (sa->create && is_fstree(sa->qgroupid)) {
		ret = -EINVAL;
		goto out;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	if (sa->create) {
		ret = btrfs_create_qgroup(trans, sa->qgroupid);
	} else {
		ret = btrfs_remove_qgroup(trans, sa->qgroupid);
	}

	err = btrfs_end_transaction(trans);
	if (err && !ret)
		ret = err;

out:
	kfree(sa);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_qgroup_limit(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ioctl_qgroup_limit_args *sa;
	struct btrfs_trans_handle *trans;
	int ret;
	int err;
	u64 qgroupid;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa)) {
		ret = PTR_ERR(sa);
		goto drop_write;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	qgroupid = sa->qgroupid;
	if (!qgroupid) {
		/* take the current subvol as qgroup */
		qgroupid = root->root_key.objectid;
	}

	ret = btrfs_limit_qgroup(trans, qgroupid, &sa->lim);

	err = btrfs_end_transaction(trans);
	if (err && !ret)
		ret = err;

out:
	kfree(sa);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_quota_rescan(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_ioctl_quota_rescan_args *qsa;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	qsa = memdup_user(arg, sizeof(*qsa));
	if (IS_ERR(qsa)) {
		ret = PTR_ERR(qsa);
		goto drop_write;
	}

	if (qsa->flags) {
		ret = -EINVAL;
		goto out;
	}

	ret = btrfs_qgroup_rescan(fs_info);

out:
	kfree(qsa);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_quota_rescan_status(struct btrfs_fs_info *fs_info,
						void __user *arg)
{
	struct btrfs_ioctl_quota_rescan_args qsa = {0};

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (fs_info->qgroup_flags & BTRFS_QGROUP_STATUS_FLAG_RESCAN) {
		qsa.flags = 1;
		qsa.progress = fs_info->qgroup_rescan_progress.objectid;
	}

	if (copy_to_user(arg, &qsa, sizeof(qsa)))
		return -EFAULT;

	return 0;
}

static long btrfs_ioctl_quota_rescan_wait(struct btrfs_fs_info *fs_info,
						void __user *arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return btrfs_qgroup_wait_for_completion(fs_info, true);
}

static long _btrfs_ioctl_set_received_subvol(struct file *file,
					    struct mnt_idmap *idmap,
					    struct btrfs_ioctl_received_subvol_args *sa)
{
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_root_item *root_item = &root->root_item;
	struct btrfs_trans_handle *trans;
	struct timespec64 ct = current_time(inode);
	int ret = 0;
	int received_uuid_changed;

	if (!inode_owner_or_capable(idmap, inode))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret < 0)
		return ret;

	down_write(&fs_info->subvol_sem);

	if (btrfs_ino(BTRFS_I(inode)) != BTRFS_FIRST_FREE_OBJECTID) {
		ret = -EINVAL;
		goto out;
	}

	if (btrfs_root_readonly(root)) {
		ret = -EROFS;
		goto out;
	}

	/*
	 * 1 - root item
	 * 2 - uuid items (received uuid + subvol uuid)
	 */
	trans = btrfs_start_transaction(root, 3);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		trans = NULL;
		goto out;
	}

	sa->rtransid = trans->transid;
	sa->rtime.sec = ct.tv_sec;
	sa->rtime.nsec = ct.tv_nsec;

	received_uuid_changed = memcmp(root_item->received_uuid, sa->uuid,
				       BTRFS_UUID_SIZE);
	if (received_uuid_changed &&
	    !btrfs_is_empty_uuid(root_item->received_uuid)) {
		ret = btrfs_uuid_tree_remove(trans, root_item->received_uuid,
					  BTRFS_UUID_KEY_RECEIVED_SUBVOL,
					  root->root_key.objectid);
		if (ret && ret != -ENOENT) {
		        btrfs_abort_transaction(trans, ret);
		        btrfs_end_transaction(trans);
		        goto out;
		}
	}
	memcpy(root_item->received_uuid, sa->uuid, BTRFS_UUID_SIZE);
	btrfs_set_root_stransid(root_item, sa->stransid);
	btrfs_set_root_rtransid(root_item, sa->rtransid);
	btrfs_set_stack_timespec_sec(&root_item->stime, sa->stime.sec);
	btrfs_set_stack_timespec_nsec(&root_item->stime, sa->stime.nsec);
	btrfs_set_stack_timespec_sec(&root_item->rtime, sa->rtime.sec);
	btrfs_set_stack_timespec_nsec(&root_item->rtime, sa->rtime.nsec);

	ret = btrfs_update_root(trans, fs_info->tree_root,
				&root->root_key, &root->root_item);
	if (ret < 0) {
		btrfs_end_transaction(trans);
		goto out;
	}
	if (received_uuid_changed && !btrfs_is_empty_uuid(sa->uuid)) {
		ret = btrfs_uuid_tree_add(trans, sa->uuid,
					  BTRFS_UUID_KEY_RECEIVED_SUBVOL,
					  root->root_key.objectid);
		if (ret < 0 && ret != -EEXIST) {
			btrfs_abort_transaction(trans, ret);
			btrfs_end_transaction(trans);
			goto out;
		}
	}
	ret = btrfs_commit_transaction(trans);
out:
	up_write(&fs_info->subvol_sem);
	mnt_drop_write_file(file);
	return ret;
}

#ifdef CONFIG_64BIT
static long btrfs_ioctl_set_received_subvol_32(struct file *file,
						void __user *arg)
{
	struct btrfs_ioctl_received_subvol_args_32 *args32 = NULL;
	struct btrfs_ioctl_received_subvol_args *args64 = NULL;
	int ret = 0;

	args32 = memdup_user(arg, sizeof(*args32));
	if (IS_ERR(args32))
		return PTR_ERR(args32);

	args64 = kmalloc(sizeof(*args64), GFP_KERNEL);
	if (!args64) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(args64->uuid, args32->uuid, BTRFS_UUID_SIZE);
	args64->stransid = args32->stransid;
	args64->rtransid = args32->rtransid;
	args64->stime.sec = args32->stime.sec;
	args64->stime.nsec = args32->stime.nsec;
	args64->rtime.sec = args32->rtime.sec;
	args64->rtime.nsec = args32->rtime.nsec;
	args64->flags = args32->flags;

	ret = _btrfs_ioctl_set_received_subvol(file, file_mnt_idmap(file), args64);
	if (ret)
		goto out;

	memcpy(args32->uuid, args64->uuid, BTRFS_UUID_SIZE);
	args32->stransid = args64->stransid;
	args32->rtransid = args64->rtransid;
	args32->stime.sec = args64->stime.sec;
	args32->stime.nsec = args64->stime.nsec;
	args32->rtime.sec = args64->rtime.sec;
	args32->rtime.nsec = args64->rtime.nsec;
	args32->flags = args64->flags;

	ret = copy_to_user(arg, args32, sizeof(*args32));
	if (ret)
		ret = -EFAULT;

out:
	kfree(args32);
	kfree(args64);
	return ret;
}
#endif

static long btrfs_ioctl_set_received_subvol(struct file *file,
					    void __user *arg)
{
	struct btrfs_ioctl_received_subvol_args *sa = NULL;
	int ret = 0;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa))
		return PTR_ERR(sa);

	ret = _btrfs_ioctl_set_received_subvol(file, file_mnt_idmap(file), sa);

	if (ret)
		goto out;

	ret = copy_to_user(arg, sa, sizeof(*sa));
	if (ret)
		ret = -EFAULT;

out:
	kfree(sa);
	return ret;
}

static int btrfs_ioctl_get_fslabel(struct btrfs_fs_info *fs_info,
					void __user *arg)
{
	size_t len;
	int ret;
	char label[BTRFS_LABEL_SIZE];

	spin_lock(&fs_info->super_lock);
	memcpy(label, fs_info->super_copy->label, BTRFS_LABEL_SIZE);
	spin_unlock(&fs_info->super_lock);

	len = strnlen(label, BTRFS_LABEL_SIZE);

	if (len == BTRFS_LABEL_SIZE) {
		btrfs_warn(fs_info,
			   "label is too long, return the first %zu bytes",
			   --len);
	}

	ret = copy_to_user(arg, label, len);

	return ret ? -EFAULT : 0;
}

static int btrfs_ioctl_set_fslabel(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_super_block *super_block = fs_info->super_copy;
	struct btrfs_trans_handle *trans;
	char label[BTRFS_LABEL_SIZE];
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(label, arg, sizeof(label)))
		return -EFAULT;

	if (strnlen(label, BTRFS_LABEL_SIZE) == BTRFS_LABEL_SIZE) {
		btrfs_err(fs_info,
			  "unable to set label with more than %d bytes",
			  BTRFS_LABEL_SIZE - 1);
		return -EINVAL;
	}

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_unlock;
	}

	spin_lock(&fs_info->super_lock);
	strcpy(super_block->label, label);
	spin_unlock(&fs_info->super_lock);
	ret = btrfs_commit_transaction(trans);

out_unlock:
	mnt_drop_write_file(file);
	return ret;
}

#define INIT_FEATURE_FLAGS(suffix) \
	{ .compat_flags = BTRFS_FEATURE_COMPAT_##suffix, \
	  .compat_ro_flags = BTRFS_FEATURE_COMPAT_RO_##suffix, \
	  .incompat_flags = BTRFS_FEATURE_INCOMPAT_##suffix }

int btrfs_ioctl_get_supported_features(void __user *arg)
{
	static const struct btrfs_ioctl_feature_flags features[3] = {
		INIT_FEATURE_FLAGS(SUPP),
		INIT_FEATURE_FLAGS(SAFE_SET),
		INIT_FEATURE_FLAGS(SAFE_CLEAR)
	};

	if (copy_to_user(arg, &features, sizeof(features)))
		return -EFAULT;

	return 0;
}

static int btrfs_ioctl_get_features(struct btrfs_fs_info *fs_info,
					void __user *arg)
{
	struct btrfs_super_block *super_block = fs_info->super_copy;
	struct btrfs_ioctl_feature_flags features;

	features.compat_flags = btrfs_super_compat_flags(super_block);
	features.compat_ro_flags = btrfs_super_compat_ro_flags(super_block);
	features.incompat_flags = btrfs_super_incompat_flags(super_block);

	if (copy_to_user(arg, &features, sizeof(features)))
		return -EFAULT;

	return 0;
}

static int check_feature_bits(struct btrfs_fs_info *fs_info,
			      enum btrfs_feature_set set,
			      u64 change_mask, u64 flags, u64 supported_flags,
			      u64 safe_set, u64 safe_clear)
{
	const char *type = btrfs_feature_set_name(set);
	char *names;
	u64 disallowed, unsupported;
	u64 set_mask = flags & change_mask;
	u64 clear_mask = ~flags & change_mask;

	unsupported = set_mask & ~supported_flags;
	if (unsupported) {
		names = btrfs_printable_features(set, unsupported);
		if (names) {
			btrfs_warn(fs_info,
				   "this kernel does not support the %s feature bit%s",
				   names, strchr(names, ',') ? "s" : "");
			kfree(names);
		} else
			btrfs_warn(fs_info,
				   "this kernel does not support %s bits 0x%llx",
				   type, unsupported);
		return -EOPNOTSUPP;
	}

	disallowed = set_mask & ~safe_set;
	if (disallowed) {
		names = btrfs_printable_features(set, disallowed);
		if (names) {
			btrfs_warn(fs_info,
				   "can't set the %s feature bit%s while mounted",
				   names, strchr(names, ',') ? "s" : "");
			kfree(names);
		} else
			btrfs_warn(fs_info,
				   "can't set %s bits 0x%llx while mounted",
				   type, disallowed);
		return -EPERM;
	}

	disallowed = clear_mask & ~safe_clear;
	if (disallowed) {
		names = btrfs_printable_features(set, disallowed);
		if (names) {
			btrfs_warn(fs_info,
				   "can't clear the %s feature bit%s while mounted",
				   names, strchr(names, ',') ? "s" : "");
			kfree(names);
		} else
			btrfs_warn(fs_info,
				   "can't clear %s bits 0x%llx while mounted",
				   type, disallowed);
		return -EPERM;
	}

	return 0;
}

#define check_feature(fs_info, change_mask, flags, mask_base)	\
check_feature_bits(fs_info, FEAT_##mask_base, change_mask, flags,	\
		   BTRFS_FEATURE_ ## mask_base ## _SUPP,	\
		   BTRFS_FEATURE_ ## mask_base ## _SAFE_SET,	\
		   BTRFS_FEATURE_ ## mask_base ## _SAFE_CLEAR)

static int btrfs_ioctl_set_features(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_super_block *super_block = fs_info->super_copy;
	struct btrfs_ioctl_feature_flags flags[2];
	struct btrfs_trans_handle *trans;
	u64 newflags;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(flags, arg, sizeof(flags)))
		return -EFAULT;

	/* Nothing to do */
	if (!flags[0].compat_flags && !flags[0].compat_ro_flags &&
	    !flags[0].incompat_flags)
		return 0;

	ret = check_feature(fs_info, flags[0].compat_flags,
			    flags[1].compat_flags, COMPAT);
	if (ret)
		return ret;

	ret = check_feature(fs_info, flags[0].compat_ro_flags,
			    flags[1].compat_ro_flags, COMPAT_RO);
	if (ret)
		return ret;

	ret = check_feature(fs_info, flags[0].incompat_flags,
			    flags[1].incompat_flags, INCOMPAT);
	if (ret)
		return ret;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_drop_write;
	}

	spin_lock(&fs_info->super_lock);
	newflags = btrfs_super_compat_flags(super_block);
	newflags |= flags[0].compat_flags & flags[1].compat_flags;
	newflags &= ~(flags[0].compat_flags & ~flags[1].compat_flags);
	btrfs_set_super_compat_flags(super_block, newflags);

	newflags = btrfs_super_compat_ro_flags(super_block);
	newflags |= flags[0].compat_ro_flags & flags[1].compat_ro_flags;
	newflags &= ~(flags[0].compat_ro_flags & ~flags[1].compat_ro_flags);
	btrfs_set_super_compat_ro_flags(super_block, newflags);

	newflags = btrfs_super_incompat_flags(super_block);
	newflags |= flags[0].incompat_flags & flags[1].incompat_flags;
	newflags &= ~(flags[0].incompat_flags & ~flags[1].incompat_flags);
	btrfs_set_super_incompat_flags(super_block, newflags);
	spin_unlock(&fs_info->super_lock);

	ret = btrfs_commit_transaction(trans);
out_drop_write:
	mnt_drop_write_file(file);

	return ret;
}

static int _btrfs_ioctl_send(struct inode *inode, void __user *argp, bool compat)
{
	struct btrfs_ioctl_send_args *arg;
	int ret;

	if (compat) {
#if defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
		struct btrfs_ioctl_send_args_32 args32 = { 0 };

		ret = copy_from_user(&args32, argp, sizeof(args32));
		if (ret)
			return -EFAULT;
		arg = kzalloc(sizeof(*arg), GFP_KERNEL);
		if (!arg)
			return -ENOMEM;
		arg->send_fd = args32.send_fd;
		arg->clone_sources_count = args32.clone_sources_count;
		arg->clone_sources = compat_ptr(args32.clone_sources);
		arg->parent_root = args32.parent_root;
		arg->flags = args32.flags;
		arg->version = args32.version;
		memcpy(arg->reserved, args32.reserved,
		       sizeof(args32.reserved));
#else
		return -ENOTTY;
#endif
	} else {
		arg = memdup_user(argp, sizeof(*arg));
		if (IS_ERR(arg))
			return PTR_ERR(arg);
	}
	ret = btrfs_ioctl_send(inode, arg);
	kfree(arg);
	return ret;
}

static int btrfs_ioctl_encoded_read(struct file *file, void __user *argp,
				    bool compat)
{
	struct btrfs_ioctl_encoded_io_args args = { 0 };
	size_t copy_end_kernel = offsetofend(struct btrfs_ioctl_encoded_io_args,
					     flags);
	size_t copy_end;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	loff_t pos;
	struct kiocb kiocb;
	ssize_t ret;

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out_acct;
	}

	if (compat) {
#if defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
		struct btrfs_ioctl_encoded_io_args_32 args32;

		copy_end = offsetofend(struct btrfs_ioctl_encoded_io_args_32,
				       flags);
		if (copy_from_user(&args32, argp, copy_end)) {
			ret = -EFAULT;
			goto out_acct;
		}
		args.iov = compat_ptr(args32.iov);
		args.iovcnt = args32.iovcnt;
		args.offset = args32.offset;
		args.flags = args32.flags;
#else
		return -ENOTTY;
#endif
	} else {
		copy_end = copy_end_kernel;
		if (copy_from_user(&args, argp, copy_end)) {
			ret = -EFAULT;
			goto out_acct;
		}
	}
	if (args.flags != 0) {
		ret = -EINVAL;
		goto out_acct;
	}

	ret = import_iovec(ITER_DEST, args.iov, args.iovcnt, ARRAY_SIZE(iovstack),
			   &iov, &iter);
	if (ret < 0)
		goto out_acct;

	if (iov_iter_count(&iter) == 0) {
		ret = 0;
		goto out_iov;
	}
	pos = args.offset;
	ret = rw_verify_area(READ, file, &pos, args.len);
	if (ret < 0)
		goto out_iov;

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = pos;

	ret = btrfs_encoded_read(&kiocb, &iter, &args);
	if (ret >= 0) {
		fsnotify_access(file);
		if (copy_to_user(argp + copy_end,
				 (char *)&args + copy_end_kernel,
				 sizeof(args) - copy_end_kernel))
			ret = -EFAULT;
	}

out_iov:
	kfree(iov);
out_acct:
	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

static int btrfs_ioctl_encoded_write(struct file *file, void __user *argp, bool compat)
{
	struct btrfs_ioctl_encoded_io_args args;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	loff_t pos;
	struct kiocb kiocb;
	ssize_t ret;

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out_acct;
	}

	if (!(file->f_mode & FMODE_WRITE)) {
		ret = -EBADF;
		goto out_acct;
	}

	if (compat) {
#if defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
		struct btrfs_ioctl_encoded_io_args_32 args32;

		if (copy_from_user(&args32, argp, sizeof(args32))) {
			ret = -EFAULT;
			goto out_acct;
		}
		args.iov = compat_ptr(args32.iov);
		args.iovcnt = args32.iovcnt;
		args.offset = args32.offset;
		args.flags = args32.flags;
		args.len = args32.len;
		args.unencoded_len = args32.unencoded_len;
		args.unencoded_offset = args32.unencoded_offset;
		args.compression = args32.compression;
		args.encryption = args32.encryption;
		memcpy(args.reserved, args32.reserved, sizeof(args.reserved));
#else
		return -ENOTTY;
#endif
	} else {
		if (copy_from_user(&args, argp, sizeof(args))) {
			ret = -EFAULT;
			goto out_acct;
		}
	}

	ret = -EINVAL;
	if (args.flags != 0)
		goto out_acct;
	if (memchr_inv(args.reserved, 0, sizeof(args.reserved)))
		goto out_acct;
	if (args.compression == BTRFS_ENCODED_IO_COMPRESSION_NONE &&
	    args.encryption == BTRFS_ENCODED_IO_ENCRYPTION_NONE)
		goto out_acct;
	if (args.compression >= BTRFS_ENCODED_IO_COMPRESSION_TYPES ||
	    args.encryption >= BTRFS_ENCODED_IO_ENCRYPTION_TYPES)
		goto out_acct;
	if (args.unencoded_offset > args.unencoded_len)
		goto out_acct;
	if (args.len > args.unencoded_len - args.unencoded_offset)
		goto out_acct;

	ret = import_iovec(ITER_SOURCE, args.iov, args.iovcnt, ARRAY_SIZE(iovstack),
			   &iov, &iter);
	if (ret < 0)
		goto out_acct;

	file_start_write(file);

	if (iov_iter_count(&iter) == 0) {
		ret = 0;
		goto out_end_write;
	}
	pos = args.offset;
	ret = rw_verify_area(WRITE, file, &pos, args.len);
	if (ret < 0)
		goto out_end_write;

	init_sync_kiocb(&kiocb, file);
	ret = kiocb_set_rw_flags(&kiocb, 0);
	if (ret)
		goto out_end_write;
	kiocb.ki_pos = pos;

	ret = btrfs_do_write_iter(&kiocb, &iter, &args);
	if (ret > 0)
		fsnotify_modify(file);

out_end_write:
	file_end_write(file);
	kfree(iov);
out_acct:
	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

long btrfs_ioctl(struct file *file, unsigned int
		cmd, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case FS_IOC_GETVERSION:
		return btrfs_ioctl_getversion(inode, argp);
	case FS_IOC_GETFSLABEL:
		return btrfs_ioctl_get_fslabel(fs_info, argp);
	case FS_IOC_SETFSLABEL:
		return btrfs_ioctl_set_fslabel(file, argp);
	case FITRIM:
		return btrfs_ioctl_fitrim(fs_info, argp);
	case BTRFS_IOC_SNAP_CREATE:
		return btrfs_ioctl_snap_create(file, argp, 0);
	case BTRFS_IOC_SNAP_CREATE_V2:
		return btrfs_ioctl_snap_create_v2(file, argp, 0);
	case BTRFS_IOC_SUBVOL_CREATE:
		return btrfs_ioctl_snap_create(file, argp, 1);
	case BTRFS_IOC_SUBVOL_CREATE_V2:
		return btrfs_ioctl_snap_create_v2(file, argp, 1);
	case BTRFS_IOC_SNAP_DESTROY:
		return btrfs_ioctl_snap_destroy(file, argp, false);
	case BTRFS_IOC_SNAP_DESTROY_V2:
		return btrfs_ioctl_snap_destroy(file, argp, true);
	case BTRFS_IOC_SUBVOL_GETFLAGS:
		return btrfs_ioctl_subvol_getflags(inode, argp);
	case BTRFS_IOC_SUBVOL_SETFLAGS:
		return btrfs_ioctl_subvol_setflags(file, argp);
	case BTRFS_IOC_DEFAULT_SUBVOL:
		return btrfs_ioctl_default_subvol(file, argp);
	case BTRFS_IOC_DEFRAG:
		return btrfs_ioctl_defrag(file, NULL);
	case BTRFS_IOC_DEFRAG_RANGE:
		return btrfs_ioctl_defrag(file, argp);
	case BTRFS_IOC_RESIZE:
		return btrfs_ioctl_resize(file, argp);
	case BTRFS_IOC_ADD_DEV:
		return btrfs_ioctl_add_dev(fs_info, argp);
	case BTRFS_IOC_RM_DEV:
		return btrfs_ioctl_rm_dev(file, argp);
	case BTRFS_IOC_RM_DEV_V2:
		return btrfs_ioctl_rm_dev_v2(file, argp);
	case BTRFS_IOC_FS_INFO:
		return btrfs_ioctl_fs_info(fs_info, argp);
	case BTRFS_IOC_DEV_INFO:
		return btrfs_ioctl_dev_info(fs_info, argp);
	case BTRFS_IOC_TREE_SEARCH:
		return btrfs_ioctl_tree_search(inode, argp);
	case BTRFS_IOC_TREE_SEARCH_V2:
		return btrfs_ioctl_tree_search_v2(inode, argp);
	case BTRFS_IOC_INO_LOOKUP:
		return btrfs_ioctl_ino_lookup(root, argp);
	case BTRFS_IOC_INO_PATHS:
		return btrfs_ioctl_ino_to_path(root, argp);
	case BTRFS_IOC_LOGICAL_INO:
		return btrfs_ioctl_logical_to_ino(fs_info, argp, 1);
	case BTRFS_IOC_LOGICAL_INO_V2:
		return btrfs_ioctl_logical_to_ino(fs_info, argp, 2);
	case BTRFS_IOC_SPACE_INFO:
		return btrfs_ioctl_space_info(fs_info, argp);
	case BTRFS_IOC_SYNC: {
		int ret;

		ret = btrfs_start_delalloc_roots(fs_info, LONG_MAX, false);
		if (ret)
			return ret;
		ret = btrfs_sync_fs(inode->i_sb, 1);
		/*
		 * The transaction thread may want to do more work,
		 * namely it pokes the cleaner kthread that will start
		 * processing uncleaned subvols.
		 */
		wake_up_process(fs_info->transaction_kthread);
		return ret;
	}
	case BTRFS_IOC_START_SYNC:
		return btrfs_ioctl_start_sync(root, argp);
	case BTRFS_IOC_WAIT_SYNC:
		return btrfs_ioctl_wait_sync(fs_info, argp);
	case BTRFS_IOC_SCRUB:
		return btrfs_ioctl_scrub(file, argp);
	case BTRFS_IOC_SCRUB_CANCEL:
		return btrfs_ioctl_scrub_cancel(fs_info);
	case BTRFS_IOC_SCRUB_PROGRESS:
		return btrfs_ioctl_scrub_progress(fs_info, argp);
	case BTRFS_IOC_BALANCE_V2:
		return btrfs_ioctl_balance(file, argp);
	case BTRFS_IOC_BALANCE_CTL:
		return btrfs_ioctl_balance_ctl(fs_info, arg);
	case BTRFS_IOC_BALANCE_PROGRESS:
		return btrfs_ioctl_balance_progress(fs_info, argp);
	case BTRFS_IOC_SET_RECEIVED_SUBVOL:
		return btrfs_ioctl_set_received_subvol(file, argp);
#ifdef CONFIG_64BIT
	case BTRFS_IOC_SET_RECEIVED_SUBVOL_32:
		return btrfs_ioctl_set_received_subvol_32(file, argp);
#endif
	case BTRFS_IOC_SEND:
		return _btrfs_ioctl_send(inode, argp, false);
#if defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
	case BTRFS_IOC_SEND_32:
		return _btrfs_ioctl_send(inode, argp, true);
#endif
	case BTRFS_IOC_GET_DEV_STATS:
		return btrfs_ioctl_get_dev_stats(fs_info, argp);
	case BTRFS_IOC_QUOTA_CTL:
		return btrfs_ioctl_quota_ctl(file, argp);
	case BTRFS_IOC_QGROUP_ASSIGN:
		return btrfs_ioctl_qgroup_assign(file, argp);
	case BTRFS_IOC_QGROUP_CREATE:
		return btrfs_ioctl_qgroup_create(file, argp);
	case BTRFS_IOC_QGROUP_LIMIT:
		return btrfs_ioctl_qgroup_limit(file, argp);
	case BTRFS_IOC_QUOTA_RESCAN:
		return btrfs_ioctl_quota_rescan(file, argp);
	case BTRFS_IOC_QUOTA_RESCAN_STATUS:
		return btrfs_ioctl_quota_rescan_status(fs_info, argp);
	case BTRFS_IOC_QUOTA_RESCAN_WAIT:
		return btrfs_ioctl_quota_rescan_wait(fs_info, argp);
	case BTRFS_IOC_DEV_REPLACE:
		return btrfs_ioctl_dev_replace(fs_info, argp);
	case BTRFS_IOC_GET_SUPPORTED_FEATURES:
		return btrfs_ioctl_get_supported_features(argp);
	case BTRFS_IOC_GET_FEATURES:
		return btrfs_ioctl_get_features(fs_info, argp);
	case BTRFS_IOC_SET_FEATURES:
		return btrfs_ioctl_set_features(file, argp);
	case BTRFS_IOC_GET_SUBVOL_INFO:
		return btrfs_ioctl_get_subvol_info(inode, argp);
	case BTRFS_IOC_GET_SUBVOL_ROOTREF:
		return btrfs_ioctl_get_subvol_rootref(root, argp);
	case BTRFS_IOC_INO_LOOKUP_USER:
		return btrfs_ioctl_ino_lookup_user(file, argp);
	case FS_IOC_ENABLE_VERITY:
		return fsverity_ioctl_enable(file, (const void __user *)argp);
	case FS_IOC_MEASURE_VERITY:
		return fsverity_ioctl_measure(file, argp);
	case BTRFS_IOC_ENCODED_READ:
		return btrfs_ioctl_encoded_read(file, argp, false);
	case BTRFS_IOC_ENCODED_WRITE:
		return btrfs_ioctl_encoded_write(file, argp, false);
#if defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
	case BTRFS_IOC_ENCODED_READ_32:
		return btrfs_ioctl_encoded_read(file, argp, true);
	case BTRFS_IOC_ENCODED_WRITE_32:
		return btrfs_ioctl_encoded_write(file, argp, true);
#endif
	}

	return -ENOTTY;
}

#ifdef CONFIG_COMPAT
long btrfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/*
	 * These all access 32-bit values anyway so no further
	 * handling is necessary.
	 */
	switch (cmd) {
	case FS_IOC32_GETVERSION:
		cmd = FS_IOC_GETVERSION;
		break;
	}

	return btrfs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif
