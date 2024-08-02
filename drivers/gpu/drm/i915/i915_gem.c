/*
 * Copyright © 2008-2015 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    Eric Anholt <eric@anholt.net>
 *
 */

#include <linux/dma-fence-array.h>
#include <linux/kthread.h>
#include <linux/dma-resv.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/swap.h>
#include <linux/pci.h>
#include <linux/dma-buf.h>
#include <linux/mman.h>

#include <drm/drm_cache.h>
#include <drm/drm_vma_manager.h>

#include "display/intel_display.h"
#include "display/intel_frontbuffer.h"

#include "gem/i915_gem_clflush.h"
#include "gem/i915_gem_context.h"
#include "gem/i915_gem_ioctls.h"
#include "gem/i915_gem_mman.h"
#include "gem/i915_gem_pm.h"
#include "gem/i915_gem_region.h"
#include "gem/i915_gem_userptr.h"
#include "gt/intel_engine_user.h"
#include "gt/intel_gt.h"
#include "gt/intel_gt_pm.h"
#include "gt/intel_workarounds.h"

#include "i915_drv.h"
#include "i915_file_private.h"
#include "i915_trace.h"
#include "i915_vgpu.h"
#include "intel_clock_gating.h"

static int
insert_mappable_node(struct i915_ggtt *ggtt, struct drm_mm_node *node, u32 size)
{
	int err;

	err = mutex_lock_interruptible(&ggtt->vm.mutex);
	if (err)
		return err;

	memset(node, 0, sizeof(*node));
	err = drm_mm_insert_node_in_range(&ggtt->vm.mm, node,
					  size, 0, I915_COLOR_UNEVICTABLE,
					  0, ggtt->mappable_end,
					  DRM_MM_INSERT_LOW);

	mutex_unlock(&ggtt->vm.mutex);

	return err;
}

static void
remove_mappable_node(struct i915_ggtt *ggtt, struct drm_mm_node *node)
{
	mutex_lock(&ggtt->vm.mutex);
	drm_mm_remove_node(node);
<<<<<<< HEAD
	mutex_unlock(&ggtt->vm.mutex);
=======
}

/* some bookkeeping */
static void i915_gem_info_add_obj(struct drm_i915_private *dev_priv,
				  u64 size)
{
	spin_lock(&dev_priv->mm.object_stat_lock);
	dev_priv->mm.object_count++;
	dev_priv->mm.object_memory += size;
	spin_unlock(&dev_priv->mm.object_stat_lock);
}

static void i915_gem_info_remove_obj(struct drm_i915_private *dev_priv,
				     u64 size)
{
	spin_lock(&dev_priv->mm.object_stat_lock);
	dev_priv->mm.object_count--;
	dev_priv->mm.object_memory -= size;
	spin_unlock(&dev_priv->mm.object_stat_lock);
}

static int
i915_gem_wait_for_error(struct i915_gpu_error *error)
{
	int ret;

	might_sleep();

	/*
	 * Only wait 10 seconds for the gpu reset to complete to avoid hanging
	 * userspace. If it takes that long something really bad is going on and
	 * we should simply try to bail out and fail as gracefully as possible.
	 */
	ret = wait_event_interruptible_timeout(error->reset_queue,
					       !i915_reset_backoff(error),
					       I915_RESET_TIMEOUT);
	if (ret == 0) {
		DRM_ERROR("Timed out waiting for the gpu reset to complete\n");
		return -EIO;
	} else if (ret < 0) {
		return ret;
	} else {
		return 0;
	}
}

int i915_mutex_lock_interruptible(struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = to_i915(dev);
	int ret;

	ret = i915_gem_wait_for_error(&dev_priv->gpu_error);
	if (ret)
		return ret;

	ret = mutex_lock_interruptible(&dev->struct_mutex);
	if (ret)
		return ret;

	return 0;
}

static u32 __i915_gem_park(struct drm_i915_private *i915)
{
	GEM_TRACE("\n");

	lockdep_assert_held(&i915->drm.struct_mutex);
	GEM_BUG_ON(i915->gt.active_requests);
	GEM_BUG_ON(!list_empty(&i915->gt.active_rings));

	if (!i915->gt.awake)
		return I915_EPOCH_INVALID;

	GEM_BUG_ON(i915->gt.epoch == I915_EPOCH_INVALID);

	/*
	 * Be paranoid and flush a concurrent interrupt to make sure
	 * we don't reactivate any irq tasklets after parking.
	 *
	 * FIXME: Note that even though we have waited for execlists to be idle,
	 * there may still be an in-flight interrupt even though the CSB
	 * is now empty. synchronize_irq() makes sure that a residual interrupt
	 * is completed before we continue, but it doesn't prevent the HW from
	 * raising a spurious interrupt later. To complete the shield we should
	 * coordinate disabling the CS irq with flushing the interrupts.
	 */
	synchronize_irq(i915->drm.irq);

	intel_engines_park(i915);
	i915_timelines_park(i915);

	i915_pmu_gt_parked(i915);
	i915_vma_parked(i915);

	i915->gt.awake = false;

	if (INTEL_GEN(i915) >= 6)
		gen6_rps_idle(i915);

	if (NEEDS_RC6_CTX_CORRUPTION_WA(i915)) {
		i915_rc6_ctx_wa_check(i915);
		intel_uncore_forcewake_put(i915, FORCEWAKE_ALL);
	}

	intel_display_power_put(i915, POWER_DOMAIN_GT_IRQ);

	intel_runtime_pm_put(i915);

	return i915->gt.epoch;
}

void i915_gem_park(struct drm_i915_private *i915)
{
	GEM_TRACE("\n");

	lockdep_assert_held(&i915->drm.struct_mutex);
	GEM_BUG_ON(i915->gt.active_requests);

	if (!i915->gt.awake)
		return;

	/* Defer the actual call to __i915_gem_park() to prevent ping-pongs */
	mod_delayed_work(i915->wq, &i915->gt.idle_work, msecs_to_jiffies(100));
}

void i915_gem_unpark(struct drm_i915_private *i915)
{
	GEM_TRACE("\n");

	lockdep_assert_held(&i915->drm.struct_mutex);
	GEM_BUG_ON(!i915->gt.active_requests);

	if (i915->gt.awake)
		return;

	intel_runtime_pm_get_noresume(i915);

	/*
	 * It seems that the DMC likes to transition between the DC states a lot
	 * when there are no connected displays (no active power domains) during
	 * command submission.
	 *
	 * This activity has negative impact on the performance of the chip with
	 * huge latencies observed in the interrupt handler and elsewhere.
	 *
	 * Work around it by grabbing a GT IRQ power domain whilst there is any
	 * GT activity, preventing any DC state transitions.
	 */
	intel_display_power_get(i915, POWER_DOMAIN_GT_IRQ);

	if (NEEDS_RC6_CTX_CORRUPTION_WA(i915))
		intel_uncore_forcewake_get(i915, FORCEWAKE_ALL);

	i915->gt.awake = true;
	if (unlikely(++i915->gt.epoch == 0)) /* keep 0 as invalid */
		i915->gt.epoch = 1;

	intel_enable_gt_powersave(i915);
	i915_update_gfx_val(i915);
	if (INTEL_GEN(i915) >= 6)
		gen6_rps_busy(i915);
	i915_pmu_gt_unparked(i915);

	intel_engines_unpark(i915);

	i915_queue_hangcheck(i915);

	queue_delayed_work(i915->wq,
			   &i915->gt.retire_work,
			   round_jiffies_up_relative(HZ));
>>>>>>> master
}

int
i915_gem_get_aperture_ioctl(struct drm_device *dev, void *data,
			    struct drm_file *file)
{
	struct drm_i915_private *i915 = to_i915(dev);
	struct i915_ggtt *ggtt = to_gt(i915)->ggtt;
	struct drm_i915_gem_get_aperture *args = data;
	struct i915_vma *vma;
	u64 pinned;

	if (mutex_lock_interruptible(&ggtt->vm.mutex))
		return -EINTR;

	pinned = ggtt->vm.reserved;
	list_for_each_entry(vma, &ggtt->vm.bound_list, vm_link)
		if (i915_vma_is_pinned(vma))
			pinned += vma->node.size;

	mutex_unlock(&ggtt->vm.mutex);

	args->aper_size = ggtt->vm.total;
	args->aper_available_size = args->aper_size - pinned;

	return 0;
}

int i915_gem_object_unbind(struct drm_i915_gem_object *obj,
			   unsigned long flags)
{
	struct intel_runtime_pm *rpm = &to_i915(obj->base.dev)->runtime_pm;
	bool vm_trylock = !!(flags & I915_GEM_OBJECT_UNBIND_VM_TRYLOCK);
	LIST_HEAD(still_in_list);
	intel_wakeref_t wakeref;
	struct i915_vma *vma;
	int ret;

	assert_object_held(obj);

	if (list_empty(&obj->vma.list))
		return 0;

	/*
	 * As some machines use ACPI to handle runtime-resume callbacks, and
	 * ACPI is quite kmalloc happy, we cannot resume beneath the vm->mutex
	 * as they are required by the shrinker. Ergo, we wake the device up
	 * first just in case.
	 */
	wakeref = intel_runtime_pm_get(rpm);

try_again:
	ret = 0;
	spin_lock(&obj->vma.lock);
	while (!ret && (vma = list_first_entry_or_null(&obj->vma.list,
						       struct i915_vma,
						       obj_link))) {
		list_move_tail(&vma->obj_link, &still_in_list);
		if (!i915_vma_is_bound(vma, I915_VMA_BIND_MASK))
			continue;

		if (flags & I915_GEM_OBJECT_UNBIND_TEST) {
			ret = -EBUSY;
			break;
		}

		/*
		 * Requiring the vm destructor to take the object lock
		 * before destroying a vma would help us eliminate the
		 * i915_vm_tryget() here, AND thus also the barrier stuff
		 * at the end. That's an easy fix, but sleeping locks in
		 * a kthread should generally be avoided.
		 */
		ret = -EAGAIN;
		if (!i915_vm_tryget(vma->vm))
			break;

		spin_unlock(&obj->vma.lock);

		/*
		 * Since i915_vma_parked() takes the object lock
		 * before vma destruction, it won't race us here,
		 * and destroy the vma from under us.
		 */

		ret = -EBUSY;
		if (flags & I915_GEM_OBJECT_UNBIND_ASYNC) {
			assert_object_held(vma->obj);
			ret = i915_vma_unbind_async(vma, vm_trylock);
		}

		if (ret == -EBUSY && (flags & I915_GEM_OBJECT_UNBIND_ACTIVE ||
				      !i915_vma_is_active(vma))) {
			if (vm_trylock) {
				if (mutex_trylock(&vma->vm->mutex)) {
					ret = __i915_vma_unbind(vma);
					mutex_unlock(&vma->vm->mutex);
				}
			} else {
				ret = i915_vma_unbind(vma);
			}
		}

		i915_vm_put(vma->vm);
		spin_lock(&obj->vma.lock);
	}
	list_splice_init(&still_in_list, &obj->vma.list);
	spin_unlock(&obj->vma.lock);

	if (ret == -EAGAIN && flags & I915_GEM_OBJECT_UNBIND_BARRIER) {
		rcu_barrier(); /* flush the i915_vm_release() */
		goto try_again;
	}

	intel_runtime_pm_put(rpm, wakeref);

	return ret;
}

static int
shmem_pread(struct page *page, int offset, int len, char __user *user_data,
	    bool needs_clflush)
{
	char *vaddr;
	int ret;

	vaddr = kmap(page);

	if (needs_clflush)
		drm_clflush_virt_range(vaddr + offset, len);

	ret = __copy_to_user(user_data, vaddr + offset, len);

	kunmap(page);

	return ret ? -EFAULT : 0;
}

static int
i915_gem_shmem_pread(struct drm_i915_gem_object *obj,
		     struct drm_i915_gem_pread *args)
{
	unsigned int needs_clflush;
	char __user *user_data;
	unsigned long offset;
	pgoff_t idx;
	u64 remain;
	int ret;

	ret = i915_gem_object_lock_interruptible(obj, NULL);
	if (ret)
		return ret;

	ret = i915_gem_object_pin_pages(obj);
	if (ret)
		goto err_unlock;

	ret = i915_gem_object_prepare_read(obj, &needs_clflush);
	if (ret)
		goto err_unpin;

	i915_gem_object_finish_access(obj);
	i915_gem_object_unlock(obj);

	remain = args->size;
	user_data = u64_to_user_ptr(args->data_ptr);
	offset = offset_in_page(args->offset);
	for (idx = args->offset >> PAGE_SHIFT; remain; idx++) {
		struct page *page = i915_gem_object_get_page(obj, idx);
		unsigned int length = min_t(u64, remain, PAGE_SIZE - offset);

		ret = shmem_pread(page, offset, length, user_data,
				  needs_clflush);
		if (ret)
			break;

		remain -= length;
		user_data += length;
		offset = 0;
	}

	i915_gem_object_unpin_pages(obj);
	return ret;

err_unpin:
	i915_gem_object_unpin_pages(obj);
err_unlock:
	i915_gem_object_unlock(obj);
	return ret;
}

static inline bool
gtt_user_read(struct io_mapping *mapping,
	      loff_t base, int offset,
	      char __user *user_data, int length)
{
	void __iomem *vaddr;
	unsigned long unwritten;

	/* We can use the cpu mem copy function because this is X86. */
	vaddr = io_mapping_map_atomic_wc(mapping, base);
	unwritten = __copy_to_user_inatomic(user_data,
					    (void __force *)vaddr + offset,
					    length);
	io_mapping_unmap_atomic(vaddr);
	if (unwritten) {
		vaddr = io_mapping_map_wc(mapping, base, PAGE_SIZE);
		unwritten = copy_to_user(user_data,
					 (void __force *)vaddr + offset,
					 length);
		io_mapping_unmap(vaddr);
	}
	return unwritten;
}

static struct i915_vma *i915_gem_gtt_prepare(struct drm_i915_gem_object *obj,
					     struct drm_mm_node *node,
					     bool write)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	struct i915_ggtt *ggtt = to_gt(i915)->ggtt;
	struct i915_vma *vma;
	struct i915_gem_ww_ctx ww;
	int ret;

	i915_gem_ww_ctx_init(&ww, true);
retry:
	vma = ERR_PTR(-ENODEV);
	ret = i915_gem_object_lock(obj, &ww);
	if (ret)
		goto err_ww;

	ret = i915_gem_object_set_to_gtt_domain(obj, write);
	if (ret)
		goto err_ww;

	if (!i915_gem_object_is_tiled(obj))
		vma = i915_gem_object_ggtt_pin_ww(obj, &ww, NULL, 0, 0,
						  PIN_MAPPABLE |
						  PIN_NONBLOCK /* NOWARN */ |
						  PIN_NOEVICT);
	if (vma == ERR_PTR(-EDEADLK)) {
		ret = -EDEADLK;
		goto err_ww;
	} else if (!IS_ERR(vma)) {
		node->start = i915_ggtt_offset(vma);
		node->flags = 0;
	} else {
		ret = insert_mappable_node(ggtt, node, PAGE_SIZE);
		if (ret)
			goto err_ww;
		GEM_BUG_ON(!drm_mm_node_allocated(node));
		vma = NULL;
	}

	ret = i915_gem_object_pin_pages(obj);
	if (ret) {
		if (drm_mm_node_allocated(node)) {
			ggtt->vm.clear_range(&ggtt->vm, node->start, node->size);
			remove_mappable_node(ggtt, node);
		} else {
			i915_vma_unpin(vma);
		}
	}

err_ww:
	if (ret == -EDEADLK) {
		ret = i915_gem_ww_ctx_backoff(&ww);
		if (!ret)
			goto retry;
	}
	i915_gem_ww_ctx_fini(&ww);

	return ret ? ERR_PTR(ret) : vma;
}

static void i915_gem_gtt_cleanup(struct drm_i915_gem_object *obj,
				 struct drm_mm_node *node,
				 struct i915_vma *vma)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	struct i915_ggtt *ggtt = to_gt(i915)->ggtt;

	i915_gem_object_unpin_pages(obj);
	if (drm_mm_node_allocated(node)) {
		ggtt->vm.clear_range(&ggtt->vm, node->start, node->size);
		remove_mappable_node(ggtt, node);
	} else {
		i915_vma_unpin(vma);
	}
}

static int
i915_gem_gtt_pread(struct drm_i915_gem_object *obj,
		   const struct drm_i915_gem_pread *args)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	struct i915_ggtt *ggtt = to_gt(i915)->ggtt;
	unsigned long remain, offset;
	intel_wakeref_t wakeref;
	struct drm_mm_node node;
	void __user *user_data;
	struct i915_vma *vma;
	int ret = 0;

	if (overflows_type(args->size, remain) ||
	    overflows_type(args->offset, offset))
		return -EINVAL;

	wakeref = intel_runtime_pm_get(&i915->runtime_pm);

	vma = i915_gem_gtt_prepare(obj, &node, false);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out_rpm;
	}

	user_data = u64_to_user_ptr(args->data_ptr);
	remain = args->size;
	offset = args->offset;

	while (remain > 0) {
		/* Operation in this page
		 *
		 * page_base = page offset within aperture
		 * page_offset = offset within page
		 * page_length = bytes to copy for this page
		 */
		u32 page_base = node.start;
		unsigned page_offset = offset_in_page(offset);
		unsigned page_length = PAGE_SIZE - page_offset;
		page_length = remain < page_length ? remain : page_length;
		if (drm_mm_node_allocated(&node)) {
			ggtt->vm.insert_page(&ggtt->vm,
					     i915_gem_object_get_dma_address(obj,
									     offset >> PAGE_SHIFT),
					     node.start,
					     i915_gem_get_pat_index(i915,
								    I915_CACHE_NONE), 0);
		} else {
			page_base += offset & PAGE_MASK;
		}

		if (gtt_user_read(&ggtt->iomap, page_base, page_offset,
				  user_data, page_length)) {
			ret = -EFAULT;
			break;
		}

		remain -= page_length;
		user_data += page_length;
		offset += page_length;
	}

	i915_gem_gtt_cleanup(obj, &node, vma);
out_rpm:
	intel_runtime_pm_put(&i915->runtime_pm, wakeref);
	return ret;
}

/**
 * i915_gem_pread_ioctl - Reads data from the object referenced by handle.
 * @dev: drm device pointer
 * @data: ioctl data blob
 * @file: drm file pointer
 *
 * On error, the contents of *data are undefined.
 */
int
i915_gem_pread_ioctl(struct drm_device *dev, void *data,
		     struct drm_file *file)
{
	struct drm_i915_private *i915 = to_i915(dev);
	struct drm_i915_gem_pread *args = data;
	struct drm_i915_gem_object *obj;
	int ret;

	/* PREAD is disallowed for all platforms after TGL-LP.  This also
	 * covers all platforms with local memory.
	 */
	if (GRAPHICS_VER(i915) >= 12 && !IS_TIGERLAKE(i915))
		return -EOPNOTSUPP;

	if (args->size == 0)
		return 0;

	if (!access_ok(u64_to_user_ptr(args->data_ptr),
		       args->size))
		return -EFAULT;

	obj = i915_gem_object_lookup(file, args->handle);
	if (!obj)
		return -ENOENT;

	/* Bounds check source.  */
	if (range_overflows_t(u64, args->offset, args->size, obj->base.size)) {
		ret = -EINVAL;
		goto out;
	}

	trace_i915_gem_object_pread(obj, args->offset, args->size);
	ret = -ENODEV;
	if (obj->ops->pread)
		ret = obj->ops->pread(obj, args);
	if (ret != -ENODEV)
		goto out;

	ret = i915_gem_object_wait(obj,
				   I915_WAIT_INTERRUPTIBLE,
				   MAX_SCHEDULE_TIMEOUT);
	if (ret)
		goto out;

	ret = i915_gem_shmem_pread(obj, args);
	if (ret == -EFAULT || ret == -ENODEV)
		ret = i915_gem_gtt_pread(obj, args);

out:
	i915_gem_object_put(obj);
	return ret;
}

/* This is the fast write path which cannot handle
 * page faults in the source data
 */

static inline bool
ggtt_write(struct io_mapping *mapping,
	   loff_t base, int offset,
	   char __user *user_data, int length)
{
	void __iomem *vaddr;
	unsigned long unwritten;

	/* We can use the cpu mem copy function because this is X86. */
	vaddr = io_mapping_map_atomic_wc(mapping, base);
	unwritten = __copy_from_user_inatomic_nocache((void __force *)vaddr + offset,
						      user_data, length);
	io_mapping_unmap_atomic(vaddr);
	if (unwritten) {
		vaddr = io_mapping_map_wc(mapping, base, PAGE_SIZE);
		unwritten = copy_from_user((void __force *)vaddr + offset,
					   user_data, length);
		io_mapping_unmap(vaddr);
	}

	return unwritten;
}

/**
 * i915_gem_gtt_pwrite_fast - This is the fast pwrite path, where we copy the data directly from the
 * user into the GTT, uncached.
 * @obj: i915 GEM object
 * @args: pwrite arguments structure
 */
static int
i915_gem_gtt_pwrite_fast(struct drm_i915_gem_object *obj,
			 const struct drm_i915_gem_pwrite *args)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	struct i915_ggtt *ggtt = to_gt(i915)->ggtt;
	struct intel_runtime_pm *rpm = &i915->runtime_pm;
	unsigned long remain, offset;
	intel_wakeref_t wakeref;
	struct drm_mm_node node;
	struct i915_vma *vma;
	void __user *user_data;
	int ret = 0;

	if (overflows_type(args->size, remain) ||
	    overflows_type(args->offset, offset))
		return -EINVAL;

	if (i915_gem_object_has_struct_page(obj)) {
		/*
		 * Avoid waking the device up if we can fallback, as
		 * waking/resuming is very slow (worst-case 10-100 ms
		 * depending on PCI sleeps and our own resume time).
		 * This easily dwarfs any performance advantage from
		 * using the cache bypass of indirect GGTT access.
		 */
		wakeref = intel_runtime_pm_get_if_in_use(rpm);
		if (!wakeref)
			return -EFAULT;
	} else {
		/* No backing pages, no fallback, we must force GGTT access */
		wakeref = intel_runtime_pm_get(rpm);
	}

	vma = i915_gem_gtt_prepare(obj, &node, true);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out_rpm;
	}

	i915_gem_object_invalidate_frontbuffer(obj, ORIGIN_CPU);

	user_data = u64_to_user_ptr(args->data_ptr);
	offset = args->offset;
	remain = args->size;
	while (remain) {
		/* Operation in this page
		 *
		 * page_base = page offset within aperture
		 * page_offset = offset within page
		 * page_length = bytes to copy for this page
		 */
		u32 page_base = node.start;
		unsigned int page_offset = offset_in_page(offset);
		unsigned int page_length = PAGE_SIZE - page_offset;
		page_length = remain < page_length ? remain : page_length;
		if (drm_mm_node_allocated(&node)) {
			/* flush the write before we modify the GGTT */
			intel_gt_flush_ggtt_writes(ggtt->vm.gt);
			ggtt->vm.insert_page(&ggtt->vm,
					     i915_gem_object_get_dma_address(obj,
									     offset >> PAGE_SHIFT),
					     node.start,
					     i915_gem_get_pat_index(i915,
								    I915_CACHE_NONE), 0);
			wmb(); /* flush modifications to the GGTT (insert_page) */
		} else {
			page_base += offset & PAGE_MASK;
		}
		/* If we get a fault while copying data, then (presumably) our
		 * source page isn't available.  Return the error and we'll
		 * retry in the slow path.
		 * If the object is non-shmem backed, we retry again with the
		 * path that handles page fault.
		 */
		if (ggtt_write(&ggtt->iomap, page_base, page_offset,
			       user_data, page_length)) {
			ret = -EFAULT;
			break;
		}

		remain -= page_length;
		user_data += page_length;
		offset += page_length;
	}

	intel_gt_flush_ggtt_writes(ggtt->vm.gt);
	i915_gem_object_flush_frontbuffer(obj, ORIGIN_CPU);

	i915_gem_gtt_cleanup(obj, &node, vma);
out_rpm:
	intel_runtime_pm_put(rpm, wakeref);
	return ret;
}

/* Per-page copy function for the shmem pwrite fastpath.
 * Flushes invalid cachelines before writing to the target if
 * needs_clflush_before is set and flushes out any written cachelines after
 * writing if needs_clflush is set.
 */
static int
shmem_pwrite(struct page *page, int offset, int len, char __user *user_data,
	     bool needs_clflush_before,
	     bool needs_clflush_after)
{
	char *vaddr;
	int ret;

	vaddr = kmap(page);

	if (needs_clflush_before)
		drm_clflush_virt_range(vaddr + offset, len);

	ret = __copy_from_user(vaddr + offset, user_data, len);
	if (!ret && needs_clflush_after)
		drm_clflush_virt_range(vaddr + offset, len);

	kunmap(page);

	return ret ? -EFAULT : 0;
}

static int
i915_gem_shmem_pwrite(struct drm_i915_gem_object *obj,
		      const struct drm_i915_gem_pwrite *args)
{
	unsigned int partial_cacheline_write;
	unsigned int needs_clflush;
	void __user *user_data;
	unsigned long offset;
	pgoff_t idx;
	u64 remain;
	int ret;

	ret = i915_gem_object_lock_interruptible(obj, NULL);
	if (ret)
		return ret;

	ret = i915_gem_object_pin_pages(obj);
	if (ret)
		goto err_unlock;

	ret = i915_gem_object_prepare_write(obj, &needs_clflush);
	if (ret)
		goto err_unpin;

	i915_gem_object_finish_access(obj);
	i915_gem_object_unlock(obj);

	/* If we don't overwrite a cacheline completely we need to be
	 * careful to have up-to-date data by first clflushing. Don't
	 * overcomplicate things and flush the entire patch.
	 */
	partial_cacheline_write = 0;
	if (needs_clflush & CLFLUSH_BEFORE)
		partial_cacheline_write = boot_cpu_data.x86_clflush_size - 1;

	user_data = u64_to_user_ptr(args->data_ptr);
	remain = args->size;
	offset = offset_in_page(args->offset);
	for (idx = args->offset >> PAGE_SHIFT; remain; idx++) {
		struct page *page = i915_gem_object_get_page(obj, idx);
		unsigned int length = min_t(u64, remain, PAGE_SIZE - offset);

		ret = shmem_pwrite(page, offset, length, user_data,
				   (offset | length) & partial_cacheline_write,
				   needs_clflush & CLFLUSH_AFTER);
		if (ret)
			break;

		remain -= length;
		user_data += length;
		offset = 0;
	}

	i915_gem_object_flush_frontbuffer(obj, ORIGIN_CPU);

	i915_gem_object_unpin_pages(obj);
	return ret;

err_unpin:
	i915_gem_object_unpin_pages(obj);
err_unlock:
	i915_gem_object_unlock(obj);
	return ret;
}

/**
 * i915_gem_pwrite_ioctl - Writes data to the object referenced by handle.
 * @dev: drm device
 * @data: ioctl data blob
 * @file: drm file
 *
 * On error, the contents of the buffer that were to be modified are undefined.
 */
int
i915_gem_pwrite_ioctl(struct drm_device *dev, void *data,
		      struct drm_file *file)
{
	struct drm_i915_private *i915 = to_i915(dev);
	struct drm_i915_gem_pwrite *args = data;
	struct drm_i915_gem_object *obj;
	int ret;

	/* PWRITE is disallowed for all platforms after TGL-LP.  This also
	 * covers all platforms with local memory.
	 */
	if (GRAPHICS_VER(i915) >= 12 && !IS_TIGERLAKE(i915))
		return -EOPNOTSUPP;

	if (args->size == 0)
		return 0;

	if (!access_ok(u64_to_user_ptr(args->data_ptr), args->size))
		return -EFAULT;

	obj = i915_gem_object_lookup(file, args->handle);
	if (!obj)
		return -ENOENT;

	/* Bounds check destination. */
	if (range_overflows_t(u64, args->offset, args->size, obj->base.size)) {
		ret = -EINVAL;
		goto err;
	}

	/* Writes not allowed into this read-only object */
	if (i915_gem_object_is_readonly(obj)) {
		ret = -EINVAL;
		goto err;
	}

	trace_i915_gem_object_pwrite(obj, args->offset, args->size);

	ret = -ENODEV;
	if (obj->ops->pwrite)
		ret = obj->ops->pwrite(obj, args);
	if (ret != -ENODEV)
		goto err;

	ret = i915_gem_object_wait(obj,
				   I915_WAIT_INTERRUPTIBLE |
				   I915_WAIT_ALL,
				   MAX_SCHEDULE_TIMEOUT);
	if (ret)
		goto err;

	ret = -EFAULT;
	/* We can only do the GTT pwrite on untiled buffers, as otherwise
	 * it would end up going through the fenced access, and we'll get
	 * different detiling behavior between reading and writing.
	 * pread/pwrite currently are reading and writing from the CPU
	 * perspective, requiring manual detiling by the client.
	 */
	if (!i915_gem_object_has_struct_page(obj) ||
	    i915_gem_cpu_write_needs_clflush(obj))
		/* Note that the gtt paths might fail with non-page-backed user
		 * pointers (e.g. gtt mappings when moving data between
		 * textures). Fallback to the shmem path in that case.
		 */
		ret = i915_gem_gtt_pwrite_fast(obj, args);

	if (ret == -EFAULT || ret == -ENOSPC) {
		if (i915_gem_object_has_struct_page(obj))
			ret = i915_gem_shmem_pwrite(obj, args);
	}

err:
	i915_gem_object_put(obj);
	return ret;
}

/**
 * i915_gem_sw_finish_ioctl - Called when user space has done writes to this buffer
 * @dev: drm device
 * @data: ioctl data blob
 * @file: drm file
 */
int
i915_gem_sw_finish_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file)
{
	struct drm_i915_gem_sw_finish *args = data;
	struct drm_i915_gem_object *obj;

	obj = i915_gem_object_lookup(file, args->handle);
	if (!obj)
		return -ENOENT;

	/*
	 * Proxy objects are barred from CPU access, so there is no
	 * need to ban sw_finish as it is a nop.
	 */

	/* Pinned buffers may be scanout, so flush the cache */
	i915_gem_object_flush_if_display(obj);
	i915_gem_object_put(obj);

	return 0;
}

<<<<<<< HEAD
void i915_gem_runtime_suspend(struct drm_i915_private *i915)
=======
static inline bool
__vma_matches(struct vm_area_struct *vma, struct file *filp,
	      unsigned long addr, unsigned long size)
{
	if (vma->vm_file != filp)
		return false;

	return vma->vm_start == addr &&
	       (vma->vm_end - vma->vm_start) == PAGE_ALIGN(size);
}

/**
 * i915_gem_mmap_ioctl - Maps the contents of an object, returning the address
 *			 it is mapped to.
 * @dev: drm device
 * @data: ioctl data blob
 * @file: drm file
 *
 * While the mapping holds a reference on the contents of the object, it doesn't
 * imply a ref on the object itself.
 *
 * IMPORTANT:
 *
 * DRM driver writers who look a this function as an example for how to do GEM
 * mmap support, please don't implement mmap support like here. The modern way
 * to implement DRM mmap support is with an mmap offset ioctl (like
 * i915_gem_mmap_gtt) and then using the mmap syscall on the DRM fd directly.
 * That way debug tooling like valgrind will understand what's going on, hiding
 * the mmap call in a driver private ioctl will break that. The i915 driver only
 * does cpu mmaps this way because we didn't know better.
 */
int
i915_gem_mmap_ioctl(struct drm_device *dev, void *data,
		    struct drm_file *file)
{
	struct drm_i915_gem_mmap *args = data;
	struct drm_i915_gem_object *obj;
	unsigned long addr;

	if (args->flags & ~(I915_MMAP_WC))
		return -EINVAL;

	if (args->flags & I915_MMAP_WC && !boot_cpu_has(X86_FEATURE_PAT))
		return -ENODEV;

	obj = i915_gem_object_lookup(file, args->handle);
	if (!obj)
		return -ENOENT;

	/* prime objects have no backing filp to GEM mmap
	 * pages from.
	 */
	if (!obj->base.filp) {
		addr = -ENXIO;
		goto err;
	}

	if (range_overflows(args->offset, args->size, (u64)obj->base.size)) {
		addr = -EINVAL;
		goto err;
	}

	addr = vm_mmap(obj->base.filp, 0, args->size,
		       PROT_READ | PROT_WRITE, MAP_SHARED,
		       args->offset);
	if (IS_ERR_VALUE(addr))
		goto err;

	if (args->flags & I915_MMAP_WC) {
		struct mm_struct *mm = current->mm;
		struct vm_area_struct *vma;

		if (down_write_killable(&mm->mmap_sem)) {
			addr = -EINTR;
			goto err;
		}
		vma = find_vma(mm, addr);
		if (vma && __vma_matches(vma, obj->base.filp, addr, args->size))
			vma->vm_page_prot =
				pgprot_writecombine(vm_get_page_prot(vma->vm_flags));
		else
			addr = -ENOMEM;
		up_write(&mm->mmap_sem);
		if (IS_ERR_VALUE(addr))
			goto err;

		/* This may race, but that's ok, it only gets set */
		WRITE_ONCE(obj->frontbuffer_ggtt_origin, ORIGIN_CPU);
	}
	i915_gem_object_put(obj);

	args->addr_ptr = (uint64_t) addr;
	return 0;

err:
	i915_gem_object_put(obj);
	return addr;
}

static unsigned int tile_row_pages(struct drm_i915_gem_object *obj)
{
	return i915_gem_object_get_tile_row_size(obj) >> PAGE_SHIFT;
}

/**
 * i915_gem_mmap_gtt_version - report the current feature set for GTT mmaps
 *
 * A history of the GTT mmap interface:
 *
 * 0 - Everything had to fit into the GTT. Both parties of a memcpy had to
 *     aligned and suitable for fencing, and still fit into the available
 *     mappable space left by the pinned display objects. A classic problem
 *     we called the page-fault-of-doom where we would ping-pong between
 *     two objects that could not fit inside the GTT and so the memcpy
 *     would page one object in at the expense of the other between every
 *     single byte.
 *
 * 1 - Objects can be any size, and have any compatible fencing (X Y, or none
 *     as set via i915_gem_set_tiling() [DRM_I915_GEM_SET_TILING]). If the
 *     object is too large for the available space (or simply too large
 *     for the mappable aperture!), a view is created instead and faulted
 *     into userspace. (This view is aligned and sized appropriately for
 *     fenced access.)
 *
 * 2 - Recognise WC as a separate cache domain so that we can flush the
 *     delayed writes via GTT before performing direct access via WC.
 *
 * Restrictions:
 *
 *  * snoopable objects cannot be accessed via the GTT. It can cause machine
 *    hangs on some architectures, corruption on others. An attempt to service
 *    a GTT page fault from a snoopable object will generate a SIGBUS.
 *
 *  * the object must be able to fit into RAM (physical memory, though no
 *    limited to the mappable aperture).
 *
 *
 * Caveats:
 *
 *  * a new GTT page fault will synchronize rendering from the GPU and flush
 *    all data to system memory. Subsequent access will not be synchronized.
 *
 *  * all mappings are revoked on runtime device suspend.
 *
 *  * there are only 8, 16 or 32 fence registers to share between all users
 *    (older machines require fence register for display and blitter access
 *    as well). Contention of the fence registers will cause the previous users
 *    to be unmapped and any new access will generate new page faults.
 *
 *  * running out of memory while servicing a fault may generate a SIGBUS,
 *    rather than the expected SIGSEGV.
 */
int i915_gem_mmap_gtt_version(void)
{
	return 2;
}

static inline struct i915_ggtt_view
compute_partial_view(struct drm_i915_gem_object *obj,
		     pgoff_t page_offset,
		     unsigned int chunk)
{
	struct i915_ggtt_view view;

	if (i915_gem_object_is_tiled(obj))
		chunk = roundup(chunk, tile_row_pages(obj));

	view.type = I915_GGTT_VIEW_PARTIAL;
	view.partial.offset = rounddown(page_offset, chunk);
	view.partial.size =
		min_t(unsigned int, chunk,
		      (obj->base.size >> PAGE_SHIFT) - view.partial.offset);

	/* If the partial covers the entire object, just create a normal VMA. */
	if (chunk >= obj->base.size >> PAGE_SHIFT)
		view.type = I915_GGTT_VIEW_NORMAL;

	return view;
}

/**
 * i915_gem_fault - fault a page into the GTT
 * @vmf: fault info
 *
 * The fault handler is set up by drm_gem_mmap() when a object is GTT mapped
 * from userspace.  The fault handler takes care of binding the object to
 * the GTT (if needed), allocating and programming a fence register (again,
 * only if needed based on whether the old reg is still valid or the object
 * is tiled) and inserting a new PTE into the faulting process.
 *
 * Note that the faulting process may involve evicting existing objects
 * from the GTT and/or fence registers to make room.  So performance may
 * suffer if the GTT working set is large or there are few fence registers
 * left.
 *
 * The current feature set supported by i915_gem_fault() and thus GTT mmaps
 * is exposed via I915_PARAM_MMAP_GTT_VERSION (see i915_gem_mmap_gtt_version).
 */
vm_fault_t i915_gem_fault(struct vm_fault *vmf)
{
#define MIN_CHUNK_PAGES (SZ_1M >> PAGE_SHIFT)
	struct vm_area_struct *area = vmf->vma;
	struct drm_i915_gem_object *obj = to_intel_bo(area->vm_private_data);
	struct drm_device *dev = obj->base.dev;
	struct drm_i915_private *dev_priv = to_i915(dev);
	struct i915_ggtt *ggtt = &dev_priv->ggtt;
	bool write = !!(vmf->flags & FAULT_FLAG_WRITE);
	struct i915_vma *vma;
	pgoff_t page_offset;
	int ret;

	/* Sanity check that we allow writing into this object */
	if (i915_gem_object_is_readonly(obj) && write)
		return VM_FAULT_SIGBUS;

	/* We don't use vmf->pgoff since that has the fake offset */
	page_offset = (vmf->address - area->vm_start) >> PAGE_SHIFT;

	trace_i915_gem_object_fault(obj, page_offset, true, write);

	/* Try to flush the object off the GPU first without holding the lock.
	 * Upon acquiring the lock, we will perform our sanity checks and then
	 * repeat the flush holding the lock in the normal manner to catch cases
	 * where we are gazumped.
	 */
	ret = i915_gem_object_wait(obj,
				   I915_WAIT_INTERRUPTIBLE,
				   MAX_SCHEDULE_TIMEOUT,
				   NULL);
	if (ret)
		goto err;

	ret = i915_gem_object_pin_pages(obj);
	if (ret)
		goto err;

	intel_runtime_pm_get(dev_priv);

	ret = i915_mutex_lock_interruptible(dev);
	if (ret)
		goto err_rpm;

	/* Access to snoopable pages through the GTT is incoherent. */
	if (obj->cache_level != I915_CACHE_NONE && !HAS_LLC(dev_priv)) {
		ret = -EFAULT;
		goto err_unlock;
	}


	/* Now pin it into the GTT as needed */
	vma = i915_gem_object_ggtt_pin(obj, NULL, 0, 0,
				       PIN_MAPPABLE |
				       PIN_NONBLOCK |
				       PIN_NONFAULT);
	if (IS_ERR(vma)) {
		/* Use a partial view if it is bigger than available space */
		struct i915_ggtt_view view =
			compute_partial_view(obj, page_offset, MIN_CHUNK_PAGES);
		unsigned int flags;

		flags = PIN_MAPPABLE;
		if (view.type == I915_GGTT_VIEW_NORMAL)
			flags |= PIN_NONBLOCK; /* avoid warnings for pinned */

		/*
		 * Userspace is now writing through an untracked VMA, abandon
		 * all hope that the hardware is able to track future writes.
		 */
		obj->frontbuffer_ggtt_origin = ORIGIN_CPU;

		vma = i915_gem_object_ggtt_pin(obj, &view, 0, 0, flags);
		if (IS_ERR(vma) && !view.type) {
			flags = PIN_MAPPABLE;
			view.type = I915_GGTT_VIEW_PARTIAL;
			vma = i915_gem_object_ggtt_pin(obj, &view, 0, 0, flags);
		}
	}
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto err_unlock;
	}

	ret = i915_gem_object_set_to_gtt_domain(obj, write);
	if (ret)
		goto err_unpin;

	ret = i915_vma_pin_fence(vma);
	if (ret)
		goto err_unpin;

	/* Finally, remap it using the new GTT offset */
	ret = remap_io_mapping(area,
			       area->vm_start + (vma->ggtt_view.partial.offset << PAGE_SHIFT),
			       (ggtt->gmadr.start + vma->node.start) >> PAGE_SHIFT,
			       min_t(u64, vma->size, area->vm_end - area->vm_start),
			       &ggtt->iomap);
	if (ret)
		goto err_fence;

	/* Mark as being mmapped into userspace for later revocation */
	assert_rpm_wakelock_held(dev_priv);
	if (!i915_vma_set_userfault(vma) && !obj->userfault_count++)
		list_add(&obj->userfault_link, &dev_priv->mm.userfault_list);
	GEM_BUG_ON(!obj->userfault_count);

	i915_vma_set_ggtt_write(vma);

err_fence:
	i915_vma_unpin_fence(vma);
err_unpin:
	__i915_vma_unpin(vma);
err_unlock:
	mutex_unlock(&dev->struct_mutex);
err_rpm:
	intel_runtime_pm_put(dev_priv);
	i915_gem_object_unpin_pages(obj);
err:
	switch (ret) {
	case -EIO:
		/*
		 * We eat errors when the gpu is terminally wedged to avoid
		 * userspace unduly crashing (gl has no provisions for mmaps to
		 * fail). But any other -EIO isn't ours (e.g. swap in failure)
		 * and so needs to be reported.
		 */
		if (!i915_terminally_wedged(&dev_priv->gpu_error))
			return VM_FAULT_SIGBUS;
		/* else: fall through */
	case -EAGAIN:
		/*
		 * EAGAIN means the gpu is hung and we'll wait for the error
		 * handler to reset everything when re-faulting in
		 * i915_mutex_lock_interruptible.
		 */
	case 0:
	case -ERESTARTSYS:
	case -EINTR:
	case -EBUSY:
		/*
		 * EBUSY is ok: this just means that another thread
		 * already did the job.
		 */
		return VM_FAULT_NOPAGE;
	case -ENOMEM:
		return VM_FAULT_OOM;
	case -ENOSPC:
	case -EFAULT:
		return VM_FAULT_SIGBUS;
	default:
		WARN_ONCE(ret, "unhandled error in i915_gem_fault: %i\n", ret);
		return VM_FAULT_SIGBUS;
	}
}

static void __i915_gem_object_release_mmap(struct drm_i915_gem_object *obj)
{
	struct i915_vma *vma;

	GEM_BUG_ON(!obj->userfault_count);

	obj->userfault_count = 0;
	list_del(&obj->userfault_link);
	drm_vma_node_unmap(&obj->base.vma_node,
			   obj->base.dev->anon_inode->i_mapping);

	for_each_ggtt_vma(vma, obj)
		i915_vma_unset_userfault(vma);
}

/**
 * i915_gem_release_mmap - remove physical page mappings
 * @obj: obj in question
 *
 * Preserve the reservation of the mmapping with the DRM core code, but
 * relinquish ownership of the pages back to the system.
 *
 * It is vital that we remove the page mapping if we have mapped a tiled
 * object through the GTT and then lose the fence register due to
 * resource pressure. Similarly if the object has been moved out of the
 * aperture, than pages mapped into userspace must be revoked. Removing the
 * mapping will then trigger a page fault on the next user access, allowing
 * fixup by i915_gem_fault().
 */
void
i915_gem_release_mmap(struct drm_i915_gem_object *obj)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);

	/* Serialisation between user GTT access and our code depends upon
	 * revoking the CPU's PTE whilst the mutex is held. The next user
	 * pagefault then has to wait until we release the mutex.
	 *
	 * Note that RPM complicates somewhat by adding an additional
	 * requirement that operations to the GGTT be made holding the RPM
	 * wakeref.
	 */
	lockdep_assert_held(&i915->drm.struct_mutex);
	intel_runtime_pm_get(i915);

	if (!obj->userfault_count)
		goto out;

	__i915_gem_object_release_mmap(obj);

	/* Ensure that the CPU's PTE are revoked and there are not outstanding
	 * memory transactions from userspace before we return. The TLB
	 * flushing implied above by changing the PTE above *should* be
	 * sufficient, an extra barrier here just provides us with a bit
	 * of paranoid documentation about our requirement to serialise
	 * memory writes before touching registers / GSM.
	 */
	wmb();

out:
	intel_runtime_pm_put(i915);
}

void i915_gem_runtime_suspend(struct drm_i915_private *dev_priv)
>>>>>>> master
{
	struct drm_i915_gem_object *obj, *on;
	int i;

	/*
	 * Only called during RPM suspend. All users of the userfault_list
	 * must be holding an RPM wakeref to ensure that this can not
	 * run concurrently with themselves (and use the struct_mutex for
	 * protection between themselves).
	 */

	list_for_each_entry_safe(obj, on,
				 &to_gt(i915)->ggtt->userfault_list, userfault_link)
		__i915_gem_object_release_mmap_gtt(obj);

	list_for_each_entry_safe(obj, on,
				 &i915->runtime_pm.lmem_userfault_list, userfault_link)
		i915_gem_object_runtime_pm_release_mmap_offset(obj);

	/*
	 * The fence will be lost when the device powers down. If any were
	 * in use by hardware (i.e. they are pinned), we should not be powering
	 * down! All other fences will be reacquired by the user upon waking.
	 */
	for (i = 0; i < to_gt(i915)->ggtt->num_fences; i++) {
		struct i915_fence_reg *reg = &to_gt(i915)->ggtt->fence_regs[i];

		/*
		 * Ideally we want to assert that the fence register is not
		 * live at this point (i.e. that no piece of code will be
		 * trying to write through fence + GTT, as that both violates
		 * our tracking of activity and associated locking/barriers,
		 * but also is illegal given that the hw is powered down).
		 *
		 * Previously we used reg->pin_count as a "liveness" indicator.
		 * That is not sufficient, and we need a more fine-grained
		 * tool if we want to have a sanity check here.
		 */

		if (!reg->vma)
			continue;

		GEM_BUG_ON(i915_vma_has_userfault(reg->vma));
		reg->dirty = true;
	}
}

static void discard_ggtt_vma(struct i915_vma *vma)
{
	struct drm_i915_gem_object *obj = vma->obj;

	spin_lock(&obj->vma.lock);
	if (!RB_EMPTY_NODE(&vma->obj_node)) {
		rb_erase(&vma->obj_node, &obj->vma.tree);
		RB_CLEAR_NODE(&vma->obj_node);
	}
	spin_unlock(&obj->vma.lock);
}

struct i915_vma *
i915_gem_object_ggtt_pin_ww(struct drm_i915_gem_object *obj,
			    struct i915_gem_ww_ctx *ww,
			    const struct i915_gtt_view *view,
			    u64 size, u64 alignment, u64 flags)
{
<<<<<<< HEAD
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	struct i915_ggtt *ggtt = to_gt(i915)->ggtt;
=======
	struct drm_i915_private *dev_priv = to_i915(obj->base.dev);
	struct i915_address_space *vm = &dev_priv->ggtt.vm;

	return i915_gem_object_pin(obj, vm, view, size, alignment,
				   flags | PIN_GLOBAL);
}

struct i915_vma *
i915_gem_object_pin(struct drm_i915_gem_object *obj,
		    struct i915_address_space *vm,
		    const struct i915_ggtt_view *view,
		    u64 size,
		    u64 alignment,
		    u64 flags)
{
	struct drm_i915_private *dev_priv = to_i915(obj->base.dev);
>>>>>>> master
	struct i915_vma *vma;
	int ret;

	GEM_WARN_ON(!ww);

	if (flags & PIN_MAPPABLE &&
	    (!view || view->type == I915_GTT_VIEW_NORMAL)) {
		/*
		 * If the required space is larger than the available
		 * aperture, we will not able to find a slot for the
		 * object and unbinding the object now will be in
		 * vain. Worse, doing so may cause us to ping-pong
		 * the object in and out of the Global GTT and
		 * waste a lot of cycles under the mutex.
		 */
		if (obj->base.size > ggtt->mappable_end)
			return ERR_PTR(-E2BIG);

		/*
		 * If NONBLOCK is set the caller is optimistically
		 * trying to cache the full object within the mappable
		 * aperture, and *must* have a fallback in place for
		 * situations where we cannot bind the object. We
		 * can be a little more lax here and use the fallback
		 * more often to avoid costly migrations of ourselves
		 * and other objects within the aperture.
		 *
		 * Half-the-aperture is used as a simple heuristic.
		 * More interesting would to do search for a free
		 * block prior to making the commitment to unbind.
		 * That caters for the self-harm case, and with a
		 * little more heuristics (e.g. NOFAULT, NOEVICT)
		 * we could try to minimise harm to others.
		 */
		if (flags & PIN_NONBLOCK &&
		    obj->base.size > ggtt->mappable_end / 2)
			return ERR_PTR(-ENOSPC);
	}

new_vma:
	vma = i915_vma_instance(obj, &ggtt->vm, view);
	if (IS_ERR(vma))
		return vma;

	if (i915_vma_misplaced(vma, size, alignment, flags)) {
		if (flags & PIN_NONBLOCK) {
			if (i915_vma_is_pinned(vma) || i915_vma_is_active(vma))
				return ERR_PTR(-ENOSPC);

			/*
			 * If this misplaced vma is too big (i.e, at-least
			 * half the size of aperture) or hasn't been pinned
			 * mappable before, we ignore the misplacement when
			 * PIN_NONBLOCK is set in order to avoid the ping-pong
			 * issue described above. In other words, we try to
			 * avoid the costly operation of unbinding this vma
			 * from the GGTT and rebinding it back because there
			 * may not be enough space for this vma in the aperture.
			 */
			if (flags & PIN_MAPPABLE &&
			    (vma->fence_size > ggtt->mappable_end / 2 ||
			    !i915_vma_is_map_and_fenceable(vma)))
				return ERR_PTR(-ENOSPC);
		}

		if (i915_vma_is_pinned(vma) || i915_vma_is_active(vma)) {
			discard_ggtt_vma(vma);
			goto new_vma;
		}

		ret = i915_vma_unbind(vma);
		if (ret)
			return ERR_PTR(ret);
	}

<<<<<<< HEAD
	ret = i915_vma_pin_ww(vma, ww, size, alignment, flags | PIN_GLOBAL);

=======
	ret = i915_vma_pin(vma, size, alignment, flags);
>>>>>>> master
	if (ret)
		return ERR_PTR(ret);

	if (vma->fence && !i915_gem_object_is_tiled(obj)) {
		mutex_lock(&ggtt->vm.mutex);
		i915_vma_revoke_fence(vma);
		mutex_unlock(&ggtt->vm.mutex);
	}

	ret = i915_vma_wait_for_bind(vma);
	if (ret) {
		i915_vma_unpin(vma);
		return ERR_PTR(ret);
	}

	return vma;
}

struct i915_vma * __must_check
i915_gem_object_ggtt_pin(struct drm_i915_gem_object *obj,
			 const struct i915_gtt_view *view,
			 u64 size, u64 alignment, u64 flags)
{
	struct i915_gem_ww_ctx ww;
	struct i915_vma *ret;
	int err;

	for_i915_gem_ww(&ww, err, true) {
		err = i915_gem_object_lock(obj, &ww);
		if (err)
			continue;

		ret = i915_gem_object_ggtt_pin_ww(obj, &ww, view, size,
						  alignment, flags);
		if (IS_ERR(ret))
			err = PTR_ERR(ret);
	}

	return err ? ERR_PTR(err) : ret;
}

int
i915_gem_madvise_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_i915_private *i915 = to_i915(dev);
	struct drm_i915_gem_madvise *args = data;
	struct drm_i915_gem_object *obj;
	int err;

	switch (args->madv) {
	case I915_MADV_DONTNEED:
	case I915_MADV_WILLNEED:
	    break;
	default:
	    return -EINVAL;
	}

	obj = i915_gem_object_lookup(file_priv, args->handle);
	if (!obj)
		return -ENOENT;

	err = i915_gem_object_lock_interruptible(obj, NULL);
	if (err)
		goto out;

	if (i915_gem_object_has_pages(obj) &&
	    i915_gem_object_is_tiled(obj) &&
	    i915->gem_quirks & GEM_QUIRK_PIN_SWIZZLED_PAGES) {
		if (obj->mm.madv == I915_MADV_WILLNEED) {
			GEM_BUG_ON(!i915_gem_object_has_tiling_quirk(obj));
			i915_gem_object_clear_tiling_quirk(obj);
			i915_gem_object_make_shrinkable(obj);
		}
		if (args->madv == I915_MADV_WILLNEED) {
			GEM_BUG_ON(i915_gem_object_has_tiling_quirk(obj));
			i915_gem_object_make_unshrinkable(obj);
			i915_gem_object_set_tiling_quirk(obj);
		}
	}

	if (obj->mm.madv != __I915_MADV_PURGED) {
		obj->mm.madv = args->madv;
		if (obj->ops->adjust_lru)
			obj->ops->adjust_lru(obj);
	}

	if (i915_gem_object_has_pages(obj) ||
	    i915_gem_object_has_self_managed_shrink_list(obj)) {
		unsigned long flags;

		spin_lock_irqsave(&i915->mm.obj_lock, flags);
		if (!list_empty(&obj->mm.link)) {
			struct list_head *list;

			if (obj->mm.madv != I915_MADV_WILLNEED)
				list = &i915->mm.purge_list;
			else
				list = &i915->mm.shrink_list;
			list_move_tail(&obj->mm.link, list);

		}
		spin_unlock_irqrestore(&i915->mm.obj_lock, flags);
	}

	/* if the object is no longer attached, discard its backing storage */
	if (obj->mm.madv == I915_MADV_DONTNEED &&
	    !i915_gem_object_has_pages(obj))
		i915_gem_object_truncate(obj);

	args->retained = obj->mm.madv != __I915_MADV_PURGED;

	i915_gem_object_unlock(obj);
out:
	i915_gem_object_put(obj);
	return err;
}

/*
 * A single pass should suffice to release all the freed objects (along most
 * call paths), but be a little more paranoid in that freeing the objects does
 * take a little amount of time, during which the rcu callbacks could have added
 * new objects into the freed list, and armed the work again.
 */
void i915_gem_drain_freed_objects(struct drm_i915_private *i915)
{
	while (atomic_read(&i915->mm.free_count)) {
		flush_work(&i915->mm.free_work);
		drain_workqueue(i915->bdev.wq);
		rcu_barrier();
	}
}

/*
 * Similar to objects above (see i915_gem_drain_freed-objects), in general we
 * have workers that are armed by RCU and then rearm themselves in their
 * callbacks. To be paranoid, we need to drain the workqueue a second time after
 * waiting for the RCU grace period so that we catch work queued via RCU from
 * the first pass. As neither drain_workqueue() nor flush_workqueue() report a
 * result, we make an assumption that we only don't require more than 3 passes
 * to catch all _recursive_ RCU delayed work.
 */
void i915_gem_drain_workqueue(struct drm_i915_private *i915)
{
	int i;

	for (i = 0; i < 3; i++) {
		flush_workqueue(i915->wq);
		rcu_barrier();
		i915_gem_drain_freed_objects(i915);
	}

	drain_workqueue(i915->wq);
}

int i915_gem_init(struct drm_i915_private *dev_priv)
{
	struct intel_gt *gt;
	unsigned int i;
	int ret;

	/*
	 * In the proccess of replacing cache_level with pat_index a tricky
	 * dependency is created on the definition of the enum i915_cache_level.
	 * in case this enum is changed, PTE encode would be broken.
	 * Add a WARNING here. And remove when we completely quit using this
	 * enum
	 */
	BUILD_BUG_ON(I915_CACHE_NONE != 0 ||
		     I915_CACHE_LLC != 1 ||
		     I915_CACHE_L3_LLC != 2 ||
		     I915_CACHE_WT != 3 ||
		     I915_MAX_CACHE_LEVEL != 4);

	/* We need to fallback to 4K pages if host doesn't support huge gtt. */
	if (intel_vgpu_active(dev_priv) && !intel_vgpu_has_huge_gtt(dev_priv))
		RUNTIME_INFO(dev_priv)->page_sizes = I915_GTT_PAGE_SIZE_4K;

	ret = i915_gem_init_userptr(dev_priv);
	if (ret)
		return ret;

	for_each_gt(gt, dev_priv, i) {
		intel_uc_fetch_firmwares(&gt->uc);
		intel_wopcm_init(&gt->wopcm);
		if (GRAPHICS_VER(dev_priv) >= 8)
			setup_private_pat(gt);
	}

	ret = i915_init_ggtt(dev_priv);
	if (ret) {
		GEM_BUG_ON(ret == -EIO);
		goto err_unlock;
	}

	/*
	 * Despite its name intel_clock_gating_init applies both display
	 * clock gating workarounds; GT mmio workarounds and the occasional
	 * GT power context workaround. Worse, sometimes it includes a context
	 * register workaround which we need to apply before we record the
	 * default HW state for all contexts.
	 *
	 * FIXME: break up the workarounds and apply them at the right time!
	 */
	intel_clock_gating_init(dev_priv);

	for_each_gt(gt, dev_priv, i) {
		ret = intel_gt_init(gt);
		if (ret)
			goto err_unlock;
	}

	/*
	 * Register engines early to ensure the engine list is in its final
	 * rb-tree form, lowering the amount of code that has to deal with
	 * the intermediate llist state.
	 */
	intel_engines_driver_register(dev_priv);

	return 0;

	/*
	 * Unwinding is complicated by that we want to handle -EIO to mean
	 * disable GPU submission but keep KMS alive. We want to mark the
	 * HW as irrevisibly wedged, but keep enough state around that the
	 * driver doesn't explode during runtime.
	 */
err_unlock:
	i915_gem_drain_workqueue(dev_priv);

	if (ret != -EIO) {
		for_each_gt(gt, dev_priv, i) {
			intel_gt_driver_remove(gt);
			intel_gt_driver_release(gt);
			intel_uc_cleanup_firmwares(&gt->uc);
		}
	}

	if (ret == -EIO) {
		mutex_lock(&dev_priv->drm.struct_mutex);

		/*
		 * Allow engines or uC initialisation to fail by marking the GPU
		 * as wedged. But we only want to do this when the GPU is angry,
		 * for all other failure, such as an allocation failure, bail.
		 */
		for_each_gt(gt, dev_priv, i) {
			if (!intel_gt_is_wedged(gt)) {
				i915_probe_error(dev_priv,
						 "Failed to initialize GPU, declaring it wedged!\n");
				intel_gt_set_wedged(gt);
			}
		}

		/* Minimal basic recovery for KMS */
		ret = i915_ggtt_enable_hw(dev_priv);
<<<<<<< HEAD
		i915_ggtt_resume(to_gt(dev_priv)->ggtt);
		intel_clock_gating_init(dev_priv);
=======
		i915_gem_restore_gtt_mappings(dev_priv);
		i915_gem_restore_fences(dev_priv);
		intel_init_clock_gating(dev_priv);

		mutex_unlock(&dev_priv->drm.struct_mutex);
>>>>>>> master
	}

	i915_gem_drain_freed_objects(dev_priv);

	return ret;
}

void i915_gem_driver_register(struct drm_i915_private *i915)
{
	i915_gem_driver_register__shrinker(i915);
}

void i915_gem_driver_unregister(struct drm_i915_private *i915)
{
	i915_gem_driver_unregister__shrinker(i915);
}

void i915_gem_driver_remove(struct drm_i915_private *dev_priv)
{
	struct intel_gt *gt;
	unsigned int i;

	i915_gem_suspend_late(dev_priv);
<<<<<<< HEAD
	for_each_gt(gt, dev_priv, i)
		intel_gt_driver_remove(gt);
	dev_priv->uabi_engines = RB_ROOT;

	/* Flush any outstanding unpin_work. */
	i915_gem_drain_workqueue(dev_priv);
=======
	intel_disable_gt_powersave(dev_priv);

	/* Flush any outstanding unpin_work. */
	i915_gem_drain_workqueue(dev_priv);

	mutex_lock(&dev_priv->drm.struct_mutex);
	intel_uc_fini_hw(dev_priv);
	intel_uc_fini(dev_priv);
	i915_gem_cleanup_engines(dev_priv);
	i915_gem_contexts_fini(dev_priv);
	mutex_unlock(&dev_priv->drm.struct_mutex);

	intel_cleanup_gt_powersave(dev_priv);

	intel_uc_fini_misc(dev_priv);
	i915_gem_cleanup_userptr(dev_priv);

	i915_gem_drain_freed_objects(dev_priv);

	WARN_ON(!list_empty(&dev_priv->contexts.list));
>>>>>>> master
}

void i915_gem_driver_release(struct drm_i915_private *dev_priv)
{
	struct intel_gt *gt;
	unsigned int i;

	for_each_gt(gt, dev_priv, i) {
		intel_gt_driver_release(gt);
		intel_uc_cleanup_firmwares(&gt->uc);
	}

	/* Flush any outstanding work, including i915_gem_context.release_work. */
	i915_gem_drain_workqueue(dev_priv);

	drm_WARN_ON(&dev_priv->drm, !list_empty(&dev_priv->gem.contexts.list));
}

static void i915_gem_init__mm(struct drm_i915_private *i915)
{
	spin_lock_init(&i915->mm.obj_lock);

	init_llist_head(&i915->mm.free_list);

	INIT_LIST_HEAD(&i915->mm.purge_list);
	INIT_LIST_HEAD(&i915->mm.shrink_list);

	i915_gem_init__objects(i915);
}

void i915_gem_init_early(struct drm_i915_private *dev_priv)
{
	i915_gem_init__mm(dev_priv);
	i915_gem_init__contexts(dev_priv);

	spin_lock_init(&dev_priv->display.fb_tracking.lock);
}

void i915_gem_cleanup_early(struct drm_i915_private *dev_priv)
{
	i915_gem_drain_workqueue(dev_priv);
	GEM_BUG_ON(!llist_empty(&dev_priv->mm.free_list));
	GEM_BUG_ON(atomic_read(&dev_priv->mm.free_count));
	drm_WARN_ON(&dev_priv->drm, dev_priv->mm.shrink_count);
}

int i915_gem_open(struct drm_i915_private *i915, struct drm_file *file)
{
	struct drm_i915_file_private *file_priv;
	struct i915_drm_client *client;
	int ret = -ENOMEM;

	drm_dbg(&i915->drm, "\n");

	file_priv = kzalloc(sizeof(*file_priv), GFP_KERNEL);
	if (!file_priv)
		goto err_alloc;

	client = i915_drm_client_alloc();
	if (!client)
		goto err_client;

	file->driver_priv = file_priv;
	file_priv->i915 = i915;
	file_priv->file = file;
	file_priv->client = client;

	file_priv->bsd_engine = -1;
	file_priv->hang_timestamp = jiffies;

	ret = i915_gem_context_open(i915, file);
	if (ret)
		goto err_context;

	return 0;

err_context:
	i915_drm_client_put(client);
err_client:
	kfree(file_priv);
err_alloc:
	return ret;
}

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "selftests/mock_gem_device.c"
#include "selftests/i915_gem.c"
#endif
