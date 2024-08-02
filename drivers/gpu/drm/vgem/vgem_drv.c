/*
 * Copyright 2011 Red Hat, Inc.
 * Copyright © 2014 The Chromium OS Authors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software")
 * to deal in the software without restriction, including without limitation
 * on the rights to use, copy, modify, merge, publish, distribute, sub
 * license, and/or sell copies of the Software, and to permit persons to whom
 * them Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTIBILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *	Adam Jackson <ajax@redhat.com>
 *	Ben Widawsky <ben@bwidawsk.net>
 */

/*
 * This is vgem, a (non-hardware-backed) GEM service.  This is used by Mesa's
 * software renderer and the X server for efficient buffer sharing.
 */

#include <linux/dma-buf.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/shmem_fs.h>
#include <linux/vmalloc.h>

#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_managed.h>
#include <drm/drm_prime.h>

#include "vgem_drv.h"

#define DRIVER_NAME	"vgem"
#define DRIVER_DESC	"Virtual GEM provider"
#define DRIVER_DATE	"20120112"
#define DRIVER_MAJOR	1
#define DRIVER_MINOR	0

static struct vgem_device {
	struct drm_device drm;
	struct platform_device *platform;
} *vgem_device;

static int vgem_open(struct drm_device *dev, struct drm_file *file)
{
	struct vgem_file *vfile;
	int ret;

	vfile = kzalloc(sizeof(*vfile), GFP_KERNEL);
	if (!vfile)
		return -ENOMEM;

	file->driver_priv = vfile;

	ret = vgem_fence_open(vfile);
	if (ret) {
		kfree(vfile);
		return ret;
	}

	return 0;
}

static void vgem_postclose(struct drm_device *dev, struct drm_file *file)
{
	struct vgem_file *vfile = file->driver_priv;

	vgem_fence_close(vfile);
	kfree(vfile);
}

static struct drm_ioctl_desc vgem_ioctls[] = {
	DRM_IOCTL_DEF_DRV(VGEM_FENCE_ATTACH, vgem_fence_attach_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(VGEM_FENCE_SIGNAL, vgem_fence_signal_ioctl, DRM_RENDER_ALLOW),
};

DEFINE_DRM_GEM_FOPS(vgem_driver_fops);

static struct drm_gem_object *vgem_gem_create_object(struct drm_device *dev, size_t size)
{
	struct drm_gem_shmem_object *obj;

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return ERR_PTR(-ENOMEM);

<<<<<<< HEAD
	/*
	 * vgem doesn't have any begin/end cpu access ioctls, therefore must use
	 * coherent memory or dma-buf sharing just wont work.
=======
	ret = drm_gem_object_init(dev, &obj->base, roundup(size, PAGE_SIZE));
	if (ret) {
		kfree(obj);
		return ERR_PTR(ret);
	}

	mutex_init(&obj->pages_lock);

	return obj;
}

static void __vgem_gem_destroy(struct drm_vgem_gem_object *obj)
{
	drm_gem_object_release(&obj->base);
	kfree(obj);
}

static struct drm_gem_object *vgem_gem_create(struct drm_device *dev,
					      struct drm_file *file,
					      unsigned int *handle,
					      unsigned long size)
{
	struct drm_vgem_gem_object *obj;
	int ret;

	obj = __vgem_gem_create(dev, size);
	if (IS_ERR(obj))
		return ERR_CAST(obj);

	ret = drm_gem_handle_create(file, &obj->base, handle);
	drm_gem_object_put_unlocked(&obj->base);
	if (ret)
		return ERR_PTR(ret);

	return &obj->base;
}

static int vgem_gem_dumb_create(struct drm_file *file, struct drm_device *dev,
				struct drm_mode_create_dumb *args)
{
	struct drm_gem_object *gem_object;
	u64 pitch, size;

	pitch = args->width * DIV_ROUND_UP(args->bpp, 8);
	size = args->height * pitch;
	if (size == 0)
		return -EINVAL;

	gem_object = vgem_gem_create(dev, file, &args->handle, size);
	if (IS_ERR(gem_object))
		return PTR_ERR(gem_object);

	args->size = gem_object->size;
	args->pitch = pitch;

	DRM_DEBUG_DRIVER("Created object of size %lld\n", size);

	return 0;
}

static int vgem_gem_dumb_map(struct drm_file *file, struct drm_device *dev,
			     uint32_t handle, uint64_t *offset)
{
	struct drm_gem_object *obj;
	int ret;

	obj = drm_gem_object_lookup(file, handle);
	if (!obj)
		return -ENOENT;

	if (!obj->filp) {
		ret = -EINVAL;
		goto unref;
	}

	ret = drm_gem_create_mmap_offset(obj);
	if (ret)
		goto unref;

	*offset = drm_vma_node_offset_addr(&obj->vma_node);
unref:
	drm_gem_object_put_unlocked(obj);

	return ret;
}

static struct drm_ioctl_desc vgem_ioctls[] = {
	DRM_IOCTL_DEF_DRV(VGEM_FENCE_ATTACH, vgem_fence_attach_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(VGEM_FENCE_SIGNAL, vgem_fence_signal_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
};

static int vgem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long flags = vma->vm_flags;
	int ret;

	ret = drm_gem_mmap(filp, vma);
	if (ret)
		return ret;

	/* Keep the WC mmaping set by drm_gem_mmap() but our pages
	 * are ordinary and not special.
>>>>>>> master
	 */
	obj->map_wc = true;

	return &obj->base;
}

static const struct drm_driver vgem_driver = {
	.driver_features		= DRIVER_GEM | DRIVER_RENDER,
	.open				= vgem_open,
	.postclose			= vgem_postclose,
	.ioctls				= vgem_ioctls,
	.num_ioctls 			= ARRAY_SIZE(vgem_ioctls),
	.fops				= &vgem_driver_fops,

	DRM_GEM_SHMEM_DRIVER_OPS,
	.gem_create_object		= vgem_gem_create_object,

	.name	= DRIVER_NAME,
	.desc	= DRIVER_DESC,
	.date	= DRIVER_DATE,
	.major	= DRIVER_MAJOR,
	.minor	= DRIVER_MINOR,
};

static int __init vgem_init(void)
{
	int ret;
	struct platform_device *pdev;

	pdev = platform_device_register_simple("vgem", -1, NULL, 0);
	if (IS_ERR(pdev))
		return PTR_ERR(pdev);

<<<<<<< HEAD
	if (!devres_open_group(&pdev->dev, NULL, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto out_unregister;
=======
	vgem_device->platform =
		platform_device_register_simple("vgem", -1, NULL, 0);
	if (IS_ERR(vgem_device->platform)) {
		ret = PTR_ERR(vgem_device->platform);
		goto out_free;
>>>>>>> master
	}

	dma_coerce_mask_and_coherent(&pdev->dev,
				     DMA_BIT_MASK(64));
	ret = drm_dev_init(&vgem_device->drm, &vgem_driver,
			   &vgem_device->platform->dev);
	if (ret)
		goto out_unregister;

	vgem_device = devm_drm_dev_alloc(&pdev->dev, &vgem_driver,
					 struct vgem_device, drm);
	if (IS_ERR(vgem_device)) {
		ret = PTR_ERR(vgem_device);
		goto out_devres;
	}
	vgem_device->platform = pdev;

	/* Final step: expose the device/driver to userspace */
	ret = drm_dev_register(&vgem_device->drm, 0);
	if (ret)
<<<<<<< HEAD
		goto out_devres;

	return 0;

out_devres:
	devres_release_group(&pdev->dev, NULL);
out_unregister:
	platform_device_unregister(pdev);
=======
		goto out_fini;

	return 0;

out_fini:
	drm_dev_fini(&vgem_device->drm);
out_unregister:
	platform_device_unregister(vgem_device->platform);
out_free:
	kfree(vgem_device);
>>>>>>> master
	return ret;
}

static void __exit vgem_exit(void)
{
	struct platform_device *pdev = vgem_device->platform;

	drm_dev_unregister(&vgem_device->drm);
	devres_release_group(&pdev->dev, NULL);
	platform_device_unregister(pdev);
}

module_init(vgem_init);
module_exit(vgem_exit);

MODULE_AUTHOR("Red Hat, Inc.");
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");
