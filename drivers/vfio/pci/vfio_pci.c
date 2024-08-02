// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 *
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * Derived from original vfio:
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "vfio_pci_priv.h"

#define DRIVER_AUTHOR   "Alex Williamson <alex.williamson@redhat.com>"
#define DRIVER_DESC     "VFIO PCI - User Level meta-driver"

static char ids[1024] __initdata;
module_param_string(ids, ids, sizeof(ids), 0);
MODULE_PARM_DESC(ids, "Initial PCI IDs to add to the vfio driver, format is \"vendor:device[:subvendor[:subdevice[:class[:class_mask]]]]\" and multiple comma separated entries can be specified");

static bool nointxmask;
module_param_named(nointxmask, nointxmask, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(nointxmask,
		  "Disable support for PCI 2.3 style INTx masking.  If this resolves problems for specific devices, report lspci -vvvxxx to linux-pci@vger.kernel.org so the device can be fixed automatically via the broken_intx_masking flag.");

#ifdef CONFIG_VFIO_PCI_VGA
static bool disable_vga;
module_param(disable_vga, bool, S_IRUGO);
MODULE_PARM_DESC(disable_vga, "Disable VGA resource access through vfio-pci");
#endif

static bool disable_idle_d3;
module_param(disable_idle_d3, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(disable_idle_d3,
		 "Disable using the PCI D3 low power state for idle, unused devices");

static bool enable_sriov;
#ifdef CONFIG_PCI_IOV
module_param(enable_sriov, bool, 0644);
MODULE_PARM_DESC(enable_sriov, "Enable support for SR-IOV configuration.  Enabling SR-IOV on a PF typically requires support of the userspace PF driver, enabling VFs without such support may result in non-functional VFs or PF.");
#endif

static bool disable_denylist;
module_param(disable_denylist, bool, 0444);
MODULE_PARM_DESC(disable_denylist, "Disable use of device denylist. Disabling the denylist allows binding to devices with known errata that may lead to exploitable stability or security issues when accessed by untrusted users.");

static bool vfio_pci_dev_in_denylist(struct pci_dev *pdev)
{
	switch (pdev->vendor) {
	case PCI_VENDOR_ID_INTEL:
		switch (pdev->device) {
		case PCI_DEVICE_ID_INTEL_QAT_C3XXX:
		case PCI_DEVICE_ID_INTEL_QAT_C3XXX_VF:
		case PCI_DEVICE_ID_INTEL_QAT_C62X:
		case PCI_DEVICE_ID_INTEL_QAT_C62X_VF:
		case PCI_DEVICE_ID_INTEL_QAT_DH895XCC:
		case PCI_DEVICE_ID_INTEL_QAT_DH895XCC_VF:
		case PCI_DEVICE_ID_INTEL_DSA_SPR0:
		case PCI_DEVICE_ID_INTEL_IAX_SPR0:
			return true;
		default:
			return false;
		}
	}

	return false;
}

static bool vfio_pci_is_denylisted(struct pci_dev *pdev)
{
	if (!vfio_pci_dev_in_denylist(pdev))
		return false;

	if (disable_denylist) {
		pci_warn(pdev,
			 "device denylist disabled - allowing device %04x:%04x.\n",
			 pdev->vendor, pdev->device);
		return false;
	}

	pci_warn(pdev, "%04x:%04x exists in vfio-pci device denylist, driver probing disallowed.\n",
		 pdev->vendor, pdev->device);

	return true;
}

static int vfio_pci_open_device(struct vfio_device *core_vdev)
{
	struct vfio_pci_core_device *vdev =
		container_of(core_vdev, struct vfio_pci_core_device, vdev);
	struct pci_dev *pdev = vdev->pdev;
	int ret;

	ret = vfio_pci_core_enable(vdev);
	if (ret)
		return ret;

	if (vfio_pci_is_vga(pdev) &&
	    pdev->vendor == PCI_VENDOR_ID_INTEL &&
	    IS_ENABLED(CONFIG_VFIO_PCI_IGD)) {
		ret = vfio_pci_igd_init(vdev);
		if (ret && ret != -ENODEV) {
			pci_warn(pdev, "Failed to setup Intel IGD regions\n");
			vfio_pci_core_disable(vdev);
			return ret;
		}
	}

	vfio_pci_core_finish_enable(vdev);

	return 0;
}

<<<<<<< HEAD
=======
static void vfio_pci_disable(struct vfio_pci_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	struct vfio_pci_dummy_resource *dummy_res, *tmp;
	struct vfio_pci_ioeventfd *ioeventfd, *ioeventfd_tmp;
	int i, bar;

	/* Stop the device from further DMA */
	pci_clear_master(pdev);

	vfio_pci_set_irqs_ioctl(vdev, VFIO_IRQ_SET_DATA_NONE |
				VFIO_IRQ_SET_ACTION_TRIGGER,
				vdev->irq_type, 0, 0, NULL);

	/* Device closed, don't need mutex here */
	list_for_each_entry_safe(ioeventfd, ioeventfd_tmp,
				 &vdev->ioeventfds_list, next) {
		vfio_virqfd_disable(&ioeventfd->virqfd);
		list_del(&ioeventfd->next);
		kfree(ioeventfd);
	}
	vdev->ioeventfds_nr = 0;

	vdev->virq_disabled = false;

	for (i = 0; i < vdev->num_regions; i++)
		vdev->region[i].ops->release(vdev, &vdev->region[i]);

	vdev->num_regions = 0;
	kfree(vdev->region);
	vdev->region = NULL; /* don't krealloc a freed pointer */

	vfio_config_free(vdev);

	for (bar = PCI_STD_RESOURCES; bar <= PCI_STD_RESOURCE_END; bar++) {
		if (!vdev->barmap[bar])
			continue;
		pci_iounmap(pdev, vdev->barmap[bar]);
		pci_release_selected_regions(pdev, 1 << bar);
		vdev->barmap[bar] = NULL;
	}

	list_for_each_entry_safe(dummy_res, tmp,
				 &vdev->dummy_resources_list, res_next) {
		list_del(&dummy_res->res_next);
		release_resource(&dummy_res->resource);
		kfree(dummy_res);
	}

	vdev->needs_reset = true;

	/*
	 * If we have saved state, restore it.  If we can reset the device,
	 * even better.  Resetting with current state seems better than
	 * nothing, but saving and restoring current state without reset
	 * is just busy work.
	 */
	if (pci_load_and_free_saved_state(pdev, &vdev->pci_saved_state)) {
		pr_info("%s: Couldn't reload %s saved state\n",
			__func__, dev_name(&pdev->dev));

		if (!vdev->reset_works)
			goto out;

		pci_save_state(pdev);
	}

	/*
	 * Disable INTx and MSI, presumably to avoid spurious interrupts
	 * during reset.  Stolen from pci_reset_function()
	 */
	pci_write_config_word(pdev, PCI_COMMAND, PCI_COMMAND_INTX_DISABLE);

	/*
	 * Try to get the locks ourselves to prevent a deadlock. The
	 * success of this is dependent on being able to lock the device,
	 * which is not always possible.
	 * We can not use the "try" reset interface here, which will
	 * overwrite the previously restored configuration information.
	 */
	if (vdev->reset_works && pci_cfg_access_trylock(pdev)) {
		if (device_trylock(&pdev->dev)) {
			if (!__pci_reset_function_locked(pdev))
				vdev->needs_reset = false;
			device_unlock(&pdev->dev);
		}
		pci_cfg_access_unlock(pdev);
	}

	pci_restore_state(pdev);
out:
	pci_disable_device(pdev);

	vfio_pci_try_bus_reset(vdev);

	if (!disable_idle_d3)
		pci_set_power_state(pdev, PCI_D3hot);
}

static void vfio_pci_release(void *device_data)
{
	struct vfio_pci_device *vdev = device_data;

	mutex_lock(&driver_lock);

	if (!(--vdev->refcnt)) {
		vfio_spapr_pci_eeh_release(vdev->pdev);
		vfio_pci_disable(vdev);
	}

	mutex_unlock(&driver_lock);

	module_put(THIS_MODULE);
}

static int vfio_pci_open(void *device_data)
{
	struct vfio_pci_device *vdev = device_data;
	int ret = 0;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	mutex_lock(&driver_lock);

	if (!vdev->refcnt) {
		ret = vfio_pci_enable(vdev);
		if (ret)
			goto error;

		vfio_spapr_pci_eeh_open(vdev->pdev);
	}
	vdev->refcnt++;
error:
	mutex_unlock(&driver_lock);
	if (ret)
		module_put(THIS_MODULE);
	return ret;
}

static int vfio_pci_get_irq_count(struct vfio_pci_device *vdev, int irq_type)
{
	if (irq_type == VFIO_PCI_INTX_IRQ_INDEX) {
		u8 pin;
		pci_read_config_byte(vdev->pdev, PCI_INTERRUPT_PIN, &pin);
		if (IS_ENABLED(CONFIG_VFIO_PCI_INTX) && !vdev->nointx && pin)
			return 1;

	} else if (irq_type == VFIO_PCI_MSI_IRQ_INDEX) {
		u8 pos;
		u16 flags;

		pos = vdev->pdev->msi_cap;
		if (pos) {
			pci_read_config_word(vdev->pdev,
					     pos + PCI_MSI_FLAGS, &flags);
			return 1 << ((flags & PCI_MSI_FLAGS_QMASK) >> 1);
		}
	} else if (irq_type == VFIO_PCI_MSIX_IRQ_INDEX) {
		u8 pos;
		u16 flags;

		pos = vdev->pdev->msix_cap;
		if (pos) {
			pci_read_config_word(vdev->pdev,
					     pos + PCI_MSIX_FLAGS, &flags);

			return (flags & PCI_MSIX_FLAGS_QSIZE) + 1;
		}
	} else if (irq_type == VFIO_PCI_ERR_IRQ_INDEX) {
		if (pci_is_pcie(vdev->pdev))
			return 1;
	} else if (irq_type == VFIO_PCI_REQ_IRQ_INDEX) {
		return 1;
	}

	return 0;
}

static int vfio_pci_count_devs(struct pci_dev *pdev, void *data)
{
	(*(int *)data)++;
	return 0;
}

struct vfio_pci_fill_info {
	int max;
	int cur;
	struct vfio_pci_dependent_device *devices;
};

static int vfio_pci_fill_devs(struct pci_dev *pdev, void *data)
{
	struct vfio_pci_fill_info *fill = data;
	struct iommu_group *iommu_group;

	if (fill->cur == fill->max)
		return -EAGAIN; /* Something changed, try again */

	iommu_group = iommu_group_get(&pdev->dev);
	if (!iommu_group)
		return -EPERM; /* Cannot reset non-isolated devices */

	fill->devices[fill->cur].group_id = iommu_group_id(iommu_group);
	fill->devices[fill->cur].segment = pci_domain_nr(pdev->bus);
	fill->devices[fill->cur].bus = pdev->bus->number;
	fill->devices[fill->cur].devfn = pdev->devfn;
	fill->cur++;
	iommu_group_put(iommu_group);
	return 0;
}

struct vfio_pci_group_entry {
	struct vfio_group *group;
	int id;
};

struct vfio_pci_group_info {
	int count;
	struct vfio_pci_group_entry *groups;
};

static int vfio_pci_validate_devs(struct pci_dev *pdev, void *data)
{
	struct vfio_pci_group_info *info = data;
	struct iommu_group *group;
	int id, i;

	group = iommu_group_get(&pdev->dev);
	if (!group)
		return -EPERM;

	id = iommu_group_id(group);

	for (i = 0; i < info->count; i++)
		if (info->groups[i].id == id)
			break;

	iommu_group_put(group);

	return (i == info->count) ? -EINVAL : 0;
}

static bool vfio_pci_dev_below_slot(struct pci_dev *pdev, struct pci_slot *slot)
{
	for (; pdev; pdev = pdev->bus->self)
		if (pdev->bus == slot->bus)
			return (pdev->slot == slot);
	return false;
}

struct vfio_pci_walk_info {
	int (*fn)(struct pci_dev *, void *data);
	void *data;
	struct pci_dev *pdev;
	bool slot;
	int ret;
};

static int vfio_pci_walk_wrapper(struct pci_dev *pdev, void *data)
{
	struct vfio_pci_walk_info *walk = data;

	if (!walk->slot || vfio_pci_dev_below_slot(pdev, walk->pdev->slot))
		walk->ret = walk->fn(pdev, walk->data);

	return walk->ret;
}

static int vfio_pci_for_each_slot_or_bus(struct pci_dev *pdev,
					 int (*fn)(struct pci_dev *,
						   void *data), void *data,
					 bool slot)
{
	struct vfio_pci_walk_info walk = {
		.fn = fn, .data = data, .pdev = pdev, .slot = slot, .ret = 0,
	};

	pci_walk_bus(pdev->bus, vfio_pci_walk_wrapper, &walk);

	return walk.ret;
}

static int msix_mmappable_cap(struct vfio_pci_device *vdev,
			      struct vfio_info_cap *caps)
{
	struct vfio_info_cap_header header = {
		.id = VFIO_REGION_INFO_CAP_MSIX_MAPPABLE,
		.version = 1
	};

	return vfio_info_add_capability(caps, &header, sizeof(header));
}

int vfio_pci_register_dev_region(struct vfio_pci_device *vdev,
				 unsigned int type, unsigned int subtype,
				 const struct vfio_pci_regops *ops,
				 size_t size, u32 flags, void *data)
{
	struct vfio_pci_region *region;

	region = krealloc(vdev->region,
			  (vdev->num_regions + 1) * sizeof(*region),
			  GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	vdev->region = region;
	vdev->region[vdev->num_regions].type = type;
	vdev->region[vdev->num_regions].subtype = subtype;
	vdev->region[vdev->num_regions].ops = ops;
	vdev->region[vdev->num_regions].size = size;
	vdev->region[vdev->num_regions].flags = flags;
	vdev->region[vdev->num_regions].data = data;

	vdev->num_regions++;

	return 0;
}

static long vfio_pci_ioctl(void *device_data,
			   unsigned int cmd, unsigned long arg)
{
	struct vfio_pci_device *vdev = device_data;
	unsigned long minsz;

	if (cmd == VFIO_DEVICE_GET_INFO) {
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.flags = VFIO_DEVICE_FLAGS_PCI;

		if (vdev->reset_works)
			info.flags |= VFIO_DEVICE_FLAGS_RESET;

		info.num_regions = VFIO_PCI_NUM_REGIONS + vdev->num_regions;
		info.num_irqs = VFIO_PCI_NUM_IRQS;

		return copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;

	} else if (cmd == VFIO_DEVICE_GET_REGION_INFO) {
		struct pci_dev *pdev = vdev->pdev;
		struct vfio_region_info info;
		struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
		int i, ret;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		switch (info.index) {
		case VFIO_PCI_CONFIG_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = pdev->cfg_size;
			info.flags = VFIO_REGION_INFO_FLAG_READ |
				     VFIO_REGION_INFO_FLAG_WRITE;
			break;
		case VFIO_PCI_BAR0_REGION_INDEX ... VFIO_PCI_BAR5_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = pci_resource_len(pdev, info.index);
			if (!info.size) {
				info.flags = 0;
				break;
			}

			info.flags = VFIO_REGION_INFO_FLAG_READ |
				     VFIO_REGION_INFO_FLAG_WRITE;
			if (vdev->bar_mmap_supported[info.index]) {
				info.flags |= VFIO_REGION_INFO_FLAG_MMAP;
				if (info.index == vdev->msix_bar) {
					ret = msix_mmappable_cap(vdev, &caps);
					if (ret)
						return ret;
				}
			}

			break;
		case VFIO_PCI_ROM_REGION_INDEX:
		{
			void __iomem *io;
			size_t size;

			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.flags = 0;

			/* Report the BAR size, not the ROM size */
			info.size = pci_resource_len(pdev, info.index);
			if (!info.size) {
				/* Shadow ROMs appear as PCI option ROMs */
				if (pdev->resource[PCI_ROM_RESOURCE].flags &
							IORESOURCE_ROM_SHADOW)
					info.size = 0x20000;
				else
					break;
			}

			/* Is it really there? */
			io = pci_map_rom(pdev, &size);
			if (!io || !size) {
				info.size = 0;
				break;
			}
			pci_unmap_rom(pdev, io);

			info.flags = VFIO_REGION_INFO_FLAG_READ;
			break;
		}
		case VFIO_PCI_VGA_REGION_INDEX:
			if (!vdev->has_vga)
				return -EINVAL;

			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = 0xc0000;
			info.flags = VFIO_REGION_INFO_FLAG_READ |
				     VFIO_REGION_INFO_FLAG_WRITE;

			break;
		default:
		{
			struct vfio_region_info_cap_type cap_type = {
					.header.id = VFIO_REGION_INFO_CAP_TYPE,
					.header.version = 1 };

			if (info.index >=
			    VFIO_PCI_NUM_REGIONS + vdev->num_regions)
				return -EINVAL;
			info.index = array_index_nospec(info.index,
							VFIO_PCI_NUM_REGIONS +
							vdev->num_regions);

			i = info.index - VFIO_PCI_NUM_REGIONS;

			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = vdev->region[i].size;
			info.flags = vdev->region[i].flags;

			cap_type.type = vdev->region[i].type;
			cap_type.subtype = vdev->region[i].subtype;

			ret = vfio_info_add_capability(&caps, &cap_type.header,
						       sizeof(cap_type));
			if (ret)
				return ret;

		}
		}

		if (caps.size) {
			info.flags |= VFIO_REGION_INFO_FLAG_CAPS;
			if (info.argsz < sizeof(info) + caps.size) {
				info.argsz = sizeof(info) + caps.size;
				info.cap_offset = 0;
			} else {
				vfio_info_cap_shift(&caps, sizeof(info));
				if (copy_to_user((void __user *)arg +
						  sizeof(info), caps.buf,
						  caps.size)) {
					kfree(caps.buf);
					return -EFAULT;
				}
				info.cap_offset = sizeof(info);
			}

			kfree(caps.buf);
		}

		return copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;

	} else if (cmd == VFIO_DEVICE_GET_IRQ_INFO) {
		struct vfio_irq_info info;

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz || info.index >= VFIO_PCI_NUM_IRQS)
			return -EINVAL;

		switch (info.index) {
		case VFIO_PCI_INTX_IRQ_INDEX ... VFIO_PCI_MSIX_IRQ_INDEX:
		case VFIO_PCI_REQ_IRQ_INDEX:
			break;
		case VFIO_PCI_ERR_IRQ_INDEX:
			if (pci_is_pcie(vdev->pdev))
				break;
		/* fall through */
		default:
			return -EINVAL;
		}

		info.flags = VFIO_IRQ_INFO_EVENTFD;

		info.count = vfio_pci_get_irq_count(vdev, info.index);

		if (info.index == VFIO_PCI_INTX_IRQ_INDEX)
			info.flags |= (VFIO_IRQ_INFO_MASKABLE |
				       VFIO_IRQ_INFO_AUTOMASKED);
		else
			info.flags |= VFIO_IRQ_INFO_NORESIZE;

		return copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;

	} else if (cmd == VFIO_DEVICE_SET_IRQS) {
		struct vfio_irq_set hdr;
		u8 *data = NULL;
		int max, ret = 0;
		size_t data_size = 0;

		minsz = offsetofend(struct vfio_irq_set, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		max = vfio_pci_get_irq_count(vdev, hdr.index);

		ret = vfio_set_irqs_validate_and_prepare(&hdr, max,
						 VFIO_PCI_NUM_IRQS, &data_size);
		if (ret)
			return ret;

		if (data_size) {
			data = memdup_user((void __user *)(arg + minsz),
					    data_size);
			if (IS_ERR(data))
				return PTR_ERR(data);
		}

		mutex_lock(&vdev->igate);

		ret = vfio_pci_set_irqs_ioctl(vdev, hdr.flags, hdr.index,
					      hdr.start, hdr.count, data);

		mutex_unlock(&vdev->igate);
		kfree(data);

		return ret;

	} else if (cmd == VFIO_DEVICE_RESET) {
		return vdev->reset_works ?
			pci_try_reset_function(vdev->pdev) : -EINVAL;

	} else if (cmd == VFIO_DEVICE_GET_PCI_HOT_RESET_INFO) {
		struct vfio_pci_hot_reset_info hdr;
		struct vfio_pci_fill_info fill = { 0 };
		struct vfio_pci_dependent_device *devices = NULL;
		bool slot = false;
		int ret = 0;

		minsz = offsetofend(struct vfio_pci_hot_reset_info, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		if (hdr.argsz < minsz)
			return -EINVAL;

		hdr.flags = 0;

		/* Can we do a slot or bus reset or neither? */
		if (!pci_probe_reset_slot(vdev->pdev->slot))
			slot = true;
		else if (pci_probe_reset_bus(vdev->pdev->bus))
			return -ENODEV;

		/* How many devices are affected? */
		ret = vfio_pci_for_each_slot_or_bus(vdev->pdev,
						    vfio_pci_count_devs,
						    &fill.max, slot);
		if (ret)
			return ret;

		WARN_ON(!fill.max); /* Should always be at least one */

		/*
		 * If there's enough space, fill it now, otherwise return
		 * -ENOSPC and the number of devices affected.
		 */
		if (hdr.argsz < sizeof(hdr) + (fill.max * sizeof(*devices))) {
			ret = -ENOSPC;
			hdr.count = fill.max;
			goto reset_info_exit;
		}

		devices = kcalloc(fill.max, sizeof(*devices), GFP_KERNEL);
		if (!devices)
			return -ENOMEM;

		fill.devices = devices;

		ret = vfio_pci_for_each_slot_or_bus(vdev->pdev,
						    vfio_pci_fill_devs,
						    &fill, slot);

		/*
		 * If a device was removed between counting and filling,
		 * we may come up short of fill.max.  If a device was
		 * added, we'll have a return of -EAGAIN above.
		 */
		if (!ret)
			hdr.count = fill.cur;

reset_info_exit:
		if (copy_to_user((void __user *)arg, &hdr, minsz))
			ret = -EFAULT;

		if (!ret) {
			if (copy_to_user((void __user *)(arg + minsz), devices,
					 hdr.count * sizeof(*devices)))
				ret = -EFAULT;
		}

		kfree(devices);
		return ret;

	} else if (cmd == VFIO_DEVICE_PCI_HOT_RESET) {
		struct vfio_pci_hot_reset hdr;
		int32_t *group_fds;
		struct vfio_pci_group_entry *groups;
		struct vfio_pci_group_info info;
		bool slot = false;
		int i, count = 0, ret = 0;

		minsz = offsetofend(struct vfio_pci_hot_reset, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		if (hdr.argsz < minsz || hdr.flags)
			return -EINVAL;

		/* Can we do a slot or bus reset or neither? */
		if (!pci_probe_reset_slot(vdev->pdev->slot))
			slot = true;
		else if (pci_probe_reset_bus(vdev->pdev->bus))
			return -ENODEV;

		/*
		 * We can't let userspace give us an arbitrarily large
		 * buffer to copy, so verify how many we think there
		 * could be.  Note groups can have multiple devices so
		 * one group per device is the max.
		 */
		ret = vfio_pci_for_each_slot_or_bus(vdev->pdev,
						    vfio_pci_count_devs,
						    &count, slot);
		if (ret)
			return ret;

		/* Somewhere between 1 and count is OK */
		if (!hdr.count || hdr.count > count)
			return -EINVAL;

		group_fds = kcalloc(hdr.count, sizeof(*group_fds), GFP_KERNEL);
		groups = kcalloc(hdr.count, sizeof(*groups), GFP_KERNEL);
		if (!group_fds || !groups) {
			kfree(group_fds);
			kfree(groups);
			return -ENOMEM;
		}

		if (copy_from_user(group_fds, (void __user *)(arg + minsz),
				   hdr.count * sizeof(*group_fds))) {
			kfree(group_fds);
			kfree(groups);
			return -EFAULT;
		}

		/*
		 * For each group_fd, get the group through the vfio external
		 * user interface and store the group and iommu ID.  This
		 * ensures the group is held across the reset.
		 */
		for (i = 0; i < hdr.count; i++) {
			struct vfio_group *group;
			struct fd f = fdget(group_fds[i]);
			if (!f.file) {
				ret = -EBADF;
				break;
			}

			group = vfio_group_get_external_user(f.file);
			fdput(f);
			if (IS_ERR(group)) {
				ret = PTR_ERR(group);
				break;
			}

			groups[i].group = group;
			groups[i].id = vfio_external_user_iommu_id(group);
		}

		kfree(group_fds);

		/* release reference to groups on error */
		if (ret)
			goto hot_reset_release;

		info.count = hdr.count;
		info.groups = groups;

		/*
		 * Test whether all the affected devices are contained
		 * by the set of groups provided by the user.
		 */
		ret = vfio_pci_for_each_slot_or_bus(vdev->pdev,
						    vfio_pci_validate_devs,
						    &info, slot);
		if (!ret)
			/* User has access, do the reset */
			ret = pci_reset_bus(vdev->pdev);

hot_reset_release:
		for (i--; i >= 0; i--)
			vfio_group_put_external_user(groups[i].group);

		kfree(groups);
		return ret;
	} else if (cmd == VFIO_DEVICE_IOEVENTFD) {
		struct vfio_device_ioeventfd ioeventfd;
		int count;

		minsz = offsetofend(struct vfio_device_ioeventfd, fd);

		if (copy_from_user(&ioeventfd, (void __user *)arg, minsz))
			return -EFAULT;

		if (ioeventfd.argsz < minsz)
			return -EINVAL;

		if (ioeventfd.flags & ~VFIO_DEVICE_IOEVENTFD_SIZE_MASK)
			return -EINVAL;

		count = ioeventfd.flags & VFIO_DEVICE_IOEVENTFD_SIZE_MASK;

		if (hweight8(count) != 1 || ioeventfd.fd < -1)
			return -EINVAL;

		return vfio_pci_ioeventfd(vdev, ioeventfd.offset,
					  ioeventfd.data, count, ioeventfd.fd);
	}

	return -ENOTTY;
}

static ssize_t vfio_pci_rw(void *device_data, char __user *buf,
			   size_t count, loff_t *ppos, bool iswrite)
{
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	struct vfio_pci_device *vdev = device_data;

	if (index >= VFIO_PCI_NUM_REGIONS + vdev->num_regions)
		return -EINVAL;

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		return vfio_pci_config_rw(vdev, buf, count, ppos, iswrite);

	case VFIO_PCI_ROM_REGION_INDEX:
		if (iswrite)
			return -EINVAL;
		return vfio_pci_bar_rw(vdev, buf, count, ppos, false);

	case VFIO_PCI_BAR0_REGION_INDEX ... VFIO_PCI_BAR5_REGION_INDEX:
		return vfio_pci_bar_rw(vdev, buf, count, ppos, iswrite);

	case VFIO_PCI_VGA_REGION_INDEX:
		return vfio_pci_vga_rw(vdev, buf, count, ppos, iswrite);
	default:
		index -= VFIO_PCI_NUM_REGIONS;
		return vdev->region[index].ops->rw(vdev, buf,
						   count, ppos, iswrite);
	}

	return -EINVAL;
}

static ssize_t vfio_pci_read(void *device_data, char __user *buf,
			     size_t count, loff_t *ppos)
{
	if (!count)
		return 0;

	return vfio_pci_rw(device_data, buf, count, ppos, false);
}

static ssize_t vfio_pci_write(void *device_data, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	if (!count)
		return 0;

	return vfio_pci_rw(device_data, (char __user *)buf, count, ppos, true);
}

static int vfio_pci_mmap(void *device_data, struct vm_area_struct *vma)
{
	struct vfio_pci_device *vdev = device_data;
	struct pci_dev *pdev = vdev->pdev;
	unsigned int index;
	u64 phys_len, req_len, pgoff, req_start;
	int ret;

	index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;
	if (index >= VFIO_PCI_ROM_REGION_INDEX)
		return -EINVAL;
	if (!vdev->bar_mmap_supported[index])
		return -EINVAL;

	phys_len = PAGE_ALIGN(pci_resource_len(pdev, index));
	req_len = vma->vm_end - vma->vm_start;
	pgoff = vma->vm_pgoff &
		((1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	req_start = pgoff << PAGE_SHIFT;

	if (req_start + req_len > phys_len)
		return -EINVAL;

	/*
	 * Even though we don't make use of the barmap for the mmap,
	 * we need to request the region and the barmap tracks that.
	 */
	if (!vdev->barmap[index]) {
		ret = pci_request_selected_regions(pdev,
						   1 << index, "vfio-pci");
		if (ret)
			return ret;

		vdev->barmap[index] = pci_iomap(pdev, index, 0);
		if (!vdev->barmap[index]) {
			pci_release_selected_regions(pdev, 1 << index);
			return -ENOMEM;
		}
	}

	vma->vm_private_data = vdev;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = (pci_resource_start(pdev, index) >> PAGE_SHIFT) + pgoff;

	return remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			       req_len, vma->vm_page_prot);
}

static void vfio_pci_request(void *device_data, unsigned int count)
{
	struct vfio_pci_device *vdev = device_data;

	mutex_lock(&vdev->igate);

	if (vdev->req_trigger) {
		if (!(count % 10))
			dev_notice_ratelimited(&vdev->pdev->dev,
				"Relaying device request to user (#%u)\n",
				count);
		eventfd_signal(vdev->req_trigger, 1);
	} else if (count == 0) {
		dev_warn(&vdev->pdev->dev,
			"No device request channel registered, blocked until released by user\n");
	}

	mutex_unlock(&vdev->igate);
}

>>>>>>> master
static const struct vfio_device_ops vfio_pci_ops = {
	.name		= "vfio-pci",
	.init		= vfio_pci_core_init_dev,
	.release	= vfio_pci_core_release_dev,
	.open_device	= vfio_pci_open_device,
	.close_device	= vfio_pci_core_close_device,
	.ioctl		= vfio_pci_core_ioctl,
	.device_feature = vfio_pci_core_ioctl_feature,
	.read		= vfio_pci_core_read,
	.write		= vfio_pci_core_write,
	.mmap		= vfio_pci_core_mmap,
	.request	= vfio_pci_core_request,
	.match		= vfio_pci_core_match,
	.bind_iommufd	= vfio_iommufd_physical_bind,
	.unbind_iommufd	= vfio_iommufd_physical_unbind,
	.attach_ioas	= vfio_iommufd_physical_attach_ioas,
	.detach_ioas	= vfio_iommufd_physical_detach_ioas,
};

static int vfio_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct vfio_pci_core_device *vdev;
	int ret;

	if (vfio_pci_is_denylisted(pdev))
		return -EINVAL;

	vdev = vfio_alloc_device(vfio_pci_core_device, vdev, &pdev->dev,
				 &vfio_pci_ops);
	if (IS_ERR(vdev))
		return PTR_ERR(vdev);

	dev_set_drvdata(&pdev->dev, vdev);
	ret = vfio_pci_core_register_device(vdev);
	if (ret)
		goto out_put_vdev;
	return 0;

out_put_vdev:
	vfio_put_device(&vdev->vdev);
	return ret;
}

static void vfio_pci_remove(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *vdev = dev_get_drvdata(&pdev->dev);

	vfio_pci_core_unregister_device(vdev);
	vfio_put_device(&vdev->vdev);
}

static int vfio_pci_sriov_configure(struct pci_dev *pdev, int nr_virtfn)
{
	struct vfio_pci_core_device *vdev = dev_get_drvdata(&pdev->dev);

	if (!enable_sriov)
		return -ENOENT;

	return vfio_pci_core_sriov_configure(vdev, nr_virtfn);
}

static const struct pci_device_id vfio_pci_table[] = {
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_ANY_ID, PCI_ANY_ID) }, /* match all by default */
	{}
};

MODULE_DEVICE_TABLE(pci, vfio_pci_table);

static struct pci_driver vfio_pci_driver = {
	.name			= "vfio-pci",
	.id_table		= vfio_pci_table,
	.probe			= vfio_pci_probe,
	.remove			= vfio_pci_remove,
	.sriov_configure	= vfio_pci_sriov_configure,
	.err_handler		= &vfio_pci_core_err_handlers,
	.driver_managed_dma	= true,
};

static void __init vfio_pci_fill_ids(void)
{
	char *p, *id;
	int rc;

	/* no ids passed actually */
	if (ids[0] == '\0')
		return;

	/* add ids specified in the module parameter */
	p = ids;
	while ((id = strsep(&p, ","))) {
		unsigned int vendor, device, subvendor = PCI_ANY_ID,
			subdevice = PCI_ANY_ID, class = 0, class_mask = 0;
		int fields;

		if (!strlen(id))
			continue;

		fields = sscanf(id, "%x:%x:%x:%x:%x:%x",
				&vendor, &device, &subvendor, &subdevice,
				&class, &class_mask);

		if (fields < 2) {
			pr_warn("invalid id string \"%s\"\n", id);
			continue;
		}

		rc = pci_add_dynid(&vfio_pci_driver, vendor, device,
				   subvendor, subdevice, class, class_mask, 0);
		if (rc)
			pr_warn("failed to add dynamic id [%04x:%04x[%04x:%04x]] class %#08x/%08x (%d)\n",
				vendor, device, subvendor, subdevice,
				class, class_mask, rc);
		else
			pr_info("add [%04x:%04x[%04x:%04x]] class %#08x/%08x\n",
				vendor, device, subvendor, subdevice,
				class, class_mask);
	}
}

static int __init vfio_pci_init(void)
{
	int ret;
	bool is_disable_vga = true;

#ifdef CONFIG_VFIO_PCI_VGA
	is_disable_vga = disable_vga;
#endif

	vfio_pci_core_set_params(nointxmask, is_disable_vga, disable_idle_d3);

	/* Register and scan for devices */
	ret = pci_register_driver(&vfio_pci_driver);
	if (ret)
		return ret;

	vfio_pci_fill_ids();

	if (disable_denylist)
		pr_warn("device denylist disabled.\n");

	return 0;
}
module_init(vfio_pci_init);

static void __exit vfio_pci_cleanup(void)
{
	pci_unregister_driver(&vfio_pci_driver);
}
module_exit(vfio_pci_cleanup);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
