// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2016 - 2018 Intel Corporation. All rights reserved. */
#include <linux/memremap.h>
#include <linux/module.h>
#include <linux/pfn_t.h>
#include "../nvdimm/pfn.h"
#include "../nvdimm/nd.h"
#include "bus.h"

static struct dev_dax *__dax_pmem_probe(struct device *dev)
{
	struct range range;
	int rc, id, region_id;
	resource_size_t offset;
	struct nd_pfn_sb *pfn_sb;
	struct dev_dax_data data;
	struct nd_namespace_io *nsio;
	struct dax_region *dax_region;
	struct dev_pagemap pgmap = { };
	struct nd_namespace_common *ndns;
	struct nd_dax *nd_dax = to_nd_dax(dev);
	struct nd_pfn *nd_pfn = &nd_dax->nd_pfn;
	struct nd_region *nd_region = to_nd_region(dev->parent);

	ndns = nvdimm_namespace_common_probe(dev);
	if (IS_ERR(ndns))
		return ERR_CAST(ndns);

	/* parse the 'pfn' info block via ->rw_bytes */
	rc = devm_namespace_enable(dev, ndns, nd_info_block_reserve());
	if (rc)
		return ERR_PTR(rc);
	rc = nvdimm_setup_pfn(nd_pfn, &pgmap);
	if (rc)
		return ERR_PTR(rc);
	devm_namespace_disable(dev, ndns);

	/* reserve the metadata area, device-dax will reserve the data */
	pfn_sb = nd_pfn->pfn_sb;
	offset = le64_to_cpu(pfn_sb->dataoff);
	nsio = to_nd_namespace_io(&ndns->dev);
	if (!devm_request_mem_region(dev, nsio->res.start, offset,
				dev_name(&ndns->dev))) {
		dev_warn(dev, "could not reserve metadata\n");
		return ERR_PTR(-EBUSY);
	}

	rc = sscanf(dev_name(&ndns->dev), "namespace%d.%d", &region_id, &id);
	if (rc != 2)
		return ERR_PTR(-EINVAL);

<<<<<<< HEAD
	/* adjust the dax_region range to the start of data */
	range = pgmap.range;
	range.start += offset;
	dax_region = alloc_dax_region(dev, region_id, &range,
			nd_region->target_node, le32_to_cpu(pfn_sb->align),
			IORESOURCE_DAX_STATIC);
	if (!dax_region)
		return ERR_PTR(-ENOMEM);
=======
static void dax_pmem_percpu_kill(struct percpu_ref *ref)
{
	struct dax_pmem *dax_pmem = to_dax_pmem(ref);
>>>>>>> master

	data = (struct dev_dax_data) {
		.dax_region = dax_region,
		.id = id,
		.pgmap = &pgmap,
		.size = range_len(&range),
	};

	return devm_create_dev_dax(&data);
}

static int dax_pmem_probe(struct device *dev)
{
<<<<<<< HEAD
	return PTR_ERR_OR_ZERO(__dax_pmem_probe(dev));
=======
	void *addr;
	struct resource res;
	int rc, id, region_id;
	struct nd_pfn_sb *pfn_sb;
	struct dev_dax *dev_dax;
	struct dax_pmem *dax_pmem;
	struct nd_namespace_io *nsio;
	struct dax_region *dax_region;
	struct nd_namespace_common *ndns;
	struct nd_dax *nd_dax = to_nd_dax(dev);
	struct nd_pfn *nd_pfn = &nd_dax->nd_pfn;

	ndns = nvdimm_namespace_common_probe(dev);
	if (IS_ERR(ndns))
		return PTR_ERR(ndns);
	nsio = to_nd_namespace_io(&ndns->dev);

	dax_pmem = devm_kzalloc(dev, sizeof(*dax_pmem), GFP_KERNEL);
	if (!dax_pmem)
		return -ENOMEM;

	/* parse the 'pfn' info block via ->rw_bytes */
	rc = devm_nsio_enable(dev, nsio);
	if (rc)
		return rc;
	rc = nvdimm_setup_pfn(nd_pfn, &dax_pmem->pgmap);
	if (rc)
		return rc;
	devm_nsio_disable(dev, nsio);

	pfn_sb = nd_pfn->pfn_sb;

	if (!devm_request_mem_region(dev, nsio->res.start,
				resource_size(&nsio->res),
				dev_name(&ndns->dev))) {
		dev_warn(dev, "could not reserve region %pR\n", &nsio->res);
		return -EBUSY;
	}

	dax_pmem->dev = dev;
	init_completion(&dax_pmem->cmp);
	rc = percpu_ref_init(&dax_pmem->ref, dax_pmem_percpu_release, 0,
			GFP_KERNEL);
	if (rc)
		return rc;

	rc = devm_add_action(dev, dax_pmem_percpu_exit, &dax_pmem->ref);
	if (rc) {
		percpu_ref_exit(&dax_pmem->ref);
		return rc;
	}

	dax_pmem->pgmap.ref = &dax_pmem->ref;
	dax_pmem->pgmap.kill = dax_pmem_percpu_kill;
	addr = devm_memremap_pages(dev, &dax_pmem->pgmap);
	if (IS_ERR(addr))
		return PTR_ERR(addr);

	/* adjust the dax_region resource to the start of data */
	memcpy(&res, &dax_pmem->pgmap.res, sizeof(res));
	res.start += le64_to_cpu(pfn_sb->dataoff);

	rc = sscanf(dev_name(&ndns->dev), "namespace%d.%d", &region_id, &id);
	if (rc != 2)
		return -EINVAL;

	dax_region = alloc_dax_region(dev, region_id, &res,
			le32_to_cpu(pfn_sb->align), addr, PFN_DEV|PFN_MAP);
	if (!dax_region)
		return -ENOMEM;

	/* TODO: support for subdividing a dax region... */
	dev_dax = devm_create_dev_dax(dax_region, id, &res, 1);

	/* child dev_dax instances now own the lifetime of the dax_region */
	dax_region_put(dax_region);

	return PTR_ERR_OR_ZERO(dev_dax);
>>>>>>> master
}

static struct nd_device_driver dax_pmem_driver = {
	.probe = dax_pmem_probe,
	.drv = {
		.name = "dax_pmem",
	},
	.type = ND_DRIVER_DAX_PMEM,
};

static int __init dax_pmem_init(void)
{
	return nd_driver_register(&dax_pmem_driver);
}
module_init(dax_pmem_init);

static void __exit dax_pmem_exit(void)
{
	driver_unregister(&dax_pmem_driver.drv);
}
module_exit(dax_pmem_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
MODULE_ALIAS_ND_DEVICE(ND_DEVICE_DAX_PMEM);
