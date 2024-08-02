/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_REPORTING_H
#define _LINUX_PAGE_REPORTING_H

#include <linux/mmzone.h>
<<<<<<< HEAD
#include <linux/scatterlist.h>

/* This value should always be a power of 2, see page_reporting_cycle() */
#define PAGE_REPORTING_CAPACITY		32

struct page_reporting_dev_info {
	/* function that alters pages to make them "reported" */
	int (*report)(struct page_reporting_dev_info *prdev,
		      struct scatterlist *sg, unsigned int nents);
=======

struct page_reporting_dev_info {
	/* function that alters pages to make them "reported" */
	void (*report)(struct page_reporting_dev_info *phdev,
		       unsigned int nents);

	/* scatterlist containing pages to be processed */
	struct scatterlist *sg;

	/*
	 * Upper limit on the number of pages that the react function
	 * expects to be placed into the batch list to be processed.
	 */
	unsigned long capacity;
>>>>>>> master

	/* work struct for processing reports */
	struct delayed_work work;

<<<<<<< HEAD
	/* Current state of page reporting */
	atomic_t state;

	/* Minimal order of page reporting */
	unsigned int order;
};

/* Tear-down and bring-up for page reporting devices */
void page_reporting_unregister(struct page_reporting_dev_info *prdev);
int page_reporting_register(struct page_reporting_dev_info *prdev);
=======
	/* The number of zones requesting reporting */
	atomic_t refcnt;
};

/* Tear-down and bring-up for page reporting devices */
void page_reporting_unregister(struct page_reporting_dev_info *phdev);
int page_reporting_register(struct page_reporting_dev_info *phdev);
>>>>>>> master
#endif /*_LINUX_PAGE_REPORTING_H */
