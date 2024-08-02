/* i915_drv.h -- Private header for the I915 driver -*- linux-c -*-
 */
/*
 *
 * Copyright 2003 Tungsten Graphics, Inc., Cedar Park, Texas.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
 * IN NO EVENT SHALL TUNGSTEN GRAPHICS AND/OR ITS SUPPLIERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef _I915_DRV_H_
#define _I915_DRV_H_

#include <uapi/drm/i915_drm.h>

#include <linux/pm_qos.h>

#include <drm/ttm/ttm_device.h>

#include "display/intel_display_limits.h"
#include "display/intel_display_core.h"

#include "gem/i915_gem_context_types.h"
#include "gem/i915_gem_shrinker.h"
#include "gem/i915_gem_stolen.h"

#include "gt/intel_engine.h"
#include "gt/intel_gt_types.h"
#include "gt/intel_region_lmem.h"
#include "gt/intel_workarounds.h"
#include "gt/uc/intel_uc.h"

#include "soc/intel_pch.h"

#include "i915_drm_client.h"
#include "i915_gem.h"
#include "i915_gpu_error.h"
#include "i915_params.h"
#include "i915_perf_types.h"
#include "i915_scheduler.h"
#include "i915_utils.h"
#include "intel_device_info.h"
#include "intel_memory_region.h"
#include "intel_runtime_pm.h"
#include "intel_step.h"
#include "intel_uncore.h"

struct drm_i915_clock_gating_funcs;
struct vlv_s0ix_state;
struct intel_pxp;

#define GEM_QUIRK_PIN_SWIZZLED_PAGES	BIT(0)

/* Data Stolen Memory (DSM) aka "i915 stolen memory" */
struct i915_dsm {
	/*
	 * The start and end of DSM which we can optionally use to create GEM
	 * objects backed by stolen memory.
	 *
	 * Note that usable_size tells us exactly how much of this we are
	 * actually allowed to use, given that some portion of it is in fact
	 * reserved for use by hardware functions.
	 */
	struct resource stolen;

	/*
	 * Reserved portion of DSM.
	 */
	struct resource reserved;

	/*
	 * Total size minus reserved ranges.
	 *
	 * DSM is segmented in hardware with different portions offlimits to
	 * certain functions.
	 *
	 * The drm_mm is initialised to the total accessible range, as found
	 * from the PCI config. On Broadwell+, this is further restricted to
	 * avoid the first page! The upper end of DSM is reserved for hardware
	 * functions and similarly removed from the accessible range.
	 */
	resource_size_t usable_size;
};

struct i915_suspend_saved_registers {
	u32 saveDSPARB;
	u32 saveSWF0[16];
	u32 saveSWF1[16];
	u32 saveSWF3[3];
	u16 saveGCDGMBUS;
};

<<<<<<< HEAD
=======
struct vlv_s0ix_state {
	/* GAM */
	u32 wr_watermark;
	u32 gfx_prio_ctrl;
	u32 arb_mode;
	u32 gfx_pend_tlb0;
	u32 gfx_pend_tlb1;
	u32 lra_limits[GEN7_LRA_LIMITS_REG_NUM];
	u32 media_max_req_count;
	u32 gfx_max_req_count;
	u32 render_hwsp;
	u32 ecochk;
	u32 bsd_hwsp;
	u32 blt_hwsp;
	u32 tlb_rd_addr;

	/* MBC */
	u32 g3dctl;
	u32 gsckgctl;
	u32 mbctl;

	/* GCP */
	u32 ucgctl1;
	u32 ucgctl3;
	u32 rcgctl1;
	u32 rcgctl2;
	u32 rstctl;
	u32 misccpctl;

	/* GPM */
	u32 gfxpause;
	u32 rpdeuhwtc;
	u32 rpdeuc;
	u32 ecobus;
	u32 pwrdwnupctl;
	u32 rp_down_timeout;
	u32 rp_deucsw;
	u32 rcubmabdtmr;
	u32 rcedata;
	u32 spare2gh;

	/* Display 1 CZ domain */
	u32 gt_imr;
	u32 gt_ier;
	u32 pm_imr;
	u32 pm_ier;
	u32 gt_scratch[GEN7_GT_SCRATCH_REG_NUM];

	/* GT SA CZ domain */
	u32 tilectl;
	u32 gt_fifoctl;
	u32 gtlc_wake_ctrl;
	u32 gtlc_survive;
	u32 pmwgicz;

	/* Display 2 CZ domain */
	u32 gu_ctl0;
	u32 gu_ctl1;
	u32 pcbr;
	u32 clock_gate_dis2;
};

struct intel_rps_ei {
	ktime_t ktime;
	u32 render_c0;
	u32 media_c0;
};

struct intel_rps {
	/*
	 * work, interrupts_enabled and pm_iir are protected by
	 * dev_priv->irq_lock
	 */
	struct work_struct work;
	bool interrupts_enabled;
	u32 pm_iir;

	/* PM interrupt bits that should never be masked */
	u32 pm_intrmsk_mbz;

	/* Frequencies are stored in potentially platform dependent multiples.
	 * In other words, *_freq needs to be multiplied by X to be interesting.
	 * Soft limits are those which are used for the dynamic reclocking done
	 * by the driver (raise frequencies under heavy loads, and lower for
	 * lighter loads). Hard limits are those imposed by the hardware.
	 *
	 * A distinction is made for overclocking, which is never enabled by
	 * default, and is considered to be above the hard limit if it's
	 * possible at all.
	 */
	u8 cur_freq;		/* Current frequency (cached, may not == HW) */
	u8 min_freq_softlimit;	/* Minimum frequency permitted by the driver */
	u8 max_freq_softlimit;	/* Max frequency permitted by the driver */
	u8 max_freq;		/* Maximum frequency, RP0 if not overclocking */
	u8 min_freq;		/* AKA RPn. Minimum frequency */
	u8 boost_freq;		/* Frequency to request when wait boosting */
	u8 idle_freq;		/* Frequency to request when we are idle */
	u8 efficient_freq;	/* AKA RPe. Pre-determined balanced frequency */
	u8 rp1_freq;		/* "less than" RP0 power/freqency */
	u8 rp0_freq;		/* Non-overclocked max frequency. */
	u16 gpll_ref_freq;	/* vlv/chv GPLL reference frequency */

	int last_adj;

	struct {
		struct mutex mutex;

		enum { LOW_POWER, BETWEEN, HIGH_POWER } mode;
		unsigned int interactive;

		u8 up_threshold; /* Current %busy required to uplock */
		u8 down_threshold; /* Current %busy required to downclock */
	} power;

	bool enabled;
	atomic_t num_waiters;
	atomic_t boosts;

	/* manual wa residency calculations */
	struct intel_rps_ei ei;
};

struct intel_rc6 {
	bool enabled;
	bool ctx_corrupted;
	u64 prev_hw_residency[4];
	u64 cur_residency[4];
};

struct intel_llc_pstate {
	bool enabled;
};

struct intel_gen6_power_mgmt {
	struct intel_rps rps;
	struct intel_rc6 rc6;
	struct intel_llc_pstate llc_pstate;
};

/* defined intel_pm.c */
extern spinlock_t mchdev_lock;

struct intel_ilk_power_mgmt {
	u8 cur_delay;
	u8 min_delay;
	u8 max_delay;
	u8 fmax;
	u8 fstart;

	u64 last_count1;
	unsigned long last_time1;
	unsigned long chipset_power;
	u64 last_count2;
	u64 last_time2;
	unsigned long gfx_power;
	u8 corr;

	int c_m;
	int r_t;
};

struct drm_i915_private;
struct i915_power_well;

struct i915_power_well_ops {
	/*
	 * Synchronize the well's hw state to match the current sw state, for
	 * example enable/disable it based on the current refcount. Called
	 * during driver init and resume time, possibly after first calling
	 * the enable/disable handlers.
	 */
	void (*sync_hw)(struct drm_i915_private *dev_priv,
			struct i915_power_well *power_well);
	/*
	 * Enable the well and resources that depend on it (for example
	 * interrupts located on the well). Called after the 0->1 refcount
	 * transition.
	 */
	void (*enable)(struct drm_i915_private *dev_priv,
		       struct i915_power_well *power_well);
	/*
	 * Disable the well and resources that depend on it. Called after
	 * the 1->0 refcount transition.
	 */
	void (*disable)(struct drm_i915_private *dev_priv,
			struct i915_power_well *power_well);
	/* Returns the hw enabled state. */
	bool (*is_enabled)(struct drm_i915_private *dev_priv,
			   struct i915_power_well *power_well);
};

/* Power well structure for haswell */
struct i915_power_well {
	const char *name;
	bool always_on;
	/* power well enable/disable usage count */
	int count;
	/* cached hw enabled state */
	bool hw_enabled;
	u64 domains;
	/* unique identifier for this power well */
	enum i915_power_well_id id;
	/*
	 * Arbitraty data associated with this power well. Platform and power
	 * well specific.
	 */
	union {
		struct {
			enum dpio_phy phy;
		} bxt;
		struct {
			/* Mask of pipes whose IRQ logic is backed by the pw */
			u8 irq_pipe_mask;
			/* The pw is backing the VGA functionality */
			bool has_vga:1;
			bool has_fuses:1;
		} hsw;
	};
	const struct i915_power_well_ops *ops;
};

struct i915_power_domains {
	/*
	 * Power wells needed for initialization at driver init and suspend
	 * time are on. They are kept on until after the first modeset.
	 */
	bool init_power_on;
	bool initializing;
	int power_well_count;

	struct mutex lock;
	int domain_use_count[POWER_DOMAIN_NUM];
	struct i915_power_well *power_wells;
};

>>>>>>> master
#define MAX_L3_SLICES 2
struct intel_l3_parity {
	u32 *remap_info[MAX_L3_SLICES];
	struct work_struct error_work;
	int which_slice;
};

struct i915_gem_mm {
	/*
	 * Shortcut for the stolen region. This points to either
	 * INTEL_REGION_STOLEN_SMEM for integrated platforms, or
	 * INTEL_REGION_STOLEN_LMEM for discrete, or NULL if the device doesn't
	 * support stolen.
	 */
	struct intel_memory_region *stolen_region;
	/** Memory allocator for GTT stolen memory */
	struct drm_mm stolen;
	/** Protects the usage of the GTT stolen memory allocator. This is
	 * always the inner lock when overlapping with struct_mutex. */
	struct mutex stolen_lock;

	/* Protects bound_list/unbound_list and #drm_i915_gem_object.mm.link */
	spinlock_t obj_lock;

	/**
	 * List of objects which are purgeable.
	 */
	struct list_head purge_list;

	/**
	 * List of objects which have allocated pages and are shrinkable.
	 */
	struct list_head shrink_list;

	/**
	 * List of objects which are pending destruction.
	 */
	struct llist_head free_list;
	struct work_struct free_work;
	/**
	 * Count of objects pending destructions. Used to skip needlessly
	 * waiting on an RCU barrier if no objects are waiting to be freed.
	 */
	atomic_t free_count;

	/**
	 * tmpfs instance used for shmem backed objects
	 */
	struct vfsmount *gemfs;

	struct intel_memory_region *regions[INTEL_REGION_UNKNOWN];

	struct notifier_block oom_notifier;
	struct notifier_block vmap_notifier;
	struct shrinker shrinker;

#ifdef CONFIG_MMU_NOTIFIER
	/**
	 * notifier_lock for mmu notifiers, memory may not be allocated
	 * while holding this lock.
	 */
	rwlock_t notifier_lock;
#endif

	/* shrinker accounting, also useful for userland debugging */
	u64 shrink_memory;
	u32 shrink_count;
};

struct i915_virtual_gpu {
	struct mutex lock; /* serialises sending of g2v_notify command pkts */
	bool active;
	u32 caps;
	u32 *initial_mmio;
	u8 *initial_cfg_space;
	struct list_head entry;
};

struct i915_selftest_stash {
	atomic_t counter;
	struct ida mock_region_instances;
};

struct drm_i915_private {
	struct drm_device drm;

	struct intel_display display;

	/* FIXME: Device release actions should all be moved to drmm_ */
	bool do_release;

	/* i915 device parameters */
	struct i915_params params;

	const struct intel_device_info *__info; /* Use INTEL_INFO() to access. */
	struct intel_runtime_info __runtime; /* Use RUNTIME_INFO() to access. */
	struct intel_driver_caps caps;

	struct i915_dsm dsm;

	struct intel_uncore uncore;
	struct intel_uncore_mmio_debug mmio_debug;

	struct i915_virtual_gpu vgpu;

	struct intel_gvt *gvt;

	struct {
		struct pci_dev *pdev;
		struct resource mch_res;
		bool mchbar_need_disable;
	} gmch;

	struct rb_root uabi_engines;
	unsigned int engine_uabi_class_count[I915_LAST_UABI_ENGINE_CLASS + 1];

	/* protects the irq masks */
	spinlock_t irq_lock;

	bool display_irqs_enabled;

	/* Sideband mailbox protection */
	struct mutex sb_lock;
	struct pm_qos_request sb_qos;

	/** Cached value of IMR to avoid reads in updating the bitfield */
	union {
		u32 irq_mask;
		u32 de_irq_mask[I915_MAX_PIPES];
	};
	u32 pipestat_irq_mask[I915_MAX_PIPES];

	bool preserve_bios_swizzle;

	unsigned int fsb_freq, mem_freq, is_ddr3;
	unsigned int skl_preferred_vco_freq;

	unsigned int max_dotclk_freq;
	unsigned int hpll_freq;
	unsigned int czclk_freq;

	/**
	 * wq - Driver workqueue for GEM.
	 *
	 * NOTE: Work items scheduled here are not allowed to grab any modeset
	 * locks, for otherwise the flushing done in the pageflip code will
	 * result in deadlocks.
	 */
	struct workqueue_struct *wq;

	/**
	 * unordered_wq - internal workqueue for unordered work
	 *
	 * This workqueue should be used for all unordered work
	 * scheduling within i915, which used to be scheduled on the
	 * system_wq before moving to a driver instance due
	 * deprecation of flush_scheduled_work().
	 */
	struct workqueue_struct *unordered_wq;

	/* pm private clock gating functions */
	const struct drm_i915_clock_gating_funcs *clock_gating_funcs;

	/* PCH chipset type */
	enum intel_pch pch_type;
	unsigned short pch_id;

	unsigned long gem_quirks;

	struct i915_gem_mm mm;

	struct intel_l3_parity l3_parity;

	/*
	 * edram size in MB.
	 * Cannot be determined by PCIID. You must always read a register.
	 */
	u32 edram_size_mb;

	struct i915_gpu_error gpu_error;

	u32 suspend_count;
	struct i915_suspend_saved_registers regfile;
	struct vlv_s0ix_state *vlv_s0ix_state;

	struct dram_info {
		bool wm_lv_0_adjust_needed;
		u8 num_channels;
		bool symmetric_memory;
		enum intel_dram_type {
			INTEL_DRAM_UNKNOWN,
			INTEL_DRAM_DDR3,
			INTEL_DRAM_DDR4,
			INTEL_DRAM_LPDDR3,
			INTEL_DRAM_LPDDR4,
			INTEL_DRAM_DDR5,
			INTEL_DRAM_LPDDR5,
		} type;
		u8 num_qgv_points;
		u8 num_psf_gv_points;
	} dram_info;

	struct intel_runtime_pm runtime_pm;

	struct i915_perf perf;

	struct i915_hwmon *hwmon;

	/* Abstract the submission mechanism (legacy ringbuffer or execlists) away */
	struct intel_gt gt0;

	/*
	 * i915->gt[0] == &i915->gt0
	 */
	struct intel_gt *gt[I915_MAX_GT];

	struct kobject *sysfs_gt;

	/* Quick lookup of media GT (current platforms only have one) */
	struct intel_gt *media_gt;

	struct {
		struct i915_gem_contexts {
			spinlock_t lock; /* locks list */
			struct list_head list;
		} contexts;

		/*
		 * We replace the local file with a global mappings as the
		 * backing storage for the mmap is on the device and not
		 * on the struct file, and we do not want to prolong the
		 * lifetime of the local fd. To minimise the number of
		 * anonymous inodes we create, we use a global singleton to
		 * share the global mapping.
		 */
		struct file *mmap_singleton;
	} gem;

	struct intel_pxp *pxp;

	/* For i915gm/i945gm vblank irq workaround */
	u8 vblank_enabled;

	bool irq_enabled;

	struct i915_pmu pmu;

	/* The TTM device structure. */
	struct ttm_device bdev;

	I915_SELFTEST_DECLARE(struct i915_selftest_stash selftest;)

	/*
	 * NOTE: This is the dri1/ums dungeon, don't add stuff here. Your patch
	 * will be rejected. Instead look for a better place.
	 */
};

static inline struct drm_i915_private *to_i915(const struct drm_device *dev)
{
	return container_of(dev, struct drm_i915_private, drm);
}

static inline struct drm_i915_private *kdev_to_i915(struct device *kdev)
{
	return dev_get_drvdata(kdev);
}

static inline struct drm_i915_private *pdev_to_i915(struct pci_dev *pdev)
{
	return pci_get_drvdata(pdev);
}

static inline struct intel_gt *to_gt(struct drm_i915_private *i915)
{
	return &i915->gt0;
}

/* Simple iterator over all initialised engines */
#define for_each_engine(engine__, gt__, id__) \
	for ((id__) = 0; \
	     (id__) < I915_NUM_ENGINES; \
	     (id__)++) \
		for_each_if ((engine__) = (gt__)->engine[(id__)])

/* Iterator over subset of engines selected by mask */
#define for_each_engine_masked(engine__, gt__, mask__, tmp__) \
	for ((tmp__) = (mask__) & (gt__)->info.engine_mask; \
	     (tmp__) ? \
	     ((engine__) = (gt__)->engine[__mask_next_bit(tmp__)]), 1 : \
	     0;)

#define rb_to_uabi_engine(rb) \
	rb_entry_safe(rb, struct intel_engine_cs, uabi_node)

#define for_each_uabi_engine(engine__, i915__) \
	for ((engine__) = rb_to_uabi_engine(rb_first(&(i915__)->uabi_engines));\
	     (engine__); \
	     (engine__) = rb_to_uabi_engine(rb_next(&(engine__)->uabi_node)))

#define for_each_uabi_class_engine(engine__, class__, i915__) \
	for ((engine__) = intel_engine_lookup_user((i915__), (class__), 0); \
	     (engine__) && (engine__)->uabi_class == (class__); \
	     (engine__) = rb_to_uabi_engine(rb_next(&(engine__)->uabi_node)))

#define INTEL_INFO(i915)	((i915)->__info)
#define RUNTIME_INFO(i915)	(&(i915)->__runtime)
#define DISPLAY_INFO(i915)	((i915)->display.info.__device_info)
#define DISPLAY_RUNTIME_INFO(i915)	(&(i915)->display.info.__runtime_info)
#define DRIVER_CAPS(i915)	(&(i915)->caps)

#define INTEL_DEVID(i915)	(RUNTIME_INFO(i915)->device_id)

#define IP_VER(ver, rel)		((ver) << 8 | (rel))

#define GRAPHICS_VER(i915)		(RUNTIME_INFO(i915)->graphics.ip.ver)
#define GRAPHICS_VER_FULL(i915)		IP_VER(RUNTIME_INFO(i915)->graphics.ip.ver, \
					       RUNTIME_INFO(i915)->graphics.ip.rel)
#define IS_GRAPHICS_VER(i915, from, until) \
	(GRAPHICS_VER(i915) >= (from) && GRAPHICS_VER(i915) <= (until))

#define MEDIA_VER(i915)			(RUNTIME_INFO(i915)->media.ip.ver)
#define MEDIA_VER_FULL(i915)		IP_VER(RUNTIME_INFO(i915)->media.ip.ver, \
					       RUNTIME_INFO(i915)->media.ip.rel)
#define IS_MEDIA_VER(i915, from, until) \
	(MEDIA_VER(i915) >= (from) && MEDIA_VER(i915) <= (until))

#define DISPLAY_VER(i915)	(DISPLAY_RUNTIME_INFO(i915)->ip.ver)
#define IS_DISPLAY_VER(i915, from, until) \
	(DISPLAY_VER(i915) >= (from) && DISPLAY_VER(i915) <= (until))

#define INTEL_REVID(i915)	(to_pci_dev((i915)->drm.dev)->revision)

#define INTEL_DISPLAY_STEP(__i915) (RUNTIME_INFO(__i915)->step.display_step)
#define INTEL_GRAPHICS_STEP(__i915) (RUNTIME_INFO(__i915)->step.graphics_step)
#define INTEL_MEDIA_STEP(__i915) (RUNTIME_INFO(__i915)->step.media_step)
#define INTEL_BASEDIE_STEP(__i915) (RUNTIME_INFO(__i915)->step.basedie_step)

#define IS_DISPLAY_STEP(__i915, since, until) \
	(drm_WARN_ON(&(__i915)->drm, INTEL_DISPLAY_STEP(__i915) == STEP_NONE), \
	 INTEL_DISPLAY_STEP(__i915) >= (since) && INTEL_DISPLAY_STEP(__i915) < (until))

#define IS_GRAPHICS_STEP(__i915, since, until) \
	(drm_WARN_ON(&(__i915)->drm, INTEL_GRAPHICS_STEP(__i915) == STEP_NONE), \
	 INTEL_GRAPHICS_STEP(__i915) >= (since) && INTEL_GRAPHICS_STEP(__i915) < (until))

#define IS_MEDIA_STEP(__i915, since, until) \
	(drm_WARN_ON(&(__i915)->drm, INTEL_MEDIA_STEP(__i915) == STEP_NONE), \
	 INTEL_MEDIA_STEP(__i915) >= (since) && INTEL_MEDIA_STEP(__i915) < (until))

#define IS_BASEDIE_STEP(__i915, since, until) \
	(drm_WARN_ON(&(__i915)->drm, INTEL_BASEDIE_STEP(__i915) == STEP_NONE), \
	 INTEL_BASEDIE_STEP(__i915) >= (since) && INTEL_BASEDIE_STEP(__i915) < (until))

static __always_inline unsigned int
__platform_mask_index(const struct intel_runtime_info *info,
		      enum intel_platform p)
{
	const unsigned int pbits =
		BITS_PER_TYPE(info->platform_mask[0]) - INTEL_SUBPLATFORM_BITS;

	/* Expand the platform_mask array if this fails. */
	BUILD_BUG_ON(INTEL_MAX_PLATFORMS >
		     pbits * ARRAY_SIZE(info->platform_mask));

	return p / pbits;
}

static __always_inline unsigned int
__platform_mask_bit(const struct intel_runtime_info *info,
		    enum intel_platform p)
{
	const unsigned int pbits =
		BITS_PER_TYPE(info->platform_mask[0]) - INTEL_SUBPLATFORM_BITS;

	return p % pbits + INTEL_SUBPLATFORM_BITS;
}

static inline u32
intel_subplatform(const struct intel_runtime_info *info, enum intel_platform p)
{
	const unsigned int pi = __platform_mask_index(info, p);

	return info->platform_mask[pi] & INTEL_SUBPLATFORM_MASK;
}

static __always_inline bool
IS_PLATFORM(const struct drm_i915_private *i915, enum intel_platform p)
{
	const struct intel_runtime_info *info = RUNTIME_INFO(i915);
	const unsigned int pi = __platform_mask_index(info, p);
	const unsigned int pb = __platform_mask_bit(info, p);

	BUILD_BUG_ON(!__builtin_constant_p(p));

	return info->platform_mask[pi] & BIT(pb);
}

static __always_inline bool
IS_SUBPLATFORM(const struct drm_i915_private *i915,
	       enum intel_platform p, unsigned int s)
{
	const struct intel_runtime_info *info = RUNTIME_INFO(i915);
	const unsigned int pi = __platform_mask_index(info, p);
	const unsigned int pb = __platform_mask_bit(info, p);
	const unsigned int msb = BITS_PER_TYPE(info->platform_mask[0]) - 1;
	const u32 mask = info->platform_mask[pi];

	BUILD_BUG_ON(!__builtin_constant_p(p));
	BUILD_BUG_ON(!__builtin_constant_p(s));
	BUILD_BUG_ON((s) >= INTEL_SUBPLATFORM_BITS);

	/* Shift and test on the MSB position so sign flag can be used. */
	return ((mask << (msb - pb)) & (mask << (msb - s))) & BIT(msb);
}

#define IS_MOBILE(i915)	(INTEL_INFO(i915)->is_mobile)
#define IS_DGFX(i915)   (INTEL_INFO(i915)->is_dgfx)

#define IS_I830(i915)	IS_PLATFORM(i915, INTEL_I830)
#define IS_I845G(i915)	IS_PLATFORM(i915, INTEL_I845G)
#define IS_I85X(i915)	IS_PLATFORM(i915, INTEL_I85X)
#define IS_I865G(i915)	IS_PLATFORM(i915, INTEL_I865G)
#define IS_I915G(i915)	IS_PLATFORM(i915, INTEL_I915G)
#define IS_I915GM(i915)	IS_PLATFORM(i915, INTEL_I915GM)
#define IS_I945G(i915)	IS_PLATFORM(i915, INTEL_I945G)
#define IS_I945GM(i915)	IS_PLATFORM(i915, INTEL_I945GM)
#define IS_I965G(i915)	IS_PLATFORM(i915, INTEL_I965G)
#define IS_I965GM(i915)	IS_PLATFORM(i915, INTEL_I965GM)
#define IS_G45(i915)	IS_PLATFORM(i915, INTEL_G45)
#define IS_GM45(i915)	IS_PLATFORM(i915, INTEL_GM45)
#define IS_G4X(i915)	(IS_G45(i915) || IS_GM45(i915))
#define IS_PINEVIEW(i915)	IS_PLATFORM(i915, INTEL_PINEVIEW)
#define IS_G33(i915)	IS_PLATFORM(i915, INTEL_G33)
#define IS_IRONLAKE(i915)	IS_PLATFORM(i915, INTEL_IRONLAKE)
#define IS_IRONLAKE_M(i915) \
	(IS_PLATFORM(i915, INTEL_IRONLAKE) && IS_MOBILE(i915))
#define IS_SANDYBRIDGE(i915) IS_PLATFORM(i915, INTEL_SANDYBRIDGE)
#define IS_IVYBRIDGE(i915)	IS_PLATFORM(i915, INTEL_IVYBRIDGE)
#define IS_IVB_GT1(i915)	(IS_IVYBRIDGE(i915) && \
				 INTEL_INFO(i915)->gt == 1)
#define IS_VALLEYVIEW(i915)	IS_PLATFORM(i915, INTEL_VALLEYVIEW)
#define IS_CHERRYVIEW(i915)	IS_PLATFORM(i915, INTEL_CHERRYVIEW)
#define IS_HASWELL(i915)	IS_PLATFORM(i915, INTEL_HASWELL)
#define IS_BROADWELL(i915)	IS_PLATFORM(i915, INTEL_BROADWELL)
#define IS_SKYLAKE(i915)	IS_PLATFORM(i915, INTEL_SKYLAKE)
#define IS_BROXTON(i915)	IS_PLATFORM(i915, INTEL_BROXTON)
#define IS_KABYLAKE(i915)	IS_PLATFORM(i915, INTEL_KABYLAKE)
#define IS_GEMINILAKE(i915)	IS_PLATFORM(i915, INTEL_GEMINILAKE)
#define IS_COFFEELAKE(i915)	IS_PLATFORM(i915, INTEL_COFFEELAKE)
#define IS_COMETLAKE(i915)	IS_PLATFORM(i915, INTEL_COMETLAKE)
#define IS_ICELAKE(i915)	IS_PLATFORM(i915, INTEL_ICELAKE)
#define IS_JASPERLAKE(i915)	IS_PLATFORM(i915, INTEL_JASPERLAKE)
#define IS_ELKHARTLAKE(i915)	IS_PLATFORM(i915, INTEL_ELKHARTLAKE)
#define IS_TIGERLAKE(i915)	IS_PLATFORM(i915, INTEL_TIGERLAKE)
#define IS_ROCKETLAKE(i915)	IS_PLATFORM(i915, INTEL_ROCKETLAKE)
#define IS_DG1(i915)        IS_PLATFORM(i915, INTEL_DG1)
#define IS_ALDERLAKE_S(i915) IS_PLATFORM(i915, INTEL_ALDERLAKE_S)
#define IS_ALDERLAKE_P(i915) IS_PLATFORM(i915, INTEL_ALDERLAKE_P)
#define IS_XEHPSDV(i915) IS_PLATFORM(i915, INTEL_XEHPSDV)
#define IS_DG2(i915)	IS_PLATFORM(i915, INTEL_DG2)
#define IS_PONTEVECCHIO(i915) IS_PLATFORM(i915, INTEL_PONTEVECCHIO)
#define IS_METEORLAKE(i915) IS_PLATFORM(i915, INTEL_METEORLAKE)

#define IS_METEORLAKE_M(i915) \
	IS_SUBPLATFORM(i915, INTEL_METEORLAKE, INTEL_SUBPLATFORM_M)
#define IS_METEORLAKE_P(i915) \
	IS_SUBPLATFORM(i915, INTEL_METEORLAKE, INTEL_SUBPLATFORM_P)
#define IS_DG2_G10(i915) \
	IS_SUBPLATFORM(i915, INTEL_DG2, INTEL_SUBPLATFORM_G10)
#define IS_DG2_G11(i915) \
	IS_SUBPLATFORM(i915, INTEL_DG2, INTEL_SUBPLATFORM_G11)
#define IS_DG2_G12(i915) \
	IS_SUBPLATFORM(i915, INTEL_DG2, INTEL_SUBPLATFORM_G12)
#define IS_RAPTORLAKE_S(i915) \
	IS_SUBPLATFORM(i915, INTEL_ALDERLAKE_S, INTEL_SUBPLATFORM_RPL)
#define IS_ALDERLAKE_P_N(i915) \
	IS_SUBPLATFORM(i915, INTEL_ALDERLAKE_P, INTEL_SUBPLATFORM_N)
#define IS_RAPTORLAKE_P(i915) \
	IS_SUBPLATFORM(i915, INTEL_ALDERLAKE_P, INTEL_SUBPLATFORM_RPL)
#define IS_RAPTORLAKE_U(i915) \
	IS_SUBPLATFORM(i915, INTEL_ALDERLAKE_P, INTEL_SUBPLATFORM_RPLU)
#define IS_HASWELL_EARLY_SDV(i915) (IS_HASWELL(i915) && \
				    (INTEL_DEVID(i915) & 0xFF00) == 0x0C00)
#define IS_BROADWELL_ULT(i915) \
	IS_SUBPLATFORM(i915, INTEL_BROADWELL, INTEL_SUBPLATFORM_ULT)
#define IS_BROADWELL_ULX(i915) \
	IS_SUBPLATFORM(i915, INTEL_BROADWELL, INTEL_SUBPLATFORM_ULX)
#define IS_BROADWELL_GT3(i915)	(IS_BROADWELL(i915) && \
				 INTEL_INFO(i915)->gt == 3)
#define IS_HASWELL_ULT(i915) \
	IS_SUBPLATFORM(i915, INTEL_HASWELL, INTEL_SUBPLATFORM_ULT)
#define IS_HASWELL_GT3(i915)	(IS_HASWELL(i915) && \
				 INTEL_INFO(i915)->gt == 3)
#define IS_HASWELL_GT1(i915)	(IS_HASWELL(i915) && \
				 INTEL_INFO(i915)->gt == 1)
/* ULX machines are also considered ULT. */
#define IS_HASWELL_ULX(i915) \
	IS_SUBPLATFORM(i915, INTEL_HASWELL, INTEL_SUBPLATFORM_ULX)
#define IS_SKYLAKE_ULT(i915) \
	IS_SUBPLATFORM(i915, INTEL_SKYLAKE, INTEL_SUBPLATFORM_ULT)
#define IS_SKYLAKE_ULX(i915) \
	IS_SUBPLATFORM(i915, INTEL_SKYLAKE, INTEL_SUBPLATFORM_ULX)
#define IS_KABYLAKE_ULT(i915) \
	IS_SUBPLATFORM(i915, INTEL_KABYLAKE, INTEL_SUBPLATFORM_ULT)
#define IS_KABYLAKE_ULX(i915) \
	IS_SUBPLATFORM(i915, INTEL_KABYLAKE, INTEL_SUBPLATFORM_ULX)
#define IS_SKYLAKE_GT2(i915)	(IS_SKYLAKE(i915) && \
				 INTEL_INFO(i915)->gt == 2)
#define IS_SKYLAKE_GT3(i915)	(IS_SKYLAKE(i915) && \
				 INTEL_INFO(i915)->gt == 3)
#define IS_SKYLAKE_GT4(i915)	(IS_SKYLAKE(i915) && \
				 INTEL_INFO(i915)->gt == 4)
#define IS_KABYLAKE_GT2(i915)	(IS_KABYLAKE(i915) && \
				 INTEL_INFO(i915)->gt == 2)
#define IS_KABYLAKE_GT3(i915)	(IS_KABYLAKE(i915) && \
				 INTEL_INFO(i915)->gt == 3)
#define IS_COFFEELAKE_ULT(i915) \
	IS_SUBPLATFORM(i915, INTEL_COFFEELAKE, INTEL_SUBPLATFORM_ULT)
#define IS_COFFEELAKE_ULX(i915) \
	IS_SUBPLATFORM(i915, INTEL_COFFEELAKE, INTEL_SUBPLATFORM_ULX)
#define IS_COFFEELAKE_GT2(i915)	(IS_COFFEELAKE(i915) && \
				 INTEL_INFO(i915)->gt == 2)
#define IS_COFFEELAKE_GT3(i915)	(IS_COFFEELAKE(i915) && \
				 INTEL_INFO(i915)->gt == 3)

#define IS_COMETLAKE_ULT(i915) \
	IS_SUBPLATFORM(i915, INTEL_COMETLAKE, INTEL_SUBPLATFORM_ULT)
#define IS_COMETLAKE_ULX(i915) \
	IS_SUBPLATFORM(i915, INTEL_COMETLAKE, INTEL_SUBPLATFORM_ULX)
#define IS_COMETLAKE_GT2(i915)	(IS_COMETLAKE(i915) && \
				 INTEL_INFO(i915)->gt == 2)

#define IS_ICL_WITH_PORT_F(i915) \
	IS_SUBPLATFORM(i915, INTEL_ICELAKE, INTEL_SUBPLATFORM_PORTF)

#define IS_TIGERLAKE_UY(i915) \
	IS_SUBPLATFORM(i915, INTEL_TIGERLAKE, INTEL_SUBPLATFORM_UY)








#define IS_XEHPSDV_GRAPHICS_STEP(__i915, since, until) \
	(IS_XEHPSDV(__i915) && IS_GRAPHICS_STEP(__i915, since, until))

#define IS_MTL_DISPLAY_STEP(__i915, since, until) \
	(IS_METEORLAKE(__i915) && \
	 IS_DISPLAY_STEP(__i915, since, until))

#define IS_MTL_MEDIA_STEP(__i915, since, until) \
	(IS_METEORLAKE(__i915) && \
	 IS_MEDIA_STEP(__i915, since, until))

/*
 * DG2 hardware steppings are a bit unusual.  The hardware design was forked to
 * create three variants (G10, G11, and G12) which each have distinct
 * workaround sets.  The G11 and G12 forks of the DG2 design reset the GT
 * stepping back to "A0" for their first iterations, even though they're more
 * similar to a G10 B0 stepping and G10 C0 stepping respectively in terms of
 * functionality and workarounds.  However the display stepping does not reset
 * in the same manner --- a specific stepping like "B0" has a consistent
 * meaning regardless of whether it belongs to a G10, G11, or G12 DG2.
 *
 * TLDR:  All GT workarounds and stepping-specific logic must be applied in
 * relation to a specific subplatform (G10/G11/G12), whereas display workarounds
 * and stepping-specific logic will be applied with a general DG2-wide stepping
 * number.
 */
#define IS_DG2_GRAPHICS_STEP(__i915, variant, since, until) \
	(IS_SUBPLATFORM(__i915, INTEL_DG2, INTEL_SUBPLATFORM_##variant) && \
	 IS_GRAPHICS_STEP(__i915, since, until))

#define IS_DG2_DISPLAY_STEP(__i915, since, until) \
	(IS_DG2(__i915) && \
	 IS_DISPLAY_STEP(__i915, since, until))

#define IS_PVC_BD_STEP(__i915, since, until) \
	(IS_PONTEVECCHIO(__i915) && \
	 IS_BASEDIE_STEP(__i915, since, until))

#define IS_PVC_CT_STEP(__i915, since, until) \
	(IS_PONTEVECCHIO(__i915) && \
	 IS_GRAPHICS_STEP(__i915, since, until))

#define IS_LP(i915)		(INTEL_INFO(i915)->is_lp)
#define IS_GEN9_LP(i915)	(GRAPHICS_VER(i915) == 9 && IS_LP(i915))
#define IS_GEN9_BC(i915)	(GRAPHICS_VER(i915) == 9 && !IS_LP(i915))

#define __HAS_ENGINE(engine_mask, id) ((engine_mask) & BIT(id))
#define HAS_ENGINE(gt, id) __HAS_ENGINE((gt)->info.engine_mask, id)

#define __ENGINE_INSTANCES_MASK(mask, first, count) ({			\
	unsigned int first__ = (first);					\
	unsigned int count__ = (count);					\
	((mask) & GENMASK(first__ + count__ - 1, first__)) >> first__;	\
})

#define ENGINE_INSTANCES_MASK(gt, first, count) \
	__ENGINE_INSTANCES_MASK((gt)->info.engine_mask, first, count)

#define RCS_MASK(gt) \
	ENGINE_INSTANCES_MASK(gt, RCS0, I915_MAX_RCS)
#define BCS_MASK(gt) \
	ENGINE_INSTANCES_MASK(gt, BCS0, I915_MAX_BCS)
#define VDBOX_MASK(gt) \
	ENGINE_INSTANCES_MASK(gt, VCS0, I915_MAX_VCS)
#define VEBOX_MASK(gt) \
	ENGINE_INSTANCES_MASK(gt, VECS0, I915_MAX_VECS)
#define CCS_MASK(gt) \
	ENGINE_INSTANCES_MASK(gt, CCS0, I915_MAX_CCS)

#define HAS_MEDIA_RATIO_MODE(i915) (INTEL_INFO(i915)->has_media_ratio_mode)

/*
 * The Gen7 cmdparser copies the scanned buffer to the ggtt for execution
 * All later gens can run the final buffer from the ppgtt
 */
#define CMDPARSER_USES_GGTT(i915) (GRAPHICS_VER(i915) == 7)

#define HAS_LLC(i915)	(INTEL_INFO(i915)->has_llc)
#define HAS_4TILE(i915)	(INTEL_INFO(i915)->has_4tile)
#define HAS_SNOOP(i915)	(INTEL_INFO(i915)->has_snoop)
#define HAS_EDRAM(i915)	((i915)->edram_size_mb)
#define HAS_SECURE_BATCHES(i915) (GRAPHICS_VER(i915) < 6)
#define HAS_WT(i915)	HAS_EDRAM(i915)

#define HWS_NEEDS_PHYSICAL(i915)	(INTEL_INFO(i915)->hws_needs_physical)

#define HAS_LOGICAL_RING_CONTEXTS(i915) \
		(INTEL_INFO(i915)->has_logical_ring_contexts)
#define HAS_LOGICAL_RING_ELSQ(i915) \
		(INTEL_INFO(i915)->has_logical_ring_elsq)

#define HAS_EXECLISTS(i915) HAS_LOGICAL_RING_CONTEXTS(i915)

<<<<<<< HEAD
#define INTEL_PPGTT(i915) (RUNTIME_INFO(i915)->ppgtt_type)
#define HAS_PPGTT(i915) \
	(INTEL_PPGTT(i915) != INTEL_PPGTT_NONE)
#define HAS_FULL_PPGTT(i915) \
	(INTEL_PPGTT(i915) >= INTEL_PPGTT_FULL)

#define HAS_PAGE_SIZES(i915, sizes) ({ \
=======
/**
 * for_each_sgt_dma - iterate over the DMA addresses of the given sg_table
 * @__dmap:	DMA address (output)
 * @__iter:	'struct sgt_iter' (iterator state, internal)
 * @__sgt:	sg_table to iterate over (input)
 */
#define for_each_sgt_dma(__dmap, __iter, __sgt)				\
	for ((__iter) = __sgt_iter((__sgt)->sgl, true);			\
	     ((__dmap) = (__iter).dma + (__iter).curr);			\
	     (((__iter).curr += I915_GTT_PAGE_SIZE) >= (__iter).max) ?	\
	     (__iter) = __sgt_iter(__sg_next((__iter).sgp), true), 0 : 0)

/**
 * for_each_sgt_page - iterate over the pages of the given sg_table
 * @__pp:	page pointer (output)
 * @__iter:	'struct sgt_iter' (iterator state, internal)
 * @__sgt:	sg_table to iterate over (input)
 */
#define for_each_sgt_page(__pp, __iter, __sgt)				\
	for ((__iter) = __sgt_iter((__sgt)->sgl, false);		\
	     ((__pp) = (__iter).pfn == 0 ? NULL :			\
	      pfn_to_page((__iter).pfn + ((__iter).curr >> PAGE_SHIFT))); \
	     (((__iter).curr += PAGE_SIZE) >= (__iter).max) ?		\
	     (__iter) = __sgt_iter(__sg_next((__iter).sgp), false), 0 : 0)

static inline unsigned int i915_sg_page_sizes(struct scatterlist *sg)
{
	unsigned int page_sizes;

	page_sizes = 0;
	while (sg) {
		GEM_BUG_ON(sg->offset);
		GEM_BUG_ON(!IS_ALIGNED(sg->length, PAGE_SIZE));
		page_sizes |= sg->length;
		sg = __sg_next(sg);
	}

	return page_sizes;
}

static inline unsigned int i915_sg_segment_size(void)
{
	unsigned int size = swiotlb_max_segment();

	if (size == 0)
		return SCATTERLIST_MAX_SEGMENT;

	size = rounddown(size, PAGE_SIZE);
	/* swiotlb_max_segment_size can return 1 byte when it means one page. */
	if (size < PAGE_SIZE)
		size = PAGE_SIZE;

	return size;
}

static inline const struct intel_device_info *
intel_info(const struct drm_i915_private *dev_priv)
{
	return &dev_priv->info;
}

#define INTEL_INFO(dev_priv)	intel_info((dev_priv))
#define DRIVER_CAPS(dev_priv)	(&(dev_priv)->caps)

#define INTEL_GEN(dev_priv)	((dev_priv)->info.gen)
#define INTEL_DEVID(dev_priv)	((dev_priv)->info.device_id)

#define REVID_FOREVER		0xff
#define INTEL_REVID(dev_priv)	((dev_priv)->drm.pdev->revision)

#define GEN_FOREVER (0)

#define INTEL_GEN_MASK(s, e) ( \
	BUILD_BUG_ON_ZERO(!__builtin_constant_p(s)) + \
	BUILD_BUG_ON_ZERO(!__builtin_constant_p(e)) + \
	GENMASK((e) != GEN_FOREVER ? (e) - 1 : BITS_PER_LONG - 1, \
		(s) != GEN_FOREVER ? (s) - 1 : 0) \
)

/*
 * Returns true if Gen is in inclusive range [Start, End].
 *
 * Use GEN_FOREVER for unbound start and or end.
 */
#define IS_GEN(dev_priv, s, e) \
	(!!((dev_priv)->info.gen_mask & INTEL_GEN_MASK((s), (e))))

/*
 * Return true if revision is in range [since,until] inclusive.
 *
 * Use 0 for open-ended since, and REVID_FOREVER for open-ended until.
 */
#define IS_REVID(p, since, until) \
	(INTEL_REVID(p) >= (since) && INTEL_REVID(p) <= (until))

#define IS_PLATFORM(dev_priv, p) ((dev_priv)->info.platform_mask & BIT(p))

#define IS_I830(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I830)
#define IS_I845G(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I845G)
#define IS_I85X(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I85X)
#define IS_I865G(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I865G)
#define IS_I915G(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I915G)
#define IS_I915GM(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I915GM)
#define IS_I945G(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I945G)
#define IS_I945GM(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I945GM)
#define IS_I965G(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I965G)
#define IS_I965GM(dev_priv)	IS_PLATFORM(dev_priv, INTEL_I965GM)
#define IS_G45(dev_priv)	IS_PLATFORM(dev_priv, INTEL_G45)
#define IS_GM45(dev_priv)	IS_PLATFORM(dev_priv, INTEL_GM45)
#define IS_G4X(dev_priv)	(IS_G45(dev_priv) || IS_GM45(dev_priv))
#define IS_PINEVIEW_G(dev_priv)	(INTEL_DEVID(dev_priv) == 0xa001)
#define IS_PINEVIEW_M(dev_priv)	(INTEL_DEVID(dev_priv) == 0xa011)
#define IS_PINEVIEW(dev_priv)	IS_PLATFORM(dev_priv, INTEL_PINEVIEW)
#define IS_G33(dev_priv)	IS_PLATFORM(dev_priv, INTEL_G33)
#define IS_IRONLAKE_M(dev_priv)	(INTEL_DEVID(dev_priv) == 0x0046)
#define IS_IVYBRIDGE(dev_priv)	IS_PLATFORM(dev_priv, INTEL_IVYBRIDGE)
#define IS_IVB_GT1(dev_priv)	(IS_IVYBRIDGE(dev_priv) && \
				 (dev_priv)->info.gt == 1)
#define IS_VALLEYVIEW(dev_priv)	IS_PLATFORM(dev_priv, INTEL_VALLEYVIEW)
#define IS_CHERRYVIEW(dev_priv)	IS_PLATFORM(dev_priv, INTEL_CHERRYVIEW)
#define IS_HASWELL(dev_priv)	IS_PLATFORM(dev_priv, INTEL_HASWELL)
#define IS_BROADWELL(dev_priv)	IS_PLATFORM(dev_priv, INTEL_BROADWELL)
#define IS_SKYLAKE(dev_priv)	IS_PLATFORM(dev_priv, INTEL_SKYLAKE)
#define IS_BROXTON(dev_priv)	IS_PLATFORM(dev_priv, INTEL_BROXTON)
#define IS_KABYLAKE(dev_priv)	IS_PLATFORM(dev_priv, INTEL_KABYLAKE)
#define IS_GEMINILAKE(dev_priv)	IS_PLATFORM(dev_priv, INTEL_GEMINILAKE)
#define IS_COFFEELAKE(dev_priv)	IS_PLATFORM(dev_priv, INTEL_COFFEELAKE)
#define IS_CANNONLAKE(dev_priv)	IS_PLATFORM(dev_priv, INTEL_CANNONLAKE)
#define IS_ICELAKE(dev_priv)	IS_PLATFORM(dev_priv, INTEL_ICELAKE)
#define IS_MOBILE(dev_priv)	((dev_priv)->info.is_mobile)
#define IS_HSW_EARLY_SDV(dev_priv) (IS_HASWELL(dev_priv) && \
				    (INTEL_DEVID(dev_priv) & 0xFF00) == 0x0C00)
#define IS_BDW_ULT(dev_priv)	(IS_BROADWELL(dev_priv) && \
				 ((INTEL_DEVID(dev_priv) & 0xf) == 0x6 ||	\
				 (INTEL_DEVID(dev_priv) & 0xf) == 0xb ||	\
				 (INTEL_DEVID(dev_priv) & 0xf) == 0xe))
/* ULX machines are also considered ULT. */
#define IS_BDW_ULX(dev_priv)	(IS_BROADWELL(dev_priv) && \
				 (INTEL_DEVID(dev_priv) & 0xf) == 0xe)
#define IS_BDW_GT3(dev_priv)	(IS_BROADWELL(dev_priv) && \
				 (dev_priv)->info.gt == 3)
#define IS_HSW_ULT(dev_priv)	(IS_HASWELL(dev_priv) && \
				 (INTEL_DEVID(dev_priv) & 0xFF00) == 0x0A00)
#define IS_HSW_GT3(dev_priv)	(IS_HASWELL(dev_priv) && \
				 (dev_priv)->info.gt == 3)
/* ULX machines are also considered ULT. */
#define IS_HSW_ULX(dev_priv)	(INTEL_DEVID(dev_priv) == 0x0A0E || \
				 INTEL_DEVID(dev_priv) == 0x0A1E)
#define IS_SKL_ULT(dev_priv)	(INTEL_DEVID(dev_priv) == 0x1906 || \
				 INTEL_DEVID(dev_priv) == 0x1913 || \
				 INTEL_DEVID(dev_priv) == 0x1916 || \
				 INTEL_DEVID(dev_priv) == 0x1921 || \
				 INTEL_DEVID(dev_priv) == 0x1926)
#define IS_SKL_ULX(dev_priv)	(INTEL_DEVID(dev_priv) == 0x190E || \
				 INTEL_DEVID(dev_priv) == 0x1915 || \
				 INTEL_DEVID(dev_priv) == 0x191E)
#define IS_KBL_ULT(dev_priv)	(INTEL_DEVID(dev_priv) == 0x5906 || \
				 INTEL_DEVID(dev_priv) == 0x5913 || \
				 INTEL_DEVID(dev_priv) == 0x5916 || \
				 INTEL_DEVID(dev_priv) == 0x5921 || \
				 INTEL_DEVID(dev_priv) == 0x5926)
#define IS_KBL_ULX(dev_priv)	(INTEL_DEVID(dev_priv) == 0x590E || \
				 INTEL_DEVID(dev_priv) == 0x5915 || \
				 INTEL_DEVID(dev_priv) == 0x591E)
#define IS_SKL_GT2(dev_priv)	(IS_SKYLAKE(dev_priv) && \
				 (dev_priv)->info.gt == 2)
#define IS_SKL_GT3(dev_priv)	(IS_SKYLAKE(dev_priv) && \
				 (dev_priv)->info.gt == 3)
#define IS_SKL_GT4(dev_priv)	(IS_SKYLAKE(dev_priv) && \
				 (dev_priv)->info.gt == 4)
#define IS_KBL_GT2(dev_priv)	(IS_KABYLAKE(dev_priv) && \
				 (dev_priv)->info.gt == 2)
#define IS_KBL_GT3(dev_priv)	(IS_KABYLAKE(dev_priv) && \
				 (dev_priv)->info.gt == 3)
#define IS_CFL_ULT(dev_priv)	(IS_COFFEELAKE(dev_priv) && \
				 (INTEL_DEVID(dev_priv) & 0x00F0) == 0x00A0)
#define IS_CFL_GT2(dev_priv)	(IS_COFFEELAKE(dev_priv) && \
				 (dev_priv)->info.gt == 2)
#define IS_CFL_GT3(dev_priv)	(IS_COFFEELAKE(dev_priv) && \
				 (dev_priv)->info.gt == 3)
#define IS_CNL_WITH_PORT_F(dev_priv)   (IS_CANNONLAKE(dev_priv) && \
					(INTEL_DEVID(dev_priv) & 0x0004) == 0x0004)

#define IS_ALPHA_SUPPORT(intel_info) ((intel_info)->is_alpha_support)

#define SKL_REVID_A0		0x0
#define SKL_REVID_B0		0x1
#define SKL_REVID_C0		0x2
#define SKL_REVID_D0		0x3
#define SKL_REVID_E0		0x4
#define SKL_REVID_F0		0x5
#define SKL_REVID_G0		0x6
#define SKL_REVID_H0		0x7

#define IS_SKL_REVID(p, since, until) (IS_SKYLAKE(p) && IS_REVID(p, since, until))

#define BXT_REVID_A0		0x0
#define BXT_REVID_A1		0x1
#define BXT_REVID_B0		0x3
#define BXT_REVID_B_LAST	0x8
#define BXT_REVID_C0		0x9

#define IS_BXT_REVID(dev_priv, since, until) \
	(IS_BROXTON(dev_priv) && IS_REVID(dev_priv, since, until))

#define KBL_REVID_A0		0x0
#define KBL_REVID_B0		0x1
#define KBL_REVID_C0		0x2
#define KBL_REVID_D0		0x3
#define KBL_REVID_E0		0x4

#define IS_KBL_REVID(dev_priv, since, until) \
	(IS_KABYLAKE(dev_priv) && IS_REVID(dev_priv, since, until))

#define GLK_REVID_A0		0x0
#define GLK_REVID_A1		0x1

#define IS_GLK_REVID(dev_priv, since, until) \
	(IS_GEMINILAKE(dev_priv) && IS_REVID(dev_priv, since, until))

#define CNL_REVID_A0		0x0
#define CNL_REVID_B0		0x1
#define CNL_REVID_C0		0x2

#define IS_CNL_REVID(p, since, until) \
	(IS_CANNONLAKE(p) && IS_REVID(p, since, until))

#define ICL_REVID_A0		0x0
#define ICL_REVID_A2		0x1
#define ICL_REVID_B0		0x3
#define ICL_REVID_B2		0x4
#define ICL_REVID_C0		0x5

#define IS_ICL_REVID(p, since, until) \
	(IS_ICELAKE(p) && IS_REVID(p, since, until))

/*
 * The genX designation typically refers to the render engine, so render
 * capability related checks should use IS_GEN, while display and other checks
 * have their own (e.g. HAS_PCH_SPLIT for ILK+ display, IS_foo for particular
 * chips, etc.).
 */
#define IS_GEN2(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(1)))
#define IS_GEN3(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(2)))
#define IS_GEN4(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(3)))
#define IS_GEN5(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(4)))
#define IS_GEN6(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(5)))
#define IS_GEN7(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(6)))
#define IS_GEN8(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(7)))
#define IS_GEN9(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(8)))
#define IS_GEN10(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(9)))
#define IS_GEN11(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(10)))

#define IS_LP(dev_priv)	(INTEL_INFO(dev_priv)->is_lp)
#define IS_GEN9_LP(dev_priv)	(IS_GEN9(dev_priv) && IS_LP(dev_priv))
#define IS_GEN9_BC(dev_priv)	(IS_GEN9(dev_priv) && !IS_LP(dev_priv))

/*
 * The Gen7 cmdparser copies the scanned buffer to the ggtt for execution
 * All later gens can run the final buffer from the ppgtt
 */
#define CMDPARSER_USES_GGTT(dev_priv) IS_GEN7(dev_priv)

#define ENGINE_MASK(id)	BIT(id)
#define RENDER_RING	ENGINE_MASK(RCS)
#define BSD_RING	ENGINE_MASK(VCS)
#define BLT_RING	ENGINE_MASK(BCS)
#define VEBOX_RING	ENGINE_MASK(VECS)
#define BSD2_RING	ENGINE_MASK(VCS2)
#define BSD3_RING	ENGINE_MASK(VCS3)
#define BSD4_RING	ENGINE_MASK(VCS4)
#define VEBOX2_RING	ENGINE_MASK(VECS2)
#define ALL_ENGINES	(~0)

#define HAS_ENGINE(dev_priv, id) \
	(!!((dev_priv)->info.ring_mask & ENGINE_MASK(id)))

#define HAS_BSD(dev_priv)	HAS_ENGINE(dev_priv, VCS)
#define HAS_BSD2(dev_priv)	HAS_ENGINE(dev_priv, VCS2)
#define HAS_BLT(dev_priv)	HAS_ENGINE(dev_priv, BCS)
#define HAS_VEBOX(dev_priv)	HAS_ENGINE(dev_priv, VECS)

#define HAS_LEGACY_SEMAPHORES(dev_priv) IS_GEN7(dev_priv)

#define HAS_SECURE_BATCHES(dev_priv) (INTEL_GEN(dev_priv) < 6)

#define HAS_LLC(dev_priv)	((dev_priv)->info.has_llc)
#define HAS_SNOOP(dev_priv)	((dev_priv)->info.has_snoop)
#define HAS_EDRAM(dev_priv)	(!!((dev_priv)->edram_cap & EDRAM_ENABLED))
#define HAS_WT(dev_priv)	((IS_HASWELL(dev_priv) || \
				 IS_BROADWELL(dev_priv)) && HAS_EDRAM(dev_priv))

#define HWS_NEEDS_PHYSICAL(dev_priv)	((dev_priv)->info.hws_needs_physical)

#define HAS_LOGICAL_RING_CONTEXTS(dev_priv) \
		((dev_priv)->info.has_logical_ring_contexts)
#define HAS_LOGICAL_RING_ELSQ(dev_priv) \
		((dev_priv)->info.has_logical_ring_elsq)
#define HAS_LOGICAL_RING_PREEMPTION(dev_priv) \
		((dev_priv)->info.has_logical_ring_preemption)

#define HAS_EXECLISTS(dev_priv) HAS_LOGICAL_RING_CONTEXTS(dev_priv)

#define USES_PPGTT(dev_priv)		(i915_modparams.enable_ppgtt)
#define USES_FULL_PPGTT(dev_priv)	(i915_modparams.enable_ppgtt >= 2)
#define USES_FULL_48BIT_PPGTT(dev_priv)	(i915_modparams.enable_ppgtt == 3)
#define HAS_PAGE_SIZES(dev_priv, sizes) ({ \
>>>>>>> master
	GEM_BUG_ON((sizes) == 0); \
	((sizes) & ~RUNTIME_INFO(i915)->page_sizes) == 0; \
})

/* Early gen2 have a totally busted CS tlb and require pinned batches. */
#define HAS_BROKEN_CS_TLB(i915)	(IS_I830(i915) || IS_I845G(i915))

#define NEEDS_RC6_CTX_CORRUPTION_WA(i915)	\
	(IS_BROADWELL(i915) || GRAPHICS_VER(i915) == 9)

#define NEEDS_RC6_CTX_CORRUPTION_WA(dev_priv)	\
	(IS_BROADWELL(dev_priv) || INTEL_GEN(dev_priv) == 9)

/* WaRsDisableCoarsePowerGating:skl,cnl */
<<<<<<< HEAD
#define NEEDS_WaRsDisableCoarsePowerGating(i915)			\
	(IS_SKYLAKE_GT3(i915) || IS_SKYLAKE_GT4(i915))
=======
#define NEEDS_WaRsDisableCoarsePowerGating(dev_priv) \
	(IS_CANNONLAKE(dev_priv) || INTEL_GEN(dev_priv) == 9)

#define HAS_GMBUS_IRQ(dev_priv) (INTEL_GEN(dev_priv) >= 4)
#define HAS_GMBUS_BURST_READ(dev_priv) (INTEL_GEN(dev_priv) >= 10 || \
					IS_GEMINILAKE(dev_priv) || \
					IS_KABYLAKE(dev_priv))
>>>>>>> master

/* With the 945 and later, Y tiling got adjusted so that it was 32 128-byte
 * rows, which changed the alignment requirements and fence programming.
 */
#define HAS_128_BYTE_Y_TILING(i915) (GRAPHICS_VER(i915) != 2 && \
					 !(IS_I915G(i915) || IS_I915GM(i915)))

#define HAS_RC6(i915)		 (INTEL_INFO(i915)->has_rc6)
#define HAS_RC6p(i915)		 (INTEL_INFO(i915)->has_rc6p)
#define HAS_RC6pp(i915)		 (false) /* HW was never validated */

#define HAS_RPS(i915)	(INTEL_INFO(i915)->has_rps)

#define HAS_HECI_PXP(i915) \
	(INTEL_INFO(i915)->has_heci_pxp)

#define HAS_HECI_GSCFI(i915) \
	(INTEL_INFO(i915)->has_heci_gscfi)

#define HAS_HECI_GSC(i915) (HAS_HECI_PXP(i915) || HAS_HECI_GSCFI(i915))

#define HAS_RUNTIME_PM(i915) (INTEL_INFO(i915)->has_runtime_pm)
#define HAS_64BIT_RELOC(i915) (INTEL_INFO(i915)->has_64bit_reloc)

#define HAS_OA_BPC_REPORTING(i915) \
	(INTEL_INFO(i915)->has_oa_bpc_reporting)
#define HAS_OA_SLICE_CONTRIB_LIMITS(i915) \
	(INTEL_INFO(i915)->has_oa_slice_contrib_limits)
#define HAS_OAM(i915) \
	(INTEL_INFO(i915)->has_oam)

/*
 * Set this flag, when platform requires 64K GTT page sizes or larger for
 * device local memory access.
 */
#define HAS_64K_PAGES(i915) (INTEL_INFO(i915)->has_64k_pages)

#define HAS_REGION(i915, i) (INTEL_INFO(i915)->memory_regions & (i))
#define HAS_LMEM(i915) HAS_REGION(i915, REGION_LMEM)

#define HAS_EXTRA_GT_LIST(i915)   (INTEL_INFO(i915)->extra_gt_list)

/*
 * Platform has the dedicated compression control state for each lmem surfaces
 * stored in lmem to support the 3D and media compression formats.
 */
#define HAS_FLAT_CCS(i915)   (INTEL_INFO(i915)->has_flat_ccs)

#define HAS_GT_UC(i915)	(INTEL_INFO(i915)->has_gt_uc)

#define HAS_POOLED_EU(i915)	(RUNTIME_INFO(i915)->has_pooled_eu)

#define HAS_GLOBAL_MOCS_REGISTERS(i915)	(INTEL_INFO(i915)->has_global_mocs)

#define HAS_GMD_ID(i915)	(INTEL_INFO(i915)->has_gmd_id)

#define HAS_L3_CCS_READ(i915) (INTEL_INFO(i915)->has_l3_ccs_read)

/* DPF == dynamic parity feature */
#define HAS_L3_DPF(i915) (INTEL_INFO(i915)->has_l3_dpf)
#define NUM_L3_SLICES(i915) (IS_HASWELL_GT3(i915) ? \
				 2 : HAS_L3_DPF(i915))

/* Only valid when HAS_DISPLAY() is true */
#define INTEL_DISPLAY_ENABLED(i915) \
	(drm_WARN_ON(&(i915)->drm, !HAS_DISPLAY(i915)),		\
	 !(i915)->params.disable_display &&				\
	 !intel_opregion_headless_sku(i915))

#define HAS_GUC_DEPRIVILEGE(i915) \
	(INTEL_INFO(i915)->has_guc_deprivilege)

#define HAS_3D_PIPELINE(i915)	(INTEL_INFO(i915)->has_3d_pipeline)

#define HAS_ONE_EU_PER_FUSE_BIT(i915)	(INTEL_INFO(i915)->has_one_eu_per_fuse_bit)

<<<<<<< HEAD
#define HAS_LMEMBAR_SMEM_STOLEN(i915) (!HAS_LMEM(i915) && \
				       GRAPHICS_VER_FULL(i915) >= IP_VER(12, 70))
=======
static inline bool
intel_ggtt_update_needs_vtd_wa(struct drm_i915_private *dev_priv)
{
	return IS_BROXTON(dev_priv) && intel_vtd_active();
}

int intel_sanitize_enable_ppgtt(struct drm_i915_private *dev_priv,
				int enable_ppgtt);

/* i915_drv.c */
void __printf(3, 4)
__i915_printk(struct drm_i915_private *dev_priv, const char *level,
	      const char *fmt, ...);

#define i915_report_error(dev_priv, fmt, ...)				   \
	__i915_printk(dev_priv, KERN_ERR, fmt, ##__VA_ARGS__)

#ifdef CONFIG_COMPAT
extern long i915_compat_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg);
#else
#define i915_compat_ioctl NULL
#endif
extern const struct dev_pm_ops i915_pm_ops;

extern int i915_driver_load(struct pci_dev *pdev,
			    const struct pci_device_id *ent);
extern void i915_driver_unload(struct drm_device *dev);
extern int intel_gpu_reset(struct drm_i915_private *dev_priv, u32 engine_mask);
extern bool intel_has_gpu_reset(struct drm_i915_private *dev_priv);

extern void i915_reset(struct drm_i915_private *i915,
		       unsigned int stalled_mask,
		       const char *reason);
extern int i915_reset_engine(struct intel_engine_cs *engine,
			     const char *reason);

extern bool intel_has_reset_engine(struct drm_i915_private *dev_priv);
extern int intel_reset_guc(struct drm_i915_private *dev_priv);
extern int intel_guc_reset_engine(struct intel_guc *guc,
				  struct intel_engine_cs *engine);
extern void intel_engine_init_hangcheck(struct intel_engine_cs *engine);
extern void intel_hangcheck_init(struct drm_i915_private *dev_priv);
extern unsigned long i915_chipset_val(struct drm_i915_private *dev_priv);
extern unsigned long i915_mch_val(struct drm_i915_private *dev_priv);
extern unsigned long i915_gfx_val(struct drm_i915_private *dev_priv);
extern void i915_update_gfx_val(struct drm_i915_private *dev_priv);
int vlv_force_gfx_clock(struct drm_i915_private *dev_priv, bool on);

int intel_engines_init_mmio(struct drm_i915_private *dev_priv);
int intel_engines_init(struct drm_i915_private *dev_priv);

u32 intel_calculate_mcr_s_ss_select(struct drm_i915_private *dev_priv);

/* intel_hotplug.c */
void intel_hpd_irq_handler(struct drm_i915_private *dev_priv,
			   u32 pin_mask, u32 long_mask);
void intel_hpd_init(struct drm_i915_private *dev_priv);
void intel_hpd_init_work(struct drm_i915_private *dev_priv);
void intel_hpd_cancel_work(struct drm_i915_private *dev_priv);
enum hpd_pin intel_hpd_pin_default(struct drm_i915_private *dev_priv,
				   enum port port);
bool intel_hpd_disable(struct drm_i915_private *dev_priv, enum hpd_pin pin);
void intel_hpd_enable(struct drm_i915_private *dev_priv, enum hpd_pin pin);

/* i915_irq.c */
static inline void i915_queue_hangcheck(struct drm_i915_private *dev_priv)
{
	unsigned long delay;

	if (unlikely(!i915_modparams.enable_hangcheck))
		return;

	/* Don't continually defer the hangcheck so that it is always run at
	 * least once after work has been scheduled on any ring. Otherwise,
	 * we will ignore a hung ring if a second ring is kept busy.
	 */

	delay = round_jiffies_up_relative(DRM_I915_HANGCHECK_JIFFIES);
	queue_delayed_work(system_long_wq,
			   &dev_priv->gpu_error.hangcheck_work, delay);
}

__printf(4, 5)
void i915_handle_error(struct drm_i915_private *dev_priv,
		       u32 engine_mask,
		       unsigned long flags,
		       const char *fmt, ...);
#define I915_ERROR_CAPTURE BIT(0)

extern void intel_irq_init(struct drm_i915_private *dev_priv);
extern void intel_irq_fini(struct drm_i915_private *dev_priv);
int intel_irq_install(struct drm_i915_private *dev_priv);
void intel_irq_uninstall(struct drm_i915_private *dev_priv);

static inline bool intel_gvt_active(struct drm_i915_private *dev_priv)
{
	return dev_priv->gvt;
}

static inline bool intel_vgpu_active(struct drm_i915_private *dev_priv)
{
	return dev_priv->vgpu.active;
}

u32 i915_pipestat_enable_mask(struct drm_i915_private *dev_priv,
			      enum pipe pipe);
void
i915_enable_pipestat(struct drm_i915_private *dev_priv, enum pipe pipe,
		     u32 status_mask);

void
i915_disable_pipestat(struct drm_i915_private *dev_priv, enum pipe pipe,
		      u32 status_mask);

void valleyview_enable_display_irqs(struct drm_i915_private *dev_priv);
void valleyview_disable_display_irqs(struct drm_i915_private *dev_priv);
void i915_hotplug_interrupt_update(struct drm_i915_private *dev_priv,
				   uint32_t mask,
				   uint32_t bits);
void ilk_update_display_irq(struct drm_i915_private *dev_priv,
			    uint32_t interrupt_mask,
			    uint32_t enabled_irq_mask);
static inline void
ilk_enable_display_irq(struct drm_i915_private *dev_priv, uint32_t bits)
{
	ilk_update_display_irq(dev_priv, bits, bits);
}
static inline void
ilk_disable_display_irq(struct drm_i915_private *dev_priv, uint32_t bits)
{
	ilk_update_display_irq(dev_priv, bits, 0);
}
void bdw_update_pipe_irq(struct drm_i915_private *dev_priv,
			 enum pipe pipe,
			 uint32_t interrupt_mask,
			 uint32_t enabled_irq_mask);
static inline void bdw_enable_pipe_irq(struct drm_i915_private *dev_priv,
				       enum pipe pipe, uint32_t bits)
{
	bdw_update_pipe_irq(dev_priv, pipe, bits, bits);
}
static inline void bdw_disable_pipe_irq(struct drm_i915_private *dev_priv,
					enum pipe pipe, uint32_t bits)
{
	bdw_update_pipe_irq(dev_priv, pipe, bits, 0);
}
void ibx_display_interrupt_update(struct drm_i915_private *dev_priv,
				  uint32_t interrupt_mask,
				  uint32_t enabled_irq_mask);
static inline void
ibx_enable_display_interrupt(struct drm_i915_private *dev_priv, uint32_t bits)
{
	ibx_display_interrupt_update(dev_priv, bits, bits);
}
static inline void
ibx_disable_display_interrupt(struct drm_i915_private *dev_priv, uint32_t bits)
{
	ibx_display_interrupt_update(dev_priv, bits, 0);
}

/* i915_gem.c */
int i915_gem_create_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *file_priv);
int i915_gem_pread_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv);
int i915_gem_pwrite_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *file_priv);
int i915_gem_mmap_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int i915_gem_mmap_gtt_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int i915_gem_set_domain_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);
int i915_gem_sw_finish_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file_priv);
int i915_gem_execbuffer_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);
int i915_gem_execbuffer2_ioctl(struct drm_device *dev, void *data,
			       struct drm_file *file_priv);
int i915_gem_busy_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int i915_gem_get_caching_ioctl(struct drm_device *dev, void *data,
			       struct drm_file *file);
int i915_gem_set_caching_ioctl(struct drm_device *dev, void *data,
			       struct drm_file *file);
int i915_gem_throttle_ioctl(struct drm_device *dev, void *data,
			    struct drm_file *file_priv);
int i915_gem_madvise_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);
int i915_gem_set_tiling_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);
int i915_gem_get_tiling_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);
int i915_gem_init_userptr(struct drm_i915_private *dev_priv);
void i915_gem_cleanup_userptr(struct drm_i915_private *dev_priv);
int i915_gem_userptr_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file);
int i915_gem_get_aperture_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file_priv);
int i915_gem_wait_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
void i915_gem_sanitize(struct drm_i915_private *i915);
int i915_gem_init_early(struct drm_i915_private *dev_priv);
void i915_gem_cleanup_early(struct drm_i915_private *dev_priv);
void i915_gem_load_init_fences(struct drm_i915_private *dev_priv);
int i915_gem_freeze(struct drm_i915_private *dev_priv);
int i915_gem_freeze_late(struct drm_i915_private *dev_priv);

void *i915_gem_object_alloc(struct drm_i915_private *dev_priv);
void i915_gem_object_free(struct drm_i915_gem_object *obj);
void i915_gem_object_init(struct drm_i915_gem_object *obj,
			 const struct drm_i915_gem_object_ops *ops);
struct drm_i915_gem_object *
i915_gem_object_create(struct drm_i915_private *dev_priv, u64 size);
struct drm_i915_gem_object *
i915_gem_object_create_from_data(struct drm_i915_private *dev_priv,
				 const void *data, size_t size);
void i915_gem_close_object(struct drm_gem_object *gem, struct drm_file *file);
void i915_gem_free_object(struct drm_gem_object *obj);

static inline void i915_gem_drain_freed_objects(struct drm_i915_private *i915)
{
	if (!atomic_read(&i915->mm.free_count))
		return;

	/* A single pass should suffice to release all the freed objects (along
	 * most call paths) , but be a little more paranoid in that freeing
	 * the objects does take a little amount of time, during which the rcu
	 * callbacks could have added new objects into the freed list, and
	 * armed the work again.
	 */
	do {
		rcu_barrier();
	} while (flush_work(&i915->mm.free_work));
}

static inline void i915_gem_drain_workqueue(struct drm_i915_private *i915)
{
	/*
	 * Similar to objects above (see i915_gem_drain_freed-objects), in
	 * general we have workers that are armed by RCU and then rearm
	 * themselves in their callbacks. To be paranoid, we need to
	 * drain the workqueue a second time after waiting for the RCU
	 * grace period so that we catch work queued via RCU from the first
	 * pass. As neither drain_workqueue() nor flush_workqueue() report
	 * a result, we make an assumption that we only don't require more
	 * than 2 passes to catch all recursive RCU delayed work.
	 *
	 */
	int pass = 2;
	do {
		rcu_barrier();
		drain_workqueue(i915->wq);
	} while (--pass);
}

struct i915_vma * __must_check
i915_gem_object_ggtt_pin(struct drm_i915_gem_object *obj,
			 const struct i915_ggtt_view *view,
			 u64 size,
			 u64 alignment,
			 u64 flags);

struct i915_vma * __must_check
i915_gem_object_pin(struct drm_i915_gem_object *obj,
		    struct i915_address_space *vm,
		    const struct i915_ggtt_view *view,
		    u64 size,
		    u64 alignment,
		    u64 flags);

int i915_gem_object_unbind(struct drm_i915_gem_object *obj);
void i915_gem_release_mmap(struct drm_i915_gem_object *obj);

void i915_gem_runtime_suspend(struct drm_i915_private *dev_priv);

static inline int __sg_page_count(const struct scatterlist *sg)
{
	return sg->length >> PAGE_SHIFT;
}

struct scatterlist *
i915_gem_object_get_sg(struct drm_i915_gem_object *obj,
		       unsigned int n, unsigned int *offset);

struct page *
i915_gem_object_get_page(struct drm_i915_gem_object *obj,
			 unsigned int n);

struct page *
i915_gem_object_get_dirty_page(struct drm_i915_gem_object *obj,
			       unsigned int n);

dma_addr_t
i915_gem_object_get_dma_address(struct drm_i915_gem_object *obj,
				unsigned long n);

void __i915_gem_object_set_pages(struct drm_i915_gem_object *obj,
				 struct sg_table *pages,
				 unsigned int sg_page_sizes);
int __i915_gem_object_get_pages(struct drm_i915_gem_object *obj);

static inline int __must_check
i915_gem_object_pin_pages(struct drm_i915_gem_object *obj)
{
	might_lock(&obj->mm.lock);

	if (atomic_inc_not_zero(&obj->mm.pages_pin_count))
		return 0;

	return __i915_gem_object_get_pages(obj);
}

static inline bool
i915_gem_object_has_pages(struct drm_i915_gem_object *obj)
{
	return !IS_ERR_OR_NULL(READ_ONCE(obj->mm.pages));
}

static inline void
__i915_gem_object_pin_pages(struct drm_i915_gem_object *obj)
{
	GEM_BUG_ON(!i915_gem_object_has_pages(obj));

	atomic_inc(&obj->mm.pages_pin_count);
}

static inline bool
i915_gem_object_has_pinned_pages(struct drm_i915_gem_object *obj)
{
	return atomic_read(&obj->mm.pages_pin_count);
}

static inline void
__i915_gem_object_unpin_pages(struct drm_i915_gem_object *obj)
{
	GEM_BUG_ON(!i915_gem_object_has_pages(obj));
	GEM_BUG_ON(!i915_gem_object_has_pinned_pages(obj));

	atomic_dec(&obj->mm.pages_pin_count);
}

static inline void
i915_gem_object_unpin_pages(struct drm_i915_gem_object *obj)
{
	__i915_gem_object_unpin_pages(obj);
}

enum i915_mm_subclass { /* lockdep subclass for obj->mm.lock */
	I915_MM_NORMAL = 0,
	I915_MM_SHRINKER
};

void __i915_gem_object_put_pages(struct drm_i915_gem_object *obj,
				 enum i915_mm_subclass subclass);
void __i915_gem_object_invalidate(struct drm_i915_gem_object *obj);

enum i915_map_type {
	I915_MAP_WB = 0,
	I915_MAP_WC,
#define I915_MAP_OVERRIDE BIT(31)
	I915_MAP_FORCE_WB = I915_MAP_WB | I915_MAP_OVERRIDE,
	I915_MAP_FORCE_WC = I915_MAP_WC | I915_MAP_OVERRIDE,
};

/**
 * i915_gem_object_pin_map - return a contiguous mapping of the entire object
 * @obj: the object to map into kernel address space
 * @type: the type of mapping, used to select pgprot_t
 *
 * Calls i915_gem_object_pin_pages() to prevent reaping of the object's
 * pages and then returns a contiguous mapping of the backing storage into
 * the kernel address space. Based on the @type of mapping, the PTE will be
 * set to either WriteBack or WriteCombine (via pgprot_t).
 *
 * The caller is responsible for calling i915_gem_object_unpin_map() when the
 * mapping is no longer required.
 *
 * Returns the pointer through which to access the mapped object, or an
 * ERR_PTR() on error.
 */
void *__must_check i915_gem_object_pin_map(struct drm_i915_gem_object *obj,
					   enum i915_map_type type);

/**
 * i915_gem_object_unpin_map - releases an earlier mapping
 * @obj: the object to unmap
 *
 * After pinning the object and mapping its pages, once you are finished
 * with your access, call i915_gem_object_unpin_map() to release the pin
 * upon the mapping. Once the pin count reaches zero, that mapping may be
 * removed.
 */
static inline void i915_gem_object_unpin_map(struct drm_i915_gem_object *obj)
{
	i915_gem_object_unpin_pages(obj);
}

int i915_gem_obj_prepare_shmem_read(struct drm_i915_gem_object *obj,
				    unsigned int *needs_clflush);
int i915_gem_obj_prepare_shmem_write(struct drm_i915_gem_object *obj,
				     unsigned int *needs_clflush);
#define CLFLUSH_BEFORE	BIT(0)
#define CLFLUSH_AFTER	BIT(1)
#define CLFLUSH_FLAGS	(CLFLUSH_BEFORE | CLFLUSH_AFTER)

static inline void
i915_gem_obj_finish_shmem_access(struct drm_i915_gem_object *obj)
{
	i915_gem_object_unpin_pages(obj);
}

int __must_check i915_mutex_lock_interruptible(struct drm_device *dev);
int i915_gem_dumb_create(struct drm_file *file_priv,
			 struct drm_device *dev,
			 struct drm_mode_create_dumb *args);
int i915_gem_mmap_gtt(struct drm_file *file_priv, struct drm_device *dev,
		      uint32_t handle, uint64_t *offset);
int i915_gem_mmap_gtt_version(void);

void i915_gem_track_fb(struct drm_i915_gem_object *old,
		       struct drm_i915_gem_object *new,
		       unsigned frontbuffer_bits);

int __must_check i915_gem_set_global_seqno(struct drm_device *dev, u32 seqno);

struct i915_request *
i915_gem_find_active_request(struct intel_engine_cs *engine);

static inline bool i915_reset_backoff(struct i915_gpu_error *error)
{
	return unlikely(test_bit(I915_RESET_BACKOFF, &error->flags));
}

static inline bool i915_reset_handoff(struct i915_gpu_error *error)
{
	return unlikely(test_bit(I915_RESET_HANDOFF, &error->flags));
}

static inline bool i915_terminally_wedged(struct i915_gpu_error *error)
{
	return unlikely(test_bit(I915_WEDGED, &error->flags));
}

static inline bool i915_reset_backoff_or_wedged(struct i915_gpu_error *error)
{
	return i915_reset_backoff(error) | i915_terminally_wedged(error);
}

static inline u32 i915_reset_count(struct i915_gpu_error *error)
{
	return READ_ONCE(error->reset_count);
}

static inline u32 i915_reset_engine_count(struct i915_gpu_error *error,
					  struct intel_engine_cs *engine)
{
	return READ_ONCE(error->reset_engine_count[engine->id]);
}

struct i915_request *
i915_gem_reset_prepare_engine(struct intel_engine_cs *engine);
int i915_gem_reset_prepare(struct drm_i915_private *dev_priv);
void i915_gem_reset(struct drm_i915_private *dev_priv,
		    unsigned int stalled_mask);
void i915_gem_reset_finish_engine(struct intel_engine_cs *engine);
void i915_gem_reset_finish(struct drm_i915_private *dev_priv);
void i915_gem_set_wedged(struct drm_i915_private *dev_priv);
bool i915_gem_unset_wedged(struct drm_i915_private *dev_priv);
void i915_gem_reset_engine(struct intel_engine_cs *engine,
			   struct i915_request *request,
			   bool stalled);

void i915_gem_init_mmio(struct drm_i915_private *i915);
int __must_check i915_gem_init(struct drm_i915_private *dev_priv);
int __must_check i915_gem_init_hw(struct drm_i915_private *dev_priv);
void i915_gem_init_swizzling(struct drm_i915_private *dev_priv);
void i915_gem_fini(struct drm_i915_private *dev_priv);
void i915_gem_cleanup_engines(struct drm_i915_private *dev_priv);
int i915_gem_wait_for_idle(struct drm_i915_private *dev_priv,
			   unsigned int flags, long timeout);
int __must_check i915_gem_suspend(struct drm_i915_private *dev_priv);
void i915_gem_suspend_late(struct drm_i915_private *dev_priv);
void i915_gem_resume(struct drm_i915_private *dev_priv);
vm_fault_t i915_gem_fault(struct vm_fault *vmf);
int i915_gem_object_wait(struct drm_i915_gem_object *obj,
			 unsigned int flags,
			 long timeout,
			 struct intel_rps_client *rps);
int i915_gem_object_wait_priority(struct drm_i915_gem_object *obj,
				  unsigned int flags,
				  const struct i915_sched_attr *attr);
#define I915_PRIORITY_DISPLAY I915_PRIORITY_MAX

int __must_check
i915_gem_object_set_to_wc_domain(struct drm_i915_gem_object *obj, bool write);
int __must_check
i915_gem_object_set_to_gtt_domain(struct drm_i915_gem_object *obj, bool write);
int __must_check
i915_gem_object_set_to_cpu_domain(struct drm_i915_gem_object *obj, bool write);
struct i915_vma * __must_check
i915_gem_object_pin_to_display_plane(struct drm_i915_gem_object *obj,
				     u32 alignment,
				     const struct i915_ggtt_view *view,
				     unsigned int flags);
void i915_gem_object_unpin_from_display_plane(struct i915_vma *vma);
int i915_gem_object_attach_phys(struct drm_i915_gem_object *obj,
				int align);
int i915_gem_open(struct drm_i915_private *i915, struct drm_file *file);
void i915_gem_release(struct drm_device *dev, struct drm_file *file);

int i915_gem_object_set_cache_level(struct drm_i915_gem_object *obj,
				    enum i915_cache_level cache_level);

struct drm_gem_object *i915_gem_prime_import(struct drm_device *dev,
				struct dma_buf *dma_buf);

struct dma_buf *i915_gem_prime_export(struct drm_device *dev,
				struct drm_gem_object *gem_obj, int flags);

static inline struct i915_hw_ppgtt *
i915_vm_to_ppgtt(struct i915_address_space *vm)
{
	return container_of(vm, struct i915_hw_ppgtt, vm);
}

/* i915_gem_fence_reg.c */
struct drm_i915_fence_reg *
i915_reserve_fence(struct drm_i915_private *dev_priv);
void i915_unreserve_fence(struct drm_i915_fence_reg *fence);

void i915_gem_revoke_fences(struct drm_i915_private *dev_priv);
void i915_gem_restore_fences(struct drm_i915_private *dev_priv);

void i915_gem_detect_bit_6_swizzle(struct drm_i915_private *dev_priv);
void i915_gem_object_do_bit_17_swizzle(struct drm_i915_gem_object *obj,
				       struct sg_table *pages);
void i915_gem_object_save_bit_17_swizzle(struct drm_i915_gem_object *obj,
					 struct sg_table *pages);

static inline struct i915_gem_context *
__i915_gem_context_lookup_rcu(struct drm_i915_file_private *file_priv, u32 id)
{
	return idr_find(&file_priv->context_idr, id);
}

static inline struct i915_gem_context *
i915_gem_context_lookup(struct drm_i915_file_private *file_priv, u32 id)
{
	struct i915_gem_context *ctx;

	rcu_read_lock();
	ctx = __i915_gem_context_lookup_rcu(file_priv, id);
	if (ctx && !kref_get_unless_zero(&ctx->ref))
		ctx = NULL;
	rcu_read_unlock();

	return ctx;
}

int i915_perf_open_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file);
int i915_perf_add_config_ioctl(struct drm_device *dev, void *data,
			       struct drm_file *file);
int i915_perf_remove_config_ioctl(struct drm_device *dev, void *data,
				  struct drm_file *file);
void i915_oa_init_reg_state(struct intel_engine_cs *engine,
			    struct i915_gem_context *ctx,
			    uint32_t *reg_state);

/* i915_gem_evict.c */
int __must_check i915_gem_evict_something(struct i915_address_space *vm,
					  u64 min_size, u64 alignment,
					  unsigned cache_level,
					  u64 start, u64 end,
					  unsigned flags);
int __must_check i915_gem_evict_for_node(struct i915_address_space *vm,
					 struct drm_mm_node *node,
					 unsigned int flags);
int i915_gem_evict_vm(struct i915_address_space *vm);

void i915_gem_flush_ggtt_writes(struct drm_i915_private *dev_priv);

/* belongs in i915_gem_gtt.h */
static inline void i915_gem_chipset_flush(struct drm_i915_private *dev_priv)
{
	wmb();
	if (INTEL_GEN(dev_priv) < 6)
		intel_gtt_chipset_flush();
}

/* i915_gem_stolen.c */
int i915_gem_stolen_insert_node(struct drm_i915_private *dev_priv,
				struct drm_mm_node *node, u64 size,
				unsigned alignment);
int i915_gem_stolen_insert_node_in_range(struct drm_i915_private *dev_priv,
					 struct drm_mm_node *node, u64 size,
					 unsigned alignment, u64 start,
					 u64 end);
void i915_gem_stolen_remove_node(struct drm_i915_private *dev_priv,
				 struct drm_mm_node *node);
int i915_gem_init_stolen(struct drm_i915_private *dev_priv);
void i915_gem_cleanup_stolen(struct drm_device *dev);
struct drm_i915_gem_object *
i915_gem_object_create_stolen(struct drm_i915_private *dev_priv,
			      resource_size_t size);
struct drm_i915_gem_object *
i915_gem_object_create_stolen_for_preallocated(struct drm_i915_private *dev_priv,
					       resource_size_t stolen_offset,
					       resource_size_t gtt_offset,
					       resource_size_t size);

/* i915_gem_internal.c */
struct drm_i915_gem_object *
i915_gem_object_create_internal(struct drm_i915_private *dev_priv,
				phys_addr_t size);

/* i915_gem_shrinker.c */
unsigned long i915_gem_shrink(struct drm_i915_private *i915,
			      unsigned long target,
			      unsigned long *nr_scanned,
			      unsigned flags);
#define I915_SHRINK_PURGEABLE 0x1
#define I915_SHRINK_UNBOUND 0x2
#define I915_SHRINK_BOUND 0x4
#define I915_SHRINK_ACTIVE 0x8
#define I915_SHRINK_VMAPS 0x10
unsigned long i915_gem_shrink_all(struct drm_i915_private *i915);
void i915_gem_shrinker_register(struct drm_i915_private *i915);
void i915_gem_shrinker_unregister(struct drm_i915_private *i915);
void i915_gem_shrinker_taints_mutex(struct mutex *mutex);

/* i915_gem_tiling.c */
static inline bool i915_gem_object_needs_bit17_swizzle(struct drm_i915_gem_object *obj)
{
	struct drm_i915_private *dev_priv = to_i915(obj->base.dev);

	return dev_priv->mm.bit_6_swizzle_x == I915_BIT_6_SWIZZLE_9_10_17 &&
		i915_gem_object_is_tiled(obj);
}

u32 i915_gem_fence_size(struct drm_i915_private *dev_priv, u32 size,
			unsigned int tiling, unsigned int stride);
u32 i915_gem_fence_alignment(struct drm_i915_private *dev_priv, u32 size,
			     unsigned int tiling, unsigned int stride);

/* i915_debugfs.c */
#ifdef CONFIG_DEBUG_FS
int i915_debugfs_register(struct drm_i915_private *dev_priv);
int i915_debugfs_connector_add(struct drm_connector *connector);
void intel_display_crc_init(struct drm_i915_private *dev_priv);
#else
static inline int i915_debugfs_register(struct drm_i915_private *dev_priv) {return 0;}
static inline int i915_debugfs_connector_add(struct drm_connector *connector)
{ return 0; }
static inline void intel_display_crc_init(struct drm_i915_private *dev_priv) {}
#endif

const char *i915_cache_level_str(struct drm_i915_private *i915, int type);

/* i915_cmd_parser.c */
int i915_cmd_parser_get_version(struct drm_i915_private *dev_priv);
void intel_engine_init_cmd_parser(struct intel_engine_cs *engine);
void intel_engine_cleanup_cmd_parser(struct intel_engine_cs *engine);
int intel_engine_cmd_parser(struct i915_gem_context *cxt,
			    struct intel_engine_cs *engine,
			    struct drm_i915_gem_object *batch_obj,
			    u64 user_batch_start,
			    u32 batch_start_offset,
			    u32 batch_len,
			    struct drm_i915_gem_object *shadow_batch_obj,
			    u64 shadow_batch_start);

/* i915_perf.c */
extern void i915_perf_init(struct drm_i915_private *dev_priv);
extern void i915_perf_fini(struct drm_i915_private *dev_priv);
extern void i915_perf_register(struct drm_i915_private *dev_priv);
extern void i915_perf_unregister(struct drm_i915_private *dev_priv);

/* i915_suspend.c */
extern int i915_save_state(struct drm_i915_private *dev_priv);
extern int i915_restore_state(struct drm_i915_private *dev_priv);

/* i915_sysfs.c */
void i915_setup_sysfs(struct drm_i915_private *dev_priv);
void i915_teardown_sysfs(struct drm_i915_private *dev_priv);

/* intel_lpe_audio.c */
int  intel_lpe_audio_init(struct drm_i915_private *dev_priv);
void intel_lpe_audio_teardown(struct drm_i915_private *dev_priv);
void intel_lpe_audio_irq_handler(struct drm_i915_private *dev_priv);
void intel_lpe_audio_notify(struct drm_i915_private *dev_priv,
			    enum pipe pipe, enum port port,
			    const void *eld, int ls_clock, bool dp_output);

/* intel_i2c.c */
extern int intel_setup_gmbus(struct drm_i915_private *dev_priv);
extern void intel_teardown_gmbus(struct drm_i915_private *dev_priv);
extern bool intel_gmbus_is_valid_pin(struct drm_i915_private *dev_priv,
				     unsigned int pin);
extern int intel_gmbus_output_aksv(struct i2c_adapter *adapter);

extern struct i2c_adapter *
intel_gmbus_get_adapter(struct drm_i915_private *dev_priv, unsigned int pin);
extern void intel_gmbus_set_speed(struct i2c_adapter *adapter, int speed);
extern void intel_gmbus_force_bit(struct i2c_adapter *adapter, bool force_bit);
static inline bool intel_gmbus_is_forced_bit(struct i2c_adapter *adapter)
{
	return container_of(adapter, struct intel_gmbus, adapter)->force_bit;
}
extern void intel_i2c_reset(struct drm_i915_private *dev_priv);

/* intel_bios.c */
void intel_bios_init(struct drm_i915_private *dev_priv);
void intel_bios_cleanup(struct drm_i915_private *dev_priv);
bool intel_bios_is_valid_vbt(const void *buf, size_t size);
bool intel_bios_is_tv_present(struct drm_i915_private *dev_priv);
bool intel_bios_is_lvds_present(struct drm_i915_private *dev_priv, u8 *i2c_pin);
bool intel_bios_is_port_present(struct drm_i915_private *dev_priv, enum port port);
bool intel_bios_is_port_edp(struct drm_i915_private *dev_priv, enum port port);
bool intel_bios_is_port_dp_dual_mode(struct drm_i915_private *dev_priv, enum port port);
bool intel_bios_is_dsi_present(struct drm_i915_private *dev_priv, enum port *port);
bool intel_bios_is_port_hpd_inverted(struct drm_i915_private *dev_priv,
				     enum port port);
bool intel_bios_is_lspcon_present(struct drm_i915_private *dev_priv,
				enum port port);

/* intel_acpi.c */
#ifdef CONFIG_ACPI
extern void intel_register_dsm_handler(void);
extern void intel_unregister_dsm_handler(void);
#else
static inline void intel_register_dsm_handler(void) { return; }
static inline void intel_unregister_dsm_handler(void) { return; }
#endif /* CONFIG_ACPI */

/* intel_device_info.c */
static inline struct intel_device_info *
mkwrite_device_info(struct drm_i915_private *dev_priv)
{
	return (struct intel_device_info *)&dev_priv->info;
}

/* modesetting */
extern void intel_modeset_init_hw(struct drm_device *dev);
extern int intel_modeset_init(struct drm_device *dev);
extern void intel_modeset_cleanup(struct drm_device *dev);
extern int intel_connector_register(struct drm_connector *);
extern void intel_connector_unregister(struct drm_connector *);
extern int intel_modeset_vga_set_state(struct drm_i915_private *dev_priv,
				       bool state);
extern void intel_display_resume(struct drm_device *dev);
extern void i915_redisable_vga(struct drm_i915_private *dev_priv);
extern void i915_redisable_vga_power_on(struct drm_i915_private *dev_priv);
extern bool ironlake_set_drps(struct drm_i915_private *dev_priv, u8 val);
extern void intel_init_pch_refclk(struct drm_i915_private *dev_priv);
extern int intel_set_rps(struct drm_i915_private *dev_priv, u8 val);
extern void intel_rps_mark_interactive(struct drm_i915_private *i915,
				       bool interactive);
extern bool intel_set_memory_cxsr(struct drm_i915_private *dev_priv,
				  bool enable);

int i915_reg_read_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file);

/* overlay */
extern struct intel_overlay_error_state *
intel_overlay_capture_error_state(struct drm_i915_private *dev_priv);
extern void intel_overlay_print_error_state(struct drm_i915_error_state_buf *e,
					    struct intel_overlay_error_state *error);

extern struct intel_display_error_state *
intel_display_capture_error_state(struct drm_i915_private *dev_priv);
extern void intel_display_print_error_state(struct drm_i915_error_state_buf *e,
					    struct intel_display_error_state *error);

int sandybridge_pcode_read(struct drm_i915_private *dev_priv, u32 mbox, u32 *val);
int sandybridge_pcode_write_timeout(struct drm_i915_private *dev_priv, u32 mbox,
				    u32 val, int fast_timeout_us,
				    int slow_timeout_ms);
#define sandybridge_pcode_write(dev_priv, mbox, val)	\
	sandybridge_pcode_write_timeout(dev_priv, mbox, val, 500, 0)

int skl_pcode_request(struct drm_i915_private *dev_priv, u32 mbox, u32 request,
		      u32 reply_mask, u32 reply, int timeout_base_ms);

/* intel_sideband.c */
u32 vlv_punit_read(struct drm_i915_private *dev_priv, u32 addr);
int vlv_punit_write(struct drm_i915_private *dev_priv, u32 addr, u32 val);
u32 vlv_nc_read(struct drm_i915_private *dev_priv, u8 addr);
u32 vlv_iosf_sb_read(struct drm_i915_private *dev_priv, u8 port, u32 reg);
void vlv_iosf_sb_write(struct drm_i915_private *dev_priv, u8 port, u32 reg, u32 val);
u32 vlv_cck_read(struct drm_i915_private *dev_priv, u32 reg);
void vlv_cck_write(struct drm_i915_private *dev_priv, u32 reg, u32 val);
u32 vlv_ccu_read(struct drm_i915_private *dev_priv, u32 reg);
void vlv_ccu_write(struct drm_i915_private *dev_priv, u32 reg, u32 val);
u32 vlv_bunit_read(struct drm_i915_private *dev_priv, u32 reg);
void vlv_bunit_write(struct drm_i915_private *dev_priv, u32 reg, u32 val);
u32 vlv_dpio_read(struct drm_i915_private *dev_priv, enum pipe pipe, int reg);
void vlv_dpio_write(struct drm_i915_private *dev_priv, enum pipe pipe, int reg, u32 val);
u32 intel_sbi_read(struct drm_i915_private *dev_priv, u16 reg,
		   enum intel_sbi_destination destination);
void intel_sbi_write(struct drm_i915_private *dev_priv, u16 reg, u32 value,
		     enum intel_sbi_destination destination);
u32 vlv_flisdsi_read(struct drm_i915_private *dev_priv, u32 reg);
void vlv_flisdsi_write(struct drm_i915_private *dev_priv, u32 reg, u32 val);

/* intel_dpio_phy.c */
void bxt_port_to_phy_channel(struct drm_i915_private *dev_priv, enum port port,
			     enum dpio_phy *phy, enum dpio_channel *ch);
void bxt_ddi_phy_set_signal_level(struct drm_i915_private *dev_priv,
				  enum port port, u32 margin, u32 scale,
				  u32 enable, u32 deemphasis);
void bxt_ddi_phy_init(struct drm_i915_private *dev_priv, enum dpio_phy phy);
void bxt_ddi_phy_uninit(struct drm_i915_private *dev_priv, enum dpio_phy phy);
bool bxt_ddi_phy_is_enabled(struct drm_i915_private *dev_priv,
			    enum dpio_phy phy);
bool bxt_ddi_phy_verify_state(struct drm_i915_private *dev_priv,
			      enum dpio_phy phy);
uint8_t bxt_ddi_phy_calc_lane_lat_optim_mask(uint8_t lane_count);
void bxt_ddi_phy_set_lane_optim_mask(struct intel_encoder *encoder,
				     uint8_t lane_lat_optim_mask);
uint8_t bxt_ddi_phy_get_lane_lat_optim_mask(struct intel_encoder *encoder);

void chv_set_phy_signal_level(struct intel_encoder *encoder,
			      u32 deemph_reg_value, u32 margin_reg_value,
			      bool uniq_trans_scale);
void chv_data_lane_soft_reset(struct intel_encoder *encoder,
			      const struct intel_crtc_state *crtc_state,
			      bool reset);
void chv_phy_pre_pll_enable(struct intel_encoder *encoder,
			    const struct intel_crtc_state *crtc_state);
void chv_phy_pre_encoder_enable(struct intel_encoder *encoder,
				const struct intel_crtc_state *crtc_state);
void chv_phy_release_cl2_override(struct intel_encoder *encoder);
void chv_phy_post_pll_disable(struct intel_encoder *encoder,
			      const struct intel_crtc_state *old_crtc_state);

void vlv_set_phy_signal_level(struct intel_encoder *encoder,
			      u32 demph_reg_value, u32 preemph_reg_value,
			      u32 uniqtranscale_reg_value, u32 tx3_demph);
void vlv_phy_pre_pll_enable(struct intel_encoder *encoder,
			    const struct intel_crtc_state *crtc_state);
void vlv_phy_pre_encoder_enable(struct intel_encoder *encoder,
				const struct intel_crtc_state *crtc_state);
void vlv_phy_reset_lanes(struct intel_encoder *encoder,
			 const struct intel_crtc_state *old_crtc_state);

int intel_gpu_freq(struct drm_i915_private *dev_priv, int val);
int intel_freq_opcode(struct drm_i915_private *dev_priv, int val);
u64 intel_rc6_residency_ns(struct drm_i915_private *dev_priv,
			   const i915_reg_t reg);

u32 intel_get_cagf(struct drm_i915_private *dev_priv, u32 rpstat1);

static inline u64 intel_rc6_residency_us(struct drm_i915_private *dev_priv,
					 const i915_reg_t reg)
{
	return DIV_ROUND_UP_ULL(intel_rc6_residency_ns(dev_priv, reg), 1000);
}

#define I915_READ8(reg)		dev_priv->uncore.funcs.mmio_readb(dev_priv, (reg), true)
#define I915_WRITE8(reg, val)	dev_priv->uncore.funcs.mmio_writeb(dev_priv, (reg), (val), true)

#define I915_READ16(reg)	dev_priv->uncore.funcs.mmio_readw(dev_priv, (reg), true)
#define I915_WRITE16(reg, val)	dev_priv->uncore.funcs.mmio_writew(dev_priv, (reg), (val), true)
#define I915_READ16_NOTRACE(reg)	dev_priv->uncore.funcs.mmio_readw(dev_priv, (reg), false)
#define I915_WRITE16_NOTRACE(reg, val)	dev_priv->uncore.funcs.mmio_writew(dev_priv, (reg), (val), false)

#define I915_READ(reg)		dev_priv->uncore.funcs.mmio_readl(dev_priv, (reg), true)
#define I915_WRITE(reg, val)	dev_priv->uncore.funcs.mmio_writel(dev_priv, (reg), (val), true)
#define I915_READ_NOTRACE(reg)		dev_priv->uncore.funcs.mmio_readl(dev_priv, (reg), false)
#define I915_WRITE_NOTRACE(reg, val)	dev_priv->uncore.funcs.mmio_writel(dev_priv, (reg), (val), false)

/* Be very careful with read/write 64-bit values. On 32-bit machines, they
 * will be implemented using 2 32-bit writes in an arbitrary order with
 * an arbitrary delay between them. This can cause the hardware to
 * act upon the intermediate value, possibly leading to corruption and
 * machine death. For this reason we do not support I915_WRITE64, or
 * dev_priv->uncore.funcs.mmio_writeq.
 *
 * When reading a 64-bit value as two 32-bit values, the delay may cause
 * the two reads to mismatch, e.g. a timestamp overflowing. Also note that
 * occasionally a 64-bit register does not actualy support a full readq
 * and must be read using two 32-bit reads.
 *
 * You have been warned.
 */
#define I915_READ64(reg)	dev_priv->uncore.funcs.mmio_readq(dev_priv, (reg), true)

#define I915_READ64_2x32(lower_reg, upper_reg) ({			\
	u32 upper, lower, old_upper, loop = 0;				\
	upper = I915_READ(upper_reg);					\
	do {								\
		old_upper = upper;					\
		lower = I915_READ(lower_reg);				\
		upper = I915_READ(upper_reg);				\
	} while (upper != old_upper && loop++ < 2);			\
	(u64)upper << 32 | lower; })

#define POSTING_READ(reg)	(void)I915_READ_NOTRACE(reg)
#define POSTING_READ16(reg)	(void)I915_READ16_NOTRACE(reg)

#define __raw_read(x, s) \
static inline uint##x##_t __raw_i915_read##x(const struct drm_i915_private *dev_priv, \
					     i915_reg_t reg) \
{ \
	return read##s(dev_priv->regs + i915_mmio_reg_offset(reg)); \
}

#define __raw_write(x, s) \
static inline void __raw_i915_write##x(const struct drm_i915_private *dev_priv, \
				       i915_reg_t reg, uint##x##_t val) \
{ \
	write##s(val, dev_priv->regs + i915_mmio_reg_offset(reg)); \
}
__raw_read(8, b)
__raw_read(16, w)
__raw_read(32, l)
__raw_read(64, q)

__raw_write(8, b)
__raw_write(16, w)
__raw_write(32, l)
__raw_write(64, q)

#undef __raw_read
#undef __raw_write

/* These are untraced mmio-accessors that are only valid to be used inside
 * critical sections, such as inside IRQ handlers, where forcewake is explicitly
 * controlled.
 *
 * Think twice, and think again, before using these.
 *
 * As an example, these accessors can possibly be used between:
 *
 * spin_lock_irq(&dev_priv->uncore.lock);
 * intel_uncore_forcewake_get__locked();
 *
 * and
 *
 * intel_uncore_forcewake_put__locked();
 * spin_unlock_irq(&dev_priv->uncore.lock);
 *
 *
 * Note: some registers may not need forcewake held, so
 * intel_uncore_forcewake_{get,put} can be omitted, see
 * intel_uncore_forcewake_for_reg().
 *
 * Certain architectures will die if the same cacheline is concurrently accessed
 * by different clients (e.g. on Ivybridge). Access to registers should
 * therefore generally be serialised, by either the dev_priv->uncore.lock or
 * a more localised lock guarding all access to that bank of registers.
 */
#define I915_READ_FW(reg__) __raw_i915_read32(dev_priv, (reg__))
#define I915_WRITE_FW(reg__, val__) __raw_i915_write32(dev_priv, (reg__), (val__))
#define I915_WRITE64_FW(reg__, val__) __raw_i915_write64(dev_priv, (reg__), (val__))
#define POSTING_READ_FW(reg__) (void)I915_READ_FW(reg__)

/* "Broadcast RGB" property */
#define INTEL_BROADCAST_RGB_AUTO 0
#define INTEL_BROADCAST_RGB_FULL 1
#define INTEL_BROADCAST_RGB_LIMITED 2

static inline i915_reg_t i915_vgacntrl_reg(struct drm_i915_private *dev_priv)
{
	if (IS_VALLEYVIEW(dev_priv) || IS_CHERRYVIEW(dev_priv))
		return VLV_VGACNTRL;
	else if (INTEL_GEN(dev_priv) >= 5)
		return CPU_VGACNTRL;
	else
		return VGACNTRL;
}

static inline unsigned long msecs_to_jiffies_timeout(const unsigned int m)
{
	unsigned long j = msecs_to_jiffies(m);

	return min_t(unsigned long, MAX_JIFFY_OFFSET, j + 1);
}

static inline unsigned long nsecs_to_jiffies_timeout(const u64 n)
{
	/* nsecs_to_jiffies64() does not guard against overflow */
	if (NSEC_PER_SEC % HZ &&
	    div_u64(n, NSEC_PER_SEC) >= MAX_JIFFY_OFFSET / HZ)
		return MAX_JIFFY_OFFSET;

        return min_t(u64, MAX_JIFFY_OFFSET, nsecs_to_jiffies64(n) + 1);
}

/*
 * If you need to wait X milliseconds between events A and B, but event B
 * doesn't happen exactly after event A, you record the timestamp (jiffies) of
 * when event A happened, then just before event B you call this function and
 * pass the timestamp as the first argument, and X as the second argument.
 */
static inline void
wait_remaining_ms_from_jiffies(unsigned long timestamp_jiffies, int to_wait_ms)
{
	unsigned long target_jiffies, tmp_jiffies, remaining_jiffies;

	/*
	 * Don't re-read the value of "jiffies" every time since it may change
	 * behind our back and break the math.
	 */
	tmp_jiffies = jiffies;
	target_jiffies = timestamp_jiffies +
			 msecs_to_jiffies_timeout(to_wait_ms);

	if (time_after(target_jiffies, tmp_jiffies)) {
		remaining_jiffies = target_jiffies - tmp_jiffies;
		while (remaining_jiffies)
			remaining_jiffies =
			    schedule_timeout_uninterruptible(remaining_jiffies);
	}
}

static inline bool
__i915_request_irq_complete(const struct i915_request *rq)
{
	struct intel_engine_cs *engine = rq->engine;
	u32 seqno;

	/* Note that the engine may have wrapped around the seqno, and
	 * so our request->global_seqno will be ahead of the hardware,
	 * even though it completed the request before wrapping. We catch
	 * this by kicking all the waiters before resetting the seqno
	 * in hardware, and also signal the fence.
	 */
	if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &rq->fence.flags))
		return true;

	/* The request was dequeued before we were awoken. We check after
	 * inspecting the hw to confirm that this was the same request
	 * that generated the HWS update. The memory barriers within
	 * the request execution are sufficient to ensure that a check
	 * after reading the value from hw matches this request.
	 */
	seqno = i915_request_global_seqno(rq);
	if (!seqno)
		return false;

	/* Before we do the heavier coherent read of the seqno,
	 * check the value (hopefully) in the CPU cacheline.
	 */
	if (__i915_request_completed(rq, seqno))
		return true;

	/* Ensure our read of the seqno is coherent so that we
	 * do not "miss an interrupt" (i.e. if this is the last
	 * request and the seqno write from the GPU is not visible
	 * by the time the interrupt fires, we will see that the
	 * request is incomplete and go back to sleep awaiting
	 * another interrupt that will never come.)
	 *
	 * Strictly, we only need to do this once after an interrupt,
	 * but it is easier and safer to do it every time the waiter
	 * is woken.
	 */
	if (engine->irq_seqno_barrier &&
	    test_and_clear_bit(ENGINE_IRQ_BREADCRUMB, &engine->irq_posted)) {
		struct intel_breadcrumbs *b = &engine->breadcrumbs;

		/* The ordering of irq_posted versus applying the barrier
		 * is crucial. The clearing of the current irq_posted must
		 * be visible before we perform the barrier operation,
		 * such that if a subsequent interrupt arrives, irq_posted
		 * is reasserted and our task rewoken (which causes us to
		 * do another __i915_request_irq_complete() immediately
		 * and reapply the barrier). Conversely, if the clear
		 * occurs after the barrier, then an interrupt that arrived
		 * whilst we waited on the barrier would not trigger a
		 * barrier on the next pass, and the read may not see the
		 * seqno update.
		 */
		engine->irq_seqno_barrier(engine);

		/* If we consume the irq, but we are no longer the bottom-half,
		 * the real bottom-half may not have serialised their own
		 * seqno check with the irq-barrier (i.e. may have inspected
		 * the seqno before we believe it coherent since they see
		 * irq_posted == false but we are still running).
		 */
		spin_lock_irq(&b->irq_lock);
		if (b->irq_wait && b->irq_wait->tsk != current)
			/* Note that if the bottom-half is changed as we
			 * are sending the wake-up, the new bottom-half will
			 * be woken by whomever made the change. We only have
			 * to worry about when we steal the irq-posted for
			 * ourself.
			 */
			wake_up_process(b->irq_wait->tsk);
		spin_unlock_irq(&b->irq_lock);

		if (__i915_request_completed(rq, seqno))
			return true;
	}

	return false;
}

void i915_memcpy_init_early(struct drm_i915_private *dev_priv);
bool i915_memcpy_from_wc(void *dst, const void *src, unsigned long len);

/* The movntdqa instructions used for memcpy-from-wc require 16-byte alignment,
 * as well as SSE4.1 support. i915_memcpy_from_wc() will report if it cannot
 * perform the operation. To check beforehand, pass in the parameters to
 * to i915_can_memcpy_from_wc() - since we only care about the low 4 bits,
 * you only need to pass in the minor offsets, page-aligned pointers are
 * always valid.
 *
 * For just checking for SSE4.1, in the foreknowledge that the future use
 * will be correctly aligned, just use i915_has_memcpy_from_wc().
 */
#define i915_can_memcpy_from_wc(dst, src, len) \
	i915_memcpy_from_wc((void *)((unsigned long)(dst) | (unsigned long)(src) | (len)), NULL, 0)

#define i915_has_memcpy_from_wc() \
	i915_memcpy_from_wc(NULL, NULL, 0)

/* i915_mm.c */
int remap_io_mapping(struct vm_area_struct *vma,
		     unsigned long addr, unsigned long pfn, unsigned long size,
		     struct io_mapping *iomap);

static inline int intel_hws_csb_write_index(struct drm_i915_private *i915)
{
	if (INTEL_GEN(i915) >= 10)
		return CNL_HWS_CSB_WRITE_INDEX;
	else
		return I915_HWS_CSB_WRITE_INDEX;
}
>>>>>>> master

#endif
