// SPDX-License-Identifier: GPL-2.0
/*
 * PCIe driver for Renesas R-Car SoCs
 *  Copyright (C) 2014-2020 Renesas Electronics Europe Ltd
 *
 * Author: Phil Edworthy <phil.edworthy@renesas.com>
 */

#include <linux/delay.h>
#include <linux/pci.h>

#include "pcie-rcar.h"

<<<<<<< HEAD
void rcar_pci_write_reg(struct rcar_pcie *pcie, u32 val, unsigned int reg)
=======
#define PCIECAR			0x000010
#define PCIECCTLR		0x000018
#define  CONFIG_SEND_ENABLE	BIT(31)
#define  TYPE0			(0 << 8)
#define  TYPE1			BIT(8)
#define PCIECDR			0x000020
#define PCIEMSR			0x000028
#define PCIEINTXR		0x000400
#define PCIEPHYSR		0x0007f0
#define  PHYRDY			BIT(0)
#define PCIEMSITXR		0x000840

/* Transfer control */
#define PCIETCTLR		0x02000
#define  DL_DOWN		BIT(3)
#define  CFINIT			1
#define PCIETSTR		0x02004
#define  DATA_LINK_ACTIVE	1
#define PCIEERRFR		0x02020
#define  UNSUPPORTED_REQUEST	BIT(4)
#define PCIEMSIFR		0x02044
#define PCIEMSIALR		0x02048
#define  MSIFE			1
#define PCIEMSIAUR		0x0204c
#define PCIEMSIIER		0x02050

/* root port address */
#define PCIEPRAR(x)		(0x02080 + ((x) * 0x4))

/* local address reg & mask */
#define PCIELAR(x)		(0x02200 + ((x) * 0x20))
#define PCIELAMR(x)		(0x02208 + ((x) * 0x20))
#define  LAM_PREFETCH		BIT(3)
#define  LAM_64BIT		BIT(2)
#define  LAR_ENABLE		BIT(1)

/* PCIe address reg & mask */
#define PCIEPALR(x)		(0x03400 + ((x) * 0x20))
#define PCIEPAUR(x)		(0x03404 + ((x) * 0x20))
#define PCIEPAMR(x)		(0x03408 + ((x) * 0x20))
#define PCIEPTCTLR(x)		(0x0340c + ((x) * 0x20))
#define  PAR_ENABLE		BIT(31)
#define  IO_SPACE		BIT(8)

/* Configuration */
#define PCICONF(x)		(0x010000 + ((x) * 0x4))
#define PMCAP(x)		(0x010040 + ((x) * 0x4))
#define EXPCAP(x)		(0x010070 + ((x) * 0x4))
#define VCCAP(x)		(0x010100 + ((x) * 0x4))

/* link layer */
#define IDSETR1			0x011004
#define TLCTLR			0x011048
#define MACSR			0x011054
#define  SPCHGFIN		BIT(4)
#define  SPCHGFAIL		BIT(6)
#define  SPCHGSUC		BIT(7)
#define  LINK_SPEED		(0xf << 16)
#define  LINK_SPEED_2_5GTS	(1 << 16)
#define  LINK_SPEED_5_0GTS	(2 << 16)
#define MACCTLR			0x011058
#define  SPEED_CHANGE		BIT(24)
#define  SCRAMBLE_DISABLE	BIT(27)
#define PMSR			0x01105c
#define MACS2R			0x011078
#define MACCGSPSETR		0x011084
#define  SPCNGRSN		BIT(31)

/* R-Car H1 PHY */
#define H1_PCIEPHYADRR		0x04000c
#define  WRITE_CMD		BIT(16)
#define  PHY_ACK		BIT(24)
#define  RATE_POS		12
#define  LANE_POS		8
#define  ADR_POS		0
#define H1_PCIEPHYDOUTR		0x040014

/* R-Car Gen2 PHY */
#define GEN2_PCIEPHYADDR	0x780
#define GEN2_PCIEPHYDATA	0x784
#define GEN2_PCIEPHYCTRL	0x78c

#define INT_PCI_MSI_NR		32

#define RCONF(x)		(PCICONF(0) + (x))
#define RPMCAP(x)		(PMCAP(0) + (x))
#define REXPCAP(x)		(EXPCAP(0) + (x))
#define RVCCAP(x)		(VCCAP(0) + (x))

#define PCIE_CONF_BUS(b)	(((b) & 0xff) << 24)
#define PCIE_CONF_DEV(d)	(((d) & 0x1f) << 19)
#define PCIE_CONF_FUNC(f)	(((f) & 0x7) << 16)

#define RCAR_PCI_MAX_RESOURCES	4
#define MAX_NR_INBOUND_MAPS	6

struct rcar_msi {
	DECLARE_BITMAP(used, INT_PCI_MSI_NR);
	struct irq_domain *domain;
	struct msi_controller chip;
	unsigned long pages;
	struct mutex lock;
	int irq1;
	int irq2;
};

static inline struct rcar_msi *to_rcar_msi(struct msi_controller *chip)
{
	return container_of(chip, struct rcar_msi, chip);
}

/* Structure representing the PCIe interface */
struct rcar_pcie {
	struct device		*dev;
	struct phy		*phy;
	void __iomem		*base;
	struct list_head	resources;
	int			root_bus_nr;
	struct clk		*bus_clk;
	struct			rcar_msi msi;
};

static void rcar_pci_write_reg(struct rcar_pcie *pcie, unsigned long val,
			       unsigned long reg)
>>>>>>> master
{
	writel(val, pcie->base + reg);
}

u32 rcar_pci_read_reg(struct rcar_pcie *pcie, unsigned int reg)
{
	return readl(pcie->base + reg);
}

void rcar_rmw32(struct rcar_pcie *pcie, int where, u32 mask, u32 data)
{
	unsigned int shift = BITS_PER_BYTE * (where & 3);
	u32 val = rcar_pci_read_reg(pcie, where & ~3);

	val &= ~(mask << shift);
	val |= data << shift;
	rcar_pci_write_reg(pcie, val, where & ~3);
}

int rcar_pcie_wait_for_phyrdy(struct rcar_pcie *pcie)
{
	unsigned int timeout = 10;

	while (timeout--) {
		if (rcar_pci_read_reg(pcie, PCIEPHYSR) & PHYRDY)
			return 0;

		msleep(5);
	}

	return -ETIMEDOUT;
}

int rcar_pcie_wait_for_dl(struct rcar_pcie *pcie)
{
	unsigned int timeout = 10000;

	while (timeout--) {
		if ((rcar_pci_read_reg(pcie, PCIETSTR) & DATA_LINK_ACTIVE))
			return 0;

		udelay(5);
		cpu_relax();
	}

	return -ETIMEDOUT;
}

void rcar_pcie_set_outbound(struct rcar_pcie *pcie, int win,
			    struct resource_entry *window)
{
	/* Setup PCIe address space mappings for each resource */
	struct resource *res = window->res;
	resource_size_t res_start;
	resource_size_t size;
	u32 mask;

	rcar_pci_write_reg(pcie, 0x00000000, PCIEPTCTLR(win));

	/*
	 * The PAMR mask is calculated in units of 128Bytes, which
	 * keeps things pretty simple.
	 */
	size = resource_size(res);
	if (size > 128)
		mask = (roundup_pow_of_two(size) / SZ_128) - 1;
	else
		mask = 0x0;
	rcar_pci_write_reg(pcie, mask << 7, PCIEPAMR(win));

	if (res->flags & IORESOURCE_IO)
		res_start = pci_pio_to_address(res->start) - window->offset;
	else
		res_start = res->start - window->offset;

	rcar_pci_write_reg(pcie, upper_32_bits(res_start), PCIEPAUR(win));
	rcar_pci_write_reg(pcie, lower_32_bits(res_start) & ~0x7F,
			   PCIEPALR(win));

	/* First resource is for IO */
	mask = PAR_ENABLE;
	if (res->flags & IORESOURCE_IO)
		mask |= IO_SPACE;

	rcar_pci_write_reg(pcie, mask, PCIEPTCTLR(win));
}

void rcar_pcie_set_inbound(struct rcar_pcie *pcie, u64 cpu_addr,
			   u64 pci_addr, u64 flags, int idx, bool host)
{
<<<<<<< HEAD
=======
	int msi;

	mutex_lock(&chip->lock);
	msi = bitmap_find_free_region(chip->used, INT_PCI_MSI_NR,
				      order_base_2(no_irqs));
	mutex_unlock(&chip->lock);

	return msi;
}

static void rcar_msi_free(struct rcar_msi *chip, unsigned long irq)
{
	mutex_lock(&chip->lock);
	clear_bit(irq, chip->used);
	mutex_unlock(&chip->lock);
}

static irqreturn_t rcar_pcie_msi_irq(int irq, void *data)
{
	struct rcar_pcie *pcie = data;
	struct rcar_msi *msi = &pcie->msi;
	struct device *dev = pcie->dev;
	unsigned long reg;

	reg = rcar_pci_read_reg(pcie, PCIEMSIFR);

	/* MSI & INTx share an interrupt - we only handle MSI here */
	if (!reg)
		return IRQ_NONE;

	while (reg) {
		unsigned int index = find_first_bit(&reg, 32);
		unsigned int irq;

		/* clear the interrupt */
		rcar_pci_write_reg(pcie, 1 << index, PCIEMSIFR);

		irq = irq_find_mapping(msi->domain, index);
		if (irq) {
			if (test_bit(index, msi->used))
				generic_handle_irq(irq);
			else
				dev_info(dev, "unhandled MSI\n");
		} else {
			/* Unknown MSI, just clear it */
			dev_dbg(dev, "unexpected MSI\n");
		}

		/* see if there's any more pending in this vector */
		reg = rcar_pci_read_reg(pcie, PCIEMSIFR);
	}

	return IRQ_HANDLED;
}

static int rcar_msi_setup_irq(struct msi_controller *chip, struct pci_dev *pdev,
			      struct msi_desc *desc)
{
	struct rcar_msi *msi = to_rcar_msi(chip);
	struct rcar_pcie *pcie = container_of(chip, struct rcar_pcie, msi.chip);
	struct msi_msg msg;
	unsigned int irq;
	int hwirq;

	hwirq = rcar_msi_alloc(msi);
	if (hwirq < 0)
		return hwirq;

	irq = irq_find_mapping(msi->domain, hwirq);
	if (!irq) {
		rcar_msi_free(msi, hwirq);
		return -EINVAL;
	}

	irq_set_msi_desc(irq, desc);

	msg.address_lo = rcar_pci_read_reg(pcie, PCIEMSIALR) & ~MSIFE;
	msg.address_hi = rcar_pci_read_reg(pcie, PCIEMSIAUR);
	msg.data = hwirq;

	pci_write_msi_msg(irq, &msg);

	return 0;
}

static int rcar_msi_setup_irqs(struct msi_controller *chip,
			       struct pci_dev *pdev, int nvec, int type)
{
	struct rcar_pcie *pcie = container_of(chip, struct rcar_pcie, msi.chip);
	struct rcar_msi *msi = to_rcar_msi(chip);
	struct msi_desc *desc;
	struct msi_msg msg;
	unsigned int irq;
	int hwirq;
	int i;

	/* MSI-X interrupts are not supported */
	if (type == PCI_CAP_ID_MSIX)
		return -EINVAL;

	WARN_ON(!list_is_singular(&pdev->dev.msi_list));
	desc = list_entry(pdev->dev.msi_list.next, struct msi_desc, list);

	hwirq = rcar_msi_alloc_region(msi, nvec);
	if (hwirq < 0)
		return -ENOSPC;

	irq = irq_find_mapping(msi->domain, hwirq);
	if (!irq)
		return -ENOSPC;

	for (i = 0; i < nvec; i++) {
		/*
		 * irq_create_mapping() called from rcar_pcie_probe() pre-
		 * allocates descs,  so there is no need to allocate descs here.
		 * We can therefore assume that if irq_find_mapping() above
		 * returns non-zero, then the descs are also successfully
		 * allocated.
		 */
		if (irq_set_msi_desc_off(irq, i, desc)) {
			/* TODO: clear */
			return -EINVAL;
		}
	}

	desc->nvec_used = nvec;
	desc->msi_attrib.multiple = order_base_2(nvec);

	msg.address_lo = rcar_pci_read_reg(pcie, PCIEMSIALR) & ~MSIFE;
	msg.address_hi = rcar_pci_read_reg(pcie, PCIEMSIAUR);
	msg.data = hwirq;

	pci_write_msi_msg(irq, &msg);

	return 0;
}

static void rcar_msi_teardown_irq(struct msi_controller *chip, unsigned int irq)
{
	struct rcar_msi *msi = to_rcar_msi(chip);
	struct irq_data *d = irq_get_irq_data(irq);

	rcar_msi_free(msi, d->hwirq);
}

static struct irq_chip rcar_msi_irq_chip = {
	.name = "R-Car PCIe MSI",
	.irq_enable = pci_msi_unmask_irq,
	.irq_disable = pci_msi_mask_irq,
	.irq_mask = pci_msi_mask_irq,
	.irq_unmask = pci_msi_unmask_irq,
};

static int rcar_msi_map(struct irq_domain *domain, unsigned int irq,
			irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &rcar_msi_irq_chip, handle_simple_irq);
	irq_set_chip_data(irq, domain->host_data);

	return 0;
}

static const struct irq_domain_ops msi_domain_ops = {
	.map = rcar_msi_map,
};

static void rcar_pcie_unmap_msi(struct rcar_pcie *pcie)
{
	struct rcar_msi *msi = &pcie->msi;
	int i, irq;

	for (i = 0; i < INT_PCI_MSI_NR; i++) {
		irq = irq_find_mapping(msi->domain, i);
		if (irq > 0)
			irq_dispose_mapping(irq);
	}

	irq_domain_remove(msi->domain);
}

static int rcar_pcie_enable_msi(struct rcar_pcie *pcie)
{
	struct device *dev = pcie->dev;
	struct rcar_msi *msi = &pcie->msi;
	phys_addr_t base;
	int err, i;

	mutex_init(&msi->lock);

	msi->chip.dev = dev;
	msi->chip.setup_irq = rcar_msi_setup_irq;
	msi->chip.setup_irqs = rcar_msi_setup_irqs;
	msi->chip.teardown_irq = rcar_msi_teardown_irq;

	msi->domain = irq_domain_add_linear(dev->of_node, INT_PCI_MSI_NR,
					    &msi_domain_ops, &msi->chip);
	if (!msi->domain) {
		dev_err(dev, "failed to create IRQ domain\n");
		return -ENOMEM;
	}

	for (i = 0; i < INT_PCI_MSI_NR; i++)
		irq_create_mapping(msi->domain, i);

	/* Two irqs are for MSI, but they are also used for non-MSI irqs */
	err = devm_request_irq(dev, msi->irq1, rcar_pcie_msi_irq,
			       IRQF_SHARED | IRQF_NO_THREAD,
			       rcar_msi_irq_chip.name, pcie);
	if (err < 0) {
		dev_err(dev, "failed to request IRQ: %d\n", err);
		goto err;
	}

	err = devm_request_irq(dev, msi->irq2, rcar_pcie_msi_irq,
			       IRQF_SHARED | IRQF_NO_THREAD,
			       rcar_msi_irq_chip.name, pcie);
	if (err < 0) {
		dev_err(dev, "failed to request IRQ: %d\n", err);
		goto err;
	}

	/* setup MSI data target */
	msi->pages = __get_free_pages(GFP_KERNEL, 0);
	if (!msi->pages) {
		err = -ENOMEM;
		goto err;
	}
	base = virt_to_phys((void *)msi->pages);

	rcar_pci_write_reg(pcie, lower_32_bits(base) | MSIFE, PCIEMSIALR);
	rcar_pci_write_reg(pcie, upper_32_bits(base), PCIEMSIAUR);

	/* enable all MSI interrupts */
	rcar_pci_write_reg(pcie, 0xffffffff, PCIEMSIIER);

	return 0;

err:
	rcar_pcie_unmap_msi(pcie);
	return err;
}

static void rcar_pcie_teardown_msi(struct rcar_pcie *pcie)
{
	struct rcar_msi *msi = &pcie->msi;

	/* Disable all MSI interrupts */
	rcar_pci_write_reg(pcie, 0, PCIEMSIIER);

	/* Disable address decoding of the MSI interrupt, MSIFE */
	rcar_pci_write_reg(pcie, 0, PCIEMSIALR);

	free_pages(msi->pages, 0);

	rcar_pcie_unmap_msi(pcie);
}

static int rcar_pcie_get_resources(struct rcar_pcie *pcie)
{
	struct device *dev = pcie->dev;
	struct resource res;
	int err, i;

	pcie->phy = devm_phy_optional_get(dev, "pcie");
	if (IS_ERR(pcie->phy))
		return PTR_ERR(pcie->phy);

	err = of_address_to_resource(dev->of_node, 0, &res);
	if (err)
		return err;

	pcie->base = devm_ioremap_resource(dev, &res);
	if (IS_ERR(pcie->base))
		return PTR_ERR(pcie->base);

	pcie->bus_clk = devm_clk_get(dev, "pcie_bus");
	if (IS_ERR(pcie->bus_clk)) {
		dev_err(dev, "cannot get pcie bus clock\n");
		return PTR_ERR(pcie->bus_clk);
	}

	i = irq_of_parse_and_map(dev->of_node, 0);
	if (!i) {
		dev_err(dev, "cannot get platform resources for msi interrupt\n");
		err = -ENOENT;
		goto err_irq1;
	}
	pcie->msi.irq1 = i;

	i = irq_of_parse_and_map(dev->of_node, 1);
	if (!i) {
		dev_err(dev, "cannot get platform resources for msi interrupt\n");
		err = -ENOENT;
		goto err_irq2;
	}
	pcie->msi.irq2 = i;

	return 0;

err_irq2:
	irq_dispose_mapping(pcie->msi.irq1);
err_irq1:
	return err;
}

static int rcar_pcie_inbound_ranges(struct rcar_pcie *pcie,
				    struct of_pci_range *range,
				    int *index)
{
	u64 restype = range->flags;
	u64 cpu_addr = range->cpu_addr;
	u64 cpu_end = range->cpu_addr + range->size;
	u64 pci_addr = range->pci_addr;
	u32 flags = LAM_64BIT | LAR_ENABLE;
	u64 mask;
	u64 size;
	int idx = *index;

	if (restype & IORESOURCE_PREFETCH)
		flags |= LAM_PREFETCH;

>>>>>>> master
	/*
	 * Set up 64-bit inbound regions as the range parser doesn't
	 * distinguish between 32 and 64-bit types.
	 */
	if (host)
		rcar_pci_write_reg(pcie, lower_32_bits(pci_addr),
				   PCIEPRAR(idx));
	rcar_pci_write_reg(pcie, lower_32_bits(cpu_addr), PCIELAR(idx));
	rcar_pci_write_reg(pcie, flags, PCIELAMR(idx));

	if (host)
		rcar_pci_write_reg(pcie, upper_32_bits(pci_addr),
				   PCIEPRAR(idx + 1));
	rcar_pci_write_reg(pcie, upper_32_bits(cpu_addr), PCIELAR(idx + 1));
	rcar_pci_write_reg(pcie, 0, PCIELAMR(idx + 1));
}
<<<<<<< HEAD
=======

static int rcar_pcie_parse_map_dma_ranges(struct rcar_pcie *pcie,
					  struct device_node *np)
{
	struct of_pci_range range;
	struct of_pci_range_parser parser;
	int index = 0;
	int err;

	if (of_pci_dma_range_parser_init(&parser, np))
		return -EINVAL;

	/* Get the dma-ranges from DT */
	for_each_of_pci_range(&parser, &range) {
		u64 end = range.cpu_addr + range.size - 1;

		dev_dbg(pcie->dev, "0x%08x 0x%016llx..0x%016llx -> 0x%016llx\n",
			range.flags, range.cpu_addr, end, range.pci_addr);

		err = rcar_pcie_inbound_ranges(pcie, &range, &index);
		if (err)
			return err;
	}

	return 0;
}

static const struct of_device_id rcar_pcie_of_match[] = {
	{ .compatible = "renesas,pcie-r8a7779",
	  .data = rcar_pcie_phy_init_h1 },
	{ .compatible = "renesas,pcie-r8a7790",
	  .data = rcar_pcie_phy_init_gen2 },
	{ .compatible = "renesas,pcie-r8a7791",
	  .data = rcar_pcie_phy_init_gen2 },
	{ .compatible = "renesas,pcie-rcar-gen2",
	  .data = rcar_pcie_phy_init_gen2 },
	{ .compatible = "renesas,pcie-r8a7795",
	  .data = rcar_pcie_phy_init_gen3 },
	{ .compatible = "renesas,pcie-rcar-gen3",
	  .data = rcar_pcie_phy_init_gen3 },
	{},
};

static int rcar_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rcar_pcie *pcie;
	unsigned int data;
	int err;
	int (*phy_init_fn)(struct rcar_pcie *);
	struct pci_host_bridge *bridge;

	bridge = pci_alloc_host_bridge(sizeof(*pcie));
	if (!bridge)
		return -ENOMEM;

	pcie = pci_host_bridge_priv(bridge);

	pcie->dev = dev;
	platform_set_drvdata(pdev, pcie);

	err = pci_parse_request_of_pci_ranges(dev, &pcie->resources, NULL);
	if (err)
		goto err_free_bridge;

	pm_runtime_enable(pcie->dev);
	err = pm_runtime_get_sync(pcie->dev);
	if (err < 0) {
		dev_err(pcie->dev, "pm_runtime_get_sync failed\n");
		goto err_pm_disable;
	}

	err = rcar_pcie_get_resources(pcie);
	if (err < 0) {
		dev_err(dev, "failed to request resources: %d\n", err);
		goto err_pm_put;
	}

	err = clk_prepare_enable(pcie->bus_clk);
	if (err) {
		dev_err(dev, "failed to enable bus clock: %d\n", err);
		goto err_unmap_msi_irqs;
	}

	err = rcar_pcie_parse_map_dma_ranges(pcie, dev->of_node);
	if (err)
		goto err_clk_disable;

	phy_init_fn = of_device_get_match_data(dev);
	err = phy_init_fn(pcie);
	if (err) {
		dev_err(dev, "failed to init PCIe PHY\n");
		goto err_clk_disable;
	}

	/* Failure to get a link might just be that no cards are inserted */
	if (rcar_pcie_hw_init(pcie)) {
		dev_info(dev, "PCIe link down\n");
		err = -ENODEV;
		goto err_phy_shutdown;
	}

	data = rcar_pci_read_reg(pcie, MACSR);
	dev_info(dev, "PCIe x%d: link up\n", (data >> 20) & 0x3f);

	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		err = rcar_pcie_enable_msi(pcie);
		if (err < 0) {
			dev_err(dev,
				"failed to enable MSI support: %d\n",
				err);
			goto err_phy_shutdown;
		}
	}

	err = rcar_pcie_enable(pcie);
	if (err)
		goto err_msi_teardown;

	return 0;

err_msi_teardown:
	if (IS_ENABLED(CONFIG_PCI_MSI))
		rcar_pcie_teardown_msi(pcie);

err_phy_shutdown:
	if (pcie->phy) {
		phy_power_off(pcie->phy);
		phy_exit(pcie->phy);
	}

err_clk_disable:
	clk_disable_unprepare(pcie->bus_clk);

err_unmap_msi_irqs:
	irq_dispose_mapping(pcie->msi.irq2);
	irq_dispose_mapping(pcie->msi.irq1);

err_pm_put:
	pm_runtime_put(dev);

err_pm_disable:
	pm_runtime_disable(dev);
	pci_free_resource_list(&pcie->resources);

err_free_bridge:
	pci_free_host_bridge(bridge);

	return err;
}

static int rcar_pcie_resume_noirq(struct device *dev)
{
	struct rcar_pcie *pcie = dev_get_drvdata(dev);

	if (rcar_pci_read_reg(pcie, PMSR) &&
	    !(rcar_pci_read_reg(pcie, PCIETCTLR) & DL_DOWN))
		return 0;

	/* Re-establish the PCIe link */
	rcar_pci_write_reg(pcie, CFINIT, PCIETCTLR);
	return rcar_pcie_wait_for_dl(pcie);
}

static const struct dev_pm_ops rcar_pcie_pm_ops = {
	.resume_noirq = rcar_pcie_resume_noirq,
};

static struct platform_driver rcar_pcie_driver = {
	.driver = {
		.name = "rcar-pcie",
		.of_match_table = rcar_pcie_of_match,
		.pm = &rcar_pcie_pm_ops,
		.suppress_bind_attrs = true,
	},
	.probe = rcar_pcie_probe,
};
builtin_platform_driver(rcar_pcie_driver);
>>>>>>> master
