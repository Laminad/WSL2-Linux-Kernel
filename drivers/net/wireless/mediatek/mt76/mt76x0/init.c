// SPDX-License-Identifier: GPL-2.0-only
/*
 * (c) Copyright 2002-2010, Ralink Technology, Inc.
 * Copyright (C) 2014 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2015 Jakub Kicinski <kubakici@wp.pl>
 * Copyright (C) 2018 Stanislaw Gruszka <stf_xl@wp.pl>
 */

#include "mt76x0.h"
#include "eeprom.h"
#include "mcu.h"
#include "initvals.h"
#include "initvals_init.h"
#include "../mt76x02_phy.h"

static void
mt76x0_set_wlan_state(struct mt76x02_dev *dev, u32 val, bool enable)
{
	u32 mask = MT_CMB_CTRL_XTAL_RDY | MT_CMB_CTRL_PLL_LD;

	/* Note: we don't turn off WLAN_CLK because that makes the device
	 *	 not respond properly on the probe path.
	 *	 In case anyone (PSM?) wants to use this function we can
	 *	 bring the clock stuff back and fixup the probe path.
	 */

	if (enable)
		val |= (MT_WLAN_FUN_CTRL_WLAN_EN |
			MT_WLAN_FUN_CTRL_WLAN_CLK_EN);
	else
		val &= ~(MT_WLAN_FUN_CTRL_WLAN_EN);

	mt76_wr(dev, MT_WLAN_FUN_CTRL, val);
	udelay(20);

	/* Note: vendor driver tries to disable/enable wlan here and retry
	 *       but the code which does it is so buggy it must have never
	 *       triggered, so don't bother.
	 */
	if (enable && !mt76_poll(dev, MT_CMB_CTRL, mask, mask, 2000))
		dev_err(dev->mt76.dev, "PLL and XTAL check failed\n");
}

void mt76x0_chip_onoff(struct mt76x02_dev *dev, bool enable, bool reset)
{
	u32 val;

	val = mt76_rr(dev, MT_WLAN_FUN_CTRL);

	if (reset) {
		val |= MT_WLAN_FUN_CTRL_GPIO_OUT_EN;
		val &= ~MT_WLAN_FUN_CTRL_FRC_WL_ANT_SEL;

		if (val & MT_WLAN_FUN_CTRL_WLAN_EN) {
			val |= (MT_WLAN_FUN_CTRL_WLAN_RESET |
				MT_WLAN_FUN_CTRL_WLAN_RESET_RF);
			mt76_wr(dev, MT_WLAN_FUN_CTRL, val);
			udelay(20);

			val &= ~(MT_WLAN_FUN_CTRL_WLAN_RESET |
				 MT_WLAN_FUN_CTRL_WLAN_RESET_RF);
		}
	}

	mt76_wr(dev, MT_WLAN_FUN_CTRL, val);
	udelay(20);

	mt76x0_set_wlan_state(dev, val, enable);
}
EXPORT_SYMBOL_GPL(mt76x0_chip_onoff);

static void mt76x0_reset_csr_bbp(struct mt76x02_dev *dev)
{
	mt76_wr(dev, MT_MAC_SYS_CTRL,
		MT_MAC_SYS_CTRL_RESET_CSR |
		MT_MAC_SYS_CTRL_RESET_BBP);
	msleep(200);
	mt76_clear(dev, MT_MAC_SYS_CTRL,
		   MT_MAC_SYS_CTRL_RESET_CSR |
		   MT_MAC_SYS_CTRL_RESET_BBP);
}

#define RANDOM_WRITE(dev, tab)			\
	mt76_wr_rp(dev, MT_MCU_MEMMAP_WLAN,	\
		   tab, ARRAY_SIZE(tab))

static int mt76x0_init_bbp(struct mt76x02_dev *dev)
{
	int ret, i;

	ret = mt76x0_phy_wait_bbp_ready(dev);
	if (ret)
		return ret;

	RANDOM_WRITE(dev, mt76x0_bbp_init_tab);

	for (i = 0; i < ARRAY_SIZE(mt76x0_bbp_switch_tab); i++) {
		const struct mt76x0_bbp_switch_item *item = &mt76x0_bbp_switch_tab[i];
		const struct mt76_reg_pair *pair = &item->reg_pair;

		if (((RF_G_BAND | RF_BW_20) & item->bw_band) == (RF_G_BAND | RF_BW_20))
			mt76_wr(dev, pair->reg, pair->value);
	}

	RANDOM_WRITE(dev, mt76x0_dcoc_tab);

	return 0;
}

static void mt76x0_init_mac_registers(struct mt76x02_dev *dev)
{
	RANDOM_WRITE(dev, common_mac_reg_table);

	/* Enable PBF and MAC clock SYS_CTRL[11:10] = 0x3 */
	RANDOM_WRITE(dev, mt76x0_mac_reg_table);

	/* Release BBP and MAC reset MAC_SYS_CTRL[1:0] = 0x0 */
	mt76_clear(dev, MT_MAC_SYS_CTRL, 0x3);

	/* Set 0x141C[15:12]=0xF */
	mt76_set(dev, MT_EXT_CCA_CFG, 0xf000);

	mt76_clear(dev, MT_FCE_L2_STUFF, MT_FCE_L2_STUFF_WR_MPDU_LEN_EN);

	/*
	 * tx_ring 9 is for mgmt frame
	 * tx_ring 8 is for in-band command frame.
	 * WMM_RG0_TXQMA: this register setting is for FCE to
	 *		  define the rule of tx_ring 9
	 * WMM_RG1_TXQMA: this register setting is for FCE to
	 *		  define the rule of tx_ring 8
	 */
	mt76_rmw(dev, MT_WMM_CTRL, 0x3ff, 0x201);
}

void mt76x0_mac_stop(struct mt76x02_dev *dev)
{
	int i = 200, ok = 0;

	mt76_clear(dev, MT_TXOP_CTRL_CFG, MT_TXOP_ED_CCA_EN);

	/* Page count on TxQ */
	while (i-- && ((mt76_rr(dev, 0x0438) & 0xffffffff) ||
		       (mt76_rr(dev, 0x0a30) & 0x000000ff) ||
		       (mt76_rr(dev, 0x0a34) & 0x00ff00ff)))
		msleep(10);

	if (!mt76_poll(dev, MT_MAC_STATUS, MT_MAC_STATUS_TX, 0, 1000))
		dev_warn(dev->mt76.dev, "Warning: MAC TX did not stop!\n");

	mt76_clear(dev, MT_MAC_SYS_CTRL, MT_MAC_SYS_CTRL_ENABLE_RX |
					 MT_MAC_SYS_CTRL_ENABLE_TX);

	/* Page count on RxQ */
	for (i = 0; i < 200; i++) {
		if (!(mt76_rr(dev, MT_RXQ_STA) & 0x00ff0000) &&
		    !mt76_rr(dev, 0x0a30) &&
		    !mt76_rr(dev, 0x0a34)) {
			if (ok++ > 5)
				break;
			continue;
		}
		msleep(1);
	}

	if (!mt76_poll(dev, MT_MAC_STATUS, MT_MAC_STATUS_RX, 0, 1000))
		dev_warn(dev->mt76.dev, "Warning: MAC RX did not stop!\n");
}
EXPORT_SYMBOL_GPL(mt76x0_mac_stop);

int mt76x0_init_hardware(struct mt76x02_dev *dev)
{
	int ret, i, k;

<<<<<<< HEAD
	if (!mt76x02_wait_for_wpdma(&dev->mt76, 1000))
		return -EIO;
=======
static void mt76x0_stop_hardware(struct mt76x0_dev *dev)
{
	mt76x0_chip_onoff(dev, false, false);
}

int mt76x0_init_hardware(struct mt76x0_dev *dev, bool reset)
{
	static const u16 beacon_offsets[16] = {
		/* 512 byte per beacon */
		0xc000,	0xc200,	0xc400,	0xc600,
		0xc800,	0xca00,	0xcc00,	0xce00,
		0xd000,	0xd200,	0xd400,	0xd600,
		0xd800,	0xda00,	0xdc00,	0xde00
	};
	int ret;

	dev->beacon_offsets = beacon_offsets;

	mt76x0_chip_onoff(dev, true, reset);

	ret = mt76x0_wait_asic_ready(dev);
	if (ret)
		goto err;
	ret = mt76x0_mcu_init(dev);
	if (ret)
		goto err;

	if (!mt76_poll_msec(dev, MT_WPDMA_GLO_CFG,
			    MT_WPDMA_GLO_CFG_TX_DMA_BUSY |
			    MT_WPDMA_GLO_CFG_RX_DMA_BUSY, 0, 100)) {
		ret = -EIO;
		goto err;
	}
>>>>>>> master

	/* Wait for ASIC ready after FW load. */
	if (!mt76x02_wait_for_mac(&dev->mt76))
		return -ETIMEDOUT;

	mt76x0_reset_csr_bbp(dev);
<<<<<<< HEAD
	ret = mt76x02_mcu_function_select(dev, Q_SELECT, 1);
=======
	mt76x0_init_usb_dma(dev);

	mt76_wr(dev, MT_HEADER_TRANS_CTRL_REG, 0x0);
	mt76_wr(dev, MT_TSO_CTRL, 0x0);

	ret = mt76x0_mcu_cmd_init(dev);
	if (ret)
		goto err;
	ret = mt76x0_dma_init(dev);
	if (ret)
		goto err_mcu;

	mt76x0_init_mac_registers(dev);

	if (!mt76_poll_msec(dev, MT_MAC_STATUS,
			    MT_MAC_STATUS_TX | MT_MAC_STATUS_RX, 0, 1000)) {
		ret = -EIO;
		goto err_rx;
	}

	ret = mt76x0_init_bbp(dev);
	if (ret)
		goto err_rx;

	ret = mt76x0_init_wcid_mem(dev);
	if (ret)
		goto err_rx;
	ret = mt76x0_init_key_mem(dev);
	if (ret)
		goto err_rx;
	ret = mt76x0_init_wcid_attr_mem(dev);
	if (ret)
		goto err_rx;

	mt76_clear(dev, MT_BEACON_TIME_CFG, (MT_BEACON_TIME_CFG_TIMER_EN |
					     MT_BEACON_TIME_CFG_SYNC_MODE |
					     MT_BEACON_TIME_CFG_TBTT_EN |
					     MT_BEACON_TIME_CFG_BEACON_TX));

	mt76x0_reset_counters(dev);

	mt76_rmw(dev, MT_US_CYC_CFG, MT_US_CYC_CNT, 0x1e);

	mt76_wr(dev, MT_TXOP_CTRL_CFG,
		   FIELD_PREP(MT_TXOP_TRUN_EN, 0x3f) |
		   FIELD_PREP(MT_TXOP_EXT_CCA_DLY, 0x58));

	ret = mt76x0_eeprom_init(dev);
	if (ret)
		goto err_rx;

	mt76x0_phy_init(dev);
	return 0;

err_rx:
	mt76x0_dma_cleanup(dev);
err_mcu:
	mt76x0_mcu_cmd_deinit(dev);
err:
	mt76x0_chip_onoff(dev, false, false);
	return ret;
}

void mt76x0_cleanup(struct mt76x0_dev *dev)
{
	if (!test_and_clear_bit(MT76_STATE_INITIALIZED, &dev->mt76.state))
		return;

	mt76x0_stop_hardware(dev);
	mt76x0_dma_cleanup(dev);
	mt76x0_mcu_cmd_deinit(dev);
}

struct mt76x0_dev *mt76x0_alloc_device(struct device *pdev)
{
	struct ieee80211_hw *hw;
	struct mt76x0_dev *dev;

	hw = ieee80211_alloc_hw(sizeof(*dev), &mt76x0_ops);
	if (!hw)
		return NULL;

	dev = hw->priv;
	dev->mt76.dev = pdev;
	dev->mt76.hw = hw;
	mutex_init(&dev->usb_ctrl_mtx);
	mutex_init(&dev->reg_atomic_mutex);
	mutex_init(&dev->hw_atomic_mutex);
	mutex_init(&dev->mutex);
	spin_lock_init(&dev->tx_lock);
	spin_lock_init(&dev->rx_lock);
	spin_lock_init(&dev->mt76.lock);
	spin_lock_init(&dev->mac_lock);
	spin_lock_init(&dev->con_mon_lock);
	atomic_set(&dev->avg_ampdu_len, 1);
	skb_queue_head_init(&dev->tx_skb_done);

	dev->stat_wq = alloc_workqueue("mt76x0", WQ_UNBOUND, 0);
	if (!dev->stat_wq) {
		ieee80211_free_hw(hw);
		return NULL;
	}

	return dev;
}

#define CHAN2G(_idx, _freq) {			\
	.band = NL80211_BAND_2GHZ,		\
	.center_freq = (_freq),			\
	.hw_value = (_idx),			\
	.max_power = 30,			\
}

static const struct ieee80211_channel mt76_channels_2ghz[] = {
	CHAN2G(1, 2412),
	CHAN2G(2, 2417),
	CHAN2G(3, 2422),
	CHAN2G(4, 2427),
	CHAN2G(5, 2432),
	CHAN2G(6, 2437),
	CHAN2G(7, 2442),
	CHAN2G(8, 2447),
	CHAN2G(9, 2452),
	CHAN2G(10, 2457),
	CHAN2G(11, 2462),
	CHAN2G(12, 2467),
	CHAN2G(13, 2472),
	CHAN2G(14, 2484),
};

#define CHAN5G(_idx, _freq) {			\
	.band = NL80211_BAND_5GHZ,		\
	.center_freq = (_freq),			\
	.hw_value = (_idx),			\
	.max_power = 30,			\
}

static const struct ieee80211_channel mt76_channels_5ghz[] = {
	CHAN5G(36, 5180),
	CHAN5G(40, 5200),
	CHAN5G(44, 5220),
	CHAN5G(46, 5230),
	CHAN5G(48, 5240),
	CHAN5G(52, 5260),
	CHAN5G(56, 5280),
	CHAN5G(60, 5300),
	CHAN5G(64, 5320),

	CHAN5G(100, 5500),
	CHAN5G(104, 5520),
	CHAN5G(108, 5540),
	CHAN5G(112, 5560),
	CHAN5G(116, 5580),
	CHAN5G(120, 5600),
	CHAN5G(124, 5620),
	CHAN5G(128, 5640),
	CHAN5G(132, 5660),
	CHAN5G(136, 5680),
	CHAN5G(140, 5700),
};

#define CCK_RATE(_idx, _rate) {					\
	.bitrate = _rate,					\
	.flags = IEEE80211_RATE_SHORT_PREAMBLE,			\
	.hw_value = (MT_PHY_TYPE_CCK << 8) | _idx,		\
	.hw_value_short = (MT_PHY_TYPE_CCK << 8) | (8 + _idx),	\
}

#define OFDM_RATE(_idx, _rate) {				\
	.bitrate = _rate,					\
	.hw_value = (MT_PHY_TYPE_OFDM << 8) | _idx,		\
	.hw_value_short = (MT_PHY_TYPE_OFDM << 8) | _idx,	\
}

static struct ieee80211_rate mt76_rates[] = {
	CCK_RATE(0, 10),
	CCK_RATE(1, 20),
	CCK_RATE(2, 55),
	CCK_RATE(3, 110),
	OFDM_RATE(0, 60),
	OFDM_RATE(1, 90),
	OFDM_RATE(2, 120),
	OFDM_RATE(3, 180),
	OFDM_RATE(4, 240),
	OFDM_RATE(5, 360),
	OFDM_RATE(6, 480),
	OFDM_RATE(7, 540),
};

static int
mt76_init_sband(struct mt76x0_dev *dev, struct ieee80211_supported_band *sband,
		const struct ieee80211_channel *chan, int n_chan,
		struct ieee80211_rate *rates, int n_rates)
{
	struct ieee80211_sta_ht_cap *ht_cap;
	void *chanlist;
	int size;

	size = n_chan * sizeof(*chan);
	chanlist = devm_kmemdup(dev->mt76.dev, chan, size, GFP_KERNEL);
	if (!chanlist)
		return -ENOMEM;

	sband->channels = chanlist;
	sband->n_channels = n_chan;
	sband->bitrates = rates;
	sband->n_bitrates = n_rates;

	ht_cap = &sband->ht_cap;
	ht_cap->ht_supported = true;
	ht_cap->cap = IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
		      IEEE80211_HT_CAP_GRN_FLD |
		      IEEE80211_HT_CAP_SGI_20 |
		      IEEE80211_HT_CAP_SGI_40 |
		      (1 << IEEE80211_HT_CAP_RX_STBC_SHIFT);

	ht_cap->mcs.rx_mask[0] = 0xff;
	ht_cap->mcs.rx_mask[4] = 0x1;
	ht_cap->mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED;
	ht_cap->ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
	ht_cap->ampdu_density = IEEE80211_HT_MPDU_DENSITY_2;

	return 0;
}

static int
mt76_init_sband_2g(struct mt76x0_dev *dev)
{
	dev->mt76.hw->wiphy->bands[NL80211_BAND_2GHZ] = &dev->mt76.sband_2g.sband;

	WARN_ON(dev->ee->reg.start - 1 + dev->ee->reg.num >
		ARRAY_SIZE(mt76_channels_2ghz));


	return mt76_init_sband(dev, &dev->mt76.sband_2g.sband,
			       mt76_channels_2ghz, ARRAY_SIZE(mt76_channels_2ghz),
			       mt76_rates, ARRAY_SIZE(mt76_rates));
}

static int
mt76_init_sband_5g(struct mt76x0_dev *dev)
{
	dev->mt76.hw->wiphy->bands[NL80211_BAND_5GHZ] = &dev->mt76.sband_5g.sband;

	return mt76_init_sband(dev, &dev->mt76.sband_5g.sband,
			       mt76_channels_5ghz, ARRAY_SIZE(mt76_channels_5ghz),
			       mt76_rates + 4, ARRAY_SIZE(mt76_rates) - 4);
}


int mt76x0_register_device(struct mt76x0_dev *dev)
{
	struct ieee80211_hw *hw = dev->mt76.hw;
	struct wiphy *wiphy = hw->wiphy;
	int ret;

	/* Reserve WCID 0 for mcast - thanks to this APs WCID will go to
	 * entry no. 1 like it does in the vendor driver.
	 */
	dev->wcid_mask[0] |= 1;

	/* init fake wcid for monitor interfaces */
	dev->mon_wcid = devm_kmalloc(dev->mt76.dev, sizeof(*dev->mon_wcid),
				     GFP_KERNEL);
	if (!dev->mon_wcid)
		return -ENOMEM;
	dev->mon_wcid->idx = 0xff;
	dev->mon_wcid->hw_key_idx = -1;

	SET_IEEE80211_DEV(hw, dev->mt76.dev);

	hw->queues = 4;
	ieee80211_hw_set(hw, SIGNAL_DBM);
	ieee80211_hw_set(hw, PS_NULLFUNC_STACK);
	ieee80211_hw_set(hw, SUPPORTS_HT_CCK_RATES);
	ieee80211_hw_set(hw, AMPDU_AGGREGATION);
	ieee80211_hw_set(hw, SUPPORTS_RC_TABLE);
	ieee80211_hw_set(hw, MFP_CAPABLE);
	hw->max_rates = 1;
	hw->max_report_rates = 7;
	hw->max_rate_tries = 1;

	hw->sta_data_size = sizeof(struct mt76_sta);
	hw->vif_data_size = sizeof(struct mt76_vif);

	SET_IEEE80211_PERM_ADDR(hw, dev->macaddr);

	wiphy->features |= NL80211_FEATURE_ACTIVE_MONITOR;
	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);

	if (dev->ee->has_2ghz) {
		ret = mt76_init_sband_2g(dev);
		if (ret)
			return ret;
	}

	if (dev->ee->has_5ghz) {
		ret = mt76_init_sband_5g(dev);
		if (ret)
			return ret;
	}

	dev->mt76.chandef.chan = &dev->mt76.sband_2g.sband.channels[0];

	INIT_DELAYED_WORK(&dev->mac_work, mt76x0_mac_work);
	INIT_DELAYED_WORK(&dev->stat_work, mt76x0_tx_stat);

	ret = ieee80211_register_hw(hw);
>>>>>>> master
	if (ret)
		return ret;

	mt76x0_init_mac_registers(dev);

	if (!mt76x02_wait_for_txrx_idle(&dev->mt76))
		return -EIO;

	ret = mt76x0_init_bbp(dev);
	if (ret)
		return ret;

	dev->mt76.rxfilter = mt76_rr(dev, MT_RX_FILTR_CFG);

	for (i = 0; i < 16; i++)
		for (k = 0; k < 4; k++)
			mt76x02_mac_shared_key_setup(dev, i, k, NULL);

	for (i = 0; i < 256; i++)
		mt76x02_mac_wcid_setup(dev, i, 0, NULL);

	ret = mt76x0_eeprom_init(dev);
	if (ret)
		return ret;

	mt76x0_phy_init(dev);

	return 0;
}
EXPORT_SYMBOL_GPL(mt76x0_init_hardware);

static void
mt76x0_init_txpower(struct mt76x02_dev *dev,
		    struct ieee80211_supported_band *sband)
{
	struct ieee80211_channel *chan;
	struct mt76x02_rate_power t;
	s8 tp;
	int i;

	for (i = 0; i < sband->n_channels; i++) {
		chan = &sband->channels[i];

		mt76x0_get_tx_power_per_rate(dev, chan, &t);
		mt76x0_get_power_info(dev, chan, &tp);

		chan->orig_mpwr = (mt76x02_get_max_rate_power(&t) + tp) / 2;
		chan->max_power = min_t(int, chan->max_reg_power,
					chan->orig_mpwr);
	}
}

int mt76x0_register_device(struct mt76x02_dev *dev)
{
	int ret;

	ret = mt76x02_init_device(dev);
	if (ret)
		return ret;

	mt76x02_config_mac_addr_list(dev);

	ret = mt76_register_device(&dev->mt76, true, mt76x02_rates,
				   ARRAY_SIZE(mt76x02_rates));
	if (ret)
		return ret;

	if (dev->mphy.cap.has_5ghz) {
		struct ieee80211_supported_band *sband;

		sband = &dev->mphy.sband_5g.sband;
		sband->vht_cap.cap &= ~IEEE80211_VHT_CAP_RXLDPC;
		mt76x0_init_txpower(dev, sband);
	}

	if (dev->mphy.cap.has_2ghz)
		mt76x0_init_txpower(dev, &dev->mphy.sband_2g.sband);

	mt76x02_init_debugfs(dev);

	return 0;
}
EXPORT_SYMBOL_GPL(mt76x0_register_device);
