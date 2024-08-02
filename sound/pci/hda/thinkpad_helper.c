// SPDX-License-Identifier: GPL-2.0
/* Helper functions for Thinkpad LED control;
 * to be included from codec driver
 */

#if IS_ENABLED(CONFIG_THINKPAD_ACPI)

#include <linux/acpi.h>
#include <linux/leds.h>

static bool is_thinkpad(struct hda_codec *codec)
{
	return (codec->core.subsystem_id >> 16 == 0x17aa) &&
	       (acpi_dev_found("LEN0068") || acpi_dev_found("LEN0268") ||
		acpi_dev_found("IBM0068"));
}

static void hda_fixup_thinkpad_acpi(struct hda_codec *codec,
				    const struct hda_fixup *fix, int action)
{
	if (action == HDA_FIXUP_ACT_PRE_PROBE) {
		if (!is_thinkpad(codec))
			return;
<<<<<<< HEAD
		snd_hda_gen_add_mute_led_cdev(codec, NULL);
		snd_hda_gen_add_micmute_led_cdev(codec, NULL);
=======
		if (!led_set_func)
			led_set_func = symbol_request(tpacpi_led_set);
		if (!led_set_func) {
			codec_warn(codec,
				   "Failed to find thinkpad-acpi symbol tpacpi_led_set\n");
			return;
		}

		removefunc = true;
		if (led_set_func(TPACPI_LED_MUTE, false) >= 0) {
			old_vmaster_hook = spec->vmaster_mute.hook;
			spec->vmaster_mute.hook = update_tpacpi_mute_led;
			removefunc = false;
		}
		if (led_set_func(TPACPI_LED_MICMUTE, false) >= 0 &&
		    !snd_hda_gen_add_micmute_led(codec,
						 update_tpacpi_micmute))
			removefunc = false;
	}

	if (led_set_func && (action == HDA_FIXUP_ACT_FREE || removefunc)) {
		symbol_put(tpacpi_led_set);
		led_set_func = NULL;
		old_vmaster_hook = NULL;
>>>>>>> master
	}
}

#else /* CONFIG_THINKPAD_ACPI */

static void hda_fixup_thinkpad_acpi(struct hda_codec *codec,
				    const struct hda_fixup *fix, int action)
{
}

#endif /* CONFIG_THINKPAD_ACPI */
