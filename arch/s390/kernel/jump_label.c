// SPDX-License-Identifier: GPL-2.0
/*
 * Jump label s390 support
 *
 * Copyright IBM Corp. 2011
 * Author(s): Jan Glauber <jang@linux.vnet.ibm.com>
 */
#include <linux/uaccess.h>
#include <linux/jump_label.h>
#include <linux/module.h>
#include <asm/text-patching.h>
#include <asm/ipl.h>

struct insn {
	u16 opcode;
	s32 offset;
} __packed;

static void jump_label_make_nop(struct jump_entry *entry, struct insn *insn)
{
	/* brcl 0,offset */
	insn->opcode = 0xc004;
	insn->offset = (jump_entry_target(entry) - jump_entry_code(entry)) >> 1;
}

static void jump_label_make_branch(struct jump_entry *entry, struct insn *insn)
{
	/* brcl 15,offset */
	insn->opcode = 0xc0f4;
	insn->offset = (jump_entry_target(entry) - jump_entry_code(entry)) >> 1;
}

static void jump_label_bug(struct jump_entry *entry, struct insn *expected,
			   struct insn *new)
{
	unsigned char *ipc = (unsigned char *)jump_entry_code(entry);
	unsigned char *ipe = (unsigned char *)expected;
	unsigned char *ipn = (unsigned char *)new;

	pr_emerg("Jump label code mismatch at %pS [%px]\n", ipc, ipc);
	pr_emerg("Found:    %6ph\n", ipc);
	pr_emerg("Expected: %6ph\n", ipe);
	pr_emerg("New:      %6ph\n", ipn);
	panic("Corrupted kernel text");
}

static void jump_label_transform(struct jump_entry *entry,
				 enum jump_label_type type)
{
	void *code = (void *)jump_entry_code(entry);
	struct insn old, new;

	if (type == JUMP_LABEL_JMP) {
		jump_label_make_nop(entry, &old);
		jump_label_make_branch(entry, &new);
	} else {
		jump_label_make_branch(entry, &old);
		jump_label_make_nop(entry, &new);
	}
	if (memcmp(code, &old, sizeof(old)))
		jump_label_bug(entry, &old, &new);
	s390_kernel_write(code, &new, sizeof(new));
}

void arch_jump_label_transform(struct jump_entry *entry,
			       enum jump_label_type type)
{
	jump_label_transform(entry, type);
	text_poke_sync();
}

bool arch_jump_label_transform_queue(struct jump_entry *entry,
				     enum jump_label_type type)
{
	jump_label_transform(entry, type);
	return true;
}
<<<<<<< HEAD

void arch_jump_label_transform_apply(void)
{
	text_poke_sync();
}
=======
>>>>>>> master
