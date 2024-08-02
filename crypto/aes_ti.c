// SPDX-License-Identifier: GPL-2.0-only
/*
 * Scalar fixed time AES core transform
 *
 * Copyright (C) 2017 Linaro Ltd <ard.biesheuvel@linaro.org>
 */

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <linux/module.h>

static int aesti_set_key(struct crypto_tfm *tfm, const u8 *in_key,
			 unsigned int key_len)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	return aes_expandkey(ctx, in_key, key_len);
}

static void aesti_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);
<<<<<<< HEAD
	unsigned long flags;
=======
	const u32 *rkp = ctx->key_enc + 4;
	int rounds = 6 + ctx->key_length / 4;
	u32 st0[4], st1[4];
	unsigned long flags;
	int round;
>>>>>>> master

	/*
	 * Temporarily disable interrupts to avoid races where cachelines are
	 * evicted when the CPU is interrupted to do something else.
	 */
	local_irq_save(flags);

<<<<<<< HEAD
	aes_encrypt(ctx, out, in);

=======
	/*
	 * Temporarily disable interrupts to avoid races where cachelines are
	 * evicted when the CPU is interrupted to do something else.
	 */
	local_irq_save(flags);

	st0[0] ^= __aesti_sbox[ 0] ^ __aesti_sbox[128];
	st0[1] ^= __aesti_sbox[32] ^ __aesti_sbox[160];
	st0[2] ^= __aesti_sbox[64] ^ __aesti_sbox[192];
	st0[3] ^= __aesti_sbox[96] ^ __aesti_sbox[224];

	for (round = 0;; round += 2, rkp += 8) {
		st1[0] = mix_columns(subshift(st0, 0)) ^ rkp[0];
		st1[1] = mix_columns(subshift(st0, 1)) ^ rkp[1];
		st1[2] = mix_columns(subshift(st0, 2)) ^ rkp[2];
		st1[3] = mix_columns(subshift(st0, 3)) ^ rkp[3];

		if (round == rounds - 2)
			break;

		st0[0] = mix_columns(subshift(st1, 0)) ^ rkp[4];
		st0[1] = mix_columns(subshift(st1, 1)) ^ rkp[5];
		st0[2] = mix_columns(subshift(st1, 2)) ^ rkp[6];
		st0[3] = mix_columns(subshift(st1, 3)) ^ rkp[7];
	}

	put_unaligned_le32(subshift(st1, 0) ^ rkp[4], out);
	put_unaligned_le32(subshift(st1, 1) ^ rkp[5], out + 4);
	put_unaligned_le32(subshift(st1, 2) ^ rkp[6], out + 8);
	put_unaligned_le32(subshift(st1, 3) ^ rkp[7], out + 12);

>>>>>>> master
	local_irq_restore(flags);
}

static void aesti_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);
<<<<<<< HEAD
	unsigned long flags;
=======
	const u32 *rkp = ctx->key_dec + 4;
	int rounds = 6 + ctx->key_length / 4;
	u32 st0[4], st1[4];
	unsigned long flags;
	int round;
>>>>>>> master

	/*
	 * Temporarily disable interrupts to avoid races where cachelines are
	 * evicted when the CPU is interrupted to do something else.
	 */
	local_irq_save(flags);

<<<<<<< HEAD
	aes_decrypt(ctx, out, in);

=======
	/*
	 * Temporarily disable interrupts to avoid races where cachelines are
	 * evicted when the CPU is interrupted to do something else.
	 */
	local_irq_save(flags);

	st0[0] ^= __aesti_inv_sbox[ 0] ^ __aesti_inv_sbox[128];
	st0[1] ^= __aesti_inv_sbox[32] ^ __aesti_inv_sbox[160];
	st0[2] ^= __aesti_inv_sbox[64] ^ __aesti_inv_sbox[192];
	st0[3] ^= __aesti_inv_sbox[96] ^ __aesti_inv_sbox[224];

	for (round = 0;; round += 2, rkp += 8) {
		st1[0] = inv_mix_columns(inv_subshift(st0, 0)) ^ rkp[0];
		st1[1] = inv_mix_columns(inv_subshift(st0, 1)) ^ rkp[1];
		st1[2] = inv_mix_columns(inv_subshift(st0, 2)) ^ rkp[2];
		st1[3] = inv_mix_columns(inv_subshift(st0, 3)) ^ rkp[3];

		if (round == rounds - 2)
			break;

		st0[0] = inv_mix_columns(inv_subshift(st1, 0)) ^ rkp[4];
		st0[1] = inv_mix_columns(inv_subshift(st1, 1)) ^ rkp[5];
		st0[2] = inv_mix_columns(inv_subshift(st1, 2)) ^ rkp[6];
		st0[3] = inv_mix_columns(inv_subshift(st1, 3)) ^ rkp[7];
	}

	put_unaligned_le32(inv_subshift(st1, 0) ^ rkp[4], out);
	put_unaligned_le32(inv_subshift(st1, 1) ^ rkp[5], out + 4);
	put_unaligned_le32(inv_subshift(st1, 2) ^ rkp[6], out + 8);
	put_unaligned_le32(inv_subshift(st1, 3) ^ rkp[7], out + 12);

>>>>>>> master
	local_irq_restore(flags);
}

static struct crypto_alg aes_alg = {
	.cra_name			= "aes",
	.cra_driver_name		= "aes-fixed-time",
	.cra_priority			= 100 + 1,
	.cra_flags			= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize			= AES_BLOCK_SIZE,
	.cra_ctxsize			= sizeof(struct crypto_aes_ctx),
	.cra_module			= THIS_MODULE,

	.cra_cipher.cia_min_keysize	= AES_MIN_KEY_SIZE,
	.cra_cipher.cia_max_keysize	= AES_MAX_KEY_SIZE,
	.cra_cipher.cia_setkey		= aesti_set_key,
	.cra_cipher.cia_encrypt		= aesti_encrypt,
	.cra_cipher.cia_decrypt		= aesti_decrypt
};

static int __init aes_init(void)
{
	return crypto_register_alg(&aes_alg);
}

static void __exit aes_fini(void)
{
	crypto_unregister_alg(&aes_alg);
}

module_init(aes_init);
module_exit(aes_fini);

MODULE_DESCRIPTION("Generic fixed time AES");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL v2");
