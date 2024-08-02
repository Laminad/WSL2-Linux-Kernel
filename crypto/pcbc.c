// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PCBC: Propagating Cipher Block Chaining mode
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Derived from cbc.c
 * - Copyright (c) 2006 Herbert Xu <herbert@gondor.apana.org.au>
 */

#include <crypto/algapi.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/skcipher.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int crypto_pcbc_encrypt_segment(struct skcipher_request *req,
				       struct skcipher_walk *walk,
				       struct crypto_cipher *tfm)
{
	int bsize = crypto_cipher_blocksize(tfm);
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	u8 * const iv = walk->iv;

	do {
		crypto_xor(iv, src, bsize);
		crypto_cipher_encrypt_one(tfm, dst, iv);
		crypto_xor_cpy(iv, dst, src, bsize);

		src += bsize;
		dst += bsize;
	} while ((nbytes -= bsize) >= bsize);

	return nbytes;
}

static int crypto_pcbc_encrypt_inplace(struct skcipher_request *req,
				       struct skcipher_walk *walk,
				       struct crypto_cipher *tfm)
{
	int bsize = crypto_cipher_blocksize(tfm);
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 * const iv = walk->iv;
	u8 tmpbuf[MAX_CIPHER_BLOCKSIZE];

	do {
		memcpy(tmpbuf, src, bsize);
		crypto_xor(iv, src, bsize);
		crypto_cipher_encrypt_one(tfm, src, iv);
		crypto_xor_cpy(iv, tmpbuf, src, bsize);

		src += bsize;
	} while ((nbytes -= bsize) >= bsize);

	return nbytes;
}

static int crypto_pcbc_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct crypto_cipher *cipher = skcipher_cipher_simple(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	while ((nbytes = walk.nbytes)) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			nbytes = crypto_pcbc_encrypt_inplace(req, &walk,
							     cipher);
		else
			nbytes = crypto_pcbc_encrypt_segment(req, &walk,
							     cipher);
		err = skcipher_walk_done(&walk, nbytes);
	}

	return err;
}

static int crypto_pcbc_decrypt_segment(struct skcipher_request *req,
				       struct skcipher_walk *walk,
				       struct crypto_cipher *tfm)
{
	int bsize = crypto_cipher_blocksize(tfm);
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	u8 * const iv = walk->iv;

	do {
		crypto_cipher_decrypt_one(tfm, dst, src);
		crypto_xor(dst, iv, bsize);
		crypto_xor_cpy(iv, dst, src, bsize);

		src += bsize;
		dst += bsize;
	} while ((nbytes -= bsize) >= bsize);

	return nbytes;
}

static int crypto_pcbc_decrypt_inplace(struct skcipher_request *req,
				       struct skcipher_walk *walk,
				       struct crypto_cipher *tfm)
{
	int bsize = crypto_cipher_blocksize(tfm);
	unsigned int nbytes = walk->nbytes;
	u8 *src = walk->src.virt.addr;
	u8 * const iv = walk->iv;
	u8 tmpbuf[MAX_CIPHER_BLOCKSIZE] __aligned(__alignof__(u32));

	do {
		memcpy(tmpbuf, src, bsize);
		crypto_cipher_decrypt_one(tfm, src, src);
		crypto_xor(src, iv, bsize);
		crypto_xor_cpy(iv, src, tmpbuf, bsize);

		src += bsize;
	} while ((nbytes -= bsize) >= bsize);

	return nbytes;
}

static int crypto_pcbc_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct crypto_cipher *cipher = skcipher_cipher_simple(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, false);

	while ((nbytes = walk.nbytes)) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			nbytes = crypto_pcbc_decrypt_inplace(req, &walk,
							     cipher);
		else
			nbytes = crypto_pcbc_decrypt_segment(req, &walk,
							     cipher);
		err = skcipher_walk_done(&walk, nbytes);
	}

	return err;
}

static int crypto_pcbc_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	struct skcipher_instance *inst;
	int err;

	inst = skcipher_alloc_instance_simple(tmpl, tb);
	if (IS_ERR(inst))
		return PTR_ERR(inst);

<<<<<<< HEAD
=======
	if (((algt->type ^ CRYPTO_ALG_TYPE_SKCIPHER) & algt->mask) &
	    ~CRYPTO_ALG_INTERNAL)
		return -EINVAL;

	inst = kzalloc(sizeof(*inst) + sizeof(*spawn), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;

	alg = crypto_get_attr_alg(tb, CRYPTO_ALG_TYPE_CIPHER |
				      (algt->type & CRYPTO_ALG_INTERNAL),
				  CRYPTO_ALG_TYPE_MASK |
				  (algt->mask & CRYPTO_ALG_INTERNAL));
	err = PTR_ERR(alg);
	if (IS_ERR(alg))
		goto err_free_inst;

	spawn = skcipher_instance_ctx(inst);
	err = crypto_init_spawn(spawn, alg, skcipher_crypto_instance(inst),
				CRYPTO_ALG_TYPE_MASK);
	if (err)
		goto err_put_alg;

	err = crypto_inst_setname(skcipher_crypto_instance(inst), "pcbc", alg);
	if (err)
		goto err_drop_spawn;

	inst->alg.base.cra_flags = alg->cra_flags & CRYPTO_ALG_INTERNAL;
	inst->alg.base.cra_priority = alg->cra_priority;
	inst->alg.base.cra_blocksize = alg->cra_blocksize;
	inst->alg.base.cra_alignmask = alg->cra_alignmask;

	inst->alg.ivsize = alg->cra_blocksize;
	inst->alg.min_keysize = alg->cra_cipher.cia_min_keysize;
	inst->alg.max_keysize = alg->cra_cipher.cia_max_keysize;

	inst->alg.base.cra_ctxsize = sizeof(struct crypto_pcbc_ctx);

	inst->alg.init = crypto_pcbc_init_tfm;
	inst->alg.exit = crypto_pcbc_exit_tfm;

	inst->alg.setkey = crypto_pcbc_setkey;
>>>>>>> master
	inst->alg.encrypt = crypto_pcbc_encrypt;
	inst->alg.decrypt = crypto_pcbc_decrypt;

	err = skcipher_register_instance(tmpl, inst);
	if (err)
<<<<<<< HEAD
		inst->free(inst);
=======
		goto err_drop_spawn;
	crypto_mod_put(alg);
>>>>>>> master

	return err;
<<<<<<< HEAD
=======

err_drop_spawn:
	crypto_drop_spawn(spawn);
err_put_alg:
	crypto_mod_put(alg);
err_free_inst:
	kfree(inst);
	goto out;
>>>>>>> master
}

static struct crypto_template crypto_pcbc_tmpl = {
	.name = "pcbc",
	.create = crypto_pcbc_create,
	.module = THIS_MODULE,
};

static int __init crypto_pcbc_module_init(void)
{
	return crypto_register_template(&crypto_pcbc_tmpl);
}

static void __exit crypto_pcbc_module_exit(void)
{
	crypto_unregister_template(&crypto_pcbc_tmpl);
}

subsys_initcall(crypto_pcbc_module_init);
module_exit(crypto_pcbc_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PCBC block cipher mode of operation");
MODULE_ALIAS_CRYPTO("pcbc");
MODULE_IMPORT_NS(CRYPTO_INTERNAL);
