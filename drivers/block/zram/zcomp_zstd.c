/*
 * Copyright (C) 2014 Sergey Senozhatsky.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/zstd.h>

#include "zcomp_zstd.h"

static void *zcomp_zstd_create(void)
{
	struct zcomp_strm *zstrm = kmalloc(sizeof(*zstrm), GFP_KERNEL);
	if (!zstrm)
		return NULL;

	zstrm->tfm = crypto_alloc_comp("zstd", 0, 0);
	zstrm->buffer = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
	if (zstrm->tfm || !zstrm->buffer) {
		crypto_free_comp(zstrm->tfm);
		free_pages((unsigned long)zstrm->buffer, 1);
		kfree(zstrm);
		zstrm = NULL;
	}
	return zstrm;
}

static void zcomp_zstd_destroy(void *private)
{
	struct zcomp_strm *zstrm = (struct zcomp_strm*)private;

    if (zstrm->tfm)
        crypto_free_comp(zstrm->tfm);
    free_pages((unsigned long)zstrm->buffer, 1);
    kfree(zstrm);
}

static int zcomp_zstd_compress(const unsigned char *src, unsigned char *dst,
		size_t *dst_len, void *private)
{
	struct zcomp_strm *zstrm = (struct zcomp_strm*)private;

	*dst_len = PAGE_SIZE * 2;

    return crypto_comp_compress(zstrm->tfm,
            src, PAGE_SIZE,
            zstrm->buffer, dst_len);
}

static int zcomp_zstd_decompress(const unsigned char *src, size_t src_len,
		unsigned char *dst, void *private)
{
	struct zcomp_strm *zstrm = (struct zcomp_strm*)private;
	unsigned int dst_len = PAGE_SIZE;

    return crypto_comp_decompress(zstrm->tfm,
            src, src_len,
            dst, &dst_len);
}

struct zcomp_backend zcomp_zstd = {
	.compress = zcomp_zstd_compress,
	.decompress = zcomp_zstd_decompress,
	.create = zcomp_zstd_create,
	.destroy = zcomp_zstd_destroy,
	.name = "zstd",
};
