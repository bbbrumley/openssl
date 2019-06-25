/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
/* The line above prevents "ISO C forbids an empty translation unit" warning */
#ifndef FIPS_MODE
# include <string.h>
# include <openssl/evp.h>
# include <openssl/hmac.h>
# include <openssl/objects.h>
# include "internal/cryptlib.h"

static int bits2int(BIGNUM *out, int qlen,
    const unsigned char *message, size_t message_len)
{

    if (BN_bin2bn(message, (int)message_len, out) == NULL)
        return 0;
    if ((int)message_len * 8 > qlen)
        return BN_rshift(out, out, (int)message_len * 8 - qlen);
    return 1;
}
static int int2octects(unsigned char *out, const BIGNUM  *num, int rlen)
{
    return BN_bn2binpad(num, out, rlen);
}
static int bits2octects(unsigned char *out, const BIGNUM  *range,
    const unsigned char *message, size_t message_len, BN_CTX  *ctx)
{
    BIGNUM *num = BN_new();
    if (
        !bits2int(num, BN_num_bits(range), message, message_len) ||
        !BN_mod(num, num, range, ctx) ||
        !BN_bn2binpad(num, out, BN_num_bytes(range)))
    {
        BN_free(num);
        return 0;
    }
    BN_clear_free(num);
    return 1;
}
int BN_generate_dsa_deterministic_nonce(BIGNUM *out, const BIGNUM *range,
    const BIGNUM *priv, const unsigned char *message,
    size_t message_len, int hash_type, BN_CTX *ctx)
{
    int ret = 0;

    const unsigned char constant[] = { 0x00, 0x01 };
    const EVP_MD *evp_md = evp_md = EVP_get_digestbynid(hash_type);
    HMAC_CTX *hctx;
    int qlen, rlen, hlen;
    unsigned char V[EVP_MAX_MD_SIZE], K[EVP_MAX_MD_SIZE];
    unsigned char *x,  *h,  *T;

    if (evp_md == NULL) {
        BNerr(BN_F_BN_GENERATE_DSA_DETERMINISTIC_NONCE, BN_R_NO_SUITABLE_DIGEST);
        return 0;
    }

    if ((hctx = HMAC_CTX_new()) == NULL)
        return 0;

    if ((qlen = BN_num_bits(range)) < 0 ||
        (rlen = BN_num_bytes(range)) < 0 ||
        (hlen = EVP_MD_size(evp_md)) < 0)
        return 0;

    if (((x = (unsigned char*)OPENSSL_malloc(rlen)) == NULL) |
        ((h = (unsigned char*)OPENSSL_malloc(rlen)) == NULL) |
        ((T = (unsigned char*)OPENSSL_malloc(rlen)) == NULL))
        goto cleanup;

    if (!int2octects(x, priv, rlen) ||
        !bits2octects(h, range, message, message_len, ctx))
        goto cleanup;

    memset(V, 1, hlen);
    memset(K, 0, hlen);

    if (!HMAC_CTX_reset(hctx) ||
        !HMAC_Init_ex(hctx, K, hlen, evp_md, NULL) ||
        !HMAC_Update(hctx, V, hlen) ||
        !HMAC_Update(hctx, constant + 0, 1) ||
        !HMAC_Update(hctx, x, rlen) ||
        !HMAC_Update(hctx, h, rlen) ||
        !HMAC_Final(hctx, K, NULL))
        goto cleanup;

    if (!HMAC_CTX_reset(hctx) ||
        !HMAC_Init_ex(hctx, K, hlen, evp_md, NULL) ||
        !HMAC_Update(hctx, V, hlen) ||
        !HMAC_Final(hctx, V, NULL))
        goto cleanup;

    if (!HMAC_CTX_reset(hctx) ||
        !HMAC_Init_ex(hctx, K, hlen, evp_md, NULL) ||
        !HMAC_Update(hctx, V, hlen) ||
        !HMAC_Update(hctx, constant + 1, 1) ||
        !HMAC_Update(hctx, x, rlen) ||
        !HMAC_Update(hctx, h, rlen) ||
        !HMAC_Final(hctx, K, NULL))
        goto cleanup;

    if (!HMAC_CTX_reset(hctx) ||
        !HMAC_Init_ex(hctx, K, hlen, evp_md, NULL) ||
        !HMAC_Update(hctx, V, hlen) ||
        !HMAC_Final(hctx, V, NULL))
        goto cleanup;

    while (1)
    {
        int offlen = 0;
        int i;
        for (i = 0; i < rlen; i += offlen)
        {
            if (!HMAC_CTX_reset(hctx) ||
                !HMAC_Init_ex(hctx, K, hlen, evp_md, NULL) ||
                !HMAC_Update(hctx, V, hlen) ||
                !HMAC_Final(hctx, V, NULL))
                goto cleanup;
            offlen = ((rlen - i) < hlen) ? (rlen - i) : hlen;
            memcpy(T + i, V, offlen);
        }
        bits2int(out, qlen, T, rlen);
        if ((!BN_is_zero(out)) && (!BN_is_one(out)) && (BN_cmp(out, range) < 0))
            break;

        if (!HMAC_CTX_reset(hctx) ||
            !HMAC_Init_ex(hctx, K, hlen, evp_md, NULL) ||
            !HMAC_Update(hctx, V, hlen) ||
            !HMAC_Update(hctx, constant + 0, 1) ||
            !HMAC_Final(hctx, K, NULL))
            goto cleanup;

        if (!HMAC_CTX_reset(hctx) ||
            !HMAC_Init_ex(hctx, K, hlen, evp_md, NULL) ||
            !HMAC_Update(hctx, V, hlen) ||
            !HMAC_Final(hctx, V, NULL))
            goto cleanup;
    }
    ret = 1;

cleanup:
    HMAC_CTX_free(hctx);
    OPENSSL_free(x);
    OPENSSL_free(h);
    OPENSSL_free(T);
    return ret;
}
#endif
