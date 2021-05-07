/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_SM4
# include <openssl/evp.h>
# include <openssl/modes.h>
# include "crypto/sm4.h"
# include "crypto/evp.h"
// # include "openssl/modes.h"
// #include "cryptoevp_locl.h"
// #include "internal/evp_int.h"
#include "crypto/modes/modes_local.h"

typedef struct {
    SM4_KEY ks;
} EVP_SM4_KEY;

//from GMSSL
typedef struct {
    union {
        double align;
        SM4_KEY ks;
    } ks;                       /* SM4 key schedule to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    GCM128_CONTEXT gcm;
    unsigned char *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */
    ctr128_f ctr;
} EVP_SM4_GCM_CTX;

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    SM4_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
    return 1;
}

static void sm4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const SM4_KEY *key,
                            unsigned char *ivec, const int enc)
{
    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
                              (block128_f)SM4_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
                              (block128_f)SM4_decrypt);
}

static void sm4_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                               size_t length, const SM4_KEY *key,
                               unsigned char *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc,
                          (block128_f)SM4_encrypt);
}

static void sm4_ecb_encrypt(const unsigned char *in, unsigned char *out,
                            const SM4_KEY *key, const int enc)
{
    if (enc)
        SM4_encrypt(in, out, key);
    else
        SM4_decrypt(in, out, key);
}

static void sm4_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                               size_t length, const SM4_KEY *key,
                               unsigned char *ivec, int *num)
{
    CRYPTO_ofb128_encrypt(in, out, length, key, ivec, num,
                          (block128_f)SM4_encrypt);
}

IMPLEMENT_BLOCK_CIPHER(sm4, ks, sm4, EVP_SM4_KEY, NID_sm4,
                       16, 16, 16, 128, EVP_CIPH_FLAG_DEFAULT_ASN1,
                       sm4_init_key, 0, 0, 0, 0)

static int sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    unsigned int num = EVP_CIPHER_CTX_num(ctx);
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY, ctx);

    CRYPTO_ctr128_encrypt(in, out, len, &dat->ks,
                          EVP_CIPHER_CTX_iv_noconst(ctx),
                          EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                          (block128_f)SM4_encrypt);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static const EVP_CIPHER sm4_ctr_mode = {
    NID_sm4_ctr, 1, 16, 16,
    EVP_CIPH_CTR_MODE,
    sm4_init_key,
    sm4_ctr_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_sm4_ctr(void)
{
    return &sm4_ctr_mode;
}



static int sm4_gcm_cleanup(EVP_CIPHER_CTX *c)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,c);
    OPENSSL_cleanse(&gctx->gcm, sizeof(gctx->gcm));
    if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(c))
        OPENSSL_free(gctx->iv);
    return 1;
}

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(unsigned char *counter)
{
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

static int sm4_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,c);
    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_CTX_iv_length(c);
        gctx->iv = EVP_CIPHER_CTX_iv_noconst(c);
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        gctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        /* Allocate memory for IV if needed */
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(c))
                OPENSSL_free(gctx->iv);
            gctx->iv = OPENSSL_malloc(arg);
            if (gctx->iv == NULL)
                return 0;
        }
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(c))
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(c)
            || gctx->taglen < 0)
            return 0;
        memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(c), arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Special case: -1 length restores whole IV */
        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        /*
         * Fixed field must be at least 4 bytes and invocation field at least
         * 8.
         */
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (EVP_CIPHER_CTX_encrypting(c)
            && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        /*
         * Invocation field will be at least 8 bytes in size and so no need
         * to check wrap around or increment more than last 8 bytes.
         */
        ctr64_inc(gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0
            || EVP_CIPHER_CTX_encrypting(c))
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        gctx->tls_aad_len = arg;
        {
            unsigned int len =
                EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8
                | EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
            /* Correct length for explicit IV */
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!EVP_CIPHER_CTX_encrypting(c))
                len -= EVP_GCM_TLS_TAG_LEN;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return EVP_GCM_TLS_TAG_LEN;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_SM4_GCM_CTX *gctx_out = EVP_C_DATA(EVP_SM4_GCM_CTX,out);
            if (gctx->gcm.key) {
                if (gctx->gcm.key != &gctx->ks)
                    return 0;
                gctx_out->gcm.key = &gctx_out->ks;
            }
            if (gctx->iv == EVP_CIPHER_CTX_iv_noconst(c))
                gctx_out->iv = EVP_CIPHER_CTX_iv_noconst(out);
            else {
                gctx_out->iv = OPENSSL_malloc(gctx->ivlen);
                if (gctx_out->iv == NULL)
                    return 0;
                memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
            }
            return 1;
        }

    default:
        return -1;

    }
}

static int sm4_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);
    if (!iv && !key)
        return 1;
    if (key) {
        do {
            (void)0;        /* terminate potentially open 'else' */

            // sm4_set_encrypt_key(&gctx->ks.ks, key);
            SM4_set_key(key, &gctx->ks.ks);
            CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks,
                               (block128_f)SM4_encrypt);
            gctx->ctr = NULL;
        } while (0);

        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
}

/*
 * Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */

static int sm4_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);
    int rv = -1;
    /* Encrypt/decrypt must be performed in place */
    if (out != in
        || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    /*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CIPHER_CTX_encrypting(ctx) ?
                            EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;
    /* Use saved AAD */
    if (CRYPTO_gcm128_aad(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
                          gctx->tls_aad_len))
        goto err;
    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        /* Encrypt payload */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        out += len;
        /* Finally write tag */
        CRYPTO_gcm128_tag(&gctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else {
        /* Decrypt */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        /* Retrieve tag */
        CRYPTO_gcm128_tag(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
                          EVP_GCM_TLS_TAG_LEN);
        /* If tag mismatch wipe buffer */
        if (CRYPTO_memcmp(EVP_CIPHER_CTX_buf_noconst(ctx), in + len,
                          EVP_GCM_TLS_TAG_LEN)) {
            OPENSSL_cleanse(out, len);
            goto err;
        }
        rv = len;
    }

 err:
    gctx->iv_set = 0;
    gctx->tls_aad_len = -1;
    return rv;
}

static int sm4_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);
    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aad_len >= 0)
        return sm4_gcm_tls_cipher(ctx, out, in, len);

    if (!gctx->iv_set)
        return -1;
    if (in) {
        if (out == NULL) {
            if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
                return -1;
        } else if (EVP_CIPHER_CTX_encrypting(ctx)) {
            if (gctx->ctr) {
                size_t bulk = 0;
                if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                                in + bulk,
                                                out + bulk,
                                                len - bulk, gctx->ctr))
                    return -1;
            } else {
                size_t bulk = 0;
                if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                          in + bulk, out + bulk, len - bulk))
                    return -1;
            }
        } else {
            if (gctx->ctr) {
                size_t bulk = 0;
                if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                                in + bulk,
                                                out + bulk,
                                                len - bulk, gctx->ctr))
                    return -1;
            } else {
                size_t bulk = 0;
                if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                          in + bulk, out + bulk, len - bulk))
                    return -1;
            }
        }
        return len;
    } else {
        if (!EVP_CIPHER_CTX_encrypting(ctx)) {
            if (gctx->taglen < 0)
                return -1;
            if (CRYPTO_gcm128_finish(&gctx->gcm,
                                     EVP_CIPHER_CTX_buf_noconst(ctx),
                                     gctx->taglen) != 0)
                return -1;
            gctx->iv_set = 0;
            return 0;
        }
        CRYPTO_gcm128_tag(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx), 16);
        gctx->taglen = 16;
        /* Don't reuse the IV */
        gctx->iv_set = 0;
        return 0;
    }
}

# define SM4_GCM_BLOCK_SIZE	1
# define SM4_GCM_IV_LENGTH	12

# define SM4_GCM_FLAGS (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_GCM_MODE \
		| EVP_CIPH_FLAG_AEAD_CIPHER)


static const EVP_CIPHER sm4_gcm_mode = {
    NID_sm4_gcm, 1, 16, 
    SM4_GCM_IV_LENGTH,
    SM4_GCM_FLAGS,
    sm4_gcm_init_key,
    sm4_gcm_cipher,

    sm4_gcm_cleanup,
    sizeof(EVP_SM4_GCM_CTX),
    NULL, NULL, sm4_gcm_ctrl, NULL
};

const EVP_CIPHER *EVP_sm4_gcm(void)
{
    return &sm4_gcm_mode;
}

//wbsm4/src/sm4/sm4_gcm.c
// void sm4_gcm128_init(gcm128_context *ctx, SM4_KEY *key) {
//     CRYPTO_gcm128_init(ctx, key, (block128_f)sm4_encrypt);
// }

// void sm4_gcm128_setiv(gcm128_context *ctx, const unsigned char *ivec,
//                       size_t len) {
//     CRYPTO_gcm128_setiv(ctx, ivec, len);
// }

// int sm4_gcm128_aad(gcm128_context *ctx, const unsigned char *aad,
//                     size_t len) {
//     return CRYPTO_gcm128_aad(ctx, aad, len);
// }

// int sm4_gcm128_encrypt(const unsigned char *in, unsigned char *out,
//                         size_t length, gcm128_context *ctx, const int enc) {
//     int ret;
//     if (enc)
//         ret = CRYPTO_gcm128_encrypt(ctx, in, out, length);
//     else
//         ret = CRYPTO_gcm128_decrypt(ctx, in, out, length);
//     return ret;
// }

// void sm4_gcm128_tag(gcm128_context *ctx, unsigned char *tag,
//                     size_t len) {
//     CRYPTO_gcm128_tag(ctx, tag, len);
// }

// int sm4_gcm128_finish(gcm128_context *ctx, const unsigned char *tag,
//                       size_t len) {
//     return CRYPTO_gcm128_finish(ctx, tag, len);
// }

// void sm4_gcm128_release(gcm128_context *ctx) {
//     CRYPTO_gcm128_release(ctx);
// }

#endif
