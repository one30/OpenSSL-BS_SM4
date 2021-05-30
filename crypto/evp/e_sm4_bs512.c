/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30: one30@m.scnu.edu.cn(email)
 * @Date         : 2021-05-11 20:36:44
 * @LastEditTime : 2021-05-26 21:04:43
 * @FilePath     : /crypto/evp/e_sm4_bs512.c
 */
#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_BS512_SM4
# include <openssl/evp.h>
#include <openssl/rand.h>
# include "crypto/sm4_bs512.h"
#include "crypto/sm4.h"
# include "crypto/evp.h"
# include "evp_local.h"
# include "openssl/objects.h"
#include "crypto/modes/modes_local.h"

typedef struct {
    SM4_BS512_KEY ks;
} EVP_SM4_BS512_KEY;

typedef struct {
    union {
        double align;
        SM4_BS512_KEY ks;
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
} EVP_SM4_BS512_GCM_CTX;

static int sm4_bs512_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    SM4_BS512_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
    return 1;
}

static int sm4_ecb_bs512_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
            size_t len)
{

    if (ctx->encrypt)
        sm4_bs512_ecb_encrypt(in, out, len, &((EVP_SM4_BS512_KEY *)ctx->cipher_data)->ks);
    else
        sm4_bs512_ecb_encrypt(in, out, len, &((EVP_SM4_BS512_KEY *)ctx->cipher_data)->ks);
    return 1;
}

static int sm4_ctr_bs512_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
            size_t len)
{

    if (ctx->encrypt)
        sm4_bs512_ctr_encrypt(in, out, len, &((EVP_SM4_BS512_KEY *)ctx->cipher_data)->ks, ctx->iv);
    else
        sm4_bs512_ctr_encrypt(in, out, len, &((EVP_SM4_BS512_KEY *)ctx->cipher_data)->ks, ctx->iv);
    return 1;
}

static const EVP_CIPHER sm4_bs512_cipher = {
    NID_sm4_bs512_ecb, 1, 16, 16,
    EVP_CIPH_ECB_MODE,
    sm4_bs512_init_key,
    sm4_ecb_bs512_encrypt, //sm4_ecb_bs_encrypt,
    NULL,
    sizeof(EVP_SM4_BS512_KEY),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_sm4_bs512_ecb(void)
{
    return &sm4_bs512_cipher;
}

static const EVP_CIPHER sm4_bs512_ctr = {
    NID_sm4_bs512_ctr, 1, 16, 16,
    EVP_CIPH_CTR_MODE,
    sm4_bs512_init_key,
    sm4_ctr_bs512_encrypt,
    NULL,
    sizeof(EVP_SM4_BS512_KEY),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_sm4_bs512_ctr(void)
{
    return &sm4_bs512_ctr;
}

# define SM4_BS512_GCM_BLOCK_SIZE	1
# define SM4_BS512_GCM_IV_LENGTH	12

# define SM4_BS512_GCM_FLAGS (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_GCM_MODE \
		| EVP_CIPH_FLAG_AEAD_CIPHER)

static int sm4_bs512_gcm_cleanup(EVP_CIPHER_CTX *c)
{
    EVP_SM4_BS512_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_BS512_GCM_CTX,c);
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

static int sm4_bs512_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_SM4_BS512_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_BS512_GCM_CTX,c);
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
            EVP_SM4_BS512_GCM_CTX *gctx_out = EVP_C_DATA(EVP_SM4_BS512_GCM_CTX,out);
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

static int sm4_bs512_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    EVP_SM4_BS512_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_BS512_GCM_CTX,ctx);
    if (!iv && !key)
        return 1;
    if (key) {
        do {
            (void)0;        /* terminate potentially open 'else' */

            // sm4_set_encrypt_key(&gctx->ks.ks, key);
            // SM4_set_key(key, &gctx->ks.ks);
            // CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks,
            //                    (block128_f)SM4_encrypt);
            SM4_BS512_set_key(key, &gctx->ks.ks);
            CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks,
                               (block128_f)SM4_bs512_ecb_encrypt);
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

static int sm4_bs512_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVP_SM4_BS512_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_BS512_GCM_CTX,ctx);
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

static int sm4_bs512_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    EVP_SM4_BS512_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_BS512_GCM_CTX,ctx);
    gctx->ctr = (ctr128_f)sm4_bs512_ctr_encrypt;//use ctr mode to encrypt not ecb mode!!!
    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aad_len >= 0)
        return sm4_bs512_gcm_tls_cipher(ctx, out, in, len);

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

static const EVP_CIPHER sm4_bs512_gcm = {
    NID_sm4_bs512_gcm, 1, 16, 
    SM4_BS512_GCM_IV_LENGTH,
    SM4_BS512_GCM_FLAGS,
    sm4_bs512_gcm_init_key,
    sm4_bs512_gcm_cipher,

    sm4_bs512_gcm_cleanup,
    sizeof(EVP_SM4_BS512_GCM_CTX),
    NULL, NULL, sm4_bs512_gcm_ctrl, NULL
};

const EVP_CIPHER *EVP_sm4_bs512_gcm(void)
{
    return &sm4_bs512_gcm;
}

#endif