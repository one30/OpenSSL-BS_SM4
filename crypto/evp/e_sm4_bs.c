/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30: one30@m.scnu.edu.cn(email)
 * @Date         : 2021-03-28 01:23:26
 * @LastEditTime : 2021-04-18 22:50:02
 * @FilePath     : /crypto/evp/e_sm4_bs.c
 */
#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_BS_SM4
# include <openssl/evp.h>
# include "crypto/sm4_bs.h"
#include "crypto/sm4.h"
# include "crypto/evp.h"
# include "evp_local.h"
# include "openssl/objects.h"

typedef struct {
    SM4_BS256_KEY ks;
} EVP_SM4_BS256_KEY;

static int sm4_bs256_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    SM4_BS256_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
    return 1;
}

static int sm4_ecb_bs_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
            size_t len)
{

    if (ctx->encrypt)
        SM4_BS256_encrypt(in, out, len, &((EVP_SM4_BS256_KEY *)ctx->cipher_data)->ks);
    else
        SM4_BS256_encrypt(in, out, len, &((EVP_SM4_BS256_KEY *)ctx->cipher_data)->ks);
    return 1;
}

// static int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
// {
//     size_t i, bl;
//     bl = ctx->cipher->block_size;
//     if (inl < bl)
//         return 1;
//     inl -= bl;
//     if (ctx->encrypt)
//     {
//         for (i = 0; i <= inl; i += bl)
//             SM4_encrypt(in + i, out + i, &((EVP_SM4_KEY *)ctx->cipher_data)->ks);
//     }
//     else
//     {
//         for (i = 0; i <= inl; i += bl)
//             SM4_decrypt(in + i, out + i, &((EVP_SM4_KEY *)ctx->cipher_data)->ks);
//     }

//     return 1;
// }

// static void sm4_ecb_encrypt(const unsigned char *in, unsigned char *out,
//                             const SM4_KEY *key, const int enc)
// {
//     if (enc)
//         SM4_encrypt(in, out, key);
//     else
//         SM4_decrypt(in, out, key);
// }

static const EVP_CIPHER sm4_bs256_cipher = {
    NID_sm4_bs256_ecb, 1, 16, 16,
    EVP_CIPH_ECB_MODE,
    sm4_bs256_init_key,
    sm4_ecb_bs_encrypt, //sm4_ecb_bs_encrypt,
    NULL,
    sizeof(EVP_SM4_BS256_KEY),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_sm4_bs256_ecb(void)
{
    return &sm4_bs256_cipher;
}

static const EVP_CIPHER sm4_bs256_ctr = {
    NID_sm4_bs256_ecb, 1, 16, 16,
    EVP_CIPH_ECB_MODE,
    sm4_bs256_init_key,
    sm4_ecb_bs_encrypt, //sm4_ecb_bs_encrypt,
    NULL,
    sizeof(EVP_SM4_BS256_KEY),
    NULL, NULL, NULL, NULL
};


const EVP_CIPHER *EVP_sm4_bs256_ctr(void)
{
    return &sm4_bs256_ctr;
}

static const EVP_CIPHER sm4_bs256_gcm = {
    NID_sm4_bs256_ecb, 1, 16, 16,
    EVP_CIPH_ECB_MODE,
    sm4_bs256_init_key,
    sm4_ecb_bs_encrypt, //sm4_ecb_bs_encrypt,
    NULL,
    sizeof(EVP_SM4_BS256_KEY),
    NULL, NULL, NULL, NULL
};


const EVP_CIPHER *EVP_sm4_bs256_gcm(void)
{
    return &sm4_bs256_gcm;
}

#endif