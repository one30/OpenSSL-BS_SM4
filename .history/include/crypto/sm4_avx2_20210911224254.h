/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30: one30@m.scnu.edu.cn(email)
 * @Date         : 2021-09-05 21:35:50
 * @LastEditTime : 2021-09-11 22:42:52
 * @FilePath     : /include/crypto/sm4_avx2.h
 */

#ifndef OSSL_CRYPTO_SM4_AVX2_H
# define OSSL_CRYPTO_SM4_AVX2_H

# include <openssl/opensslconf.h>
# include <openssl/e_os2.h>
# include <stdio.h>

# ifdef OPENSSL_NO_AVX2_SM4
#  error SM4_AVX2 is disabled.
# endif

#include <immintrin.h>

# define SM4_AVX2_ENCRYPT     1
# define SM4_AVX2_DECRYPT     0

# define SM4_BLOCK_SIZE    16
# define SM4_KEY_SCHEDULE  32

typedef struct SM4_AVX2_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_AVX2_KEY;

int SM4_AVX2_set_key(const uint8_t *key, SM4_AVX2_KEY *ks);

void SM4_AVX2_encrypt(const unsigned char *in, int *out, int size, const SM4_AVX2_KEY *key);
void sm4_avx2_ctr_encrypt(const uint8_t *in, uint8_t *out, int size, const SM4_AVX2_KEY *key, uint8_t * iv);
// void SM4_AVX2_decrypt(const uint8_t *in, uint8_t *out, const SM4_AVX2_KEY *ks);

#endif