/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30: one30@m.scnu.edu.cn(email)
 * @Date         : 2021-03-28 10:02:59
 * @LastEditTime : 2021-04-14 19:27:39
 * @FilePath     : /include/crypto/sm4_bs.h
 */
#ifndef OSSL_CRYPTO_SM4_BS_H
#define OSSL_CRYPTO_SM4_BS_H

#include <openssl/opensslconf.h>
#include <openssl/e_os2.h>

#ifdef OPENSSL_NO_SM4_BS
#error SM4_BS is disabled
#endif

#define SM4_BS256_ENCRYPT 1
#define SM4_BS256_DECRYPT 0

# define SM4_BS256_BLOCK_SIZE    16*256
# define SM4_BS256_KEY_SCHEDULE  32

#include <immintrin.h>
typedef struct SM4_BS256_KEY_st {
    uint32_t rk[SM4_BS256_KEY_SCHEDULE];
    __m256i bs_rk[SM4_BS256_KEY_SCHEDULE][32];
} SM4_BS256_KEY;

// typedef SM4_BS256_KEY SM4_KEY;

typedef struct {
  __m256i b0;
  __m256i b1;
  __m256i b2;
  __m256i b3;
  __m256i b4;
  __m256i b5;
  __m256i b6;
  __m256i b7;
} bits;

int SM4_BS256_set_key(const uint8_t *key, SM4_BS256_KEY *ks);
void SM4_BS256_encrypt(const uint8_t *in, uint8_t *out, int size, const SM4_BS256_KEY *ks);
void SM4_BS256_decrypt(const uint8_t *in, uint8_t *out, const SM4_BS256_KEY *ks);



#endif