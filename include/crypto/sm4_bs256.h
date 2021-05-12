/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30: one30@m.scnu.edu.cn(email)
 * @Date         : 2021-03-28 10:02:59
 * @LastEditTime : 2021-05-12 16:17:05
 * @FilePath     : /include/crypto/sm4_bs256.h
 */
#ifndef OSSL_CRYPTO_SM4_BS256_H
#define OSSL_CRYPTO_SM4_BS256_H

#include <openssl/opensslconf.h>
#include <openssl/e_os2.h>
#include <string.h>
#include <stdio.h>

#ifdef OPENSSL_NO_SM4_BS256
#error SM4_BS256 is disabled
#endif

#include <immintrin.h>

#define SM4_BS256_ENCRYPT 1
#define SM4_BS256_DECRYPT 0

# define SM4_BS256_BLOCK_SIZE    16*256
# define SM4_BS256_KEY_SCHEDULE  32

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))

#define _mm256_set_m128i(v0, v1)  _mm256_insertf128_si256(_mm256_castsi128_si256(v1), (v0), 1)
#define _mm256_setr_m128i(v0, v1) _mm256_set_m128i((v1), (v0))


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
void sm4_bs256_ecb_encrypt(const uint8_t *in, uint8_t *out, int size, const SM4_BS256_KEY *ks);
void sm4_bs256_ecb_decrypt(const uint8_t *in, uint8_t *out, const SM4_BS256_KEY *ks);
void SM4_bs256_ecb_encrypt(const uint8_t *in, uint8_t *out, const SM4_BS256_KEY *ks);
void sm4_bs256_ctr_encrypt(const uint8_t * inputb, uint8_t * outputb, int size, const SM4_BS256_KEY *ks, uint8_t * iv);

#define GCM_BLOCK_SIZE  16       /* block size in bytes, AES 128-128 */
#define GCM_DEFAULT_IV_LEN (12)              /* default iv length in bytes */
#define GCM_FIELD_CONST (0xe100000000000000) /* the const value in filed */

/*
 * basic functions of a block cipher
 */
typedef int (*block_key_schedule_p)(const uint8_t *key, uint8_t *roundkeys);
typedef int (*block_encrypt_p)(const uint8_t *roundkeys, const uint8_t *input, uint8_t *output);
typedef int (*block_decrypt_p)(const uint8_t *roundkeys, const uint8_t *input, uint8_t *output);

#endif