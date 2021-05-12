/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30: one30@m.scnu.edu.cn(email)
 * @Date         : 2021-03-28 10:02:59
 * @LastEditTime : 2021-05-12 10:06:29
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
void sm4_bs256_gcm_encrypt(uint8_t *inputb, uint8_t *outputb, int size,
    __m256i (*rk)[32], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, uint8_t T[][256][16]);
void computeTable(uint8_t T[][256][16], uint8_t H[]);

#define GCM_BLOCK_SIZE  16       /* block size in bytes, AES 128-128 */
#define GCM_DEFAULT_IV_LEN (12)              /* default iv length in bytes */
#define GCM_FIELD_CONST (0xe100000000000000) /* the const value in filed */

/*
 * basic functions of a block cipher
 */
typedef int (*block_key_schedule_p)(const uint8_t *key, uint8_t *roundkeys);
typedef int (*block_encrypt_p)(const uint8_t *roundkeys, const uint8_t *input, uint8_t *output);
typedef int (*block_decrypt_p)(const uint8_t *roundkeys, const uint8_t *input, uint8_t *output);

/*
 * block cipher context structure
 */
typedef struct {
    // rounds keys of block cipher
    uint8_t *rk;
    // block cipher encryption
    block_encrypt_p block_encrypt;
    uint8_t H[GCM_BLOCK_SIZE];
    uint8_t buff[GCM_BLOCK_SIZE];
    uint8_t T[GCM_BLOCK_SIZE][256][GCM_BLOCK_SIZE];
} gcm_context;

/**
 * @par purpose
 *    Initialize GCM context (just makes references valid)
 *    Makes the context ready for gcm_setkey() or
 *    gcm_free().
 */
void *gcm_init();


void gcm_free( void *ctx );

/**
 * compute T1, T2, ... , and T15
 * suppose 0^n is a string with n bit zeros, s1||s2 is a jointed string of s1 and s2
 * 
 * T1 = T0 . P^8
 * 	where P^8 = 0^8 || 1 || 0^119
 * T2 = T1 . P^8 = T0 . P^16
 * 	where P^16 = 0^16 || 1 || 0^111
 * T3 = T2 . P^8 = T0 . P^24
 * ...
 * T15 = T14 . P^8 = T0 . P^120
 * 	where P^120 = 0^120 || 1 || 0^7
 *
 */
 void otherT(uint8_t T[][256][16]);

/**
 * @purpose
 * compute table T0 = X0 . H
 * only the first byte of X0 is nonzero, other bytes are all 0
 * @T
 * the final tables: 16 tables in total, each has 256 elements, the value of which is 16 bytes
 * @H
 * 128-bit, H = E(K, 0^128)
 * the leftmost(most significant) bit of H[0] is bit-0 of H(in GCM)
 * the rightmost(least significant) bit of H[15] is bit-127 of H(in GCM)
 */
void computeTable(uint8_t T[][256][16], uint8_t H[]);

/*
 * a: additional authenticated data
 * c: the cipher text or initial vector
 */
void ghash(uint8_t T[][256][16],
		const uint8_t *add, 
		size_t add_len,
		const uint8_t *cipher,
		size_t length,
		uint8_t *output);

/**
 * return the value of (output.H) by looking up tables
 */
 static void multi(uint8_t T[][256][16], uint8_t *output);

#endif