/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30: one30@m.scnu.edu.cn(email)
 * @Date         : 2021-03-28 10:02:59
 * @LastEditTime : 2021-05-11 21:25:42
 * @FilePath     : /include/crypto/sm4_bs512.h
 */
#ifndef OSSL_CRYPTO_SM4_BS512_H
#define OSSL_CRYPTO_SM4_BS512_H

#include <openssl/opensslconf.h>
#include <openssl/e_os2.h>
#include <string.h>
#include <stdio.h>

#ifdef OPENSSL_NO_SM4_BS512
#error SM4_BS512 is disabled
#endif

#define SM4_BS512_ENCRYPT 1
#define SM4_BS512_DECRYPT 0

# define SM4_BS512_BLOCK_SIZE    16*512
# define SM4_BS512_KEY_SCHEDULE  32

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))

#include <immintrin.h>
typedef struct SM4_BS512_KEY_st {
    uint32_t rk[SM4_BS512_KEY_SCHEDULE];
    __m512i bs512_rk[SM4_BS512_KEY_SCHEDULE][32];
} SM4_BS512_KEY;

// typedef SM4_BS256_KEY SM4_KEY;

typedef struct {
  __m512i b0;
  __m512i b1;
  __m512i b2;
  __m512i b3;
  __m512i b4;
  __m512i b5;
  __m512i b6;
  __m512i b7;
} bits;

int SM4_BS512_set_key(const uint8_t *key, SM4_BS512_KEY *ks);
void SM4_bs512_ecb_encrypt(const uint8_t* inputb,uint8_t* outputb,const SM4_BS512_KEY *ks);
void sm4_bs512_ecb_encrypt(const uint8_t* inputb,uint8_t* outputb,int size,const SM4_BS512_KEY *ks);
void sm4_bs512_ctr_encrypt(const uint8_t * inputb, uint8_t * outputb, int size, const SM4_BS512_KEY *ks, uint8_t * iv);

#endif