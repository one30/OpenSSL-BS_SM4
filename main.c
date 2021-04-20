/** 文件名: https://github.com/liuqun/openssl-sm4-demo/blob/cmake/src/main.c */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/openssl/err.h"
#include "include/openssl/evp.h"

/* Before OpenSSL 1.1.1-pre1, we did not have EVP_sm4_ecb() */
#if defined(OPENSSL_VERSION_NUMBER) \
    && OPENSSL_VERSION_NUMBER < 0x10101001L
static const EVP_CIPHER *(*EVP_sm4_ecb)()=EVP_aes_128_ecb;
#endif

typedef struct {
    const unsigned char *in_data;
    size_t in_data_len;
    int in_data_is_already_padded;
    const unsigned char *in_ivec;
    const unsigned char *in_key;
    size_t in_key_len;
} test_case_t;


void test_encrypt_with_cipher(const test_case_t *in, const EVP_CIPHER *cipher)
{
 
	unsigned char *out_buf = NULL;
	int out_len;
	int out_padding_len;
    EVP_CIPHER_CTX *ctx;
 
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, in->in_key, in->in_ivec);

    if (in->in_data_is_already_padded)
    {
        /* Check whether the input data is already padded.
        And its length must be an integral multiple of the cipher's block size. */
        const size_t bs = EVP_CIPHER_block_size(cipher);
        if (in->in_data_len % bs != 0)
        {
            printf("ERROR-1: data length=%d which is not added yet; block size=%d\n", (int) in->in_data_len, (int) bs);
            /* Warning: Remember to do some clean-ups */
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        /* Disable the implicit PKCS#7 padding defined in EVP_CIPHER */
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    out_buf = (unsigned char *) malloc(((in->in_data_len>>4)+1) << 4);
    out_len = 0;
    EVP_EncryptUpdate(ctx, out_buf, &out_len, in->in_data, in->in_data_len);
    if (1)
    {
        printf("Debug: out_len=%d\n", out_len);
    }

    out_padding_len = 0;
    EVP_EncryptFinal_ex(ctx, out_buf+out_len, &out_padding_len);
    if (1)
    {
        printf("Debug: out_padding_len=%d\n", out_padding_len);
    }

    EVP_CIPHER_CTX_free(ctx);
    if (1)
    {
        int i;
        int len;
        len = out_len + out_padding_len;
        for (i=0; i<len; i++)
        {
            printf("%02x ", out_buf[i]);
            if((i+1)%16 == 0)
                printf("\n");
        }
        printf("\n");
    }

    if (out_buf)
    {
        free(out_buf);
        out_buf = NULL;
    }
}

void main()
{
    int have_sm4 = (OPENSSL_VERSION_NUMBER >= 0x10101001L);
    int have_aes = 1;
    int have_sm4_bs256 = 1;
    const unsigned char data[]=
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char ivec[EVP_MAX_IV_LENGTH]; ///< IV 向量
    const unsigned char key1[16] = ///< key_data, 密钥内容, 至少16字节
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

    test_case_t tc;
    tc.in_data = data;
    tc.in_data_len = sizeof(data);
    tc.in_data_is_already_padded = (tc.in_data_len % 16)==0; // Hard coded 16 as the cipher's block size
    tc.in_key = key1;
    tc.in_key_len = sizeof(key1);
    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    tc.in_ivec = ivec;

    const unsigned char data_2[16*2]={
        0xAA,0xAA,0xAA,0xAA,0xBB,0xBB,0xBB,0xBB,0xCC,0xCC,0xCC,0xCC,0xDD,0xDD,0xDD,0xDD,
        0xEE,0xEE,0xEE,0xEE,0xFF,0xFF,0xFF,0xFF,0xAA,0xAA,0xAA,0xAA,0xBB,0xBB,0xBB,0xBB
    };
    unsigned char cipher_2[16*2]={
        0x5E,0xC8,0x14,0x3D,0xE5,0x09,0xCF,0xF7,0xB5,0x17,0x9F,0x8F,0x47,0x4B,0x86,0x19,
        0x2F,0x1D,0x30,0x5A,0x7F,0xB1,0x7D,0xF9,0x85,0xF8,0x1C,0x84,0x82,0x19,0x23,0x04
    };

    test_case_t tc_2;
    tc_2.in_data = data_2;
    tc_2.in_data_len = sizeof(data_2);
    tc_2.in_data_is_already_padded = (tc_2.in_data_len % 16)==0; // Hard coded 16 as the cipher's block size
    tc_2.in_key = key1;
    tc_2.in_key_len = sizeof(key1);
    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    tc_2.in_ivec = ivec;

#if defined(OPENSSL_NO_SM4)
    have_sm4 = 0;
#endif
    if (have_sm4)
    {
        printf("[1]\n");
        printf("Debug: EVP_sm4_ecb() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_ecb());
        test_encrypt_with_cipher(&tc_2, EVP_sm4_ecb());
        printf("Debug: EVP_sm4_ctr() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_ctr());
    }

#if defined(OPENSSL_NO_BS_SM4)
    have_sm4_bs256 = 0;
#endif
    if (have_sm4_bs256)
    {
        printf("[2]\n");
        printf("Debug: EVP_sm4_bs256_ecb() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_bs256_ecb());
        test_encrypt_with_cipher(&tc_2, EVP_sm4_bs256_ecb());
    }

#if defined(OPENSSL_NO_AES)
    have_aes = 0;
#endif
    if (have_aes)
    {
        printf("[3]\n");
        printf("Debug: EVP_aes_128_ecb() test\n");
        test_encrypt_with_cipher(&tc, EVP_aes_128_ecb());
    }

}