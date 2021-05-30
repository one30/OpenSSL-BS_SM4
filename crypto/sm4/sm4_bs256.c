#include <openssl/e_os2.h>
#include "crypto/sm4.h"
#include "crypto/sm4_bs256.h"

static const uint8_t SM4_S[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
    0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
    0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
    0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
    0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
    0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
    0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
    0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
    0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
    0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
    0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
    0xD7, 0xCB, 0x39, 0x48
};

/*
 * SM4_SBOX_T[j] == L(SM4_SBOX[j]).
 */
static const uint32_t SM4_SBOX_T[256] = {
    0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x06FDFBFB, 0xFCCF3333, 0x65E28787,
    0xC93DF4F4, 0x6BB5DEDE, 0x4E165858, 0x6EB4DADA, 0x44145050, 0xCAC10B0B,
    0x8828A0A0, 0x17F8EFEF, 0x9C2CB0B0, 0x11051414, 0x872BACAC, 0xFB669D9D,
    0xF2986A6A, 0xAE77D9D9, 0x822AA8A8, 0x46BCFAFA, 0x14041010, 0xCFC00F0F,
    0x02A8AAAA, 0x54451111, 0x5F134C4C, 0xBE269898, 0x6D482525, 0x9E841A1A,
    0x1E061818, 0xFD9B6666, 0xEC9E7272, 0x4A430909, 0x10514141, 0x24F7D3D3,
    0xD5934646, 0x53ECBFBF, 0xF89A6262, 0x927BE9E9, 0xFF33CCCC, 0x04555151,
    0x270B2C2C, 0x4F420D0D, 0x59EEB7B7, 0xF3CC3F3F, 0x1CAEB2B2, 0xEA638989,
    0x74E79393, 0x7FB1CECE, 0x6C1C7070, 0x0DABA6A6, 0xEDCA2727, 0x28082020,
    0x48EBA3A3, 0xC1975656, 0x80820202, 0xA3DC7F7F, 0xC4965252, 0x12F9EBEB,
    0xA174D5D5, 0xB38D3E3E, 0xC33FFCFC, 0x3EA49A9A, 0x5B461D1D, 0x1B071C1C,
    0x3BA59E9E, 0x0CFFF3F3, 0x3FF0CFCF, 0xBF72CDCD, 0x4B175C5C, 0x52B8EAEA,
    0x8F810E0E, 0x3D586565, 0xCC3CF0F0, 0x7D196464, 0x7EE59B9B, 0x91871616,
    0x734E3D3D, 0x08AAA2A2, 0xC869A1A1, 0xC76AADAD, 0x85830606, 0x7AB0CACA,
    0xB570C5C5, 0xF4659191, 0xB2D96B6B, 0xA7892E2E, 0x18FBE3E3, 0x47E8AFAF,
    0x330F3C3C, 0x674A2D2D, 0xB071C1C1, 0x0E575959, 0xE99F7676, 0xE135D4D4,
    0x661E7878, 0xB4249090, 0x360E3838, 0x265F7979, 0xEF628D8D, 0x38596161,
    0x95D24747, 0x2AA08A8A, 0xB1259494, 0xAA228888, 0x8C7DF1F1, 0xD73BECEC,
    0x05010404, 0xA5218484, 0x9879E1E1, 0x9B851E1E, 0x84D75353, 0x00000000,
    0x5E471919, 0x0B565D5D, 0xE39D7E7E, 0x9FD04F4F, 0xBB279C9C, 0x1A534949,
    0x7C4D3131, 0xEE36D8D8, 0x0A020808, 0x7BE49F9F, 0x20A28282, 0xD4C71313,
    0xE8CB2323, 0xE69C7A7A, 0x42E9ABAB, 0x43BDFEFE, 0xA2882A2A, 0x9AD14B4B,
    0x40410101, 0xDBC41F1F, 0xD838E0E0, 0x61B7D6D6, 0x2FA18E8E, 0x2BF4DFDF,
    0x3AF1CBCB, 0xF6CD3B3B, 0x1DFAE7E7, 0xE5608585, 0x41155454, 0x25A38686,
    0x60E38383, 0x16ACBABA, 0x295C7575, 0x34A69292, 0xF7996E6E, 0xE434D0D0,
    0x721A6868, 0x01545555, 0x19AFB6B6, 0xDF914E4E, 0xFA32C8C8, 0xF030C0C0,
    0x21F6D7D7, 0xBC8E3232, 0x75B3C6C6, 0x6FE08F8F, 0x691D7474, 0x2EF5DBDB,
    0x6AE18B8B, 0x962EB8B8, 0x8A800A0A, 0xFE679999, 0xE2C92B2B, 0xE0618181,
    0xC0C30303, 0x8D29A4A4, 0xAF238C8C, 0x07A9AEAE, 0x390D3434, 0x1F524D4D,
    0x764F3939, 0xD36EBDBD, 0x81D65757, 0xB7D86F6F, 0xEB37DCDC, 0x51441515,
    0xA6DD7B7B, 0x09FEF7F7, 0xB68C3A3A, 0x932FBCBC, 0x0F030C0C, 0x03FCFFFF,
    0xC26BA9A9, 0xBA73C9C9, 0xD96CB5B5, 0xDC6DB1B1, 0x375A6D6D, 0x15504545,
    0xB98F3636, 0x771B6C6C, 0x13ADBEBE, 0xDA904A4A, 0x57B9EEEE, 0xA9DE7777,
    0x4CBEF2F2, 0x837EFDFD, 0x55114444, 0xBDDA6767, 0x2C5D7171, 0x45400505,
    0x631F7C7C, 0x50104040, 0x325B6969, 0xB8DB6363, 0x220A2828, 0xC5C20707,
    0xF531C4C4, 0xA88A2222, 0x31A79696, 0xF9CE3737, 0x977AEDED, 0x49BFF6F6,
    0x992DB4B4, 0xA475D1D1, 0x90D34343, 0x5A124848, 0x58BAE2E2, 0x71E69797,
    0x64B6D2D2, 0x70B2C2C2, 0xAD8B2626, 0xCD68A5A5, 0xCB955E5E, 0x624B2929,
    0x3C0C3030, 0xCE945A5A, 0xAB76DDDD, 0x867FF9F9, 0xF1649595, 0x5DBBE6E6,
    0x35F2C7C7, 0x2D092424, 0xD1C61717, 0xD66FB9B9, 0xDEC51B1B, 0x94861212,
    0x78186060, 0x30F3C3C3, 0x897CF5F5, 0x5CEFB3B3, 0xD23AE8E8, 0xACDF7373,
    0x794C3535, 0xA0208080, 0x9D78E5E5, 0x56EDBBBB, 0x235E7D7D, 0xC63EF8F8,
    0x8BD45F5F, 0xE7C82F2F, 0xDD39E4E4, 0x68492121 };

static ossl_inline uint32_t rotl(uint32_t a, uint8_t n)
{
    return (a << n) | (a >> (32 - n));
}

static ossl_inline uint32_t load_u32_be(const uint8_t *b, uint32_t n)
{
    return ((uint32_t)b[4 * n] << 24) |
           ((uint32_t)b[4 * n + 1] << 16) |
           ((uint32_t)b[4 * n + 2] << 8) |
           ((uint32_t)b[4 * n + 3]);
}

static ossl_inline void store_u32_be(uint32_t v, uint8_t *b)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

static ossl_inline uint32_t SM4_T_slow(uint32_t X)
{
    uint32_t t = 0;

    t |= ((uint32_t)SM4_S[(uint8_t)(X >> 24)]) << 24;
    t |= ((uint32_t)SM4_S[(uint8_t)(X >> 16)]) << 16;
    t |= ((uint32_t)SM4_S[(uint8_t)(X >> 8)]) << 8;
    t |= SM4_S[(uint8_t)X];

    /*
     * L linear transform
     */
    return t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24);
}

static ossl_inline uint32_t SM4_T(uint32_t X)
{
    return SM4_SBOX_T[(uint8_t)(X >> 24)] ^
           rotl(SM4_SBOX_T[(uint8_t)(X >> 16)], 24) ^
           rotl(SM4_SBOX_T[(uint8_t)(X >> 8)], 16) ^
           rotl(SM4_SBOX_T[(uint8_t)X], 8);
}


// int SM4_set_key(const uint8_t *key, SM4_KEY *ks)
// {
//     /*
//      * Family Key
//      */
//     static const uint32_t FK[4] =
//         { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

//     /*
//      * Constant Key
//      */
//     static const uint32_t CK[32] = {
//         0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
//         0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
//         0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
//         0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
//         0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
//         0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
//         0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
//         0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
//     };

//     uint32_t K[4];
//     int i;

//     K[0] = load_u32_be(key, 0) ^ FK[0];
//     K[1] = load_u32_be(key, 1) ^ FK[1];
//     K[2] = load_u32_be(key, 2) ^ FK[2];
//     K[3] = load_u32_be(key, 3) ^ FK[3];

//     for (i = 0; i != SM4_KEY_SCHEDULE; ++i) {
//         uint32_t X = K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i];
//         uint32_t t = 0;

//         t |= ((uint32_t)SM4_S[(uint8_t)(X >> 24)]) << 24;
//         t |= ((uint32_t)SM4_S[(uint8_t)(X >> 16)]) << 16;
//         t |= ((uint32_t)SM4_S[(uint8_t)(X >> 8)]) << 8;
//         t |= SM4_S[(uint8_t)X];

//         t = t ^ rotl(t, 13) ^ rotl(t, 23);
//         K[i % 4] ^= t;
//         ks->rk[i] = K[i % 4];
//     }

//     return 1;
// }

int SM4_BS256_set_key(const uint8_t *key, SM4_BS256_KEY *ks){
    /*
     * Family Key
     */
    static const uint32_t FK[4] =
        { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

    /*
     * Constant Key
     */
    static const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    uint32_t K[4];
    int i;

    K[0] = load_u32_be(key, 0) ^ FK[0];
    K[1] = load_u32_be(key, 1) ^ FK[1];
    K[2] = load_u32_be(key, 2) ^ FK[2];
    K[3] = load_u32_be(key, 3) ^ FK[3];

    for (i = 0; i != SM4_KEY_SCHEDULE; ++i) {
        uint32_t X = K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i];
        uint32_t t = 0;

        t |= ((uint32_t)SM4_S[(uint8_t)(X >> 24)]) << 24;
        t |= ((uint32_t)SM4_S[(uint8_t)(X >> 16)]) << 16;
        t |= ((uint32_t)SM4_S[(uint8_t)(X >> 8)]) << 8;
        t |= SM4_S[(uint8_t)X];

        t = t ^ rotl(t, 13) ^ rotl(t, 23);
        K[i % 4] ^= t;
        ks->rk[i] = K[i % 4];
    }

    // calculate BS_RK
    uint64_t BS_RK[32][32][4];
    for(int i = 0; i<32; i++)
    {
        // printf("rkey[%d]=%08x\n",i,ks->rk[i]);
        uint64_t t = 0x1;
        for(int j = 0; j < 32; j++)
        {
            for(int k = 0; k < 4; k++)
            {
                if(ks->rk[i] & t)
                    BS_RK[i][31-j][k] = ~0;
                else
                {
                    BS_RK[i][31-j][k] = 0;
                }
            }
            t = t << 1;
        }
    }

    for(int i = 0; i < 32; i++)//load data
    {
        for(int j = 0; j < 32; j++)
        {
            ks->bs_rk[i][j] = _mm256_loadu_si256((__m256i*)(BS_RK[i][j]));
        }
    }

/*     uint64_t BS_RK[4];
    for(int i = 0; i<32; i++)
    {
        //printf("rkey[%d]=%08x\n",i,rkey[i]);
        uint64_t t = 0x1;
        for(int j = 0; j < 32; j++)
        {
            for(int k = 0; k < 8; k++)
            {
                if( ks->rk[i] & t)
                    BS_RK[k] = ~0;
                else
                {
                    BS_RK[k] = 0;
                }
            }
            ks->bs_rk[i][31-j] = _mm256_loadu_si256((__m256i*)BS_RK);
            t = t << 1;
        }
    } */

    return 1;
}

//from usuba sse.h
static ossl_inline void Ortho_128x128(__m128i data[]) {

  __m128i mask_l[7] = {
    _mm_set1_epi64x(0xaaaaaaaaaaaaaaaaUL),
    _mm_set1_epi64x(0xccccccccccccccccUL),
    _mm_set1_epi64x(0xf0f0f0f0f0f0f0f0UL),
    _mm_set1_epi64x(0xff00ff00ff00ff00UL),
    _mm_set1_epi64x(0xffff0000ffff0000UL),
    _mm_set1_epi64x(0xffffffff00000000UL),
    _mm_set_epi64x(0x0000000000000000UL,0xffffffffffffffffUL),

  };

  __m128i mask_r[7] = {
    _mm_set1_epi64x(0x5555555555555555UL),
    _mm_set1_epi64x(0x3333333333333333UL),
    _mm_set1_epi64x(0x0f0f0f0f0f0f0f0fUL),
    _mm_set1_epi64x(0x00ff00ff00ff00ffUL),
    _mm_set1_epi64x(0x0000ffff0000ffffUL),
    _mm_set1_epi64x(0x00000000ffffffffUL),
    _mm_set_epi64x(0xffffffffffffffffUL,0x0000000000000000UL),
  };

  for (int i = 0; i < 7; i ++) {
    int n = (1UL << i);
    for (int j = 0; j < 128; j += (2 * n))
      for (int k = 0; k < n; k ++) {
        __m128i u = _mm_and_si128(data[j + k], mask_l[i]);
        __m128i v = _mm_and_si128(data[j + k], mask_r[i]);
        __m128i x = _mm_and_si128(data[j + n + k], mask_l[i]);
        __m128i y = _mm_and_si128(data[j + n + k], mask_r[i]);
        if (i <= 5) {
          data[j + k] = _mm_or_si128(u, _mm_srli_epi64(x, n));
          data[j + n + k] = _mm_or_si128(_mm_slli_epi64(v, n), y);
        } else {
          /* Note the "inversion" of srli and slli. */
          data[j + k] = _mm_or_si128(u, _mm_slli_si128(x, 8));
          data[j + n + k] = _mm_or_si128(_mm_srli_si128(v, 8), y);
        }
      }
  }
}

static ossl_inline void BS_TRANS_128x256(__m128i* M,__m256i* N){
    Ortho_128x128(M);
    Ortho_128x128(&M[128]);
    for(int i=0; i<128; i++)
        N[i] = _mm256_set_m128i(M[i], M[128+i]); 
}

static ossl_inline void BS_TRANS_VER_128x256(__m256i* N,__m128i* M){
    __m128i t[2];
    for(int i=0; i<128; i++)
    {
        _mm256_store_si256((__m256i*)t, N[i]);
        M[i] = t[1];
        M[128+i] = t[0];
    }
    Ortho_128x128(M);
    Ortho_128x128(&(M[128]));
}


/* static ossl_inline void BS_TRANS_128x256(__m128i* M,__m256i* N){
    __m256i mask[7];
    __m256i mk[7];
    uint64_t m0[4] = {0x5555555555555555,0x5555555555555555,0x5555555555555555,0x5555555555555555};
    uint64_t m1[4] = {0x3333333333333333,0x3333333333333333,0x3333333333333333,0x3333333333333333};
    uint64_t m2[4] = {0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f};
    uint64_t m3[4] = {0x00ff00ff00ff00ff,0x00ff00ff00ff00ff,0x00ff00ff00ff00ff,0x00ff00ff00ff00ff};
    uint64_t m4[4] = {0x0000ffff0000ffff,0x0000ffff0000ffff,0x0000ffff0000ffff,0x0000ffff0000ffff};
    uint64_t m5[4] = {0x00000000ffffffff,0x00000000ffffffff,0x00000000ffffffff,0x00000000ffffffff};
    uint64_t m6[4] = {0x0000000000000000,0xffffffffffffffff,0x0000000000000000,0xffffffffffffffff};
    mask[0] = _mm256_load_si256((__m256i*)m0);
    mask[1] = _mm256_load_si256((__m256i*)m1);
    mask[2] = _mm256_load_si256((__m256i*)m2);
    mask[3] = _mm256_load_si256((__m256i*)m3);
    mask[4] = _mm256_load_si256((__m256i*)m4);
    mask[5] = _mm256_load_si256((__m256i*)m5);
    mask[6] = _mm256_load_si256((__m256i*)m6);
    __m256i test[128];
    for(int i = 0; i < 128; i++)
    {
        N[i] = _mm256_setr_m128i(M[i],M[128+i]);  
    }

    uint64_t k,k2,kt,l;
    uint64_t t1[4],t2[4];
    uint64_t zero = 0;
    __m256i temp,m,n,a,b,o,p;
    for(int j=0; j<7; j++)
    {
        k = 1<<j;
        k2 = k*2;
        kt = 0;
        //r = k-1;
        if(j==6)//when shift bit = 64,128 bit SIMD with shift operation has bug
        {
            for(int i=0; i<64; i++)
            {
                l = kt%127;
                m = N[l];
                n = N[l+k];

                _mm256_store_si256((__m256i*)t1,n);
                o = _mm256_setr_epi64x(zero,t1[0],zero,t1[2]);

                _mm256_store_si256((__m256i*)t2,m);
                p = _mm256_setr_epi64x(t2[1],zero,t2[3],zero);

                temp = (m&~mask[j]) ^ o;
                N[l+k] = (n&(mask[j])) ^ p;
                N[l] = temp;
                kt+=k2;
            }            
        }
        else
        {
            for(int i=0; i<64; i++)
            {
                l = kt%127;
                m = N[l];
                n = N[l+k];
                temp = (m&~mask[j]) ^ ((n>>k)&mask[j]);
                N[l+k] = (n&(mask[j])) ^ ((m<<k)&~mask[j]);
                N[l] = temp;
                kt+=k2;           
            }
        }      
    }
} */

/* static ossl_inline void BS_TRANS_VER_128x256(__m256i* N,__m128i* M){
    __m256i mask[7];
    __m256i mk[7];
    uint64_t m0[4] = {0x5555555555555555,0x5555555555555555,0x5555555555555555,0x5555555555555555};
    uint64_t m1[4] = {0x3333333333333333,0x3333333333333333,0x3333333333333333,0x3333333333333333};
    uint64_t m2[4] = {0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f};
    uint64_t m3[4] = {0x00ff00ff00ff00ff,0x00ff00ff00ff00ff,0x00ff00ff00ff00ff,0x00ff00ff00ff00ff};
    uint64_t m4[4] = {0x0000ffff0000ffff,0x0000ffff0000ffff,0x0000ffff0000ffff,0x0000ffff0000ffff};
    uint64_t m5[4] = {0x00000000ffffffff,0x00000000ffffffff,0x00000000ffffffff,0x00000000ffffffff};
    uint64_t m6[4] = {0x0000000000000000,0xffffffffffffffff,0x0000000000000000,0xffffffffffffffff};
    mask[0] = _mm256_load_si256((__m256i*)m0);
    mask[1] = _mm256_load_si256((__m256i*)m1);
    mask[2] = _mm256_load_si256((__m256i*)m2);
    mask[3] = _mm256_load_si256((__m256i*)m3);
    mask[4] = _mm256_load_si256((__m256i*)m4);
    mask[5] = _mm256_load_si256((__m256i*)m5);
    mask[6] = _mm256_load_si256((__m256i*)m6);
    __m256i M_temp[128];
    uint64_t k,k2,kt,l;
    uint64_t t1[4],t2[4];
    uint64_t zero = 0;
    //_mm_setzero_si64();
    __m256i temp,m,n,a,b,o,p;
    //temp = (test[0] & mask[6]) ^ ((test[0]&~mask[6])<<1);
    //temp = (test[0]&~mask[0])<<2；


    for(int j=0; j<7; j++)
    {
        k = 1<<j;
        k2 = k*2;
        kt = 0;
        //r = k-1;
        //when shift bit = 64,128 bit SIMD with shift operation has bug
        //set j==7
        if(j==6)
        {
            for(int i=0; i<64; i++)
            {
                l = kt%127;
                m = N[l];
                n = N[l+k];

                _mm256_store_si256((__m256i*)t1,n);
                o = _mm256_setr_epi64x(zero,t1[0],zero,t1[2]);

                _mm256_store_si256((__m256i*)t2,m);
                p = _mm256_setr_epi64x(t2[1],zero,t2[3],zero);

                temp = (m&~mask[j]) ^ o;
                N[l+k] = (n&(mask[j])) ^ p;
                N[l] = temp;

                kt+=k2;
            }

            
        }
        else
        {
            for(int i=0; i<64; i++)
            {
                l = kt%127;
                m = N[l];
                n = N[l+k];
                temp = (m&~mask[j]) ^ ((n>>k)&mask[j]);
                N[l+k] = (n&(mask[j])) ^ ((m<<k)&~mask[j]);
                N[l] = temp;

                kt+=k2;           
            }
        }      
    }

    __m128i t[2];
    for(int i = 0; i < 128; i++)
    {
        _mm256_store_si256((__m256i*)t,N[i]);
        M[i] = t[0];
        M[128+i] = t[1];         
    }
} */

static ossl_inline void Sm4_BoolFun(bits in, __m256i *out0, __m256i *out1, __m256i *out2, __m256i *out3, __m256i *out4, __m256i *out5, __m256i *out6, __m256i *out7){
        __m256i y_t[21], t_t[8], t_m[46], y_m[18], t_b[30];
  	    y_t[18] = in.b2 ^in.b6;
		t_t[ 0] = in.b3 ^in.b4;
		t_t[ 1] = in.b2 ^in.b7;
		t_t[ 2] = in.b7 ^y_t[18];
		t_t[ 3] = in.b1 ^t_t[ 1];
		t_t[ 4] = in.b6 ^in.b7;
		t_t[ 5] = in.b0 ^y_t[18];
		t_t[ 6] = in.b3 ^in.b6;
		y_t[10] = in.b1 ^y_t[18];
		y_t[ 0] = in.b5 ^~ y_t[10];
		y_t[ 1] = t_t[ 0] ^t_t[ 3];
		y_t[ 2] = in.b0 ^t_t[ 0];
		y_t[ 4] = in.b0 ^t_t[ 3];
		y_t[ 3] = in.b3 ^y_t[ 4];
		y_t[ 5] = in.b5 ^t_t[ 5];
		y_t[ 6] = in.b0 ^~ in.b1;
		y_t[ 7] = t_t[ 0] ^~ y_t[10];
		y_t[ 8] = t_t[ 0] ^t_t[ 5];
		y_t[ 9] = in.b3;
		y_t[11] = t_t[ 0] ^t_t[ 4];
		y_t[12] = in.b5 ^t_t[ 4];
		y_t[13] = in.b5 ^~ y_t[ 1];
		y_t[14] = in.b4 ^~ t_t[ 2];
		y_t[15] = in.b1 ^~ t_t[ 6];
		y_t[16] = in.b0 ^~ t_t[ 2];
		y_t[17] = t_t[ 0] ^~ t_t[ 2];
		y_t[19] = in.b5 ^~ y_t[14];
		y_t[20] = in.b0 ^t_t[ 1];

    //The shared non-linear middle part for AES, AES^-1, and SM4
  	t_m[ 0] = y_t[ 3] ^	 y_t[12];
		t_m[ 1] = y_t[ 9] &	 y_t[ 5];
		t_m[ 2] = y_t[17] &	 y_t[ 6];
		t_m[ 3] = y_t[10] ^	 t_m[ 1];
		t_m[ 4] = y_t[14] &	 y_t[ 0];
		t_m[ 5] = t_m[ 4] ^	 t_m[ 1];
		t_m[ 6] = y_t[ 3] &	 y_t[12];
		t_m[ 7] = y_t[16] &	 y_t[ 7];
		t_m[ 8] = t_m[ 0] ^	 t_m[ 6];
		t_m[ 9] = y_t[15] &	 y_t[13];
		t_m[10] = t_m[ 9] ^	 t_m[ 6];
		t_m[11] = y_t[ 1] &	 y_t[11];
		t_m[12] = y_t[ 4] &	 y_t[20];
		t_m[13] = t_m[12] ^	 t_m[11];
		t_m[14] = y_t[ 2] &	 y_t[ 8];
		t_m[15] = t_m[14] ^	 t_m[11];
		t_m[16] = t_m[ 3] ^	 t_m[ 2];
		t_m[17] = t_m[ 5] ^	 y_t[18];
		t_m[18] = t_m[ 8] ^	 t_m[ 7];
		t_m[19] = t_m[10] ^	 t_m[15];
		t_m[20] = t_m[16] ^	 t_m[13];
		t_m[21] = t_m[17] ^	 t_m[15];
		t_m[22] = t_m[18] ^	 t_m[13];
		t_m[23] = t_m[19] ^	 y_t[19];
		t_m[24] = t_m[22] ^	 t_m[23];
		t_m[25] = t_m[22] &	 t_m[20];
		t_m[26] = t_m[21] ^	 t_m[25];
		t_m[27] = t_m[20] ^	 t_m[21];
		t_m[28] = t_m[23] ^	 t_m[25];
		t_m[29] = t_m[28] &	 t_m[27];
		t_m[30] = t_m[26] &	 t_m[24];
		t_m[31] = t_m[20] &	 t_m[23];
		t_m[32] = t_m[27] &	 t_m[31];
		t_m[33] = t_m[27] ^	 t_m[25];
		t_m[34] = t_m[21] &	 t_m[22];
		t_m[35] = t_m[24] &	 t_m[34];
		t_m[36] = t_m[24] ^	 t_m[25];
		t_m[37] = t_m[21] ^	 t_m[29];
		t_m[38] = t_m[32] ^	 t_m[33];
		t_m[39] = t_m[23] ^	 t_m[30];
		t_m[40] = t_m[35] ^	 t_m[36];
		t_m[41] = t_m[38] ^	 t_m[40];
		t_m[42] = t_m[37] ^	 t_m[39];
		t_m[43] = t_m[37] ^	 t_m[38];
		t_m[44] = t_m[39] ^	 t_m[40];
		t_m[45] = t_m[42] ^	 t_m[41];
		y_m[ 0] = t_m[38] &	 y_t[ 7];
		y_m[ 1] = t_m[37] &	 y_t[13];
		y_m[ 2] = t_m[42] &	 y_t[11];
		y_m[ 3] = t_m[45] &	 y_t[20];
		y_m[ 4] = t_m[41] &	 y_t[ 8];
		y_m[ 5] = t_m[44] &	 y_t[ 9];
		y_m[ 6] = t_m[40] &	 y_t[17];
		y_m[ 7] = t_m[39] &	 y_t[14];
		y_m[ 8] = t_m[43] &	 y_t[ 3];
		y_m[ 9] = t_m[38] &	 y_t[16];
		y_m[10] = t_m[37] &	 y_t[15];
		y_m[11] = t_m[42] &	 y_t[ 1];
		y_m[12] = t_m[45] &	 y_t[ 4];
		y_m[13] = t_m[41] &	 y_t[ 2];
		y_m[14] = t_m[44] &	 y_t[ 5];
		y_m[15] = t_m[40] &	 y_t[ 6];
		y_m[16] = t_m[39] &	 y_t[ 0];
		y_m[17] = t_m[43] &	 y_t[12];

  //bottom(outer) linear layer for sm4
  	t_b[ 0] = y_m[ 4] ^	 y_m[ 7];
		t_b[ 1] = y_m[13] ^	 y_m[15];
		t_b[ 2] = y_m[ 2] ^	 y_m[16];
		t_b[ 3] = y_m[ 6] ^	 t_b[ 0];
		t_b[ 4] = y_m[12] ^	 t_b[ 1];
		t_b[ 5] = y_m[ 9] ^	 y_m[10];
		t_b[ 6] = y_m[11] ^	 t_b[ 2];
		t_b[ 7] = y_m[ 1] ^	 t_b[ 4];
		t_b[ 8] = y_m[ 0] ^	 y_m[17];
		t_b[ 9] = y_m[ 3] ^	 y_m[17];
		t_b[10] = y_m[ 8] ^	 t_b[ 3];
		t_b[11] = t_b[ 2] ^	 t_b[ 5];
		t_b[12] = y_m[14] ^	 t_b[ 6];
		t_b[13] = t_b[ 7] ^	 t_b[ 9];
		t_b[14] = y_m[ 0] ^	 y_m[ 6];
		t_b[15] = y_m[ 7] ^	 y_m[16];
		t_b[16] = y_m[ 5] ^	 y_m[13];
		t_b[17] = y_m[ 3] ^	 y_m[15];
		t_b[18] = y_m[10] ^	 y_m[12];
		t_b[19] = y_m[ 9] ^	 t_b[ 1];
		t_b[20] = y_m[ 4] ^	 t_b[ 4];
		t_b[21] = y_m[14] ^	 t_b[ 3];
		t_b[22] = y_m[16] ^	 t_b[ 5];
		t_b[23] = t_b[ 7] ^	 t_b[14];
		t_b[24] = t_b[ 8] ^	 t_b[11];
		t_b[25] = t_b[ 0] ^	 t_b[12];
		t_b[26] = t_b[17] ^	 t_b[ 3];
		t_b[27] = t_b[18] ^	 t_b[10];
		t_b[28] = t_b[19] ^	 t_b[ 6];
		t_b[29] = t_b[ 8] ^	 t_b[10];
		*out0 = t_b[11] ^~ t_b[13];
		*out1 = t_b[15] ^~ t_b[23];
		*out2 = t_b[20] ^	 t_b[24];
		*out3 = t_b[16] ^	 t_b[25];
		*out4 = t_b[26] ^~ t_b[22];
		*out5 = t_b[21] ^	 t_b[13];
		*out6 = t_b[27] ^~ t_b[12];
		*out7 = t_b[28] ^~ t_b[29];
}

static ossl_inline void S_box(int round,__m256i buf_256[36][32])
{
    bits sm4;

    for(int i = 0; i<4; i++)
    {
        sm4.b7 = buf_256[round+4][i*8];
        sm4.b6 = buf_256[round+4][i*8+1];
        sm4.b5 = buf_256[round+4][i*8+2];
        sm4.b4 = buf_256[round+4][i*8+3];
        sm4.b3 = buf_256[round+4][i*8+4];
        sm4.b2 = buf_256[round+4][i*8+5];
        sm4.b1 = buf_256[round+4][i*8+6];
        sm4.b0 = buf_256[round+4][i*8+7];

        Sm4_BoolFun(sm4,&buf_256[round+4][i*8+7],&buf_256[round+4][i*8+6],&buf_256[round+4][i*8+5],&buf_256[round+4][i*8+4],
            &buf_256[round+4][i*8+3],&buf_256[round+4][i*8+2],&buf_256[round+4][i*8+1],&buf_256[round+4][i*8]);

    }
    //for(int )

}

static ossl_inline void BS_iteration(__m256i* N,const __m256i BS_RK_256[32][32])
{
    int i = 0;
    __m256i buf_256[36][32];
    __m256i temp_256[36][32];

    for(int j = 0; j < 4; j++)
    {
        for(int k = 0; k < 32; k++)
        {
            buf_256[j][k] = N[32*j+k];//load data
        }     
    }
        
    while(i < 32)//32轮迭代计算
    {

        for(int j = 0; j < 32; j++)//4道32bit数据操作:
        {
            buf_256[4+i][j]= buf_256[i+1][j] ^ buf_256[i+2][j] ^ buf_256[i+3][j] ^ BS_RK_256[i][j];
        }

        S_box(i,buf_256);//bingo256 合成置换T的非线性变换
        
        //printf("\tafter shift\n");
        for(int j = 0; j < 32; j++)//bingo256 4道32bit数据操作:合成置换T的线性变换L
        {
            temp_256[4+i][j]= buf_256[4+i][j] ^ buf_256[4+i][(j+2)%32] ^ buf_256[4+i][(j+10)%32] ^ buf_256[4+i][(j+18)%32] ^ buf_256[4+i][(j+24)%32];
        }
        for(int j = 0; j < 32; j++)//4道32bit数据操作
        {
            buf_256[4+i][j]= temp_256[i+4][j] ^ buf_256[i][j];
        }        
        i++;
    }

    for(int j = 0; j < 4; j++)//反序计算
    {
        for(int k = 0; k < 32; k++)
        {

            N[32*j+k] = buf_256[35-j][k];
        }
    }

}

static ossl_inline void sm4_bs256_enc(__m128i M[256],__m256i N[128],const __m256i rk[32][32])
{
    BS_TRANS_128x256(M,N);
    BS_iteration(N,rk);
    BS_TRANS_VER_128x256(N,M);
}

void SM4_bs256_ecb_encrypt(const uint8_t *in, uint8_t *out, const SM4_BS256_KEY *ks)
{
    //int size = sizeof(in);
    int size = 16;
    // printf("size=%d\t",size);
    // int size = 48;
    int BS_BLOCK_SIZE = 4096;
     __m256i output_space[128];
    __m128i input_space[128*2];
    __m128i state[256];
    __m128i t;
    __m256i t2;
    //the masking for shuffle the data
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m256i vindex_swap2 = _mm256_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);

    // memset(out,0,size);
    uint8_t temp[size];
    memmove(temp, in, size);
    // __m256i* out_256 = (__m256i*)out;
    __m128i* in_128 = (__m128i*)temp;
    
    // sm4_bs256_key_schedule(key,rk);

    while(size > 0)
    {
        if(size < BS_BLOCK_SIZE)
        {
            memset(input_space,0,BS_BLOCK_SIZE);
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(in_128[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }

            sm4_bs256_enc(input_space,output_space,ks->bs_rk);

            __m128i* out_t = (__m128i*)out;
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(input_space[i],vindex_swap);
                _mm_storeu_si128(out_t,t);
                out_t++;
            }
            out += size;
            size = 0;
        }
        else
        {
            memmove(state,in,BS_BLOCK_SIZE);
            for(int i=0; i<128*2; i++){
                t = _mm_shuffle_epi8(in_128[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }
            sm4_bs256_enc(input_space,output_space,ks->bs_rk);
            __m256i* out_t = (__m256i*)out;
            for(int i=0; i<128; i++)
            {
                t2 = _mm256_shuffle_epi8(output_space[i],vindex_swap2);
                _mm256_storeu_si256(out_t,t2); 
                out_t++;         
            }
            size -= BS_BLOCK_SIZE;
            out += 128;
            in += 128*2;
        }
        
    }
}

void sm4_bs256_ecb_encrypt(const uint8_t *in, uint8_t *out, int size, const SM4_BS256_KEY *ks)
{
    //printf("size=%d\t",size);
    int BS_BLOCK_SIZE = 4096;
     __m256i output_space[128];
    __m128i input_space[128*2];
    __m128i state[256];
    __m128i t;
    __m256i t2;
    //the masking for shuffle the data
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m256i vindex_swap2 = _mm256_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);

    // memset(out,0,size);
    uint8_t temp[size];
    memmove(temp, in, size);
    // __m256i* out_256 = (__m256i*)out;
    __m128i* in_128 = (__m128i*)temp;
    

    while(size > 0)
    {
        if(size < BS_BLOCK_SIZE)
        {
            memset(input_space,0,BS_BLOCK_SIZE);
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(in_128[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }

            sm4_bs256_enc(input_space,output_space,ks->bs_rk);

            __m128i* out_t = (__m128i*)out;
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(input_space[i],vindex_swap);
                _mm_storeu_si128(out_t,t);
                out_t++;
            }
            out += size;
            size = 0;
        }
        else
        {
            memmove(state,in,BS_BLOCK_SIZE);
            for(int i=0; i<128*2; i++){
                t = _mm_shuffle_epi8(in_128[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }
            sm4_bs256_enc(input_space,output_space,ks->bs_rk);

            __m256i* out_t = (__m256i*)out;
            for(int i=0; i<128; i++)
            {
                t2 = _mm256_shuffle_epi8(output_space[i],vindex_swap2);
                _mm256_storeu_si256(out_t,t2);       
                out_t++;   
            }
            size -= BS_BLOCK_SIZE;
            out += 128;
            in += 128*2;
        }
        
    }
}

void sm4_bs256_ctr_encrypt(const uint8_t * inputb, uint8_t * outputb, int size, const SM4_BS256_KEY *ks, uint8_t * iv)
{
    //printf("size=%d\t",size);
    int BLOCK_SIZE = 128;
    int BS_BLOCK_SIZE = 4096;
    __m128i ctr[BLOCK_SIZE*2];
    __m256i output_space[BLOCK_SIZE];
    __m128i iv_copy;
    __m128i t;
    __m128i count = _mm_setzero_si128();
    //uint64_t count = 0;
    uint64_t op[2] = {0,1};
    __m128i cnt = _mm_loadu_si128((__m128i*)op);
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);

    memset(outputb,0,size);
    memset(ctr,0,sizeof(ctr));
    // t = _mm_load_si128((__m128i *)iv);
    t = _mm_loadu_si128((__m128i *)iv);
    iv_copy = _mm_shuffle_epi8(t,vindex_swap);

    while(size)
    {
        int chunk = MIN(size, BS_BLOCK_SIZE);
        int blocks = chunk / (BLOCK_SIZE/8);

        int i;
        for (i = 0; i < blocks; i++)
        {
            //memmove(ctr + (i * WORDS_PER_BLOCK), iv_copy, BLOCK_SIZE/8);
            // Attention: the ctr mode iv counter from 0 while gcm is from ;//512*16;1
            //count = _mm_add_epi64(count,cnt);
            ctr[i] = iv_copy + count;
            count = _mm_add_epi64(count,cnt);
        }

        sm4_bs256_enc(ctr,output_space,ks->bs_rk);
        for(i=0; i<blocks; i++)
        {
            ctr[i] = _mm_shuffle_epi8(ctr[i],vindex_swap);     
        }
        size -= chunk;

        uint8_t * ctr_p = (uint8_t *) ctr;
        for(i=0; i<chunk; i++)
        {
            outputb[i] = *ctr_p++ ^ inputb[i];
        }

    }
}