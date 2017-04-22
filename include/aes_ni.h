#ifndef __AES_NI_H__
#define __AES_NI_H__

#include <stdint.h>     //for int8_t
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI
//compile using gcc and following arguments: -g;-O0;-Wall;-msse2;-msse;-march=native;-maes

//internal stuff

//macros
#define DO_ENC_BLOCK(m,k) \
    do{\
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenclast_si128(m, k[10]);\
    }while(0)

#define DO_DEC_BLOCK(m,k) \
    do{\
        m = _mm_xor_si128       (m, k[10+0]); \
        m = _mm_aesdec_si128    (m, k[10+1]); \
        m = _mm_aesdec_si128    (m, k[10+2]); \
        m = _mm_aesdec_si128    (m, k[10+3]); \
        m = _mm_aesdec_si128    (m, k[10+4]); \
        m = _mm_aesdec_si128    (m, k[10+5]); \
        m = _mm_aesdec_si128    (m, k[10+6]); \
        m = _mm_aesdec_si128    (m, k[10+7]); \
        m = _mm_aesdec_si128    (m, k[10+8]); \
        m = _mm_aesdec_si128    (m, k[10+9]); \
        m = _mm_aesdeclast_si128(m, k[0]);\
    }while(0)

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened){
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

//public API
static void aes128_load_key_enc_only(uint8_t *enc_key, __m128i *key_schedule){
    key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
    key_schedule[1]  = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2]  = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3]  = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4]  = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5]  = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6]  = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7]  = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8]  = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9]  = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
}

static void aes128_load_key(uint8_t *enc_key, __m128i *key_schedule){
    aes128_load_key_enc_only(enc_key, key_schedule);

    // generate decryption keys in reverse order.
    // k[10] is shared by last encryption and first decryption rounds
    // k[0] is shared by first encryption round and last decryption round (and is the original user key)
    // For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
    key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
    key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
    key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
    key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
    key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
    key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
    key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
    key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
    key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
}

static void aes128_enc(__m128i *key_schedule, uint8_t *plainText,uint8_t *cipherText){
    __m128i m = _mm_loadu_si128((__m128i *) plainText);

    DO_ENC_BLOCK(m,key_schedule);

    _mm_storeu_si128((__m128i *) cipherText, m);
}

static void aes128_dec(__m128i *key_schedule, uint8_t *cipherText,uint8_t *plainText){
    __m128i m = _mm_loadu_si128((__m128i *) cipherText);

    DO_DEC_BLOCK(m,key_schedule);

    _mm_storeu_si128((__m128i *) plainText, m);
}

//return 0 if no error
//1 if encryption failed
//2 if decryption failed
//3 if both failed
static int aes128_self_test(void){
    uint8_t plain[]      = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t enc_key[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t cipher[]     = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
    uint8_t computed_cipher[16];
    uint8_t computed_plain[16];
    int out=0;
    __m128i key_schedule[20];
    aes128_load_key(enc_key,key_schedule);
    aes128_enc(key_schedule,plain,computed_cipher);
    aes128_dec(key_schedule,cipher,computed_plain);
    if(memcmp(cipher,computed_cipher,sizeof(cipher))) out=1;
    if(memcmp(plain,computed_plain,sizeof(plain))) out|=2;
    return out;
}
#endif
