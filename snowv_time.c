
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h> 




typedef uint8_t u8;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

u8 SBox[256] =
    {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
u32 AesKey1[4] = {0, 0, 0, 0};
u32 AesKey2[4] = {0, 0, 0, 0};
#define MAKEU32(a, b) (((u32)(a) << 16) | ((u32)(b)))
#define MAKEU16(a, b) (((u16)(a) << 8) | ((u16)(b)))
#define BLOCK_SIZE 10000
#define KEY_SIZE 32
#define SALT_SIZE 16
#define ITERATIONS 1

u16 A[16], B[16];        // LFSR
u32 R1[4], R2[4], R3[4]; // FSM Registers

void aes_enc_round(u32 *result, u32 *state, u32 *roundKey)
{
#define ROTL32(word32, offset) ((word32 << offset) | (word32 >> (32 - offset)))
#define SB(index, offset) (((u32)(sb[(index) % 16])) << (offset * 8))
#define MKSTEP(j)                                                                       \
    w = SB(j * 4 + 0, 3) | SB(j * 4 + 5, 0) | SB(j * 4 + 10, 1) | SB(j * 4 + 15, 2);    \
    t = ROTL32(w, 16) ^ ((w << 1) & 0xfefefefeUL) ^ (((w >> 7) & 0x01010101UL) * 0x1b); \
    result[j] = roundKey[j] ^ w ^ t ^ ROTL32(t, 8)
    u32 w, t;
    u8 sb[16];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            sb[i * 4 + j] = SBox[(state[i] >> (j * 8)) & 0xff];
    MKSTEP(0);
    MKSTEP(1);
    MKSTEP(2);
    MKSTEP(3);
}
u16 mul_x(u16 v, u16 c)
{
    if (v & 0x8000)
        return (v << 1) ^ c;
    else
        return (v << 1);
}
u16 mul_x_inv(u16 v, u16 d)
{
    if (v & 0x0001)
        return (v >> 1) ^ d;
    else
        return (v >> 1);
}
void fsm_update(void)
{
    u32 R1temp[4];
    memcpy(R1temp, R1, sizeof(R1));
    for (int i = 0; i < 4; i++)
    {
        u32 T2 = MAKEU32(A[2 * i + 1], A[2 * i]);
        R1[i] = (T2 ^ R3[i]) + R2[i];
    }
    aes_enc_round(R3, R2, AesKey2);
    aes_enc_round(R2, R1temp, AesKey1);
}
void lfsr_update(void)
{
    for (int i = 0; i < 8; i++)
    {
        u16 u = mul_x(A[0], 0x990f) ^ A[1] ^ mul_x_inv(A[8], 0xcc87) ^ B[0];
        u16 v = mul_x(B[0], 0xc963) ^ B[3] ^ mul_x_inv(B[8], 0xe4b1) ^ A[0];
        for (int j = 0; j < 15; j++)
        {
            A[j] = A[j + 1];
            B[j] = B[j + 1];
        }
        A[15] = u;
        B[15] = v;
    }
}
void genKeystream(u8 *z)
{
    for (int i = 0; i < 4; i++)
    {
        u32 T1 = MAKEU32(B[2 * i + 9], B[2 * i + 8]);
        u32 v = (T1 + R1[i]) ^ R2[i];
        z[i * 4 + 0] = (v >> 0) & 0xff;
        z[i * 4 + 1] = (v >> 8) & 0xff;
        z[i * 4 + 2] = (v >> 16) & 0xff;
        z[i * 4 + 3] = (v >> 24) & 0xff;
    }
    fsm_update();
    lfsr_update();
}
void keyiv_setup(u8 *key, u8 *iv)
{
    for (int i = 0; i < 8; i++)
    {
        A[i] = MAKEU16(iv[2 * i + 1], iv[2 * i]);
        A[i + 8] = MAKEU16(key[2 * i + 1], key[2 * i]);
        B[i] = 0x0000;
        B[i + 8] = MAKEU16(key[2 * i + 17], key[2 * i + 16]);
    }
    for (int i = 0; i < 4; i++)
        R1[i] = R2[i] = R3[i] = 0x00000000;
    for (int i = 0; i < 16; i++)
    {
        u8 z[16];
        genKeystream(z);
        for (int j = 0; j < 8; j++)
            A[j + 8] ^= MAKEU16(z[2 * j + 1], z[2 * j]);
        if (i == 14)
            for (int j = 0; j < 4; j++)
                R1[j] ^= MAKEU32(MAKEU16(key[4 * j + 3], key[4 * j + 2]),
                                 MAKEU16(key[4 * j + 1], key[4 * j + 0]));
        if (i == 15)
            for (int j = 0; j < 4; j++)
                R1[j] ^= MAKEU32(MAKEU16(key[4 * j + 19], key[4 * j + 18]),
                                 MAKEU16(key[4 * j + 17], key[4 * j + 16]));
    }
}



#define XOR2x64(dst, src) do { \
   ((u32*)(dst))[0] ^= ((const u32*)(src))[0]; \
   ((u32*)(dst))[1] ^= ((const u32*)(src))[1]; \
 } while(0)
 
 #define XOR3x64(dst, src1, src2) do { \
   ((u32*)(dst))[0] = ((const u32*)(src1))[0] ^ ((const u32*)(src2))[0]; \
   ((u32*)(dst))[1] = ((const u32*)(src1))[1] ^ ((const u32*)(src2))[1]; \
 } while(0)
 
 /* Multiply in GF(2^128) with 128-bit x,y -> 128-bit out. */
 static void ghash_mult(u8 *out, const u8 *x, const u8 *y)
 {
     u32 yh0 = ((const u32*)y)[0];
     u32 yh1 = ((const u32*)y)[1];
 
     memset(out, 0, 16);
 
     for(int i=0; i<16; i++){
         for(int j=7; j>=0; j--){
             if((x[i] >> j) & 1){
                 ((u32*)out)[0] ^= yh0;
                 ((u32*)out)[1] ^= yh1;
             }
             /* shift yh0,yh1 right by 1 with poly 0xe1 if carry out */
             u32 carry = (yh1 & 1) ? 0xe100000000000000ULL : 0ULL;
             yh1 = (yh1 >> 1) | ((yh0 & 1ULL) << 63);
             yh0 = (yh0 >> 1) ^ carry;
         }
     }
 }
 
 static void ghash_update(const u8 *H, u8 *A, const u8 *data, long long length)
 {
     while(length >= 16){
         u8 tmp[16];
         XOR3x64(tmp, data, A);
         ghash_mult(A, tmp, H);
         data   += 16;
         length -= 16;
     }
     if(length > 0){
         u8 tmp[16];
         memset(tmp, 0, 16);
         memcpy(tmp, data, length);
         XOR2x64(tmp, A);
         ghash_mult(A, tmp, H);
     }
 }
 
 static void ghash_final(const u8 *H, u8 *A, u32 lenAAD, u32 lenC, const u8 *maskingBlock)
 {
     u8 tmp[16];
     memset(tmp, 0, 16);
 
     /* length fields in bits */
     lenAAD <<= 3;
     lenC   <<= 3;
 
     for(int i=0; i<8; i++){
         tmp[7-i]  = (u8)(lenAAD >> (8*i));
         tmp[15-i] = (u8)(lenC   >> (8*i));
     }
     XOR2x64(tmp, A);
     ghash_mult(A, tmp, H);
 
     XOR2x64(A, maskingBlock);
 }
 
 /* -------------------------------------------------------------------------
  *  SNOW-V GCM Encryption
  * ------------------------------------------------------------------------- */
 void snowv_gcm_encrypt(
     u8 *authTag,
     u8 *ciphertext, 
     const u8 *plaintext, 
     u32 plaintext_sz,
     const u8 *aad, 
     u32 aad_sz, 
     const u8 *key32,
     const u8 *iv16
 )
 {
     
     u8 Hkey[16], endPad[16];
     memset(authTag, 0, 16);
 
     keyiv_setup(key32, iv16);
 
     /* Derive GHASH key */
     genKeystream(Hkey);
     /* Next block for final masking */
     genKeystream(endPad);
 
     /* GHASH on AAD */
     ghash_update(Hkey, authTag, aad, aad_sz);
 
     /* Encrypt plaintext */
     u32 offset = 0;
     while(offset < plaintext_sz){
         u8 ks[16];
         genKeystream(ks);
 
         u32 block_len = (plaintext_sz - offset < 16) ? (plaintext_sz - offset) : 16;
         for(u32 i=0; i<block_len; i++){
             ciphertext[offset + i] = ks[i] ^ plaintext[offset + i];
         }
         offset += block_len;
     }
 
     /* GHASH on ciphertext */
     ghash_update(Hkey, authTag, ciphertext, plaintext_sz);
 
     /* Final GHASH => authTag */
     ghash_final(Hkey, authTag, aad_sz, plaintext_sz, endPad);
 }
 
 /* -------------------------------------------------------------------------
  *  SNOW-V GCM Decryption
  * ------------------------------------------------------------------------- */
 int snowv_gcm_decrypt(
     const u8 *authTag,
     u8 *plaintext,
     const u8 *ciphertext,
     u32 ciphertext_sz,
     const u8 *aad,
     u32 aad_sz,
     const u8 *key32,
     const u8 *iv16
 )
 {
     
     u8 Hkey[16], endPad[16], checkAuth[16];
     memset(checkAuth, 0, 16);
 
     keyiv_setup(key32, iv16);
 
     /* GHASH key & mask */
     genKeystream(Hkey);
     genKeystream(endPad);
 
     /* GHASH on AAD + ciphertext */
     ghash_update(Hkey, checkAuth, aad, aad_sz);
     ghash_update(Hkey, checkAuth, ciphertext, ciphertext_sz);
     ghash_final(Hkey, checkAuth, aad_sz, ciphertext_sz, endPad);
 
     /* Compare checkAuth vs authTag */
     if(memcmp(checkAuth, authTag, 16) != 0){
         /* Authentication failed */
         return -1;
     }
 
     /* If valid, decrypt */
     u32 offset = 0;
     while(offset < ciphertext_sz){
         u8 z[16];
         genKeystream(z);
 
         u32 block_len = (ciphertext_sz - offset < 16) ? (ciphertext_sz - offset) : 16;
         for(u32 i=0; i<block_len; i++){
             plaintext[offset + i] = z[i] ^ ciphertext[offset + i];
         }
         offset += block_len;
     }
 
     return 0; /* success */
 }
 
 /* -------------------------------------------------------------------------
  *  Example main() - Demonstrates usage, printing ciphertext & timing decrypt
  * ------------------------------------------------------------------------- */
 int main(void)
 {
     /* 256-bit key, 128-bit IV. Example only. */
     u8 key[32];
     u8 iv[16];
 
     /* Fill with test data */
     for(int i=0; i<32; i++){
         key[i] = (u8)(0xAA + i);
     }
     for(int i=0; i<16; i++){
         iv[i] = (u8)(0xBB + i);
     }

     FILE* fp = fopen("example.txt", "r");

     /* Some example plaintext and AAD */
     char pt_str[10000];
     fgets(pt_str, sizeof(pt_str), fp);

     const char *aad_str  = "Additional Authenticated Data";
     u32 pt_len  = (u32)strlen(pt_str);
     u32 aad_len = (u32)strlen(aad_str);
 
     u8 plaintext[10000];
     u8 ciphertext[10000];
     u8 decrypted[10000];
     u8 authTag[16];
 
     memset(plaintext,  0, sizeof(plaintext));
     memset(ciphertext, 0, sizeof(ciphertext));
     memset(decrypted,  0, sizeof(decrypted));
     memset(authTag,    0, sizeof(authTag));
 
     /* Copy test plaintext into buffer */
     memcpy(plaintext, pt_str, pt_len);
 
     /* Encrypt */
     snowv_gcm_encrypt(
         authTag,
         ciphertext,
         plaintext,
         pt_len,
         (const u8*)aad_str,
         aad_len,
         key,
         iv
     );
 
     /* Print ciphertext in hex */
     printf("Ciphertext (hex):\n");
     for (u32 i = 0; i < pt_len; i++) {
         printf("%02X", ciphertext[i]);
     }
     printf("\n\n");
 
     /* Measure decryption time */
     clock_t start = clock();
     int ret = snowv_gcm_decrypt(
         authTag,
         decrypted,
         ciphertext,
         pt_len,
         (const u8*)aad_str,
         aad_len,
         key,
         iv
     );
     clock_t end = clock();
 
     double time_taken = (double)(end - start) / CLOCKS_PER_SEC;
 
     if(ret == 0) {
         printf("Decryption OK.\n");
         printf("Decrypted text: '%s'\n", decrypted);
     } else {
         printf("Authentication FAILED!\n");
     }
 
     printf("Time taken for decryption: %f seconds\n", time_taken);
 
     return 0;
 }
 