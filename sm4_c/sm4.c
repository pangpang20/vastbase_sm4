/*
 * SM4 Algorithm Implementation
 * 国密SM4分组密码算法实现
 * 
 * 基于GB/T 32907-2016标准实现
 */

#include "sm4.h"
#include <string.h>
#include <stdlib.h>

#ifdef USE_OPENSSL_KDF
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#endif

/* SM4 S盒 */
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

/* 系统参数FK */
static const uint32_t SM4_FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

/* 固定参数CK */
static const uint32_t SM4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

/* 循环左移 */
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* 字节序转换 */
static uint32_t load_u32_be(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |
           ((uint32_t)b[3]);
}

static void store_u32_be(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

/* τ变换: 非线性变换 */
static uint32_t sm4_tau(uint32_t x)
{
    uint8_t a[4];
    a[0] = SM4_SBOX[(x >> 24) & 0xff];
    a[1] = SM4_SBOX[(x >> 16) & 0xff];
    a[2] = SM4_SBOX[(x >> 8) & 0xff];
    a[3] = SM4_SBOX[x & 0xff];
    return ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | 
           ((uint32_t)a[2] << 8) | ((uint32_t)a[3]);
}

/* L变换: 线性变换 */
static uint32_t sm4_l(uint32_t x)
{
    return x ^ ROTL(x, 2) ^ ROTL(x, 10) ^ ROTL(x, 18) ^ ROTL(x, 24);
}

/* L'变换: 密钥扩展用的线性变换 */
static uint32_t sm4_l_prime(uint32_t x)
{
    return x ^ ROTL(x, 13) ^ ROTL(x, 23);
}

/* T变换 */
static uint32_t sm4_t(uint32_t x)
{
    return sm4_l(sm4_tau(x));
}

/* T'变换 (密钥扩展用) */
static uint32_t sm4_t_prime(uint32_t x)
{
    return sm4_l_prime(sm4_tau(x));
}

/* 密钥扩展 */
void sm4_setkey(sm4_context *ctx, const uint8_t *key)
{
    uint32_t k[36];
    int i;

    /* 初始密钥与FK异或 */
    k[0] = load_u32_be(key) ^ SM4_FK[0];
    k[1] = load_u32_be(key + 4) ^ SM4_FK[1];
    k[2] = load_u32_be(key + 8) ^ SM4_FK[2];
    k[3] = load_u32_be(key + 12) ^ SM4_FK[3];

    /* 生成32个轮密钥 */
    for (i = 0; i < SM4_NUM_ROUNDS; i++) {
        k[i + 4] = k[i] ^ sm4_t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]);
        ctx->rk[i] = k[i + 4];
    }
}

/* 加密单个块 */
void sm4_encrypt_block(const sm4_context *ctx, const uint8_t *input, uint8_t *output)
{
    uint32_t x[36];
    int i;

    /* 加载输入 */
    x[0] = load_u32_be(input);
    x[1] = load_u32_be(input + 4);
    x[2] = load_u32_be(input + 8);
    x[3] = load_u32_be(input + 12);

    /* 32轮迭代 */
    for (i = 0; i < SM4_NUM_ROUNDS; i++) {
        x[i + 4] = x[i] ^ sm4_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ ctx->rk[i]);
    }

    /* 反序变换输出 */
    store_u32_be(output, x[35]);
    store_u32_be(output + 4, x[34]);
    store_u32_be(output + 8, x[33]);
    store_u32_be(output + 12, x[32]);
}

/* 解密单个块 */
void sm4_decrypt_block(const sm4_context *ctx, const uint8_t *input, uint8_t *output)
{
    uint32_t x[36];
    int i;

    /* 加载输入 */
    x[0] = load_u32_be(input);
    x[1] = load_u32_be(input + 4);
    x[2] = load_u32_be(input + 8);
    x[3] = load_u32_be(input + 12);

    /* 32轮迭代(使用逆序轮密钥) */
    for (i = 0; i < SM4_NUM_ROUNDS; i++) {
        x[i + 4] = x[i] ^ sm4_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ ctx->rk[SM4_NUM_ROUNDS - 1 - i]);
    }

    /* 反序变换输出 */
    store_u32_be(output, x[35]);
    store_u32_be(output + 4, x[34]);
    store_u32_be(output + 8, x[33]);
    store_u32_be(output + 12, x[32]);
}

/* PKCS7填充 */
static size_t pkcs7_pad(const uint8_t *input, size_t input_len, uint8_t *output)
{
    size_t pad_len = SM4_BLOCK_SIZE - (input_len % SM4_BLOCK_SIZE);
    size_t total_len = input_len + pad_len;
    size_t i;

    memcpy(output, input, input_len);
    for (i = input_len; i < total_len; i++) {
        output[i] = (uint8_t)pad_len;
    }
    return total_len;
}

/* PKCS7去填充 */
static int pkcs7_unpad(uint8_t *data, size_t data_len, size_t *out_len)
{
    uint8_t pad_len;
    size_t i;

    if (data_len == 0 || data_len % SM4_BLOCK_SIZE != 0) {
        return -1;
    }

    pad_len = data[data_len - 1];
    if (pad_len == 0 || pad_len > SM4_BLOCK_SIZE) {
        return -1;
    }

    for (i = data_len - pad_len; i < data_len; i++) {
        if (data[i] != pad_len) {
            return -1;
        }
    }

    *out_len = data_len - pad_len;
    return 0;
}

/* ECB模式加密 */
int sm4_ecb_encrypt(const uint8_t *key, const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t *output_len)
{
    sm4_context ctx;
    size_t padded_len;
    size_t i;
    uint8_t *padded;

    if (!key || !input || !output || !output_len) {
        return -1;
    }

    /* 计算填充后的长度 */
    padded_len = input_len + SM4_BLOCK_SIZE - (input_len % SM4_BLOCK_SIZE);
    
    /* 临时缓冲区用于填充 */
    padded = (uint8_t *)malloc(padded_len);
    if (!padded) {
        return -1;
    }
    
    pkcs7_pad(input, input_len, padded);
    sm4_setkey(&ctx, key);

    /* 分块加密 */
    for (i = 0; i < padded_len; i += SM4_BLOCK_SIZE) {
        sm4_encrypt_block(&ctx, padded + i, output + i);
    }

    free(padded);
    *output_len = padded_len;
    return 0;
}

/* ECB模式解密 */
int sm4_ecb_decrypt(const uint8_t *key, const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t *output_len)
{
    sm4_context ctx;
    size_t i;

    if (!key || !input || !output || !output_len) {
        return -1;
    }

    if (input_len == 0 || input_len % SM4_BLOCK_SIZE != 0) {
        return -1;
    }

    sm4_setkey(&ctx, key);

    /* 分块解密 */
    for (i = 0; i < input_len; i += SM4_BLOCK_SIZE) {
        sm4_decrypt_block(&ctx, input + i, output + i);
    }

    /* 去除填充 */
    if (pkcs7_unpad(output, input_len, output_len) != 0) {
        return -1;
    }

    return 0;
}

/* CBC模式加密 */
int sm4_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                    const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t *output_len)
{
    sm4_context ctx;
    size_t padded_len;
    size_t i, j;
    uint8_t block[SM4_BLOCK_SIZE];
    uint8_t prev[SM4_BLOCK_SIZE];
    uint8_t *padded;

    if (!key || !iv || !input || !output || !output_len) {
        return -1;
    }

    padded_len = input_len + SM4_BLOCK_SIZE - (input_len % SM4_BLOCK_SIZE);
    
    padded = (uint8_t *)malloc(padded_len);
    if (!padded) {
        return -1;
    }
    
    pkcs7_pad(input, input_len, padded);
    sm4_setkey(&ctx, key);
    memcpy(prev, iv, SM4_BLOCK_SIZE);

    /* 分块加密 */
    for (i = 0; i < padded_len; i += SM4_BLOCK_SIZE) {
        /* 与前一密文块(或IV)异或 */
        for (j = 0; j < SM4_BLOCK_SIZE; j++) {
            block[j] = padded[i + j] ^ prev[j];
        }
        sm4_encrypt_block(&ctx, block, output + i);
        memcpy(prev, output + i, SM4_BLOCK_SIZE);
    }

    free(padded);
    *output_len = padded_len;
    return 0;
}

/* CBC模式解密 */
int sm4_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                    const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t *output_len)
{
    sm4_context ctx;
    size_t i, j;
    uint8_t block[SM4_BLOCK_SIZE];
    uint8_t prev[SM4_BLOCK_SIZE];

    if (!key || !iv || !input || !output || !output_len) {
        return -1;
    }

    if (input_len == 0 || input_len % SM4_BLOCK_SIZE != 0) {
        return -1;
    }

    sm4_setkey(&ctx, key);
    memcpy(prev, iv, SM4_BLOCK_SIZE);

    /* 分块解密 */
    for (i = 0; i < input_len; i += SM4_BLOCK_SIZE) {
        sm4_decrypt_block(&ctx, input + i, block);
        /* 与前一密文块(或IV)异或 */
        for (j = 0; j < SM4_BLOCK_SIZE; j++) {
            output[i + j] = block[j] ^ prev[j];
        }
        memcpy(prev, input + i, SM4_BLOCK_SIZE);
    }

    /* 去除填充 */
    if (pkcs7_unpad(output, input_len, output_len) != 0) {
        return -1;
    }

    return 0;
}

/* GF(2^128)中的乘法运算 (用于GHASH) */
static void gf128_mul(const uint8_t *x, const uint8_t *y, uint8_t *result)
{
    uint8_t v[16];
    uint8_t z[16] = {0};
    int i, j, k;
    uint8_t lsb;

    memcpy(v, y, 16);

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            /* 如果 x[i] 的第 (7-j) 位为1 */
            if (x[i] & (1 << (7 - j))) {
                /* z = z ⊕ v */
                for (k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }

            /* v右移1位 */
            lsb = v[15] & 1;
            for (k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | (v[k - 1] << 7);
            }
            v[0] = v[0] >> 1;

            /* 如果最低位为1,则与R异或 */
            if (lsb) {
                v[0] ^= 0xe1;
            }
        }
    }

    memcpy(result, z, 16);
}

/* GHASH函数 */
static void ghash(const uint8_t *h, const uint8_t *data, size_t data_len, uint8_t *result)
{
    size_t i;
    uint8_t block[16];

    memset(result, 0, 16);

    for (i = 0; i < data_len; i += 16) {
        size_t block_len = (data_len - i < 16) ? (data_len - i) : 16;
        int j;

        memset(block, 0, 16);
        memcpy(block, data + i, block_len);

        /* result = result ⊕ block */
        for (j = 0; j < 16; j++) {
            result[j] ^= block[j];
        }

        /* result = result * H */
        gf128_mul(result, h, result);
    }
}

/* 增量函数 (用于GCM的计数器) */
static void gcm_inc32(uint8_t *counter)
{
    uint32_t val;

    /* 读取最后4字节作为大端序32位整数 */
    val = ((uint32_t)counter[12] << 24) |
          ((uint32_t)counter[13] << 16) |
          ((uint32_t)counter[14] << 8) |
          ((uint32_t)counter[15]);

    val++;

    /* 写回 */
    counter[12] = (uint8_t)(val >> 24);
    counter[13] = (uint8_t)(val >> 16);
    counter[14] = (uint8_t)(val >> 8);
    counter[15] = (uint8_t)(val);
}

/* GCTR函数 (GCM的计数器模式加密) */
static void gctr(const sm4_context *ctx, const uint8_t *icb, 
                 const uint8_t *input, size_t input_len, uint8_t *output)
{
    uint8_t counter[16];
    uint8_t encrypted_counter[16];
    size_t i, j;

    if (input_len == 0) {
        return;
    }

    memcpy(counter, icb, 16);

    for (i = 0; i < input_len; i += 16) {
        sm4_encrypt_block(ctx, counter, encrypted_counter);

        for (j = 0; j < 16 && (i + j) < input_len; j++) {
            output[i + j] = input[i + j] ^ encrypted_counter[j];
        }

        gcm_inc32(counter);
    }
}

/* SM4 GCM模式加密 */
int sm4_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *input, size_t input_len,
                    uint8_t *output, uint8_t *tag)
{
    sm4_context ctx;
    uint8_t h[16] = {0};
    uint8_t j0[16];
    uint8_t ghash_input[1024];
    size_t ghash_len = 0;
    uint64_t aad_bits, input_bits;
    uint8_t s[16];
    int i;

    if (!key || !iv || !output || !tag) {
        return -1;
    }

    /* 设置密钥 */
    sm4_setkey(&ctx, key);

    /* 计算H = E(K, 0^128) */
    sm4_encrypt_block(&ctx, h, h);

    /* 计算J0 */
    if (iv_len == 12) {
        /* 推荐的IV长度 */
        memcpy(j0, iv, 12);
        j0[12] = j0[13] = j0[14] = 0;
        j0[15] = 1;
    } else {
        /* 其他IV长度 */
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        int j;

        for (j = 0; j < 8; j++) {
            len_block[15 - j] = (uint8_t)(iv_bits >> (j * 8));
        }

        memset(j0, 0, 16);
        ghash(h, iv, iv_len, j0);

        for (j = 0; j < 16; j++) {
            j0[j] ^= len_block[j];
        }
        gf128_mul(j0, h, j0);
    }

    /* 加密: C = GCTR(K, inc32(J0), P) */
    uint8_t icb[16];
    memcpy(icb, j0, 16);
    gcm_inc32(icb);
    gctr(&ctx, icb, input, input_len, output);

    /* 构造GHASH输入: AAD || 0* || C || 0* || len(AAD) || len(C) */
    memset(ghash_input, 0, sizeof(ghash_input));
    ghash_len = 0;

    /* 添加AAD */
    if (aad && aad_len > 0) {
        memcpy(ghash_input, aad, aad_len);
        ghash_len = aad_len;
        /* 填充到16字节边界 */
        if (ghash_len % 16 != 0) {
            ghash_len += 16 - (ghash_len % 16);
        }
    }

    /* 添加密文 */
    memcpy(ghash_input + ghash_len, output, input_len);
    ghash_len += input_len;
    /* 填充到16字节边界 */
    if (ghash_len % 16 != 0) {
        ghash_len += 16 - (ghash_len % 16);
    }

    /* 添加长度字段 */
    aad_bits = (uint64_t)aad_len * 8;
    input_bits = (uint64_t)input_len * 8;

    for (i = 0; i < 8; i++) {
        ghash_input[ghash_len + i] = (uint8_t)(aad_bits >> (56 - i * 8));
        ghash_input[ghash_len + 8 + i] = (uint8_t)(input_bits >> (56 - i * 8));
    }
    ghash_len += 16;

    /* 计算S = GHASH(H, ghash_input) */
    ghash(h, ghash_input, ghash_len, s);

    /* Tag = MSB(GCTR(K, J0, S)) */
    gctr(&ctx, j0, s, 16, tag);

    return 0;
}

/* SM4 GCM模式解密 */
int sm4_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *input, size_t input_len,
                    const uint8_t *tag, uint8_t *output)
{
    sm4_context ctx;
    uint8_t h[16] = {0};
    uint8_t j0[16];
    uint8_t ghash_input[1024];
    size_t ghash_len = 0;
    uint64_t aad_bits, input_bits;
    uint8_t s[16];
    uint8_t computed_tag[16];
    int i;

    if (!key || !iv || !input || !tag || !output) {
        return -1;
    }

    /* 设置密钥 */
    sm4_setkey(&ctx, key);

    /* 计算H = E(K, 0^128) */
    sm4_encrypt_block(&ctx, h, h);

    /* 计算J0 */
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = j0[13] = j0[14] = 0;
        j0[15] = 1;
    } else {
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        int j;

        for (j = 0; j < 8; j++) {
            len_block[15 - j] = (uint8_t)(iv_bits >> (j * 8));
        }

        memset(j0, 0, 16);
        ghash(h, iv, iv_len, j0);

        for (j = 0; j < 16; j++) {
            j0[j] ^= len_block[j];
        }
        gf128_mul(j0, h, j0);
    }

    /* 构造GHASH输入用于验证 */
    memset(ghash_input, 0, sizeof(ghash_input));
    ghash_len = 0;

    /* 添加AAD */
    if (aad && aad_len > 0) {
        memcpy(ghash_input, aad, aad_len);
        ghash_len = aad_len;
        if (ghash_len % 16 != 0) {
            ghash_len += 16 - (ghash_len % 16);
        }
    }

    /* 添加密文 */
    memcpy(ghash_input + ghash_len, input, input_len);
    ghash_len += input_len;
    if (ghash_len % 16 != 0) {
        ghash_len += 16 - (ghash_len % 16);
    }

    /* 添加长度字段 */
    aad_bits = (uint64_t)aad_len * 8;
    input_bits = (uint64_t)input_len * 8;

    for (i = 0; i < 8; i++) {
        ghash_input[ghash_len + i] = (uint8_t)(aad_bits >> (56 - i * 8));
        ghash_input[ghash_len + 8 + i] = (uint8_t)(input_bits >> (56 - i * 8));
    }
    ghash_len += 16;

    /* 计算S = GHASH(H, ghash_input) */
    ghash(h, ghash_input, ghash_len, s);

    /* 计算Tag */
    gctr(&ctx, j0, s, 16, computed_tag);

    /* 验证Tag */
    for (i = 0; i < 16; i++) {
        if (computed_tag[i] != tag[i]) {
            return -1;  /* 认证失败 */
        }
    }

    /* 解密: P = GCTR(K, inc32(J0), C) */
    uint8_t icb[16];
    memcpy(icb, j0, 16);
    gcm_inc32(icb);
    gctr(&ctx, icb, input, input_len, output);

    return 0;
}

#ifdef USE_OPENSSL_KDF
/*
 * 使用PBKDF2派生密钥和IV（用于KDF功能）
 */
static int derive_key_and_iv(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    const char *hash_algo,
    uint8_t *key,
    uint8_t *iv)
{
    const EVP_MD *md = NULL;
    uint8_t derived[32];
    int iterations = 10000;

    /* 选择哈希算法 */
    if (strcmp(hash_algo, "sha256") == 0) {
        md = EVP_sha256();
    } else if (strcmp(hash_algo, "sha384") == 0) {
        md = EVP_sha384();
    } else if (strcmp(hash_algo, "sha512") == 0) {
        md = EVP_sha512();
    } else if (strcmp(hash_algo, "sm3") == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        md = EVP_sm3();
#else
        return -1;
#endif
    } else {
        return -1;
    }

    /* 使用PBKDF2派生密钥材料 */
    if (PKCS5_PBKDF2_HMAC(
            (const char *)password, password_len,
            salt, salt_len,
            iterations,
            md,
            32,
            derived) != 1) {
        return -1;
    }

    memcpy(key, derived, 16);
    memcpy(iv, derived + 16, 16);
    memset(derived, 0, sizeof(derived));

    return 0;
}

/*
 * DWS gs_encrypt 密钥派生（测试版本）
 * 尝试多种可能的密钥派生方式
 * mode 1: hash(password + salt)
 * mode 2: hash(salt + password)
 * mode 3: 直接使用password作为key，salt作为iv
 * mode 4: EVP_BytesToKey (OpenSSL标准)
 */
static int derive_key_and_iv_dws(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    const char *hash_algo,
    uint8_t *key,
    uint8_t *iv)
{
    const EVP_MD *md = NULL;
    unsigned char hash_output[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *ctx = NULL;
    int mode = 4;  /* 尝试模式4：EVP_BytesToKey */
    
    /* 选择哈希算法 */
    if (strcmp(hash_algo, "sha256") == 0) {
        md = EVP_sha256();
    } else if (strcmp(hash_algo, "sha384") == 0) {
        md = EVP_sha384();
    } else if (strcmp(hash_algo, "sha512") == 0) {
        md = EVP_sha512();
    } else if (strcmp(hash_algo, "sm3") == 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        md = EVP_sm3();
#else
        return -1;
#endif
    } else {
        return -1;
    }

    if (mode == 4) {
        /* 模式4: EVP_BytesToKey (OpenSSL标准密钥派生) */
        int ret = EVP_BytesToKey(
            EVP_sm4_cbc(),      /* cipher */
            md,                 /* hash algorithm */
            salt,               /* salt */
            password,           /* password */
            password_len,       /* password length */
            1,                  /* iteration count (DWS可能用1次) */
            key,                /* output key */
            iv                  /* output iv */
        );
        
        if (ret != 16) {  /* 应该返回密钥长度16 */
            return -1;
        }
        
    } else if (mode == 1) {
        /* 模式1: hash(password + salt) */
        ctx = EVP_MD_CTX_new();
        if (!ctx) {
            return -1;
        }

        if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        
        if (EVP_DigestUpdate(ctx, password, password_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        
        if (EVP_DigestUpdate(ctx, salt, salt_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        
        if (EVP_DigestFinal_ex(ctx, hash_output, &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        
        EVP_MD_CTX_free(ctx);

        /* 从哈希值中提取密钥和IV */
        memcpy(key, hash_output, 16);
        memcpy(iv, hash_output + 16, 16);
        
    } else if (mode == 2) {
        /* 模式2: hash(salt + password) */
        ctx = EVP_MD_CTX_new();
        if (!ctx) {
            return -1;
        }

        if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        
        if (EVP_DigestUpdate(ctx, salt, salt_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        
        if (EVP_DigestUpdate(ctx, password, password_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        
        if (EVP_DigestFinal_ex(ctx, hash_output, &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        
        EVP_MD_CTX_free(ctx);

        memcpy(key, hash_output, 16);
        memcpy(iv, hash_output + 16, 16);
        
    } else if (mode == 3) {
        /* 模式3: 直接使用password作为key，salt作为iv */
        memset(key, 0, 16);
        memset(iv, 0, 16);
        
        if (password_len >= 16) {
            memcpy(key, password, 16);
        } else {
            memcpy(key, password, password_len);
        }
        memcpy(iv, salt, 16);
    }
    
    return 0;
}

/*
 * SM4 CBC模式加密（带密钥派生）
 * 输出格式: salt[16] + ciphertext
 */
int sm4_cbc_encrypt_kdf(
    const uint8_t *password,
    size_t password_len,
    const char *hash_algo,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t *output_len)
{
    uint8_t salt[16];
    uint8_t key[SM4_KEY_SIZE];
    uint8_t iv[SM4_BLOCK_SIZE];
    size_t cipher_len;
    int ret;

    if (!password || !hash_algo || !input || !output || !output_len) {
        return -1;
    }

    /* 生成随机盐值 */
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        return -1;
    }

    /* 派生密钥和IV */
    if (derive_key_and_iv(password, password_len, salt, sizeof(salt),
                          hash_algo, key, iv) != 0) {
        return -1;
    }

    /* 存储盐值到输出缓冲区 */
    memcpy(output, salt, sizeof(salt));

    /* 使用标准CBC加密 */
    ret = sm4_cbc_encrypt(key, iv, input, input_len,
                          output + sizeof(salt), &cipher_len);

    /* 清理敏感数据 */
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    if (ret != 0) {
        return -1;
    }

    *output_len = sizeof(salt) + cipher_len;
    return 0;
}

/*
 * SM4 CBC模式解密（带密钥派生）
 * 输入格式: salt[16] + ciphertext
 */
int sm4_cbc_decrypt_kdf(
    const uint8_t *password,
    size_t password_len,
    const char *hash_algo,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t *output_len)
{
    uint8_t key[SM4_KEY_SIZE];
    uint8_t iv[SM4_BLOCK_SIZE];
    const uint8_t *salt;
    const uint8_t *ciphertext;
    size_t cipher_len;
    int ret;

    if (!password || !hash_algo || !input || !output || !output_len) {
        return -1;
    }

    /* 输入必须至少包含盐值 */
    if (input_len < 16) {
        return -1;
    }

    /* 提取盐值和密文 */
    salt = input;
    ciphertext = input + 16;
    cipher_len = input_len - 16;

    /* 派生密钥和IV */
    if (derive_key_and_iv(password, password_len, salt, 16,
                          hash_algo, key, iv) != 0) {
        return -1;
    }

    /* 使用标准CBC解密 */
    ret = sm4_cbc_decrypt(key, iv, ciphertext, cipher_len,
                          output, output_len);

    /* 清理敏感数据 */
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    return ret;
}

/* Base64 编码表 */
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 解码表 */
static const uint8_t base64_decode_table[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

/* Base64 编码函数 */
static size_t base64_encode_internal(const uint8_t *data, size_t len, char *output)
{
    size_t i, j = 0;
    uint32_t val;

    for (i = 0; i < len; i += 3) {
        val = (uint32_t)data[i] << 16;
        if (i + 1 < len) val |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) val |= (uint32_t)data[i + 2];

        output[j++] = base64_table[(val >> 18) & 0x3F];
        output[j++] = base64_table[(val >> 12) & 0x3F];
        output[j++] = (i + 1 < len) ? base64_table[(val >> 6) & 0x3F] : '=';
        output[j++] = (i + 2 < len) ? base64_table[val & 0x3F] : '=';
    }
    output[j] = '\0';
    return j;
}

/* Base64 解码函数 */
static int base64_decode_internal(const uint8_t *input, size_t len, uint8_t *output, size_t *out_len)
{
    size_t i, j = 0;
    uint32_t val;
    size_t padding = 0;

    if (len % 4 != 0) {
        return -1;
    }

    if (len >= 2 && input[len - 1] == '=') padding++;
    if (len >= 2 && input[len - 2] == '=') padding++;

    *out_len = (len / 4) * 3 - padding;

    for (i = 0; i < len; i += 4) {
        val = 0;
        val |= base64_decode_table[input[i]] << 18;
        val |= base64_decode_table[input[i + 1]] << 12;
        if (input[i + 2] != '=') val |= base64_decode_table[input[i + 2]] << 6;
        if (input[i + 3] != '=') val |= base64_decode_table[input[i + 3]];

        output[j++] = (val >> 16) & 0xFF;
        if (input[i + 2] != '=' && j < *out_len) output[j++] = (val >> 8) & 0xFF;
        if (input[i + 3] != '=' && j < *out_len) output[j++] = val & 0xFF;
    }

    return 0;
}

/*
 * SM4 CBC模式加密（兼容gs_encrypt格式）
 * 输出格式: Base64(version[1] + reserved[7] + salt[16] + ciphertext)
 * DWS格式：在明文前添加48字节随机数据
 */
int sm4_cbc_encrypt_gs_format(
    const uint8_t *password,
    size_t password_len,
    const char *hash_algo,
    const uint8_t *input,
    size_t input_len,
    char *output,
    size_t *output_len)
{
    uint8_t header[8];  /* version(1) + reserved(7) - DWS格式 */
    uint8_t salt[16];
    uint8_t key[SM4_KEY_SIZE];
    uint8_t iv[SM4_BLOCK_SIZE];
    uint8_t *binary_output;
    uint8_t *plaintext_with_random;
    size_t plaintext_total_len;
    size_t cipher_len;
    size_t total_len;
    int ret;
    const size_t RANDOM_PREFIX_LEN = 56;  /* DWS在明文前添加56字节随机数据（第3次测试） */

    if (!password || !hash_algo || !input || !output || !output_len) {
        return -1;
    }

    /* 设置版本号和保留字段（DWS格式：版本03 + 7字节全零） */
    header[0] = 0x03;  /* 版本 3 */
    memset(header + 1, 0, 7);  /* 保留字段全零 */

    /* DWS使用固定盐值（通过逆向工程发现） */
    const uint8_t fixed_salt[16] = {
        0xfc, 0xc2, 0xa7, 0x39, 0x72, 0x4d, 0xb4, 0x09,
        0xa3, 0xf6, 0x0e, 0xab, 0x11, 0xd9, 0xd9, 0xdb
    };
    memcpy(salt, fixed_salt, 16);

    /* 派生密钥和IV - 使用DWS密钥派生方式 */
    if (derive_key_and_iv_dws(password, password_len, salt, sizeof(salt),
                              hash_algo, key, iv) != 0) {
        return -1;
    }

    /* 准备明文：48字节随机数据 + 原始明文 */
    plaintext_total_len = RANDOM_PREFIX_LEN + input_len;
    plaintext_with_random = (uint8_t *)malloc(plaintext_total_len);
    if (!plaintext_with_random) {
        return -1;
    }

    /* 生成48字节随机前缀 */
    if (RAND_bytes(plaintext_with_random, RANDOM_PREFIX_LEN) != 1) {
        free(plaintext_with_random);
        return -1;
    }

    /* 拷贝原始明文 */
    memcpy(plaintext_with_random + RANDOM_PREFIX_LEN, input, input_len);

    /* 分配二进制输出缓冲区: header(8) + salt(16) + ciphertext */
    cipher_len = plaintext_total_len + SM4_BLOCK_SIZE;  /* 最大填充后长度 */
    binary_output = (uint8_t *)malloc(8 + 16 + cipher_len);
    if (!binary_output) {
        free(plaintext_with_random);
        return -1;
    }

    /* 拷贝 header 和 salt */
    memcpy(binary_output, header, 8);
    memcpy(binary_output + 8, salt, 16);

    /* 使用标准CBC加密（包含随机前缀的明文） */
    ret = sm4_cbc_encrypt(key, iv, plaintext_with_random, plaintext_total_len,
                          binary_output + 24, &cipher_len);

    /* 清理敏感数据 */
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    free(plaintext_with_random);

    if (ret != 0) {
        free(binary_output);
        return -1;
    }

    total_len = 24 + cipher_len;  /* header(8) + salt(16) + ciphertext */

    /* Base64编码 */
    *output_len = base64_encode_internal(binary_output, total_len, output);

    free(binary_output);
    return 0;
}

/*
 * SM4 CBC模式解密（兼容gs_encrypt格式）
 * 输入格式: Base64(version[1] + reserved[7] + salt[16] + ciphertext)
 * 注意：DWS格式不在数据中存储哈希算法，需要通过参数指定
 */
int sm4_cbc_decrypt_gs_format(
    const uint8_t *password,
    size_t password_len,
    const char *hash_algo,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t *output_len)
{
    uint8_t *binary_data;
    size_t binary_len;
    uint8_t version;
    const uint8_t *salt;
    const uint8_t *ciphertext;
    size_t cipher_len;
    uint8_t key[SM4_KEY_SIZE];
    uint8_t iv[SM4_BLOCK_SIZE];
    int ret;

    if (!password || !hash_algo || !input || !output || !output_len) {
        return -1;
    }

    /* Base64解码 */
    binary_data = (uint8_t *)malloc(input_len);  /* 分配足够的空间 */
    if (!binary_data) {
        return -1;
    }

    if (base64_decode_internal(input, input_len, binary_data, &binary_len) != 0) {
        free(binary_data);
        return -1;
    }

    /* 检查最小长度: header(8) + salt(16) + 至少一个块(16) */
    if (binary_len < 40) {
        free(binary_data);
        return -1;
    }

    /* 解析 header - DWS格式只检查版本号 */
    version = binary_data[0];

    /* 验证版本号 */
    if (version != 0x03) {
        free(binary_data);
        return -1;  /* 不支持的版本 */
    }

    /* 提取盐值和密文 */
    salt = binary_data + 8;
    ciphertext = binary_data + 24;
    cipher_len = binary_len - 24;

    /* 派生密钥和IV - 使用DWS密钥派生方式 */
    if (derive_key_and_iv_dws(password, password_len, salt, 16,
                              hash_algo, key, iv) != 0) {
        free(binary_data);
        return -1;
    }
    
    /* 分配临时缓冲区用于解密（包含随机前缀） */
    uint8_t *decrypted_with_random = (uint8_t *)malloc(cipher_len);
    size_t decrypted_len;
    const size_t RANDOM_PREFIX_LEN = 56;  /* DWS在明文前添加56字节随机数据（第3次测试） */
        
    if (!decrypted_with_random) {
        free(binary_data);
        return -1;
    }
    
    /* 使用标准CBC解密 */
    ret = sm4_cbc_decrypt(key, iv, ciphertext, cipher_len,
                          decrypted_with_random, &decrypted_len);
    
    /* 清理敏感数据 */
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    free(binary_data);
    
    if (ret != 0) {
        free(decrypted_with_random);
        return ret;
    }
    
    /* 检查解密后的数据长度是否足够 */
    if (decrypted_len < RANDOM_PREFIX_LEN) {
        free(decrypted_with_random);
        return -1;  /* 数据太短，不符合DWS格式 */
    }
    
    /* 移除前48字节随机数据，提取原始明文 */
    *output_len = decrypted_len - RANDOM_PREFIX_LEN;
    memcpy(output, decrypted_with_random + RANDOM_PREFIX_LEN, *output_len);
    
    free(decrypted_with_random);
    return 0;
}
#endif /* USE_OPENSSL_KDF */
