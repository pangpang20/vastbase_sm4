/*
 * SM4 Algorithm Implementation
 * 国密SM4分组密码算法实现
 * 
 * 基于GB/T 32907-2016标准实现
 */

#include "sm4.h"
#include <string.h>
#include <stdlib.h>

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
