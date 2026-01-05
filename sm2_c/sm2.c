/*
 * SM2 Algorithm Implementation
 * 国密SM2椭圆曲线公钥密码算法实现
 * 
 * 基于GB/T 32918-2016标准实现
 */

#include "sm2.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/*
 * SM2曲线参数 (sm2p256v1)
 * 基于GB/T 32918.5-2017
 */

/* 素数p */
static const uint8_t SM2_P[32] = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* 曲线参数a */
static const uint8_t SM2_A[32] = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

/* 曲线参数b */
static const uint8_t SM2_B[32] = {
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
    0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
    0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93
};

/* 曲线阶n */
static const uint8_t SM2_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
    0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23
};

/* 基点G的x坐标 */
static const uint8_t SM2_GX[32] = {
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
    0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
    0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
};

/* 基点G的y坐标 */
static const uint8_t SM2_GY[32] = {
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
    0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
    0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
};

/* 全局变量: 曲线参数 */
static sm2_bn SM2_P_BN, SM2_A_BN, SM2_B_BN, SM2_N_BN;
static sm2_point SM2_G;
static int sm2_params_initialized = 0;

/* 默认用户标识 */
static const uint8_t SM2_DEFAULT_ID[] = "1234567812345678";
static const size_t SM2_DEFAULT_ID_LEN = 16;

/*
 * ============== SM3哈希算法实现 ==============
 */

/* SM3初始值 */
static const uint32_t SM3_IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

/* SM3常量T */
#define SM3_T(j) ((j) < 16 ? 0x79cc4519 : 0x7a879d8a)

/* 循环左移 */
#define SM3_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* 布尔函数FF */
#define SM3_FF(x, y, z, j) ((j) < 16 ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | ((x) & (z)) | ((y) & (z))))

/* 布尔函数GG */
#define SM3_GG(x, y, z, j) ((j) < 16 ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | ((~(x)) & (z))))

/* P0置换 */
#define SM3_P0(x) ((x) ^ SM3_ROTL((x), 9) ^ SM3_ROTL((x), 17))

/* P1置换 */
#define SM3_P1(x) ((x) ^ SM3_ROTL((x), 15) ^ SM3_ROTL((x), 23))

/* 大端序读取32位整数 */
static uint32_t sm3_load_u32_be(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | ((uint32_t)b[3]);
}

/* 大端序存储32位整数 */
static void sm3_store_u32_be(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

/* SM3压缩函数 */
static void sm3_compress(sm3_context *ctx, const uint8_t *block)
{
    uint32_t W[68], W_prime[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    /* 消息扩展 */
    for (j = 0; j < 16; j++) {
        W[j] = sm3_load_u32_be(block + j * 4);
    }
    for (j = 16; j < 68; j++) {
        W[j] = SM3_P1(W[j-16] ^ W[j-9] ^ SM3_ROTL(W[j-3], 15)) ^
               SM3_ROTL(W[j-13], 7) ^ W[j-6];
    }
    for (j = 0; j < 64; j++) {
        W_prime[j] = W[j] ^ W[j+4];
    }

    /* 压缩函数 */
    A = ctx->state[0]; B = ctx->state[1];
    C = ctx->state[2]; D = ctx->state[3];
    E = ctx->state[4]; F = ctx->state[5];
    G = ctx->state[6]; H = ctx->state[7];

    for (j = 0; j < 64; j++) {
        SS1 = SM3_ROTL(SM3_ROTL(A, 12) + E + SM3_ROTL(SM3_T(j), j % 32), 7);
        SS2 = SS1 ^ SM3_ROTL(A, 12);
        TT1 = SM3_FF(A, B, C, j) + D + SS2 + W_prime[j];
        TT2 = SM3_GG(E, F, G, j) + H + SS1 + W[j];
        D = C;
        C = SM3_ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = SM3_ROTL(F, 19);
        F = E;
        E = SM3_P0(TT2);
    }

    ctx->state[0] ^= A; ctx->state[1] ^= B;
    ctx->state[2] ^= C; ctx->state[3] ^= D;
    ctx->state[4] ^= E; ctx->state[5] ^= F;
    ctx->state[6] ^= G; ctx->state[7] ^= H;
}

void sm3_init(sm3_context *ctx)
{
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
    ctx->total = 0;
}

void sm3_update(sm3_context *ctx, const uint8_t *data, size_t len)
{
    size_t fill, left;

    if (len == 0) return;

    left = ctx->total & 0x3F;
    fill = 64 - left;
    ctx->total += len;

    if (left && len >= fill) {
        memcpy(ctx->buffer + left, data, fill);
        sm3_compress(ctx, ctx->buffer);
        data += fill;
        len -= fill;
        left = 0;
    }

    while (len >= 64) {
        sm3_compress(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer + left, data, len);
    }
}

void sm3_final(sm3_context *ctx, uint8_t *digest)
{
    uint8_t padding[64];
    uint64_t bits = ctx->total * 8;
    size_t pad_len = (ctx->total & 0x3F) < 56 ? 56 - (ctx->total & 0x3F) : 120 - (ctx->total & 0x3F);
    int i;

    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;

    sm3_update(ctx, padding, pad_len);

    /* 追加长度 */
    for (i = 0; i < 8; i++) {
        padding[i] = (uint8_t)(bits >> (56 - i * 8));
    }
    sm3_update(ctx, padding, 8);

    /* 输出哈希值 */
    for (i = 0; i < 8; i++) {
        sm3_store_u32_be(digest + i * 4, ctx->state[i]);
    }
}

void sm3_hash(const uint8_t *data, size_t len, uint8_t *digest)
{
    sm3_context ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

/*
 * ============== 大整数运算 ==============
 */

void sm2_bn_from_bytes(sm2_bn *bn, const uint8_t *bytes)
{
    int i;
    for (i = 0; i < 8; i++) {
        bn->d[7-i] = ((uint32_t)bytes[i*4] << 24) |
                     ((uint32_t)bytes[i*4+1] << 16) |
                     ((uint32_t)bytes[i*4+2] << 8) |
                     ((uint32_t)bytes[i*4+3]);
    }
}

void sm2_bn_to_bytes(const sm2_bn *bn, uint8_t *bytes)
{
    int i;
    for (i = 0; i < 8; i++) {
        bytes[i*4] = (uint8_t)(bn->d[7-i] >> 24);
        bytes[i*4+1] = (uint8_t)(bn->d[7-i] >> 16);
        bytes[i*4+2] = (uint8_t)(bn->d[7-i] >> 8);
        bytes[i*4+3] = (uint8_t)(bn->d[7-i]);
    }
}

int sm2_bn_is_zero(const sm2_bn *a)
{
    int i;
    for (i = 0; i < 8; i++) {
        if (a->d[i] != 0) return 0;
    }
    return 1;
}

int sm2_bn_cmp(const sm2_bn *a, const sm2_bn *b)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return 1;
        if (a->d[i] < b->d[i]) return -1;
    }
    return 0;
}

/* 大整数加法: r = a + b, 返回进位 */
static uint32_t sm2_bn_add(sm2_bn *r, const sm2_bn *a, const sm2_bn *b)
{
    uint64_t carry = 0;
    int i;
    for (i = 0; i < 8; i++) {
        carry += (uint64_t)a->d[i] + (uint64_t)b->d[i];
        r->d[i] = (uint32_t)carry;
        carry >>= 32;
    }
    return (uint32_t)carry;
}

/* 大整数减法: r = a - b, 返回借位 */
static uint32_t sm2_bn_sub(sm2_bn *r, const sm2_bn *a, const sm2_bn *b)
{
    int64_t borrow = 0;
    int i;
    for (i = 0; i < 8; i++) {
        borrow = (int64_t)a->d[i] - (int64_t)b->d[i] - borrow;
        r->d[i] = (uint32_t)borrow;
        borrow = (borrow < 0) ? 1 : 0;
    }
    return (uint32_t)borrow;
}

void sm2_bn_mod_add(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *n)
{
    uint32_t carry;
    carry = sm2_bn_add(r, a, b);
    if (carry || sm2_bn_cmp(r, n) >= 0) {
        sm2_bn_sub(r, r, n);
    }
}

void sm2_bn_mod_sub(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *n)
{
    uint32_t borrow;
    borrow = sm2_bn_sub(r, a, b);
    if (borrow) {
        sm2_bn_add(r, r, n);
    }
}

/* 512位乘法结果 */
typedef struct {
    uint32_t d[16];
} sm2_bn512;

/* 大整数乘法: r = a * b (512位结果) */
static void sm2_bn_mul(sm2_bn512 *r, const sm2_bn *a, const sm2_bn *b)
{
    int i, j;
    uint64_t carry;

    memset(r, 0, sizeof(sm2_bn512));

    for (i = 0; i < 8; i++) {
        carry = 0;
        for (j = 0; j < 8; j++) {
            carry += (uint64_t)r->d[i+j] + (uint64_t)a->d[i] * (uint64_t)b->d[j];
            r->d[i+j] = (uint32_t)carry;
            carry >>= 32;
        }
        r->d[i+8] = (uint32_t)carry;
    }
}

/*
 * SM2快速约减算法
 * SM2素数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 * 
 * 对于 512位数 A = A15*2^480 + A14*2^448 + ... + A1*2^32 + A0
 * 使用特定的约减公式
 */
static void sm2_bn_mod_p(sm2_bn *r, const sm2_bn512 *a)
{
    int64_t carry;
    uint64_t t[8];
    int i;
    
    /* 复制低256位 */
    for (i = 0; i < 8; i++) {
        t[i] = a->d[i];
    }
    
    /* 
     * SM2约减: 利用 p 的特殊结构
     * 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
     */
    
    /* 处理 a[8..15] */
    /* s1 = (a15, a14, a13, a12, a11, 0, a9, a8) */
    t[0] += a->d[8];
    t[1] += a->d[9];
    /* t[2] += 0 */
    t[3] += a->d[11];
    t[4] += a->d[12];
    t[5] += a->d[13];
    t[6] += a->d[14];
    t[7] += a->d[15];
    
    /* s2 = (0, a15, a14, a13, a12, 0, a10, a9) */
    t[0] += a->d[9];
    t[1] += a->d[10];
    /* t[2] += 0 */
    t[3] += a->d[12];
    t[4] += a->d[13];
    t[5] += a->d[14];
    t[6] += a->d[15];
    /* t[7] += 0 */
    
    /* s3 = (a15, a14, 0, 0, 0, a10, a9, a8) */
    t[0] += a->d[8];
    t[1] += a->d[9];
    t[2] += a->d[10];
    /* t[3..4] += 0 */
    /* t[5] += 0 */
    t[6] += a->d[14];
    t[7] += a->d[15];
    
    /* s4 = (a8, a13, a15, a14, a13, a11, a10, a9) */
    t[0] += a->d[9];
    t[1] += a->d[10];
    t[2] += a->d[11];
    t[3] += a->d[13];
    t[4] += a->d[14];
    t[5] += a->d[15];
    t[6] += a->d[13];
    t[7] += a->d[8];
    
    /* s5 = (a10, a8, 0, 0, 0, a13, a12, a11) * 2 */
    t[0] += (uint64_t)a->d[11] * 2;
    t[1] += (uint64_t)a->d[12] * 2;
    t[2] += (uint64_t)a->d[13] * 2;
    /* t[3..5] += 0 */
    t[6] += (uint64_t)a->d[8] * 2;
    t[7] += (uint64_t)a->d[10] * 2;
    
    /* d1 = (a11, a9, 0, 0, a15, a14, a13, a12) */
    t[0] -= a->d[12];
    t[1] -= a->d[13];
    t[2] -= a->d[14];
    t[3] -= a->d[15];
    /* t[4..5] -= 0 */
    t[6] -= a->d[9];
    t[7] -= a->d[11];
    
    /* d2 = (a12, 0, a10, a9, a8, a15, a14, a13) */
    t[0] -= a->d[13];
    t[1] -= a->d[14];
    t[2] -= a->d[15];
    t[3] -= a->d[8];
    t[4] -= a->d[9];
    t[5] -= a->d[10];
    /* t[6] -= 0 */
    t[7] -= a->d[12];
    
    /* d3 = (a13, 0, a11, a10, a9, 0, a15, a14) */
    t[0] -= a->d[14];
    t[1] -= a->d[15];
    /* t[2] -= 0 */
    t[3] -= a->d[9];
    t[4] -= a->d[10];
    t[5] -= a->d[11];
    /* t[6] -= 0 */
    t[7] -= a->d[13];
    
    /* d4 = (a14, 0, a12, a11, a10, 0, 0, a15) */
    t[0] -= a->d[15];
    /* t[1..2] -= 0 */
    t[3] -= a->d[10];
    t[4] -= a->d[11];
    t[5] -= a->d[12];
    /* t[6] -= 0 */
    t[7] -= a->d[14];
    
    /* 进位传播 */
    carry = 0;
    for (i = 0; i < 8; i++) {
        carry += (int64_t)t[i];
        r->d[i] = (uint32_t)(carry & 0xFFFFFFFF);
        carry >>= 32;
    }
    
    /* 处理可能的溢出或下溢 */
    while (carry > 0) {
        sm2_bn_sub(r, r, &SM2_P_BN);
        carry--;
    }
    while (carry < 0 || sm2_bn_cmp(r, &SM2_P_BN) >= 0) {
        if (carry < 0) {
            sm2_bn_add(r, r, &SM2_P_BN);
            carry++;
        } else {
            sm2_bn_sub(r, r, &SM2_P_BN);
        }
    }
}

/* 通用模约减（用于模n运算） */
static void sm2_bn_mod(sm2_bn *r, const sm2_bn512 *a, const sm2_bn *n)
{
    /* 使用移位和减法的方式进行约减 */
    sm2_bn q, temp;
    sm2_bn512 qn;
    int i;
    int cmp;
    
    /* 复制低256位到结果 */
    for (i = 0; i < 8; i++) {
        r->d[i] = a->d[i];
    }
    
    /* 复制高256位作为商的估计 */
    for (i = 0; i < 8; i++) {
        q.d[i] = a->d[i + 8];
    }
    
    /* 如果高位为0，只需简单约减 */
    if (sm2_bn_is_zero(&q)) {
        while (sm2_bn_cmp(r, n) >= 0) {
            sm2_bn_sub(r, r, n);
        }
        return;
    }
    
    /* q * n */
    sm2_bn_mul(&qn, &q, n);
    
    /* 从qn中减去低256位 */
    /* r = a - q*n 的低256位 */
    {
        int64_t borrow = 0;
        for (i = 0; i < 8; i++) {
            borrow = (int64_t)r->d[i] - (int64_t)qn.d[i] - borrow;
            r->d[i] = (uint32_t)(borrow & 0xFFFFFFFF);
            borrow = (borrow < 0) ? 1 : 0;
        }
        
        /* 处理高位借位 */
        for (i = 8; i < 16; i++) {
            borrow = (int64_t)a->d[i] - (int64_t)qn.d[i] - borrow;
            temp.d[i-8] = (uint32_t)(borrow & 0xFFFFFFFF);
            borrow = (borrow < 0) ? 1 : 0;
        }
        
        /* 如果高位不为零，需要调整 */
        while (!sm2_bn_is_zero(&temp)) {
            sm2_bn_add(r, r, n);
            /* 减少temp */
            int64_t borrow2 = 1;
            for (i = 0; i < 8; i++) {
                borrow2 = (int64_t)temp.d[i] - borrow2;
                temp.d[i] = (uint32_t)(borrow2 & 0xFFFFFFFF);
                borrow2 = (borrow2 < 0) ? 1 : 0;
                if (!borrow2) break;
            }
        }
    }
    
    /* 最终约减 */
    while (sm2_bn_cmp(r, n) >= 0) {
        sm2_bn_sub(r, r, n);
    }
}

/* 模p乘法（使用快速约减） */
void sm2_bn_mod_mul_p(sm2_bn *r, const sm2_bn *a, const sm2_bn *b)
{
    sm2_bn512 product;
    sm2_bn_mul(&product, a, b);
    sm2_bn_mod_p(r, &product);
}

/* 通用模乘法 */
void sm2_bn_mod_mul(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *n)
{
    sm2_bn512 product;
    sm2_bn_mul(&product, a, b);
    /* 判断是否为模p运算 */
    if (sm2_bn_cmp(n, &SM2_P_BN) == 0) {
        sm2_bn_mod_p(r, &product);
    } else {
        sm2_bn_mod(r, &product, n);
    }
}

/* 扩展欧几里得算法求模逆 */
int sm2_bn_mod_inv(sm2_bn *r, const sm2_bn *a, const sm2_bn *n)
{
    sm2_bn u, v, x1, x2;
    int k;

    if (sm2_bn_is_zero(a)) {
        return -1;
    }

    /* u = a, v = n */
    memcpy(&u, a, sizeof(sm2_bn));
    memcpy(&v, n, sizeof(sm2_bn));

    /* x1 = 1, x2 = 0 */
    memset(&x1, 0, sizeof(sm2_bn));
    x1.d[0] = 1;
    memset(&x2, 0, sizeof(sm2_bn));

    while (!sm2_bn_is_zero(&u) && !sm2_bn_is_zero(&v)) {
        while ((u.d[0] & 1) == 0) {
            /* u = u / 2 */
            for (k = 0; k < 7; k++) {
                u.d[k] = (u.d[k] >> 1) | (u.d[k+1] << 31);
            }
            u.d[7] >>= 1;

            if (x1.d[0] & 1) {
                sm2_bn_add(&x1, &x1, n);
            }
            /* x1 = x1 / 2 */
            for (k = 0; k < 7; k++) {
                x1.d[k] = (x1.d[k] >> 1) | (x1.d[k+1] << 31);
            }
            x1.d[7] >>= 1;
        }

        while ((v.d[0] & 1) == 0) {
            /* v = v / 2 */
            for (k = 0; k < 7; k++) {
                v.d[k] = (v.d[k] >> 1) | (v.d[k+1] << 31);
            }
            v.d[7] >>= 1;

            if (x2.d[0] & 1) {
                sm2_bn_add(&x2, &x2, n);
            }
            /* x2 = x2 / 2 */
            for (k = 0; k < 7; k++) {
                x2.d[k] = (x2.d[k] >> 1) | (x2.d[k+1] << 31);
            }
            x2.d[7] >>= 1;
        }

        if (sm2_bn_cmp(&u, &v) >= 0) {
            sm2_bn_sub(&u, &u, &v);
            sm2_bn_mod_sub(&x1, &x1, &x2, n);
        } else {
            sm2_bn_sub(&v, &v, &u);
            sm2_bn_mod_sub(&x2, &x2, &x1, n);
        }
    }

    if (!sm2_bn_is_zero(&u)) {
        /* u = 1 */
        if (u.d[0] == 1) {
            int zero = 1;
            for (k = 1; k < 8; k++) {
                if (u.d[k] != 0) { zero = 0; break; }
            }
            if (zero) {
                memcpy(r, &x1, sizeof(sm2_bn));
                return 0;
            }
        }
    } else {
        /* v = 1 */
        if (v.d[0] == 1) {
            int zero = 1;
            for (k = 1; k < 8; k++) {
                if (v.d[k] != 0) { zero = 0; break; }
            }
            if (zero) {
                memcpy(r, &x2, sizeof(sm2_bn));
                return 0;
            }
        }
    }

    return -1; /* 不存在逆元 */
}

/*
 * ============== 椭圆曲线运算 ==============
 */

/* 初始化SM2曲线参数 */
static void sm2_init_params(void)
{
    if (sm2_params_initialized) return;

    sm2_bn_from_bytes(&SM2_P_BN, SM2_P);
    sm2_bn_from_bytes(&SM2_A_BN, SM2_A);
    sm2_bn_from_bytes(&SM2_B_BN, SM2_B);
    sm2_bn_from_bytes(&SM2_N_BN, SM2_N);

    sm2_bn_from_bytes(&SM2_G.x, SM2_GX);
    sm2_bn_from_bytes(&SM2_G.y, SM2_GY);
    SM2_G.infinity = 0;

    sm2_params_initialized = 1;
}

void sm2_point_double(sm2_point *r, const sm2_point *p)
{
    sm2_bn lambda, t1, t2, t3;

    sm2_init_params();

    if (p->infinity || sm2_bn_is_zero(&p->y)) {
        r->infinity = 1;
        return;
    }

    /* lambda = (3*x^2 + a) / (2*y) mod p */
    
    /* t1 = x^2 */
    sm2_bn_mod_mul(&t1, &p->x, &p->x, &SM2_P_BN);
    
    /* t2 = 3*x^2 */
    sm2_bn_mod_add(&t2, &t1, &t1, &SM2_P_BN);
    sm2_bn_mod_add(&t2, &t2, &t1, &SM2_P_BN);
    
    /* t2 = 3*x^2 + a */
    sm2_bn_mod_add(&t2, &t2, &SM2_A_BN, &SM2_P_BN);
    
    /* t3 = 2*y */
    sm2_bn_mod_add(&t3, &p->y, &p->y, &SM2_P_BN);
    
    /* t3 = (2*y)^(-1) */
    if (sm2_bn_mod_inv(&t3, &t3, &SM2_P_BN) != 0) {
        r->infinity = 1;
        return;
    }
    
    /* lambda = t2 * t3 */
    sm2_bn_mod_mul(&lambda, &t2, &t3, &SM2_P_BN);

    /* x' = lambda^2 - 2*x */
    sm2_bn_mod_mul(&t1, &lambda, &lambda, &SM2_P_BN);
    sm2_bn_mod_sub(&t1, &t1, &p->x, &SM2_P_BN);
    sm2_bn_mod_sub(&r->x, &t1, &p->x, &SM2_P_BN);

    /* y' = lambda*(x - x') - y */
    sm2_bn_mod_sub(&t2, &p->x, &r->x, &SM2_P_BN);
    sm2_bn_mod_mul(&t2, &lambda, &t2, &SM2_P_BN);
    sm2_bn_mod_sub(&r->y, &t2, &p->y, &SM2_P_BN);

    r->infinity = 0;
}

void sm2_point_add(sm2_point *r, const sm2_point *p, const sm2_point *q)
{
    sm2_bn lambda, t1, t2;

    sm2_init_params();

    if (p->infinity) {
        memcpy(r, q, sizeof(sm2_point));
        return;
    }
    if (q->infinity) {
        memcpy(r, p, sizeof(sm2_point));
        return;
    }

    /* 检查是否为相同点 */
    if (sm2_bn_cmp(&p->x, &q->x) == 0) {
        if (sm2_bn_cmp(&p->y, &q->y) == 0) {
            sm2_point_double(r, p);
            return;
        } else {
            /* P + (-P) = O */
            r->infinity = 1;
            return;
        }
    }

    /* lambda = (y2 - y1) / (x2 - x1) mod p */
    sm2_bn_mod_sub(&t1, &q->y, &p->y, &SM2_P_BN);
    sm2_bn_mod_sub(&t2, &q->x, &p->x, &SM2_P_BN);
    
    if (sm2_bn_mod_inv(&t2, &t2, &SM2_P_BN) != 0) {
        r->infinity = 1;
        return;
    }
    
    sm2_bn_mod_mul(&lambda, &t1, &t2, &SM2_P_BN);

    /* x' = lambda^2 - x1 - x2 */
    sm2_bn_mod_mul(&t1, &lambda, &lambda, &SM2_P_BN);
    sm2_bn_mod_sub(&t1, &t1, &p->x, &SM2_P_BN);
    sm2_bn_mod_sub(&r->x, &t1, &q->x, &SM2_P_BN);

    /* y' = lambda*(x1 - x') - y1 */
    sm2_bn_mod_sub(&t2, &p->x, &r->x, &SM2_P_BN);
    sm2_bn_mod_mul(&t2, &lambda, &t2, &SM2_P_BN);
    sm2_bn_mod_sub(&r->y, &t2, &p->y, &SM2_P_BN);

    r->infinity = 0;
}

void sm2_point_mul(sm2_point *r, const sm2_bn *k, const sm2_point *p)
{
    sm2_point R, Q;
    int i, j;
    uint32_t bit;

    sm2_init_params();

    R.infinity = 1;
    memcpy(&Q, p, sizeof(sm2_point));

    /* 从低位到高位的双倍-加法算法 */
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 32; j++) {
            bit = (k->d[i] >> j) & 1;
            if (bit) {
                sm2_point_add(&R, &R, &Q);
            }
            sm2_point_double(&Q, &Q);
        }
    }

    memcpy(r, &R, sizeof(sm2_point));
}

int sm2_point_is_on_curve(const sm2_point *p)
{
    sm2_bn left, right, t1, t2;

    sm2_init_params();

    if (p->infinity) return 1;

    /* y^2 = x^3 + ax + b mod p */
    
    /* left = y^2 */
    sm2_bn_mod_mul(&left, &p->y, &p->y, &SM2_P_BN);
    
    /* t1 = x^2 */
    sm2_bn_mod_mul(&t1, &p->x, &p->x, &SM2_P_BN);
    
    /* t2 = x^3 */
    sm2_bn_mod_mul(&t2, &t1, &p->x, &SM2_P_BN);
    
    /* t1 = ax */
    sm2_bn_mod_mul(&t1, &SM2_A_BN, &p->x, &SM2_P_BN);
    
    /* right = x^3 + ax */
    sm2_bn_mod_add(&right, &t2, &t1, &SM2_P_BN);
    
    /* right = x^3 + ax + b */
    sm2_bn_mod_add(&right, &right, &SM2_B_BN, &SM2_P_BN);

    return sm2_bn_cmp(&left, &right) == 0;
}

int sm2_point_from_bytes(sm2_point *p, const uint8_t *bytes, size_t len)
{
    if (len == 65 && bytes[0] == 0x04) {
        /* 非压缩格式: 04 || X || Y */
        sm2_bn_from_bytes(&p->x, bytes + 1);
        sm2_bn_from_bytes(&p->y, bytes + 33);
        p->infinity = 0;
        return sm2_point_is_on_curve(p) ? 0 : -1;
    } else if (len == 64) {
        /* 64字节格式: X || Y */
        sm2_bn_from_bytes(&p->x, bytes);
        sm2_bn_from_bytes(&p->y, bytes + 32);
        p->infinity = 0;
        return sm2_point_is_on_curve(p) ? 0 : -1;
    }
    return -1;
}

void sm2_point_to_bytes(const sm2_point *p, uint8_t *bytes)
{
    bytes[0] = 0x04;
    sm2_bn_to_bytes(&p->x, bytes + 1);
    sm2_bn_to_bytes(&p->y, bytes + 33);
}

/*
 * ============== SM2密钥操作 ==============
 */

void sm2_init(sm2_context *ctx)
{
    memset(ctx, 0, sizeof(sm2_context));
    sm2_init_params();
}

/* 简单的随机数生成 */
int sm2_random_bytes(uint8_t *buf, size_t len)
{
    size_t i;
    static int seeded = 0;
    
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0;
}

int sm2_generate_keypair(sm2_context *ctx)
{
    uint8_t rand_bytes[32];
    int attempts = 0;

    sm2_init_params();

    /* 生成随机私钥 d ∈ [1, n-2] */
    do {
        if (attempts++ > 100) return -1;
        
        sm2_random_bytes(rand_bytes, 32);
        sm2_bn_from_bytes(&ctx->private_key, rand_bytes);
        
    } while (sm2_bn_is_zero(&ctx->private_key) || 
             sm2_bn_cmp(&ctx->private_key, &SM2_N_BN) >= 0);

    ctx->has_private_key = 1;

    /* 计算公钥 P = [d]G */
    sm2_point_mul(&ctx->public_key, &ctx->private_key, &SM2_G);
    ctx->has_public_key = 1;

    return 0;
}

int sm2_derive_public_key(sm2_context *ctx)
{
    if (!ctx->has_private_key) return -1;

    sm2_init_params();
    sm2_point_mul(&ctx->public_key, &ctx->private_key, &SM2_G);
    ctx->has_public_key = 1;

    return 0;
}

int sm2_set_private_key(sm2_context *ctx, const uint8_t *key)
{
    sm2_init_params();
    sm2_bn_from_bytes(&ctx->private_key, key);

    /* 验证私钥范围 */
    if (sm2_bn_is_zero(&ctx->private_key) || 
        sm2_bn_cmp(&ctx->private_key, &SM2_N_BN) >= 0) {
        return -1;
    }

    ctx->has_private_key = 1;
    return 0;
}

int sm2_set_public_key(sm2_context *ctx, const uint8_t *key, size_t len)
{
    sm2_init_params();
    
    if (sm2_point_from_bytes(&ctx->public_key, key, len) != 0) {
        return -1;
    }

    ctx->has_public_key = 1;
    return 0;
}

int sm2_get_private_key(const sm2_context *ctx, uint8_t *key)
{
    if (!ctx->has_private_key) return -1;
    sm2_bn_to_bytes(&ctx->private_key, key);
    return 0;
}

int sm2_get_public_key(const sm2_context *ctx, uint8_t *key)
{
    if (!ctx->has_public_key) return -1;
    sm2_bn_to_bytes(&ctx->public_key.x, key);
    sm2_bn_to_bytes(&ctx->public_key.y, key + 32);
    return 0;
}

/*
 * ============== KDF密钥派生 ==============
 */

void sm2_kdf(const uint8_t *z, size_t z_len, size_t klen, uint8_t *key)
{
    uint32_t ct = 1;
    size_t offset = 0;
    size_t hash_len;
    uint8_t *buf;
    uint8_t hash[32];
    uint8_t ct_bytes[4];

    buf = (uint8_t *)malloc(z_len + 4);
    if (!buf) return;

    memcpy(buf, z, z_len);

    while (offset < klen) {
        ct_bytes[0] = (uint8_t)(ct >> 24);
        ct_bytes[1] = (uint8_t)(ct >> 16);
        ct_bytes[2] = (uint8_t)(ct >> 8);
        ct_bytes[3] = (uint8_t)(ct);
        memcpy(buf + z_len, ct_bytes, 4);

        sm3_hash(buf, z_len + 4, hash);

        hash_len = (klen - offset < 32) ? (klen - offset) : 32;
        memcpy(key + offset, hash, hash_len);
        offset += hash_len;
        ct++;
    }

    free(buf);
}

/*
 * ============== SM2加密 ==============
 */

int sm2_encrypt(const uint8_t *pub_key,
                const uint8_t *input, size_t input_len,
                uint8_t *output, size_t *output_len)
{
    sm2_point P, C1_point, kP;
    sm2_bn k;
    uint8_t rand_bytes[32];
    uint8_t x2y2[64];
    uint8_t *kdf_key;
    uint8_t hash_input[32 + 256 + 32];  /* x2 + M + y2 最大 */
    size_t hash_input_len;
    int i, attempts = 0;
    int all_zero;

    sm2_init_params();

    /* 加载公钥 */
    if (sm2_point_from_bytes(&P, pub_key, 64) != 0) {
        return -1;
    }

    /* 生成随机数k */
    do {
        if (attempts++ > 100) return -1;
        
        sm2_random_bytes(rand_bytes, 32);
        sm2_bn_from_bytes(&k, rand_bytes);
        
    } while (sm2_bn_is_zero(&k) || sm2_bn_cmp(&k, &SM2_N_BN) >= 0);

    /* C1 = [k]G */
    sm2_point_mul(&C1_point, &k, &SM2_G);

    /* [k]PB = (x2, y2) */
    sm2_point_mul(&kP, &k, &P);
    sm2_bn_to_bytes(&kP.x, x2y2);
    sm2_bn_to_bytes(&kP.y, x2y2 + 32);

    /* t = KDF(x2 || y2, klen) */
    kdf_key = (uint8_t *)malloc(input_len);
    if (!kdf_key) return -1;
    
    sm2_kdf(x2y2, 64, input_len, kdf_key);

    /* 检查t是否全0 */
    all_zero = 1;
    for (i = 0; i < (int)input_len; i++) {
        if (kdf_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        free(kdf_key);
        return -1;
    }

    /* 输出C1 (65字节) */
    sm2_point_to_bytes(&C1_point, output);

    /* C3 = SM3(x2 || M || y2) */
    hash_input_len = 0;
    memcpy(hash_input, x2y2, 32);  /* x2 */
    hash_input_len += 32;
    memcpy(hash_input + hash_input_len, input, input_len);  /* M */
    hash_input_len += input_len;
    memcpy(hash_input + hash_input_len, x2y2 + 32, 32);  /* y2 */
    hash_input_len += 32;
    
    sm3_hash(hash_input, hash_input_len, output + 65);

    /* C2 = M xor t */
    for (i = 0; i < (int)input_len; i++) {
        output[65 + 32 + i] = input[i] ^ kdf_key[i];
    }

    *output_len = 65 + 32 + input_len;

    free(kdf_key);
    return 0;
}

/*
 * ============== SM2解密 ==============
 */

int sm2_decrypt(const uint8_t *priv_key,
                const uint8_t *input, size_t input_len,
                uint8_t *output, size_t *output_len)
{
    sm2_point C1, dC1;
    sm2_bn d;
    uint8_t x2y2[64];
    uint8_t *kdf_key;
    uint8_t computed_c3[32];
    uint8_t hash_input[32 + 256 + 32];
    size_t hash_input_len;
    size_t c2_len;
    const uint8_t *c3;
    const uint8_t *c2;
    int i, all_zero;

    sm2_init_params();

    /* 密文格式: C1(65字节) || C3(32字节) || C2(明文长度) */
    if (input_len < 65 + 32 + 1) {
        return -1;
    }

    c2_len = input_len - 65 - 32;
    c3 = input + 65;
    c2 = input + 65 + 32;

    /* 解析C1 */
    if (sm2_point_from_bytes(&C1, input, 65) != 0) {
        return -1;
    }

    /* 加载私钥 */
    sm2_bn_from_bytes(&d, priv_key);

    /* [d]C1 = (x2, y2) */
    sm2_point_mul(&dC1, &d, &C1);
    sm2_bn_to_bytes(&dC1.x, x2y2);
    sm2_bn_to_bytes(&dC1.y, x2y2 + 32);

    /* t = KDF(x2 || y2, klen) */
    kdf_key = (uint8_t *)malloc(c2_len);
    if (!kdf_key) return -1;
    
    sm2_kdf(x2y2, 64, c2_len, kdf_key);

    /* 检查t是否全0 */
    all_zero = 1;
    for (i = 0; i < (int)c2_len; i++) {
        if (kdf_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        free(kdf_key);
        return -1;
    }

    /* M = C2 xor t */
    for (i = 0; i < (int)c2_len; i++) {
        output[i] = c2[i] ^ kdf_key[i];
    }

    /* 验证 C3 = SM3(x2 || M || y2) */
    hash_input_len = 0;
    memcpy(hash_input, x2y2, 32);  /* x2 */
    hash_input_len += 32;
    memcpy(hash_input + hash_input_len, output, c2_len);  /* M */
    hash_input_len += c2_len;
    memcpy(hash_input + hash_input_len, x2y2 + 32, 32);  /* y2 */
    hash_input_len += 32;
    
    sm3_hash(hash_input, hash_input_len, computed_c3);

    if (memcmp(computed_c3, c3, 32) != 0) {
        free(kdf_key);
        return -1;
    }

    *output_len = c2_len;

    free(kdf_key);
    return 0;
}

/*
 * ============== SM2签名 ==============
 */

int sm2_compute_z(const uint8_t *pub_key,
                  const uint8_t *id, size_t id_len,
                  uint8_t *z)
{
    sm3_context ctx;
    uint8_t entla[2];
    uint16_t id_bits;

    sm2_init_params();

    if (!id) {
        id = SM2_DEFAULT_ID;
        id_len = SM2_DEFAULT_ID_LEN;
    }

    id_bits = (uint16_t)(id_len * 8);
    entla[0] = (uint8_t)(id_bits >> 8);
    entla[1] = (uint8_t)(id_bits);

    sm3_init(&ctx);
    sm3_update(&ctx, entla, 2);
    sm3_update(&ctx, id, id_len);
    sm3_update(&ctx, SM2_A, 32);
    sm3_update(&ctx, SM2_B, 32);
    sm3_update(&ctx, SM2_GX, 32);
    sm3_update(&ctx, SM2_GY, 32);
    sm3_update(&ctx, pub_key, 32);      /* xA */
    sm3_update(&ctx, pub_key + 32, 32); /* yA */
    sm3_final(&ctx, z);

    return 0;
}

int sm2_sign(const uint8_t *priv_key,
             const uint8_t *msg, size_t msg_len,
             const uint8_t *id, size_t id_len,
             uint8_t *signature)
{
    sm2_context ctx;
    sm2_bn e, k, r, s, t1, t2;
    sm2_point kG;
    uint8_t z[32];
    uint8_t e_hash[32];
    uint8_t rand_bytes[32];
    uint8_t pub_key[64];
    sm3_context hash_ctx;
    int attempts;

    sm2_init_params();

    /* 加载私钥 */
    if (sm2_set_private_key(&ctx, priv_key) != 0) {
        return -1;
    }

    /* 派生公钥 */
    sm2_derive_public_key(&ctx);
    sm2_get_public_key(&ctx, pub_key);

    /* 计算Z */
    sm2_compute_z(pub_key, id, id_len, z);

    /* e = SM3(Z || M) */
    sm3_init(&hash_ctx);
    sm3_update(&hash_ctx, z, 32);
    sm3_update(&hash_ctx, msg, msg_len);
    sm3_final(&hash_ctx, e_hash);
    sm2_bn_from_bytes(&e, e_hash);

    attempts = 0;
    do {
        if (attempts++ > 100) return -1;

        /* 生成随机数k */
        do {
            sm2_random_bytes(rand_bytes, 32);
            sm2_bn_from_bytes(&k, rand_bytes);
        } while (sm2_bn_is_zero(&k) || sm2_bn_cmp(&k, &SM2_N_BN) >= 0);

        /* (x1, y1) = [k]G */
        sm2_point_mul(&kG, &k, &SM2_G);

        /* r = (e + x1) mod n */
        sm2_bn_mod_add(&r, &e, &kG.x, &SM2_N_BN);

        /* 检查 r == 0 或 r + k == n */
        if (sm2_bn_is_zero(&r)) continue;
        sm2_bn_mod_add(&t1, &r, &k, &SM2_N_BN);
        if (sm2_bn_is_zero(&t1)) continue;

        /* s = ((1 + dA)^(-1) * (k - r*dA)) mod n */
        /* t1 = 1 + dA */
        memset(&t1, 0, sizeof(sm2_bn));
        t1.d[0] = 1;
        sm2_bn_mod_add(&t1, &t1, &ctx.private_key, &SM2_N_BN);

        /* t1 = (1 + dA)^(-1) */
        if (sm2_bn_mod_inv(&t1, &t1, &SM2_N_BN) != 0) continue;

        /* t2 = r * dA */
        sm2_bn_mod_mul(&t2, &r, &ctx.private_key, &SM2_N_BN);

        /* t2 = k - r*dA */
        sm2_bn_mod_sub(&t2, &k, &t2, &SM2_N_BN);

        /* s = t1 * t2 */
        sm2_bn_mod_mul(&s, &t1, &t2, &SM2_N_BN);

    } while (sm2_bn_is_zero(&s));

    /* 输出签名 (r, s) */
    sm2_bn_to_bytes(&r, signature);
    sm2_bn_to_bytes(&s, signature + 32);

    return 0;
}

/*
 * ============== SM2验签 ==============
 */

int sm2_verify(const uint8_t *pub_key,
               const uint8_t *msg, size_t msg_len,
               const uint8_t *id, size_t id_len,
               const uint8_t *signature)
{
    sm2_point P, sG, tP, R_point;
    sm2_bn r, s, e, t, R;
    uint8_t z[32];
    uint8_t e_hash[32];
    sm3_context hash_ctx;

    sm2_init_params();

    /* 解析签名 */
    sm2_bn_from_bytes(&r, signature);
    sm2_bn_from_bytes(&s, signature + 32);

    /* 验证 r, s ∈ [1, n-1] */
    if (sm2_bn_is_zero(&r) || sm2_bn_cmp(&r, &SM2_N_BN) >= 0) {
        return -1;
    }
    if (sm2_bn_is_zero(&s) || sm2_bn_cmp(&s, &SM2_N_BN) >= 0) {
        return -1;
    }

    /* 加载公钥 */
    if (sm2_point_from_bytes(&P, pub_key, 64) != 0) {
        return -1;
    }

    /* 计算Z */
    sm2_compute_z(pub_key, id, id_len, z);

    /* e = SM3(Z || M) */
    sm3_init(&hash_ctx);
    sm3_update(&hash_ctx, z, 32);
    sm3_update(&hash_ctx, msg, msg_len);
    sm3_final(&hash_ctx, e_hash);
    sm2_bn_from_bytes(&e, e_hash);

    /* t = (r + s) mod n */
    sm2_bn_mod_add(&t, &r, &s, &SM2_N_BN);
    if (sm2_bn_is_zero(&t)) {
        return -1;
    }

    /* (x1, y1) = [s]G + [t]PA */
    sm2_point_mul(&sG, &s, &SM2_G);
    sm2_point_mul(&tP, &t, &P);
    sm2_point_add(&R_point, &sG, &tP);

    /* R = (e + x1) mod n */
    sm2_bn_mod_add(&R, &e, &R_point.x, &SM2_N_BN);

    /* 验证 R == r */
    if (sm2_bn_cmp(&R, &r) != 0) {
        return -1;
    }

    return 0;
}

/*
 * ============== 辅助函数 ==============
 */

int sm2_hex_to_bytes(const char *hex, size_t hex_len, uint8_t *bytes, size_t *bytes_len)
{
    size_t i, j = 0;
    char buf[3] = {0};

    if (hex_len % 2 != 0) {
        return -1;
    }

    for (i = 0; i < hex_len; i += 2) {
        buf[0] = hex[i];
        buf[1] = hex[i + 1];
        bytes[j++] = (uint8_t)strtol(buf, NULL, 16);
    }

    *bytes_len = j;
    return 0;
}

void sm2_bytes_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex)
{
    size_t i;
    static const char hex_chars[] = "0123456789abcdef";

    for (i = 0; i < bytes_len; i++) {
        hex[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0f];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0f];
    }
    hex[bytes_len * 2] = '\0';
}

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* sm2_base64_encode(const uint8_t *data, size_t len, size_t *out_len)
{
    size_t output_len = ((len + 2) / 3) * 4;
    char *out = (char *)malloc(output_len + 1);
    size_t i, j = 0;

    if (!out) return NULL;

    for (i = 0; i < len; i += 3) {
        uint32_t val = (uint32_t)data[i] << 16;
        if (i + 1 < len) val |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) val |= (uint32_t)data[i + 2];

        out[j++] = base64_chars[(val >> 18) & 0x3F];
        out[j++] = base64_chars[(val >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? base64_chars[(val >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? base64_chars[val & 0x3F] : '=';
    }
    out[j] = '\0';
    
    if (out_len) *out_len = j;
    return out;
}

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

uint8_t* sm2_base64_decode(const char *input, size_t *out_len)
{
    size_t in_len = strlen(input);
    size_t padding = 0;
    size_t i, j = 0;
    uint8_t *out;

    if (in_len % 4 != 0) {
        *out_len = 0;
        return NULL;
    }

    if (in_len >= 2 && input[in_len - 1] == '=') padding++;
    if (in_len >= 2 && input[in_len - 2] == '=') padding++;

    *out_len = (in_len / 4) * 3 - padding;
    out = (uint8_t *)malloc(*out_len);
    if (!out) return NULL;

    for (i = 0; i < in_len; i += 4) {
        uint32_t val = 0;
        val |= base64_decode_table[(uint8_t)input[i]] << 18;
        val |= base64_decode_table[(uint8_t)input[i + 1]] << 12;
        if (input[i + 2] != '=') val |= base64_decode_table[(uint8_t)input[i + 2]] << 6;
        if (input[i + 3] != '=') val |= base64_decode_table[(uint8_t)input[i + 3]];

        out[j++] = (val >> 16) & 0xFF;
        if (input[i + 2] != '=' && j < *out_len) out[j++] = (val >> 8) & 0xFF;
        if (input[i + 3] != '=' && j < *out_len) out[j++] = val & 0xFF;
    }

    return out;
}