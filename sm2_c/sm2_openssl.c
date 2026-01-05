/*
 * SM2 Implementation using OpenSSL
 * 基于 OpenSSL 的高性能 SM2 实现
 * 
 * 性能优化:
 * 1. 使用 OpenSSL 优化的椭圆曲线运算
 * 2. 利用硬件加速(AES-NI等)
 * 3. 避免内存拷贝和临时分配
 */

#include "sm2_openssl.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>

/* OpenSSL 版本兼容性检查 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "OpenSSL version must be >= 1.1.0"
#endif

/* SM2 曲线 NID */
#ifndef NID_sm2
/* OpenSSL 1.1.1 中 SM2 曲线的 NID */
#define NID_sm2 1172
#endif
#define NID_SM2 NID_sm2

/*
 * ============== 辅助函数 ==============
 */

/* 创建 SM2 EC_KEY */
static EC_KEY* create_sm2_key(void)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_SM2);
    if (key) {
        EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
    }
    return key;
}

/* 从 64 字节原始数据创建 EC_POINT */
static EC_POINT* point_from_bytes(const EC_GROUP *group, const uint8_t *bytes, size_t len)
{
    EC_POINT *point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    
    if (len == 64) {
        /* X || Y 格式 */
        x = BN_bin2bn(bytes, 32, NULL);
        y = BN_bin2bn(bytes + 32, 32, NULL);
    } else if (len == 65 && bytes[0] == 0x04) {
        /* 04 || X || Y 格式 */
        x = BN_bin2bn(bytes + 1, 32, NULL);
        y = BN_bin2bn(bytes + 33, 32, NULL);
    } else {
        return NULL;
    }
    
    if (x && y) {
        point = EC_POINT_new(group);
        if (point) {
            if (!EC_POINT_set_affine_coordinates(group, point, x, y, NULL)) {
                EC_POINT_free(point);
                point = NULL;
            }
        }
    }
    
    BN_free(x);
    BN_free(y);
    return point;
}

/* 将 EC_POINT 转换为 64 字节原始数据 */
static int point_to_bytes(const EC_GROUP *group, const EC_POINT *point, uint8_t *bytes)
{
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    int ret = -1;
    
    if (x && y) {
        if (EC_POINT_get_affine_coordinates(group, point, x, y, NULL)) {
            BN_bn2binpad(x, bytes, 32);
            BN_bn2binpad(y, bytes + 32, 32);
            ret = 0;
        }
    }
    
    BN_free(x);
    BN_free(y);
    return ret;
}

/*
 * ============== SM2 密钥管理 ==============
 */

void sm2_init(sm2_context *ctx)
{
    memset(ctx, 0, sizeof(sm2_context));
}

void sm2_free(sm2_context *ctx)
{
    if (ctx->pkey) {
        EVP_PKEY_free(ctx->pkey);
        ctx->pkey = NULL;
    }
    if (ctx->ec_key) {
        EC_KEY_free(ctx->ec_key);
        ctx->ec_key = NULL;
    }
    ctx->has_private_key = 0;
    ctx->has_public_key = 0;
}

int sm2_generate_keypair(sm2_context *ctx)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    int ret = -1;
    
    /* 创建密钥生成上下文 */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) goto cleanup;
    
    /* 初始化密钥生成 */
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto cleanup;
    
    /* 设置 SM2 曲线 */
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_SM2) <= 0) goto cleanup;
    
    /* 生成密钥对 */
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto cleanup;
    
    /* 提取 EC_KEY */
    ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) goto cleanup;
    
    /* 保存到上下文 */
    if (ctx->pkey) EVP_PKEY_free(ctx->pkey);
    if (ctx->ec_key) EC_KEY_free(ctx->ec_key);
    
    ctx->pkey = pkey;
    ctx->ec_key = ec_key;
    ctx->has_private_key = 1;
    ctx->has_public_key = 1;
    pkey = NULL;  /* 防止被释放 */
    ec_key = NULL;
    ret = 0;
    
cleanup:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (ec_key) EC_KEY_free(ec_key);
    return ret;
}

int sm2_set_private_key(sm2_context *ctx, const uint8_t *key)
{
    EC_KEY *ec_key = NULL;
    BIGNUM *priv_bn = NULL;
    const EC_GROUP *group;
    EC_POINT *pub_point = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -1;
    
    /* 创建 SM2 密钥 */
    ec_key = create_sm2_key();
    if (!ec_key) goto cleanup;
    
    /* 设置私钥 */
    priv_bn = BN_bin2bn(key, 32, NULL);
    if (!priv_bn) goto cleanup;
    
    if (!EC_KEY_set_private_key(ec_key, priv_bn)) goto cleanup;
    
    /* 计算公钥 */
    group = EC_KEY_get0_group(ec_key);
    pub_point = EC_POINT_new(group);
    if (!pub_point) goto cleanup;
    
    if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) goto cleanup;
    
    if (!EC_KEY_set_public_key(ec_key, pub_point)) goto cleanup;
    
    /* 创建 EVP_PKEY */
    pkey = EVP_PKEY_new();
    if (!pkey) goto cleanup;
    
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto cleanup;
    }
    
    /* 设置 EVP_PKEY 类型为 SM2 (关键！) */
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    
    /* 保存到上下文 */
    if (ctx->pkey) EVP_PKEY_free(ctx->pkey);
    if (ctx->ec_key) EC_KEY_free(ctx->ec_key);
    
    ctx->pkey = pkey;
    ctx->ec_key = ec_key;
    ctx->has_private_key = 1;
    ctx->has_public_key = 1;
    ec_key = NULL;  /* 防止被释放 */
    pkey = NULL;
    ret = 0;
    
cleanup:
    if (priv_bn) BN_free(priv_bn);
    if (pub_point) EC_POINT_free(pub_point);
    if (ec_key) EC_KEY_free(ec_key);
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}

int sm2_set_public_key(sm2_context *ctx, const uint8_t *key, size_t len)
{
    EC_KEY *ec_key = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group;
    EVP_PKEY *pkey = NULL;
    int ret = -1;
    
    /* 创建 SM2 密钥 */
    ec_key = create_sm2_key();
    if (!ec_key) goto cleanup;
    
    group = EC_KEY_get0_group(ec_key);
    
    /* 从字节创建公钥点 */
    point = point_from_bytes(group, key, len);
    if (!point) goto cleanup;
    
    if (!EC_KEY_set_public_key(ec_key, point)) goto cleanup;
    
    /* 创建 EVP_PKEY */
    pkey = EVP_PKEY_new();
    if (!pkey) goto cleanup;
    
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto cleanup;
    }
    
    /* 设置 EVP_PKEY 类型为 SM2 (关键！) */
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    
    /* 保存到上下文 */
    if (ctx->pkey) EVP_PKEY_free(ctx->pkey);
    if (ctx->ec_key) EC_KEY_free(ctx->ec_key);
    
    ctx->pkey = pkey;
    ctx->ec_key = ec_key;
    ctx->has_public_key = 1;
    ec_key = NULL;  /* 防止被释放 */
    pkey = NULL;
    ret = 0;
    
cleanup:
    if (point) EC_POINT_free(point);
    if (ec_key) EC_KEY_free(ec_key);
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}

int sm2_derive_public_key(sm2_context *ctx)
{
    if (!ctx->has_private_key || !ctx->ec_key) return -1;
    
    const EC_GROUP *group = EC_KEY_get0_group(ctx->ec_key);
    const BIGNUM *priv = EC_KEY_get0_private_key(ctx->ec_key);
    EC_POINT *pub_point = EC_POINT_new(group);
    
    if (!pub_point) return -1;
    
    if (!EC_POINT_mul(group, pub_point, priv, NULL, NULL, NULL)) {
        EC_POINT_free(pub_point);
        return -1;
    }
    
    if (!EC_KEY_set_public_key(ctx->ec_key, pub_point)) {
        EC_POINT_free(pub_point);
        return -1;
    }
    
    EC_POINT_free(pub_point);
    ctx->has_public_key = 1;
    return 0;
}

int sm2_get_private_key(const sm2_context *ctx, uint8_t *key)
{
    if (!ctx->has_private_key || !ctx->ec_key) return -1;
    
    const BIGNUM *priv = EC_KEY_get0_private_key(ctx->ec_key);
    if (!priv) return -1;
    
    BN_bn2binpad(priv, key, 32);
    return 0;
}

int sm2_get_public_key(const sm2_context *ctx, uint8_t *key)
{
    if (!ctx->has_public_key || !ctx->ec_key) return -1;
    
    const EC_GROUP *group = EC_KEY_get0_group(ctx->ec_key);
    const EC_POINT *pub = EC_KEY_get0_public_key(ctx->ec_key);
    
    if (!pub) return -1;
    
    return point_to_bytes(group, pub, key);
}

/*
 * ============== SM2 加解密 ==============
 * 
 * 使用 EVP 接口实现高性能加解密
 */

int sm2_encrypt(const uint8_t *pub_key,
                const uint8_t *input, size_t input_len,
                uint8_t *output, size_t *output_len)
{
    sm2_context ctx;
    EVP_PKEY_CTX *pctx = NULL;
    size_t out_len = *output_len;
    int ret = -1;
    
    sm2_init(&ctx);
    
    /* 设置公钥 */
    if (sm2_set_public_key(&ctx, pub_key, 64) != 0) {
        goto cleanup;
    }
    
    /* 创建加密上下文 */
    pctx = EVP_PKEY_CTX_new(ctx.pkey, NULL);
    if (!pctx) goto cleanup;
    
    /* 初始化加密 */
    if (EVP_PKEY_encrypt_init(pctx) <= 0) goto cleanup;
    
    /* 执行加密 */
    if (EVP_PKEY_encrypt(pctx, output, &out_len, input, input_len) <= 0) {
        goto cleanup;
    }
    
    *output_len = out_len;
    ret = 0;
    
cleanup:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    sm2_free(&ctx);
    return ret;
}

int sm2_decrypt(const uint8_t *priv_key,
                const uint8_t *input, size_t input_len,
                uint8_t *output, size_t *output_len)
{
    sm2_context ctx;
    EVP_PKEY_CTX *pctx = NULL;
    size_t out_len = 0;
    int ret = -1;
    
    sm2_init(&ctx);
    
    /* 设置私钥 */
    if (sm2_set_private_key(&ctx, priv_key) != 0) {
        goto cleanup;
    }
    
    /* 创建解密上下文 */
    pctx = EVP_PKEY_CTX_new(ctx.pkey, NULL);
    if (!pctx) goto cleanup;
    
    /* 初始化解密 */
    if (EVP_PKEY_decrypt_init(pctx) <= 0) goto cleanup;
    
    /* 第一次调用：查询需要的缓冲区大小 */
    if (EVP_PKEY_decrypt(pctx, NULL, &out_len, input, input_len) <= 0) {
        goto cleanup;
    }
    
    /* 检查缓冲区是否足够大 */
    if (out_len > *output_len) {
        /* 缓冲区不够，返回需要的大小 */
        *output_len = out_len;
        goto cleanup;
    }
    
    /* 第二次调用：执行实际解密 */
    if (EVP_PKEY_decrypt(pctx, output, &out_len, input, input_len) <= 0) {
        goto cleanup;
    }
    
    *output_len = out_len;
    ret = 0;
    
cleanup:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    sm2_free(&ctx);
    return ret;
}

/*
 * ============== SM2 数字签名 ==============
 */

int sm2_sign(const uint8_t *priv_key,
             const uint8_t *msg, size_t msg_len,
             uint8_t *signature)
{
    sm2_context ctx;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t sig_len = 64;
    int ret = -1;
    
    sm2_init(&ctx);
    
    /* 设置私钥 */
    if (sm2_set_private_key(&ctx, priv_key) != 0) {
        goto cleanup;
    }
    
    /* 创建签名上下文 */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto cleanup;
    
    /* 初始化签名 */
    if (EVP_DigestSignInit(mdctx, &pctx, EVP_sm3(), NULL, ctx.pkey) <= 0) {
        goto cleanup;
    }
    
    /* 执行签名 */
    if (EVP_DigestSign(mdctx, signature, &sig_len, msg, msg_len) <= 0) {
        goto cleanup;
    }
    
    ret = 0;
    
cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    sm2_free(&ctx);
    return ret;
}

int sm2_verify(const uint8_t *pub_key,
               const uint8_t *msg, size_t msg_len,
               const uint8_t *signature)
{
    sm2_context ctx;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret = -1;
    
    sm2_init(&ctx);
    
    /* 设置公钥 */
    if (sm2_set_public_key(&ctx, pub_key, 64) != 0) {
        goto cleanup;
    }
    
    /* 创建验签上下文 */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto cleanup;
    
    /* 初始化验签 */
    if (EVP_DigestVerifyInit(mdctx, &pctx, EVP_sm3(), NULL, ctx.pkey) <= 0) {
        goto cleanup;
    }
    
    /* 执行验签 */
    if (EVP_DigestVerify(mdctx, signature, 64, msg, msg_len) <= 0) {
        goto cleanup;
    }
    
    ret = 0;
    
cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    sm2_free(&ctx);
    return ret;
}
