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
    /* 注意：ec_key 的所有权已转移给 pkey，不要再单独释放 */
    ctx->ec_key = NULL;
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
    int pkey_id;
    
    fprintf(stderr, "[SM2_DEBUG] sm2_set_private_key: entering, ctx=%p, key=%p\n", (void*)ctx, (void*)key);
    fflush(stderr);
    
    /* 检查参数 */
    if (!ctx) {
        fprintf(stderr, "[SM2_DEBUG] ERROR: ctx is NULL\n");
        fflush(stderr);
        return -1;
    }
    if (!key) {
        fprintf(stderr, "[SM2_DEBUG] ERROR: key is NULL\n");
        fflush(stderr);
        return -1;
    }
    
    /* 打印私钥前4字节用于验证 */
    fprintf(stderr, "[SM2_DEBUG] key bytes: %02x %02x %02x %02x...\n", key[0], key[1], key[2], key[3]);
    fflush(stderr);
    
    /* 创建 SM2 密钥 */
    fprintf(stderr, "[SM2_DEBUG] calling create_sm2_key...\n");
    fflush(stderr);
    ec_key = create_sm2_key();
    if (!ec_key) {
        fprintf(stderr, "[SM2_DEBUG] create_sm2_key FAILED\n");
        fflush(stderr);
        goto cleanup;
    }
    fprintf(stderr, "[SM2_DEBUG] create_sm2_key OK, ec_key=%p\n", (void*)ec_key);
    fflush(stderr);
    
    /* 设置私钥 */
    fprintf(stderr, "[SM2_DEBUG] calling BN_bin2bn...\n");
    fflush(stderr);
    priv_bn = BN_bin2bn(key, 32, NULL);
    fprintf(stderr, "[SM2_DEBUG] BN_bin2bn returned %p\n", (void*)priv_bn);
    fflush(stderr);
    if (!priv_bn) {
        fprintf(stderr, "[SM2_DEBUG] BN_bin2bn FAILED\n");
        fflush(stderr);
        goto cleanup;
    }
    
    if (!EC_KEY_set_private_key(ec_key, priv_bn)) {
        fprintf(stderr, "[SM2_DEBUG] EC_KEY_set_private_key FAILED\n");
        fflush(stderr);
        goto cleanup;
    }
    fprintf(stderr, "[SM2_DEBUG] Private key set to EC_KEY\n");
    fflush(stderr);
    
    /* 计算公钥 */
    group = EC_KEY_get0_group(ec_key);
    pub_point = EC_POINT_new(group);
    if (!pub_point) goto cleanup;
    
    if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
        fprintf(stderr, "[SM2_DEBUG] EC_POINT_mul FAILED\n");
        fflush(stderr);
        goto cleanup;
    }
    
    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        fprintf(stderr, "[SM2_DEBUG] EC_KEY_set_public_key FAILED\n");
        fflush(stderr);
        goto cleanup;
    }
    fprintf(stderr, "[SM2_DEBUG] Public key computed and set\n");
    fflush(stderr);
    
    /* 创建 EVP_PKEY */
    pkey = EVP_PKEY_new();
    if (!pkey) goto cleanup;
    
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto cleanup;
    }
    
    /* 检查 EVP_PKEY 类型 */
    pkey_id = EVP_PKEY_id(pkey);
    fprintf(stderr, "[SM2_DEBUG] EVP_PKEY created, id=%d (EC=%d, SM2=%d)\n", 
            pkey_id, EVP_PKEY_EC, EVP_PKEY_SM2);
    fflush(stderr);
    
    /* 保存到上下文 */
    if (ctx->pkey) EVP_PKEY_free(ctx->pkey);
    /* 注意：ec_key 的所有权已转移给 pkey，不要保存到 ctx->ec_key */
    
    ctx->pkey = pkey;
    ctx->ec_key = NULL;  /* 不再保存，由 pkey 管理 */
    ctx->has_private_key = 1;
    ctx->has_public_key = 1;
    ec_key = NULL;  /* 防止被释放 */
    pkey = NULL;
    ret = 0;
    
    fprintf(stderr, "[SM2_DEBUG] sm2_set_private_key SUCCESS\n");
    fflush(stderr);
    
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
    
    /* 注意：OpenSSL 3.0 不需要显式设置 SM2 类型，
     * 因为 EVP_PKEY_assign_EC_KEY 会保留 EC_KEY 的曲线信息 */
    
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
    size_t out_len = *output_len;
    int ret = -1;
    unsigned long err;
    
    /* 调试日志 */
    fprintf(stderr, "[SM2_DEBUG] sm2_decrypt: input_len=%zu, output_len=%zu\n", input_len, *output_len);
    fflush(stderr);
    
    sm2_init(&ctx);
    
    /* 设置私钥 */
    fprintf(stderr, "[SM2_DEBUG] Setting private key...\n");
    fflush(stderr);
    if (sm2_set_private_key(&ctx, priv_key) != 0) {
        fprintf(stderr, "[SM2_DEBUG] sm2_set_private_key FAILED\n");
        fflush(stderr);
        goto cleanup;
    }
    fprintf(stderr, "[SM2_DEBUG] Private key set OK, pkey=%p\n", (void*)ctx.pkey);
    fflush(stderr);
    
    /* 创建解密上下文 */
    fprintf(stderr, "[SM2_DEBUG] Creating EVP_PKEY_CTX...\n");
    fflush(stderr);
    pctx = EVP_PKEY_CTX_new(ctx.pkey, NULL);
    if (!pctx) {
        err = ERR_get_error();
        fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_CTX_new FAILED, err=%lu\n", err);
        fflush(stderr);
        goto cleanup;
    }
    fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_CTX created OK\n");
    fflush(stderr);
    
    /* 初始化解密 */
    fprintf(stderr, "[SM2_DEBUG] Calling EVP_PKEY_decrypt_init...\n");
    fflush(stderr);
    if (EVP_PKEY_decrypt_init(pctx) <= 0) {
        err = ERR_get_error();
        fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_decrypt_init FAILED, err=%lu\n", err);
        fflush(stderr);
        goto cleanup;
    }
    fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_decrypt_init OK\n");
    fflush(stderr);
    
    /* 执行解密 */
    fprintf(stderr, "[SM2_DEBUG] Calling EVP_PKEY_decrypt with output=%p, out_len=%zu...\n", 
            (void*)output, out_len);
    fflush(stderr);
    if (EVP_PKEY_decrypt(pctx, output, &out_len, input, input_len) <= 0) {
        err = ERR_get_error();
        fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_decrypt FAILED, err=%lu\n", err);
        fflush(stderr);
        goto cleanup;
    }
    fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_decrypt OK, decrypted %zu bytes\n", out_len);
    fflush(stderr);
    
    *output_len = out_len;
    ret = 0;
    
cleanup:
    fprintf(stderr, "[SM2_DEBUG] cleanup, ret=%d\n", ret);
    fflush(stderr);
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
