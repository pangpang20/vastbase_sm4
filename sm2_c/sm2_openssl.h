/*
 * SM2 Extension Header for VastBase/OpenGauss
 * 基于 OpenSSL 高性能实现
 * 
 * GB/T 32918-2016 标准
 */

#ifndef SM2_OPENSSL_H
#define SM2_OPENSSL_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* SM2 密钥长度 */
#define SM2_PRIVATE_KEY_SIZE    32
#define SM2_PUBLIC_KEY_SIZE     64
#define SM2_MAX_PLAINTEXT_SIZE  255
#define SM2_MAX_CIPHERTEXT_SIZE (1 + 64 + 32 + SM2_MAX_PLAINTEXT_SIZE)

/* SM2 上下文结构 */
typedef struct {
    EVP_PKEY *pkey;          /* OpenSSL 密钥对象 */
    EC_KEY *ec_key;          /* EC 密钥 */
    int has_private_key;
    int has_public_key;
} sm2_context;

/*
 * ============== SM2 密钥管理 ==============
 */

/* 初始化上下文 */
void sm2_init(sm2_context *ctx);

/* 释放上下文 */
void sm2_free(sm2_context *ctx);

/* 生成密钥对 */
int sm2_generate_keypair(sm2_context *ctx);

/* 从私钥派生公钥 */
int sm2_derive_public_key(sm2_context *ctx);

/* 设置私钥(32字节) */
int sm2_set_private_key(sm2_context *ctx, const uint8_t *key);

/* 设置公钥(64字节:X||Y 或 65字节:04||X||Y) */
int sm2_set_public_key(sm2_context *ctx, const uint8_t *key, size_t len);

/* 获取私钥(32字节) */
int sm2_get_private_key(const sm2_context *ctx, uint8_t *key);

/* 获取公钥(64字节:X||Y) */
int sm2_get_public_key(const sm2_context *ctx, uint8_t *key);

/*
 * ============== SM2 加解密 ==============
 */

/* 
 * SM2 公钥加密
 * output: C1(65字节) || C3(32字节) || C2(明文长度)
 * output_len: 输出实际长度
 */
int sm2_encrypt(const uint8_t *pub_key,
                const uint8_t *input, size_t input_len,
                uint8_t *output, size_t *output_len);

/*
 * SM2 私钥解密
 * output: 明文
 * output_len: 输出实际长度
 */
int sm2_decrypt(const uint8_t *priv_key,
                const uint8_t *input, size_t input_len,
                uint8_t *output, size_t *output_len);

/*
 * ============== SM2 数字签名 ==============
 */

/*
 * SM2 签名
 * signature: r || s (64字节)
 */
int sm2_sign(const uint8_t *priv_key,
             const uint8_t *msg, size_t msg_len,
             uint8_t *signature);

/*
 * SM2 验签
 * 返回: 0=验证通过, -1=验证失败
 */
int sm2_verify(const uint8_t *pub_key,
               const uint8_t *msg, size_t msg_len,
               const uint8_t *signature);

#endif /* SM2_OPENSSL_H */
