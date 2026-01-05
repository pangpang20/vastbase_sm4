/*
 * SM2 Algorithm Header
 * 国密SM2椭圆曲线公钥密码算法
 * 
 * 基于GB/T 32918-2016标准实现
 */

#ifndef SM2_H
#define SM2_H

#include <stdint.h>
#include <stddef.h>

/* SM2曲线参数长度 */
#define SM2_KEY_SIZE        32   /* 私钥长度: 256位 */
#define SM2_PUBKEY_SIZE     64   /* 公钥长度: 512位 (X + Y坐标) */
#define SM2_PUBKEY_COMPRESSED_SIZE  33  /* 压缩公钥长度 */
#define SM2_SIGNATURE_SIZE  64   /* 签名长度: 512位 (r + s) */
#define SM2_MAX_PLAINTEXT_SIZE  136  /* 加密明文最大长度建议 */

/* SM3哈希输出长度 */
#define SM3_DIGEST_SIZE     32

/* 大整数结构 (256位) */
typedef struct {
    uint32_t d[8];      /* 低位在前 */
} sm2_bn;

/* 椭圆曲线点结构 */
typedef struct {
    sm2_bn x;
    sm2_bn y;
    int infinity;       /* 是否为无穷远点 */
} sm2_point;

/* SM2上下文结构 */
typedef struct {
    sm2_bn private_key;         /* 私钥 d */
    sm2_point public_key;       /* 公钥 P = [d]G */
    int has_private_key;
    int has_public_key;
} sm2_context;

/* SM3上下文结构 */
typedef struct {
    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t total;
} sm3_context;

/*
 * 大整数操作
 */

/* 从字节数组加载大整数 (大端序) */
void sm2_bn_from_bytes(sm2_bn *bn, const uint8_t *bytes);

/* 将大整数导出为字节数组 (大端序) */
void sm2_bn_to_bytes(const sm2_bn *bn, uint8_t *bytes);

/* 大整数比较: 返回 1 if a > b, -1 if a < b, 0 if a == b */
int sm2_bn_cmp(const sm2_bn *a, const sm2_bn *b);

/* 大整数模加法: r = (a + b) mod n */
void sm2_bn_mod_add(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *n);

/* 大整数模减法: r = (a - b) mod n */
void sm2_bn_mod_sub(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *n);

/* 大整数模乘法: r = (a * b) mod n */
void sm2_bn_mod_mul(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *n);

/* 大整数模逆: r = a^(-1) mod n */
int sm2_bn_mod_inv(sm2_bn *r, const sm2_bn *a, const sm2_bn *n);

/* 检查大整数是否为零 */
int sm2_bn_is_zero(const sm2_bn *a);

/*
 * 椭圆曲线点操作
 */

/* 点加法: R = P + Q */
void sm2_point_add(sm2_point *r, const sm2_point *p, const sm2_point *q);

/* 点倍乘: R = 2P */
void sm2_point_double(sm2_point *r, const sm2_point *p);

/* 标量乘法: R = [k]P */
void sm2_point_mul(sm2_point *r, const sm2_bn *k, const sm2_point *p);

/* 检查点是否在曲线上 */
int sm2_point_is_on_curve(const sm2_point *p);

/* 点从字节数组加载 (04 || X || Y 格式) */
int sm2_point_from_bytes(sm2_point *p, const uint8_t *bytes, size_t len);

/* 点导出为字节数组 (04 || X || Y 格式) */
void sm2_point_to_bytes(const sm2_point *p, uint8_t *bytes);

/*
 * SM3哈希算法
 */

/* 初始化SM3上下文 */
void sm3_init(sm3_context *ctx);

/* 更新SM3哈希数据 */
void sm3_update(sm3_context *ctx, const uint8_t *data, size_t len);

/* 完成SM3哈希计算 */
void sm3_final(sm3_context *ctx, uint8_t *digest);

/* 一次性计算SM3哈希 */
void sm3_hash(const uint8_t *data, size_t len, uint8_t *digest);

/*
 * SM2密钥操作
 */

/*
 * 初始化SM2上下文
 */
void sm2_init(sm2_context *ctx);

/*
 * 生成SM2密钥对
 * @param ctx: SM2上下文
 * @return: 0成功，-1失败
 */
int sm2_generate_keypair(sm2_context *ctx);

/*
 * 从私钥导出公钥
 * @param ctx: SM2上下文(必须已设置私钥)
 * @return: 0成功，-1失败
 */
int sm2_derive_public_key(sm2_context *ctx);

/*
 * 设置私钥 (32字节)
 * @param ctx: SM2上下文
 * @param key: 32字节私钥
 * @return: 0成功，-1失败
 */
int sm2_set_private_key(sm2_context *ctx, const uint8_t *key);

/*
 * 设置公钥 (64字节或65字节)
 * @param ctx: SM2上下文
 * @param key: 64字节(X||Y) 或 65字节(04||X||Y)公钥
 * @param len: 密钥长度
 * @return: 0成功，-1失败
 */
int sm2_set_public_key(sm2_context *ctx, const uint8_t *key, size_t len);

/*
 * 导出私钥 (32字节)
 * @param ctx: SM2上下文
 * @param key: 输出缓冲区(32字节)
 * @return: 0成功，-1失败
 */
int sm2_get_private_key(const sm2_context *ctx, uint8_t *key);

/*
 * 导出公钥 (64字节)
 * @param ctx: SM2上下文
 * @param key: 输出缓冲区(64字节)
 * @return: 0成功，-1失败
 */
int sm2_get_public_key(const sm2_context *ctx, uint8_t *key);

/*
 * SM2加密
 * @param pub_key: 公钥(64字节)
 * @param input: 输入明文
 * @param input_len: 明文长度
 * @param output: 输出密文缓冲区(长度至少为 input_len + 97)
 * @param output_len: 输出密文长度
 * @return: 0成功，-1失败
 *
 * 密文格式: C1(65字节) || C3(32字节SM3哈希) || C2(等长密文)
 * 其中C1 = [k]G, C3 = SM3(x2||M||y2), C2 = M xor KDF(x2||y2)
 */
int sm2_encrypt(const uint8_t *pub_key,
                const uint8_t *input, size_t input_len,
                uint8_t *output, size_t *output_len);

/*
 * SM2解密
 * @param priv_key: 私钥(32字节)
 * @param input: 输入密文
 * @param input_len: 密文长度
 * @param output: 输出明文缓冲区
 * @param output_len: 输出明文长度
 * @return: 0成功，-1失败
 */
int sm2_decrypt(const uint8_t *priv_key,
                const uint8_t *input, size_t input_len,
                uint8_t *output, size_t *output_len);

/*
 * SM2签名
 * @param priv_key: 私钥(32字节)
 * @param msg: 待签名消息
 * @param msg_len: 消息长度
 * @param id: 用户标识(可为NULL，默认使用"1234567812345678")
 * @param id_len: 用户标识长度
 * @param signature: 输出签名(64字节)
 * @return: 0成功，-1失败
 *
 * 签名格式: r(32字节) || s(32字节)
 */
int sm2_sign(const uint8_t *priv_key,
             const uint8_t *msg, size_t msg_len,
             const uint8_t *id, size_t id_len,
             uint8_t *signature);

/*
 * SM2验签
 * @param pub_key: 公钥(64字节)
 * @param msg: 原始消息
 * @param msg_len: 消息长度
 * @param id: 用户标识(可为NULL)
 * @param id_len: 用户标识长度
 * @param signature: 签名(64字节)
 * @return: 0成功(验签通过)，-1失败
 */
int sm2_verify(const uint8_t *pub_key,
               const uint8_t *msg, size_t msg_len,
               const uint8_t *id, size_t id_len,
               const uint8_t *signature);

/*
 * 计算用户标识哈希 Z
 * Z = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
 * @param pub_key: 公钥(64字节)
 * @param id: 用户标识
 * @param id_len: 用户标识长度
 * @param z: 输出哈希(32字节)
 * @return: 0成功，-1失败
 */
int sm2_compute_z(const uint8_t *pub_key,
                  const uint8_t *id, size_t id_len,
                  uint8_t *z);

/*
 * KDF密钥派生函数
 * @param z: 共享信息
 * @param z_len: 共享信息长度
 * @param klen: 需要派生的密钥长度
 * @param key: 输出密钥
 */
void sm2_kdf(const uint8_t *z, size_t z_len, size_t klen, uint8_t *key);

/*
 * 辅助函数
 */

/* 安全随机数生成 */
int sm2_random_bytes(uint8_t *buf, size_t len);

/* 十六进制字符串转字节数组 */
int sm2_hex_to_bytes(const char *hex, size_t hex_len, uint8_t *bytes, size_t *bytes_len);

/* 字节数组转十六进制字符串 */
void sm2_bytes_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex);

/* Base64编码 */
char* sm2_base64_encode(const uint8_t *data, size_t len, size_t *out_len);

/* Base64解码 */
uint8_t* sm2_base64_decode(const char *input, size_t *out_len);

#endif /* SM2_H */
