/*
 * SM4 Algorithm Header
 * 国密SM4分组密码算法
 */

#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>

#define SM4_BLOCK_SIZE  16
#define SM4_KEY_SIZE    16
#define SM4_NUM_ROUNDS  32
#define SM4_GCM_IV_SIZE 12  /* 推荐的GCM IV长度 */
#define SM4_GCM_TAG_SIZE 16 /* GCM认证标签长度 */

typedef struct {
    uint32_t rk[SM4_NUM_ROUNDS];  /* 轮密钥 */
} sm4_context;

/*
 * SM4密钥扩展
 * @param ctx: SM4上下文
 * @param key: 16字节密钥
 */
void sm4_setkey(sm4_context *ctx, const uint8_t *key);

/*
 * SM4加密单个块(16字节)
 * @param ctx: SM4上下文
 * @param input: 16字节明文
 * @param output: 16字节密文
 */
void sm4_encrypt_block(const sm4_context *ctx, const uint8_t *input, uint8_t *output);

/*
 * SM4解密单个块(16字节)
 * @param ctx: SM4上下文
 * @param input: 16字节密文
 * @param output: 16字节明文
 */
void sm4_decrypt_block(const sm4_context *ctx, const uint8_t *input, uint8_t *output);

/*
 * SM4 ECB模式加密
 * @param key: 16字节密钥
 * @param input: 输入数据
 * @param input_len: 输入长度
 * @param output: 输出缓冲区(需预分配，长度为PKCS7填充后的大小)
 * @param output_len: 输出长度指针
 * @return: 0成功，-1失败
 */
int sm4_ecb_encrypt(const uint8_t *key, const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t *output_len);

/*
 * SM4 ECB模式解密
 * @param key: 16字节密钥
 * @param input: 输入数据
 * @param input_len: 输入长度(必须是16的倍数)
 * @param output: 输出缓冲区
 * @param output_len: 输出长度指针
 * @return: 0成功，-1失败
 */
int sm4_ecb_decrypt(const uint8_t *key, const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t *output_len);

/*
 * SM4 CBC模式加密
 * @param key: 16字节密钥
 * @param iv: 16字节初始向量
 * @param input: 输入数据
 * @param input_len: 输入长度
 * @param output: 输出缓冲区
 * @param output_len: 输出长度指针
 * @return: 0成功，-1失败
 */
int sm4_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                    const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t *output_len);

/*
 * SM4 CBC模式解密
 * @param key: 16字节密钥
 * @param iv: 16字节初始向量
 * @param input: 输入数据
 * @param input_len: 输入长度
 * @param output: 输出缓冲区
 * @param output_len: 输出长度指针
 * @return: 0成功，-1失败
 */
int sm4_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                    const uint8_t *input, size_t input_len,
                    uint8_t *output, size_t *output_len);

/*
 * SM4 GCM模式加密
 * @param key: 16字节密钥
 * @param iv: 初始向量(推荐12字节)
 * @param iv_len: IV长度
 * @param aad: 附加认证数据(可选)
 * @param aad_len: AAD长度
 * @param input: 输入数据
 * @param input_len: 输入长度
 * @param output: 输出缓冲区(长度应为input_len)
 * @param tag: 认证标签输出(16字节)
 * @return: 0成功，-1失败
 */
int sm4_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *input, size_t input_len,
                    uint8_t *output, uint8_t *tag);

/*
 * SM4 GCM模式解密
 * @param key: 16字节密钥
 * @param iv: 初始向量
 * @param iv_len: IV长度
 * @param aad: 附加认证数据(可选)
 * @param aad_len: AAD长度
 * @param input: 输入数据
 * @param input_len: 输入长度
 * @param tag: 认证标签(16字节)
 * @param output: 输出缓冲区
 * @return: 0成功，-1失败(认证失败或其他错误)
 */
int sm4_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *input, size_t input_len,
                    const uint8_t *tag, uint8_t *output);

/*
 * SM4 CBC模式加密（带密钥派生）
 * @param password: 原始密码/密钥
 * @param password_len: 密码长度
 * @param hash_algo: 哈希算法名称 ("sha256", "sha384", "sha512", "sm3")
 * @param input: 输入数据
 * @param input_len: 输入长度
 * @param output: 输出缓冲区（包含：salt[16] + ciphertext）
 * @param output_len: 输出长度指针
 * @return: 0成功，-1失败
 */
int sm4_cbc_encrypt_kdf(const uint8_t *password, size_t password_len,
                        const char *hash_algo,
                        const uint8_t *input, size_t input_len,
                        uint8_t *output, size_t *output_len);

/*
 * SM4 CBC模式解密（带密钥派生）
 * @param password: 原始密码/密钥
 * @param password_len: 密码长度
 * @param hash_algo: 哈希算法名称 ("sha256", "sha384", "sha512", "sm3")
 * @param input: 输入数据（包含：salt[16] + ciphertext）
 * @param input_len: 输入长度
 * @param output: 输出缓冲区
 * @param output_len: 输出长度指针
 * @return: 0成功，-1失败
 */
int sm4_cbc_decrypt_kdf(const uint8_t *password, size_t password_len,
                        const char *hash_algo,
                        const uint8_t *input, size_t input_len,
                        uint8_t *output, size_t *output_len);

/*
 * SM4 CBC模式加密（兼容gs_encrypt格式）
 * @param password: 原始密码/密钥
 * @param password_len: 密码长度
 * @param hash_algo: 哈希算法名称 ("sha256", "sha384", "sha512", "sm3")
 * @param input: 输入数据
 * @param input_len: 输入长度
 * @param output: 输出缓冲区（包含：header + salt + ciphertext，Base64编码）
 * @param output_len: 输出长度指针
 * @return: 0成功，-1失败
 */
int sm4_cbc_encrypt_gs_format(const uint8_t *password, size_t password_len,
                               const char *hash_algo,
                               const uint8_t *input, size_t input_len,
                               char *output, size_t *output_len);

/*
 * SM4 CBC模式解密（兼容gs_encrypt格式）
 * @param password: 原始密码/密钥
 * @param password_len: 密码长度
 * @param hash_algo: 哈希算法名称 ("sha256", "sha384", "sha512", "sm3")
 * @param input: 输入数据（Base64编码的gs_encrypt格式）
 * @param input_len: 输入长度
 * @param output: 输出缓冲区
 * @param output_len: 输出长度指针
 * @return: 0成功，-1失败
 */
int sm4_cbc_decrypt_gs_format(const uint8_t *password, size_t password_len,
                               const char *hash_algo,
                               const uint8_t *input, size_t input_len,
                               uint8_t *output, size_t *output_len);

#endif /* SM4_H */
