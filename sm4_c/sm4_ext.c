/*
 * SM4 Extension for VastBase/OpenGauss
 * PostgreSQL/OpenGauss扩展接口
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "mb/pg_wchar.h"
#include "sm4.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>

PG_MODULE_MAGIC;

/* 函数声明 */
PG_FUNCTION_INFO_V1(sm4_encrypt);
PG_FUNCTION_INFO_V1(sm4_decrypt);
PG_FUNCTION_INFO_V1(sm4_encrypt_cbc);
PG_FUNCTION_INFO_V1(sm4_decrypt_cbc);
PG_FUNCTION_INFO_V1(sm4_encrypt_hex);
PG_FUNCTION_INFO_V1(sm4_decrypt_hex);
PG_FUNCTION_INFO_V1(sm4_encrypt_gcm);
PG_FUNCTION_INFO_V1(sm4_decrypt_gcm);
PG_FUNCTION_INFO_V1(sm4_encrypt_gcm_base64);
PG_FUNCTION_INFO_V1(sm4_decrypt_gcm_base64);
PG_FUNCTION_INFO_V1(sm4_encrypt_gcm_auto_iv);
PG_FUNCTION_INFO_V1(sm4_decrypt_gcm_auto_iv);
PG_FUNCTION_INFO_V1(sm4_encrypt_gcm_auto_iv_base64);
PG_FUNCTION_INFO_V1(sm4_decrypt_gcm_auto_iv_base64);

/* 工具函数: 单个十六进制字符转数值，返回-1表示非法字符 */
static int hex_char_to_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 工具函数: 十六进制字符串转字节数组 */
static int hex_to_bytes(const char *hex, size_t hex_len, uint8_t *bytes, size_t *bytes_len)
{
    size_t i;
    size_t j = 0;
    int hi, lo;

    if (hex_len % 2 != 0) {
        return -1;
    }

    for (i = 0; i < hex_len; i += 2) {
        hi = hex_char_to_val(hex[i]);
        lo = hex_char_to_val(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;  /* 非法十六进制字符 */
        }
        bytes[j++] = (uint8_t)((hi << 4) | lo);
    }

    *bytes_len = j;
    return 0;
}

/* 工具函数: 字节数组转十六进制字符串 */
static void bytes_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex)
{
    size_t i;
    static const char hex_chars[] = "0123456789abcdef";

    for (i = 0; i < bytes_len; i++) {
        hex[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0f];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0f];
    }
    hex[bytes_len * 2] = '\0';
}

/* 验证并获取16字节密钥 */
static int get_key_bytes(text *key_text, uint8_t *key_bytes)
{
    char *key_str = text_to_cstring(key_text);
    size_t key_len = strlen(key_str);

    if (key_len == 16) {
        /* 直接使用16字节字符串作为密钥 */
        memcpy(key_bytes, key_str, 16);
    } else if (key_len == 32) {
        /* 32字符十六进制字符串 */
        size_t bytes_len;
        if (hex_to_bytes(key_str, 32, key_bytes, &bytes_len) != 0) {
            memset(key_str, 0, key_len);
            pfree(key_str);
            return -1;
        }
    } else {
        memset(key_str, 0, key_len);
        pfree(key_str);
        return -1;
    }

    memset(key_str, 0, key_len);
    pfree(key_str);
    return 0;
}

/*
 * sm4_encrypt(plaintext text, key text) -> bytea
 * ECB模式加密，返回二进制数据
 */
extern "C" Datum
sm4_encrypt(PG_FUNCTION_ARGS)
{
    text *plaintext = PG_GETARG_TEXT_PP(0);
    text *key = PG_GETARG_TEXT_PP(1);
    uint8_t key_bytes[SM4_KEY_SIZE];
    char *plain_str;
    size_t plain_len;
    size_t cipher_len;
    uint8_t *cipher;
    bytea *result;

    /* ECB模式安全警告 (Feature-5) */
    ereport(WARNING,
            (errmsg("SM4 ECB mode is not recommended for production use. Consider using CBC or GCM mode.")));

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取明文 */
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);

    /* 空字符串检查 (Feature-1) */
    if (plain_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(plain_str);
        PG_RETURN_NULL();
    }

    /* 分配密文缓冲区(最大填充后长度) */
    cipher_len = plain_len + SM4_BLOCK_SIZE;
    cipher = (uint8_t *)palloc(cipher_len);

    /* 加密 */
    if (sm4_ecb_encrypt(key_bytes, (uint8_t *)plain_str, plain_len, cipher, &cipher_len) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(plain_str);
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 encryption failed")));
    }

    /* 构造bytea结果 */
    result = (bytea *)palloc(VARHDRSZ + cipher_len);
    SET_VARSIZE(result, VARHDRSZ + cipher_len);
    memcpy(VARDATA(result), cipher, cipher_len);

    /* 清零敏感数据 (Feature-4) */
    memset(key_bytes, 0, sizeof(key_bytes));
    pfree(plain_str);
    pfree(cipher);

    PG_RETURN_BYTEA_P(result);
}

/*
 * sm4_decrypt(ciphertext bytea, key text) -> text
 * ECB模式解密
 */
extern "C" Datum
sm4_decrypt(PG_FUNCTION_ARGS)
{
    bytea *ciphertext = PG_GETARG_BYTEA_PP(0);
    text *key = PG_GETARG_TEXT_PP(1);
    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t *cipher;
    size_t cipher_len;
    uint8_t *plain;
    size_t plain_len;
    text *result;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取密文 */
    cipher = (uint8_t *)VARDATA_ANY(ciphertext);
    cipher_len = VARSIZE_ANY_EXHDR(ciphertext);

    /* 空密文检查 (Feature-1) */
    if (cipher_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        PG_RETURN_NULL();
    }

    /* 分配明文缓冲区 */
    plain = (uint8_t *)palloc(cipher_len + 1);

    /* 解密 */
    if (sm4_ecb_decrypt(key_bytes, cipher, cipher_len, plain, &plain_len) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 decryption failed")));
    }

    plain[plain_len] = '\0';

    /* 构造text结果 */
    result = cstring_to_text((char *)plain);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    pfree(plain);

    PG_RETURN_TEXT_P(result);
}

/*
 * sm4_encrypt_cbc(plaintext text, key text, iv text) -> bytea
 * CBC模式加密
 */
extern "C" Datum
sm4_encrypt_cbc(PG_FUNCTION_ARGS)
{
    text *plaintext = PG_GETARG_TEXT_PP(0);
    text *key = PG_GETARG_TEXT_PP(1);
    text *iv_text = PG_GETARG_TEXT_PP(2);
    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t iv_bytes[SM4_BLOCK_SIZE];
    char *plain_str;
    char *iv_str;
    size_t plain_len;
    size_t cipher_len;
    size_t iv_len;
    uint8_t *cipher;
    bytea *result;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取IV */
    iv_str = text_to_cstring(iv_text);
    iv_len = strlen(iv_str);
    if (iv_len == 16) {
        memcpy(iv_bytes, iv_str, 16);
    } else if (iv_len == 32) {
        size_t bytes_len;
        if (hex_to_bytes(iv_str, 32, iv_bytes, &bytes_len) != 0) {
            memset(iv_str, 0, iv_len);
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 IV must be 16 bytes or 32 hex characters")));
        }
    } else {
        memset(iv_str, 0, iv_len);
        pfree(iv_str);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 IV must be 16 bytes or 32 hex characters")));
    }
    memset(iv_str, 0, iv_len);
    pfree(iv_str);

    /* 获取明文 */
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);

    /* 空字符串检查 (Feature-1) */
    if (plain_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        pfree(plain_str);
        PG_RETURN_NULL();
    }

    /* 分配密文缓冲区 */
    cipher_len = plain_len + SM4_BLOCK_SIZE;
    cipher = (uint8_t *)palloc(cipher_len);

    /* 加密 */
    if (sm4_cbc_encrypt(key_bytes, iv_bytes, (uint8_t *)plain_str, plain_len, cipher, &cipher_len) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        pfree(plain_str);
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 CBC encryption failed")));
    }

    /* 构造bytea结果 */
    result = (bytea *)palloc(VARHDRSZ + cipher_len);
    SET_VARSIZE(result, VARHDRSZ + cipher_len);
    memcpy(VARDATA(result), cipher, cipher_len);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    pfree(plain_str);
    pfree(cipher);

    PG_RETURN_BYTEA_P(result);
}

/*
 * sm4_decrypt_cbc(ciphertext bytea, key text, iv text) -> text
 * CBC模式解密
 */
extern "C" Datum
sm4_decrypt_cbc(PG_FUNCTION_ARGS)
{
    bytea *ciphertext = PG_GETARG_BYTEA_PP(0);
    text *key = PG_GETARG_TEXT_PP(1);
    text *iv_text = PG_GETARG_TEXT_PP(2);
    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t iv_bytes[SM4_BLOCK_SIZE];
    uint8_t *cipher;
    char *iv_str;
    size_t cipher_len;
    size_t iv_len;
    uint8_t *plain;
    size_t plain_len;
    text *result;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取IV */
    iv_str = text_to_cstring(iv_text);
    iv_len = strlen(iv_str);
    if (iv_len == 16) {
        memcpy(iv_bytes, iv_str, 16);
    } else if (iv_len == 32) {
        size_t bytes_len;
        if (hex_to_bytes(iv_str, 32, iv_bytes, &bytes_len) != 0) {
            memset(iv_str, 0, iv_len);
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 IV must be 16 bytes or 32 hex characters")));
        }
    } else {
        memset(iv_str, 0, iv_len);
        pfree(iv_str);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 IV must be 16 bytes or 32 hex characters")));
    }
    memset(iv_str, 0, iv_len);
    pfree(iv_str);

    /* 获取密文 */
    cipher = (uint8_t *)VARDATA_ANY(ciphertext);
    cipher_len = VARSIZE_ANY_EXHDR(ciphertext);

    /* 空密文检查 */
    if (cipher_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        PG_RETURN_NULL();
    }

    /* 分配明文缓冲区 */
    plain = (uint8_t *)palloc(cipher_len + 1);

    /* 解密 */
    if (sm4_cbc_decrypt(key_bytes, iv_bytes, cipher, cipher_len, plain, &plain_len) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 CBC decryption failed")));
    }

    plain[plain_len] = '\0';

    /* 构造text结果 */
    result = cstring_to_text((char *)plain);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    pfree(plain);

    PG_RETURN_TEXT_P(result);
}

/*
 * sm4_encrypt_hex(plaintext text, key text) -> text
 * ECB模式加密，返回十六进制字符串
 */
extern "C" Datum
sm4_encrypt_hex(PG_FUNCTION_ARGS)
{
    text *plaintext = PG_GETARG_TEXT_PP(0);
    text *key = PG_GETARG_TEXT_PP(1);
    uint8_t key_bytes[SM4_KEY_SIZE];
    char *plain_str;
    size_t plain_len;
    size_t cipher_len;
    uint8_t *cipher;
    char *hex_str;
    text *result;

    /* ECB模式安全警告 */
    ereport(WARNING,
            (errmsg("SM4 ECB mode is not recommended for production use. Consider using CBC or GCM mode.")));

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取明文 */
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);

    /* 空字符串检查 */
    if (plain_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(plain_str);
        PG_RETURN_NULL();
    }

    /* 分配密文缓冲区 */
    cipher_len = plain_len + SM4_BLOCK_SIZE;
    cipher = (uint8_t *)palloc(cipher_len);

    /* 加密 */
    if (sm4_ecb_encrypt(key_bytes, (uint8_t *)plain_str, plain_len, cipher, &cipher_len) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(plain_str);
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 encryption failed")));
    }

    /* 转换为十六进制字符串 */
    hex_str = (char *)palloc(cipher_len * 2 + 1);
    bytes_to_hex(cipher, cipher_len, hex_str);

    result = cstring_to_text(hex_str);

    memset(key_bytes, 0, sizeof(key_bytes));
    pfree(plain_str);
    pfree(cipher);
    pfree(hex_str);

    PG_RETURN_TEXT_P(result);
}

/*
 * sm4_decrypt_hex(ciphertext_hex text, key text) -> text
 * ECB模式解密，输入为十六进制字符串
 */
extern "C" Datum
sm4_decrypt_hex(PG_FUNCTION_ARGS)
{
    text *ciphertext_hex = PG_GETARG_TEXT_PP(0);
    text *key = PG_GETARG_TEXT_PP(1);
    uint8_t key_bytes[SM4_KEY_SIZE];
    char *hex_str;
    size_t hex_len;
    uint8_t *cipher;
    size_t cipher_len;
    uint8_t *plain;
    size_t plain_len;
    text *result;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取十六进制密文 */
    hex_str = text_to_cstring(ciphertext_hex);
    hex_len = strlen(hex_str);

    /* 空密文检查 */
    if (hex_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(hex_str);
        PG_RETURN_NULL();
    }

    /* 转换为字节数组 */
    cipher = (uint8_t *)palloc(hex_len / 2);
    if (hex_to_bytes(hex_str, hex_len, cipher, &cipher_len) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(hex_str);
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid hex string")));
    }

    /* 分配明文缓冲区 */
    plain = (uint8_t *)palloc(cipher_len + 1);

    /* 解密 */
    if (sm4_ecb_decrypt(key_bytes, cipher, cipher_len, plain, &plain_len) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(hex_str);
        pfree(cipher);
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 decryption failed")));
    }

    plain[plain_len] = '\0';

    /* 构造text结果 */
    result = cstring_to_text((char *)plain);

    memset(key_bytes, 0, sizeof(key_bytes));
    pfree(hex_str);
    pfree(cipher);
    pfree(plain);

    PG_RETURN_TEXT_P(result);
}

/*
 * sm4_encrypt_gcm(plaintext text, key text, iv text, aad text) -> bytea
 * GCM模式加密，返回密文+Tag（16字节）
 */
extern "C" Datum
sm4_encrypt_gcm(PG_FUNCTION_ARGS)
{
    text *plaintext;
    text *key;
    text *iv_text;
    text *aad_text;

    /* NULL输入检查 */
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2))
        PG_RETURN_NULL();

    plaintext = PG_GETARG_TEXT_PP(0);
    key = PG_GETARG_TEXT_PP(1);
    iv_text = PG_GETARG_TEXT_PP(2);
    aad_text = PG_ARGISNULL(3) ? NULL : PG_GETARG_TEXT_PP(3);

    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t iv_bytes[SM4_BLOCK_SIZE];  /* 最大支持16字节IV */
    char *plain_str;
    char *iv_str;
    size_t plain_len;
    size_t iv_len;
    size_t iv_bytes_len;  /* 实际IV字节长度 */
    uint8_t *cipher;
    uint8_t tag[SM4_GCM_TAG_SIZE];
    bytea *result;
    char *aad_str = NULL;
    size_t aad_len = 0;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取IV - 支持12字节（推荐）或16字节 */
    iv_str = text_to_cstring(iv_text);
    iv_len = strlen(iv_str);
    
    if (iv_len == 12) {
        /* 12字节原始字符串（推荐） */
        memcpy(iv_bytes, iv_str, 12);
        iv_bytes_len = 12;
    } else if (iv_len == 16) {
        /* 16字节原始字符串 */
        memcpy(iv_bytes, iv_str, 16);
        iv_bytes_len = 16;
    } else if (iv_len == 24) {
        /* 24位十六进制字符串 -> 12字节 */
        if (hex_to_bytes(iv_str, 24, iv_bytes, &iv_bytes_len) != 0 || iv_bytes_len != 12) {
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 GCM IV: 24 hex characters must decode to 12 bytes")));
        }
    } else if (iv_len == 32) {
        /* 32位十六进制字符串 -> 16字节 */
        if (hex_to_bytes(iv_str, 32, iv_bytes, &iv_bytes_len) != 0 || iv_bytes_len != 16) {
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 GCM IV: 32 hex characters must decode to 16 bytes")));
        }
    } else {
        memset(iv_str, 0, iv_len);
        pfree(iv_str);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 GCM IV must be 12 or 16 bytes (or 24/32 hex characters)")));
    }
    memset(iv_str, 0, iv_len);
    pfree(iv_str);

    /* 获取AAD (可选) */
    if (aad_text) {
        aad_str = text_to_cstring(aad_text);
        aad_len = strlen(aad_str);
    }

    /* 获取明文 */
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);

    /* 空字符串检查 (Feature-1) */
    if (plain_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(plain_str);
        PG_RETURN_NULL();
    }

    /* 分配密文缓冲区 */
    cipher = (uint8_t *)palloc(plain_len);

    /* 加密 */
    if (sm4_gcm_encrypt(key_bytes, iv_bytes, iv_bytes_len,
                        (uint8_t *)aad_str, aad_len,
                        (uint8_t *)plain_str, plain_len,
                        cipher, tag) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        pfree(plain_str);
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 GCM encryption failed")));
    }

    /* 构造bytea结果: 密文 + Tag */
    result = (bytea *)palloc(VARHDRSZ + plain_len + SM4_GCM_TAG_SIZE);
    SET_VARSIZE(result, VARHDRSZ + plain_len + SM4_GCM_TAG_SIZE);
    memcpy(VARDATA(result), cipher, plain_len);
    memcpy(VARDATA(result) + plain_len, tag, SM4_GCM_TAG_SIZE);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    memset(tag, 0, sizeof(tag));
    pfree(plain_str);
    if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
    pfree(cipher);

    PG_RETURN_BYTEA_P(result);
}

/*
 * sm4_decrypt_gcm(ciphertext_with_tag bytea, key text, iv text, aad text) -> text
 * GCM模式解密
 */
extern "C" Datum
sm4_decrypt_gcm(PG_FUNCTION_ARGS)
{
    bytea *ciphertext_with_tag;
    text *key;
    text *iv_text;
    text *aad_text;

    /* NULL输入检查 */
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2))
        PG_RETURN_NULL();

    ciphertext_with_tag = PG_GETARG_BYTEA_PP(0);
    key = PG_GETARG_TEXT_PP(1);
    iv_text = PG_GETARG_TEXT_PP(2);
    aad_text = PG_ARGISNULL(3) ? NULL : PG_GETARG_TEXT_PP(3);

    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t iv_bytes[SM4_BLOCK_SIZE];  /* 最大支持16字节IV */
    uint8_t *cipher_with_tag;
    char *iv_str;
    size_t cipher_with_tag_len;
    size_t cipher_len;
    size_t iv_len;
    size_t iv_bytes_len;  /* 实际IV字节长度 */
    uint8_t *cipher;
    uint8_t *tag;
    uint8_t *plain;
    text *result;
    char *aad_str = NULL;
    size_t aad_len = 0;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取IV - 支持12字节（推荐）或16字节 */
    iv_str = text_to_cstring(iv_text);
    iv_len = strlen(iv_str);
    
    if (iv_len == 12) {
        /* 12字节原始字符串（推荐） */
        memcpy(iv_bytes, iv_str, 12);
        iv_bytes_len = 12;
    } else if (iv_len == 16) {
        /* 16字节原始字符串 */
        memcpy(iv_bytes, iv_str, 16);
        iv_bytes_len = 16;
    } else if (iv_len == 24) {
        /* 24位十六进制字符串 -> 12字节 */
        if (hex_to_bytes(iv_str, 24, iv_bytes, &iv_bytes_len) != 0 || iv_bytes_len != 12) {
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 GCM IV: 24 hex characters must decode to 12 bytes")));
        }
    } else if (iv_len == 32) {
        /* 32位十六进制字符串 -> 16字节 */
        if (hex_to_bytes(iv_str, 32, iv_bytes, &iv_bytes_len) != 0 || iv_bytes_len != 16) {
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 GCM IV: 32 hex characters must decode to 16 bytes")));
        }
    } else {
        memset(iv_str, 0, iv_len);
        pfree(iv_str);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 GCM IV must be 12 or 16 bytes (or 24/32 hex characters)")));
    }
    memset(iv_str, 0, iv_len);
    pfree(iv_str);

    /* 获取AAD */
    if (aad_text) {
        aad_str = text_to_cstring(aad_text);
        aad_len = strlen(aad_str);
    }

    /* 获取密文+Tag */
    cipher_with_tag = (uint8_t *)VARDATA_ANY(ciphertext_with_tag);
    cipher_with_tag_len = VARSIZE_ANY_EXHDR(ciphertext_with_tag);

    /* 空密文检查 */
    if (cipher_with_tag_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        PG_RETURN_NULL();
    }

    /* 检查长度 */
    if (cipher_with_tag_len < SM4_GCM_TAG_SIZE) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid ciphertext length for GCM decryption")));
    }

    cipher_len = cipher_with_tag_len - SM4_GCM_TAG_SIZE;
    cipher = cipher_with_tag;
    tag = cipher_with_tag + cipher_len;

    /* 分配明文缓冲区 */
    plain = (uint8_t *)palloc(cipher_len + 1);

    /* 解密 */
    if (sm4_gcm_decrypt(key_bytes, iv_bytes, iv_bytes_len,
                        (uint8_t *)aad_str, aad_len,
                        cipher, cipher_len,
                        tag, plain) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 GCM decryption failed or authentication failed")));
    }

    plain[cipher_len] = '\0';

    /* 构造text结果 */
    result = cstring_to_text((char *)plain);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
    pfree(plain);

    PG_RETURN_TEXT_P(result);
}

/* Base64 编码辅助函数 */
static char* base64_encode(const uint8_t *data, size_t len)
{
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = ((len + 2) / 3) * 4;
    char *out = (char *)palloc(out_len + 1);
    size_t i, j = 0;

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
    return out;
}

/* Base64 解码辅助函数 */
static uint8_t* base64_decode(const char *input, size_t *out_len)
{
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

    size_t in_len = strlen(input);
    if (in_len % 4 != 0) {
        *out_len = 0;
        return NULL;
    }

    size_t padding = 0;
    if (in_len >= 2 && input[in_len - 1] == '=') padding++;
    if (in_len >= 2 && input[in_len - 2] == '=') padding++;

    *out_len = (in_len / 4) * 3 - padding;
    uint8_t *out = (uint8_t *)palloc(*out_len);
    size_t i, j = 0;

    for (i = 0; i < in_len; i += 4) {
        uint32_t val = 0;
        uint8_t d0, d1, d2, d3;

        d0 = base64_decode_table[(uint8_t)input[i]];
        d1 = base64_decode_table[(uint8_t)input[i + 1]];
        d2 = (input[i + 2] != '=') ? base64_decode_table[(uint8_t)input[i + 2]] : 0;
        d3 = (input[i + 3] != '=') ? base64_decode_table[(uint8_t)input[i + 3]] : 0;

        /* 检查非法字符（查找表中非法字符映射为64） */
        if (d0 == 64 || d1 == 64 ||
            (input[i + 2] != '=' && d2 == 64) ||
            (input[i + 3] != '=' && d3 == 64)) {
            pfree(out);
            *out_len = 0;
            return NULL;
        }

        val = ((uint32_t)d0 << 18) | ((uint32_t)d1 << 12) |
              ((uint32_t)d2 << 6) | (uint32_t)d3;

        out[j++] = (val >> 16) & 0xFF;
        if (input[i + 2] != '=' && j < *out_len) out[j++] = (val >> 8) & 0xFF;
        if (input[i + 3] != '=' && j < *out_len) out[j++] = val & 0xFF;
    }

    return out;
}

/*
 * sm4_c_encrypt_gcm_base64(plaintext text, key text, iv text, aad text) -> text
 * GCM模式加密，返回Base64编码的密文+Tag
 */
extern "C" Datum
sm4_encrypt_gcm_base64(PG_FUNCTION_ARGS)
{
    text *plaintext;
    text *key;
    text *iv_text;
    text *aad_text;

    /* NULL输入检查 */
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2))
        PG_RETURN_NULL();

    plaintext = PG_GETARG_TEXT_PP(0);
    key = PG_GETARG_TEXT_PP(1);
    iv_text = PG_GETARG_TEXT_PP(2);
    aad_text = PG_ARGISNULL(3) ? NULL : PG_GETARG_TEXT_PP(3);

    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t iv_bytes[SM4_BLOCK_SIZE];
    char *plain_str;
    char *iv_str;
    size_t plain_len;
    size_t iv_len;
    size_t iv_bytes_len;
    uint8_t *cipher;
    uint8_t tag[SM4_GCM_TAG_SIZE];
    uint8_t *cipher_with_tag;
    char *base64_result;
    text *result;
    char *aad_str = NULL;
    size_t aad_len = 0;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取IV - 支持12字节（推荐）或16字节 */
    iv_str = text_to_cstring(iv_text);
    iv_len = strlen(iv_str);
    
    if (iv_len == 12) {
        memcpy(iv_bytes, iv_str, 12);
        iv_bytes_len = 12;
    } else if (iv_len == 16) {
        memcpy(iv_bytes, iv_str, 16);
        iv_bytes_len = 16;
    } else if (iv_len == 24) {
        if (hex_to_bytes(iv_str, 24, iv_bytes, &iv_bytes_len) != 0 || iv_bytes_len != 12) {
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 GCM IV: 24 hex characters must decode to 12 bytes")));
        }
    } else if (iv_len == 32) {
        if (hex_to_bytes(iv_str, 32, iv_bytes, &iv_bytes_len) != 0 || iv_bytes_len != 16) {
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 GCM IV: 32 hex characters must decode to 16 bytes")));
        }
    } else {
        memset(iv_str, 0, iv_len);
        pfree(iv_str);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 GCM IV must be 12 or 16 bytes (or 24/32 hex characters)")));
    }
    memset(iv_str, 0, iv_len);
    pfree(iv_str);

    /* 获取AAD */
    if (aad_text) {
        aad_str = text_to_cstring(aad_text);
        aad_len = strlen(aad_str);
    }

    /* 获取明文 */
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);

    /* 空字符串检查 */
    if (plain_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(plain_str);
        PG_RETURN_NULL();
    }

    /* 分配密文缓冲区 */
    cipher = (uint8_t *)palloc(plain_len);

    /* 加密 */
    if (sm4_gcm_encrypt(key_bytes, iv_bytes, iv_bytes_len,
                        (uint8_t *)aad_str, aad_len,
                        (uint8_t *)plain_str, plain_len,
                        cipher, tag) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        pfree(plain_str);
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 GCM encryption failed")));
    }

    /* 构造密文+Tag */
    cipher_with_tag = (uint8_t *)palloc(plain_len + SM4_GCM_TAG_SIZE);
    memcpy(cipher_with_tag, cipher, plain_len);
    memcpy(cipher_with_tag + plain_len, tag, SM4_GCM_TAG_SIZE);

    /* Base64编码 */
    base64_result = base64_encode(cipher_with_tag, plain_len + SM4_GCM_TAG_SIZE);

    /* 构造text结果 */
    result = cstring_to_text(base64_result);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    memset(tag, 0, sizeof(tag));
    pfree(plain_str);
    if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
    pfree(cipher);
    pfree(cipher_with_tag);
    pfree(base64_result);

    PG_RETURN_TEXT_P(result);
}

/*
 * sm4_c_decrypt_gcm_base64(ciphertext_base64 text, key text, iv text, aad text) -> text
 * GCM模式解密，接收Base64编码的密文+Tag
 */
extern "C" Datum
sm4_decrypt_gcm_base64(PG_FUNCTION_ARGS)
{
    text *ciphertext_base64;
    text *key;
    text *iv_text;
    text *aad_text;

    /* NULL输入检查 */
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2))
        PG_RETURN_NULL();

    ciphertext_base64 = PG_GETARG_TEXT_PP(0);
    key = PG_GETARG_TEXT_PP(1);
    iv_text = PG_GETARG_TEXT_PP(2);
    aad_text = PG_ARGISNULL(3) ? NULL : PG_GETARG_TEXT_PP(3);

    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t iv_bytes[SM4_BLOCK_SIZE];
    char *cipher_base64_str;
    uint8_t *cipher_with_tag;
    size_t cipher_with_tag_len;
    char *iv_str;
    size_t cipher_len;
    size_t iv_len;
    size_t iv_bytes_len;
    uint8_t *cipher;
    uint8_t *tag;
    uint8_t *plain;
    text *result;
    char *aad_str = NULL;
    size_t aad_len = 0;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取IV */
    iv_str = text_to_cstring(iv_text);
    iv_len = strlen(iv_str);
    
    if (iv_len == 12) {
        memcpy(iv_bytes, iv_str, 12);
        iv_bytes_len = 12;
    } else if (iv_len == 16) {
        memcpy(iv_bytes, iv_str, 16);
        iv_bytes_len = 16;
    } else if (iv_len == 24) {
        if (hex_to_bytes(iv_str, 24, iv_bytes, &iv_bytes_len) != 0 || iv_bytes_len != 12) {
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 GCM IV: 24 hex characters must decode to 12 bytes")));
        }
    } else if (iv_len == 32) {
        if (hex_to_bytes(iv_str, 32, iv_bytes, &iv_bytes_len) != 0 || iv_bytes_len != 16) {
            pfree(iv_str);
            ereport(ERROR,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("SM4 GCM IV: 32 hex characters must decode to 16 bytes")));
        }
    } else {
        memset(iv_str, 0, iv_len);
        pfree(iv_str);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 GCM IV must be 12 or 16 bytes (or 24/32 hex characters)")));
    }
    memset(iv_str, 0, iv_len);
    pfree(iv_str);

    /* 获取AAD */
    if (aad_text) {
        aad_str = text_to_cstring(aad_text);
        aad_len = strlen(aad_str);
    }

    /* 空密文检查 */
    {
        size_t b64_len = VARSIZE_ANY_EXHDR(ciphertext_base64);
        if (b64_len == 0) {
            memset(key_bytes, 0, sizeof(key_bytes));
            memset(iv_bytes, 0, sizeof(iv_bytes));
            if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
            PG_RETURN_NULL();
        }
    }

    /* Base64解码 */
    cipher_base64_str = text_to_cstring(ciphertext_base64);
    cipher_with_tag = base64_decode(cipher_base64_str, &cipher_with_tag_len);
    pfree(cipher_base64_str);

    if (!cipher_with_tag) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid Base64 encoded ciphertext")));
    }

    /* 检查长度 */
    if (cipher_with_tag_len < SM4_GCM_TAG_SIZE) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(cipher_with_tag);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid ciphertext length for GCM decryption")));
    }

    cipher_len = cipher_with_tag_len - SM4_GCM_TAG_SIZE;
    cipher = cipher_with_tag;
    tag = cipher_with_tag + cipher_len;

    /* 分配明文缓冲区 */
    plain = (uint8_t *)palloc(cipher_len + 1);

    /* 解密 */
    if (sm4_gcm_decrypt(key_bytes, iv_bytes, iv_bytes_len,
                        (uint8_t *)aad_str, aad_len,
                        cipher, cipher_len,
                        tag, plain) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(cipher_with_tag);
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 GCM decryption failed or authentication failed")));
    }

    plain[cipher_len] = '\0';

    /* 构造text结果 */
    result = cstring_to_text((char *)plain);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
    pfree(cipher_with_tag);
    pfree(plain);

    PG_RETURN_TEXT_P(result);
}

/*
 * sm4_encrypt_gcm_auto_iv(plaintext text, key text, aad text) -> bytea
 * GCM模式加密，自动生成12字节随机IV，返回 IV(12) + 密文 + Tag(16)
 */
extern "C" Datum
sm4_encrypt_gcm_auto_iv(PG_FUNCTION_ARGS)
{
    text *plaintext;
    text *key;
    text *aad_text;

    /* NULL输入检查 */
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
        PG_RETURN_NULL();

    plaintext = PG_GETARG_TEXT_PP(0);
    key = PG_GETARG_TEXT_PP(1);
    aad_text = PG_ARGISNULL(2) ? NULL : PG_GETARG_TEXT_PP(2);

    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t iv_bytes[SM4_GCM_IV_SIZE];
    char *plain_str;
    size_t plain_len;
    uint8_t *cipher;
    uint8_t tag[SM4_GCM_TAG_SIZE];
    bytea *result;
    char *aad_str = NULL;
    size_t aad_len = 0;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取AAD */
    if (aad_text) {
        aad_str = text_to_cstring(aad_text);
        aad_len = strlen(aad_str);
    }

    /* 获取明文 */
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);

    /* 空字符串检查 */
    if (plain_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(plain_str);
        PG_RETURN_NULL();
    }

    /* 自动生成12字节随机IV */
    if (RAND_bytes(iv_bytes, SM4_GCM_IV_SIZE) != 1) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(plain_str);
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("Failed to generate random IV")));
    }

    /* 分配密文缓冲区 */
    cipher = (uint8_t *)palloc(plain_len);

    /* 加密 */
    if (sm4_gcm_encrypt(key_bytes, iv_bytes, SM4_GCM_IV_SIZE,
                        (uint8_t *)aad_str, aad_len,
                        (uint8_t *)plain_str, plain_len,
                        cipher, tag) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        pfree(plain_str);
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 GCM encryption failed")));
    }

    /* 构造bytea结果: IV(12) + 密文 + Tag(16) */
    result = (bytea *)palloc(VARHDRSZ + SM4_GCM_IV_SIZE + plain_len + SM4_GCM_TAG_SIZE);
    SET_VARSIZE(result, VARHDRSZ + SM4_GCM_IV_SIZE + plain_len + SM4_GCM_TAG_SIZE);
    memcpy(VARDATA(result), iv_bytes, SM4_GCM_IV_SIZE);
    memcpy(VARDATA(result) + SM4_GCM_IV_SIZE, cipher, plain_len);
    memcpy(VARDATA(result) + SM4_GCM_IV_SIZE + plain_len, tag, SM4_GCM_TAG_SIZE);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    memset(tag, 0, sizeof(tag));
    pfree(plain_str);
    if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
    pfree(cipher);

    PG_RETURN_BYTEA_P(result);
}

/*
 * sm4_decrypt_gcm_auto_iv(ciphertext bytea, key text, aad text) -> text
 * GCM模式解密，从输入中提取前12字节作为IV
 */
extern "C" Datum
sm4_decrypt_gcm_auto_iv(PG_FUNCTION_ARGS)
{
    bytea *ciphertext;
    text *key;
    text *aad_text;

    /* NULL输入检查 */
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
        PG_RETURN_NULL();

    ciphertext = PG_GETARG_BYTEA_PP(0);
    key = PG_GETARG_TEXT_PP(1);
    aad_text = PG_ARGISNULL(2) ? NULL : PG_GETARG_TEXT_PP(2);

    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t *data;
    size_t data_len;
    uint8_t iv_bytes[SM4_GCM_IV_SIZE];
    uint8_t *cipher;
    size_t cipher_len;
    uint8_t *tag;
    uint8_t *plain;
    text *result;
    char *aad_str = NULL;
    size_t aad_len = 0;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取AAD */
    if (aad_text) {
        aad_str = text_to_cstring(aad_text);
        aad_len = strlen(aad_str);
    }

    /* 获取密文数据 */
    data = (uint8_t *)VARDATA_ANY(ciphertext);
    data_len = VARSIZE_ANY_EXHDR(ciphertext);

    /* 空密文检查 */
    if (data_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        PG_RETURN_NULL();
    }

    /* 检查最小长度: IV(12) + Tag(16) = 28 */
    if (data_len < SM4_GCM_IV_SIZE + SM4_GCM_TAG_SIZE) {
        memset(key_bytes, 0, sizeof(key_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid ciphertext length: must be at least 28 bytes (IV + Tag)")));
    }

    /* 提取IV、密文、Tag */
    memcpy(iv_bytes, data, SM4_GCM_IV_SIZE);
    cipher = data + SM4_GCM_IV_SIZE;
    cipher_len = data_len - SM4_GCM_IV_SIZE - SM4_GCM_TAG_SIZE;
    tag = data + SM4_GCM_IV_SIZE + cipher_len;

    /* 分配明文缓冲区 */
    plain = (uint8_t *)palloc(cipher_len + 1);

    /* 解密 */
    if (sm4_gcm_decrypt(key_bytes, iv_bytes, SM4_GCM_IV_SIZE,
                        (uint8_t *)aad_str, aad_len,
                        cipher, cipher_len,
                        tag, plain) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 GCM decryption failed or authentication failed")));
    }

    plain[cipher_len] = '\0';

    /* 构造text结果 */
    result = cstring_to_text((char *)plain);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
    pfree(plain);

    PG_RETURN_TEXT_P(result);
}

/*
 * sm4_encrypt_gcm_auto_iv_base64(plaintext text, key text, aad text) -> text
 * GCM模式加密，自动生成IV，返回Base64编码的 IV+密文+Tag
 */
extern "C" Datum
sm4_encrypt_gcm_auto_iv_base64(PG_FUNCTION_ARGS)
{
    text *plaintext;
    text *key;
    text *aad_text;

    /* NULL输入检查 */
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
        PG_RETURN_NULL();

    plaintext = PG_GETARG_TEXT_PP(0);
    key = PG_GETARG_TEXT_PP(1);
    aad_text = PG_ARGISNULL(2) ? NULL : PG_GETARG_TEXT_PP(2);

    uint8_t key_bytes[SM4_KEY_SIZE];
    uint8_t iv_bytes[SM4_GCM_IV_SIZE];
    char *plain_str;
    size_t plain_len;
    uint8_t *cipher;
    uint8_t tag[SM4_GCM_TAG_SIZE];
    uint8_t *iv_cipher_tag;
    char *base64_result;
    text *result;
    char *aad_str = NULL;
    size_t aad_len = 0;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取AAD */
    if (aad_text) {
        aad_str = text_to_cstring(aad_text);
        aad_len = strlen(aad_str);
    }

    /* 获取明文 */
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);

    /* 空字符串检查 */
    if (plain_len == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(plain_str);
        PG_RETURN_NULL();
    }

    /* 自动生成12字节随机IV */
    if (RAND_bytes(iv_bytes, SM4_GCM_IV_SIZE) != 1) {
        memset(key_bytes, 0, sizeof(key_bytes));
        pfree(plain_str);
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("Failed to generate random IV")));
    }

    /* 分配密文缓冲区 */
    cipher = (uint8_t *)palloc(plain_len);

    /* 加密 */
    if (sm4_gcm_encrypt(key_bytes, iv_bytes, SM4_GCM_IV_SIZE,
                        (uint8_t *)aad_str, aad_len,
                        (uint8_t *)plain_str, plain_len,
                        cipher, tag) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        pfree(plain_str);
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 GCM encryption failed")));
    }

    /* 构造 IV + 密文 + Tag */
    iv_cipher_tag = (uint8_t *)palloc(SM4_GCM_IV_SIZE + plain_len + SM4_GCM_TAG_SIZE);
    memcpy(iv_cipher_tag, iv_bytes, SM4_GCM_IV_SIZE);
    memcpy(iv_cipher_tag + SM4_GCM_IV_SIZE, cipher, plain_len);
    memcpy(iv_cipher_tag + SM4_GCM_IV_SIZE + plain_len, tag, SM4_GCM_TAG_SIZE);

    /* Base64编码 */
    base64_result = base64_encode(iv_cipher_tag, SM4_GCM_IV_SIZE + plain_len + SM4_GCM_TAG_SIZE);

    /* 构造text结果 */
    result = cstring_to_text(base64_result);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    memset(tag, 0, sizeof(tag));
    pfree(plain_str);
    if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
    pfree(cipher);
    pfree(iv_cipher_tag);
    pfree(base64_result);

    PG_RETURN_TEXT_P(result);
}

/*
 * sm4_decrypt_gcm_auto_iv_base64(ciphertext_base64 text, key text, aad text) -> text
 * GCM模式解密，从Base64解码后提取前12字节作为IV
 */
extern "C" Datum
sm4_decrypt_gcm_auto_iv_base64(PG_FUNCTION_ARGS)
{
    text *ciphertext_base64;
    text *key;
    text *aad_text;

    /* NULL输入检查 */
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
        PG_RETURN_NULL();

    ciphertext_base64 = PG_GETARG_TEXT_PP(0);
    key = PG_GETARG_TEXT_PP(1);
    aad_text = PG_ARGISNULL(2) ? NULL : PG_GETARG_TEXT_PP(2);

    uint8_t key_bytes[SM4_KEY_SIZE];
    char *cipher_base64_str;
    uint8_t *data;
    size_t data_len;
    uint8_t iv_bytes[SM4_GCM_IV_SIZE];
    uint8_t *cipher;
    size_t cipher_len;
    uint8_t *tag;
    uint8_t *plain;
    text *result;
    char *aad_str = NULL;
    size_t aad_len = 0;

    /* 获取密钥 */
    if (get_key_bytes(key, key_bytes) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM4 key must be 16 bytes or 32 hex characters")));
    }

    /* 获取AAD */
    if (aad_text) {
        aad_str = text_to_cstring(aad_text);
        aad_len = strlen(aad_str);
    }

    /* 空密文检查 */
    {
        size_t b64_len = VARSIZE_ANY_EXHDR(ciphertext_base64);
        if (b64_len == 0) {
            memset(key_bytes, 0, sizeof(key_bytes));
            if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
            PG_RETURN_NULL();
        }
    }

    /* Base64解码 */
    cipher_base64_str = text_to_cstring(ciphertext_base64);
    data = base64_decode(cipher_base64_str, &data_len);
    pfree(cipher_base64_str);

    if (!data) {
        memset(key_bytes, 0, sizeof(key_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid Base64 encoded ciphertext")));
    }

    /* 检查最小长度: IV(12) + Tag(16) = 28 */
    if (data_len < SM4_GCM_IV_SIZE + SM4_GCM_TAG_SIZE) {
        memset(key_bytes, 0, sizeof(key_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(data);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid ciphertext length: must be at least 28 bytes (IV + Tag)")));
    }

    /* 提取IV、密文、Tag */
    memcpy(iv_bytes, data, SM4_GCM_IV_SIZE);
    cipher = data + SM4_GCM_IV_SIZE;
    cipher_len = data_len - SM4_GCM_IV_SIZE - SM4_GCM_TAG_SIZE;
    tag = data + SM4_GCM_IV_SIZE + cipher_len;

    /* 分配明文缓冲区 */
    plain = (uint8_t *)palloc(cipher_len + 1);

    /* 解密 */
    if (sm4_gcm_decrypt(key_bytes, iv_bytes, SM4_GCM_IV_SIZE,
                        (uint8_t *)aad_str, aad_len,
                        cipher, cipher_len,
                        tag, plain) != 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        memset(iv_bytes, 0, sizeof(iv_bytes));
        if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
        pfree(data);
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM4 GCM decryption failed or authentication failed")));
    }

    plain[cipher_len] = '\0';

    /* 构造text结果 */
    result = cstring_to_text((char *)plain);

    /* 清零敏感数据 */
    memset(key_bytes, 0, sizeof(key_bytes));
    memset(iv_bytes, 0, sizeof(iv_bytes));
    if (aad_str) { memset(aad_str, 0, aad_len); pfree(aad_str); }
    pfree(data);
    pfree(plain);

    PG_RETURN_TEXT_P(result);
}
