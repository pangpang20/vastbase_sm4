/*
 * SM2 Extension for VastBase/OpenGauss
 * PostgreSQL/OpenGauss 扩展接口 (基于 OpenSSL)
 * 
 * 高性能实现,使用 OpenSSL 优化的 SM2 算法
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "utils/array.h"
#include "catalog/pg_type.h"
#include "mb/pg_wchar.h"
#include "sm2_openssl.h"
#include <string.h>
#include <stdlib.h>

PG_MODULE_MAGIC;

/* 函数声明 */
PG_FUNCTION_INFO_V1(sm2_generate_key);
PG_FUNCTION_INFO_V1(sm2_get_pubkey);
PG_FUNCTION_INFO_V1(sm2_encrypt_func);
PG_FUNCTION_INFO_V1(sm2_decrypt_func);
PG_FUNCTION_INFO_V1(sm2_sign_func);
PG_FUNCTION_INFO_V1(sm2_verify_func);
PG_FUNCTION_INFO_V1(sm2_encrypt_hex);
PG_FUNCTION_INFO_V1(sm2_decrypt_hex);
PG_FUNCTION_INFO_V1(sm2_encrypt_base64);
PG_FUNCTION_INFO_V1(sm2_decrypt_base64);
PG_FUNCTION_INFO_V1(sm2_sign_hex);
PG_FUNCTION_INFO_V1(sm2_verify_hex);

/* 工具函数: 十六进制字符串转字节数组 */
static int hex_to_bytes(const char *hex, size_t hex_len, uint8_t *bytes, size_t *bytes_len)
{
    size_t i;
    size_t j = 0;
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

/* 验证并获取32字节私钥 */
static int get_private_key_bytes(text *key_text, uint8_t *key_bytes)
{
    char *key_str = text_to_cstring(key_text);
    size_t key_len = strlen(key_str);

    if (key_len == 32) {
        /* 直接使用32字节字符串作为私钥 */
        memcpy(key_bytes, key_str, 32);
    } else if (key_len == 64) {
        /* 64字符十六进制字符串 */
        size_t bytes_len;
        if (hex_to_bytes(key_str, 64, key_bytes, &bytes_len) != 0) {
            pfree(key_str);
            return -1;
        }
    } else {
        pfree(key_str);
        return -1;
    }

    pfree(key_str);
    return 0;
}

/* 验证并获取64字节公钥 */
static int get_public_key_bytes(text *key_text, uint8_t *key_bytes)
{
    char *key_str = text_to_cstring(key_text);
    size_t key_len = strlen(key_str);

    if (key_len == 64) {
        /* 直接使用64字节字符串作为公钥 */
        memcpy(key_bytes, key_str, 64);
    } else if (key_len == 128) {
        /* 128字符十六进制字符串 */
        size_t bytes_len;
        if (hex_to_bytes(key_str, 128, key_bytes, &bytes_len) != 0) {
            pfree(key_str);
            return -1;
        }
    } else if (key_len == 130 && key_str[0] == '0' && key_str[1] == '4') {
        /* 130字符十六进制字符串 (04 || X || Y格式) */
        size_t bytes_len;
        if (hex_to_bytes(key_str + 2, 128, key_bytes, &bytes_len) != 0) {
            pfree(key_str);
            return -1;
        }
    } else {
        pfree(key_str);
        return -1;
    }

    pfree(key_str);
    return 0;
}

/* Base64编码 */
static char* base64_encode_ext(const uint8_t *data, size_t len)
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

/* Base64解码 */
static uint8_t* base64_decode_ext(const char *input, size_t *out_len)
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
    out = (uint8_t *)palloc(*out_len);

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

/*
 * sm2_generate_key() -> text[]
 * 生成SM2密钥对，返回数组 [私钥hex, 公钥hex]
 */
extern "C" Datum
sm2_generate_key(PG_FUNCTION_ARGS)
{
    sm2_context ctx;
    uint8_t priv_key[32];
    uint8_t pub_key[64];
    char *priv_hex;
    char *pub_hex;
    Datum result[2];
    ArrayType *arr;
    
    sm2_init(&ctx);
    
    if (sm2_generate_keypair(&ctx) != 0) {
        sm2_free(&ctx);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM2 key generation failed")));
    }
    
    sm2_get_private_key(&ctx, priv_key);
    sm2_get_public_key(&ctx, pub_key);
    
    priv_hex = (char *)palloc(65);
    pub_hex = (char *)palloc(129);
    
    bytes_to_hex(priv_key, 32, priv_hex);
    bytes_to_hex(pub_key, 64, pub_hex);
    
    result[0] = PointerGetDatum(cstring_to_text(priv_hex));
    result[1] = PointerGetDatum(cstring_to_text(pub_hex));
    
    arr = construct_array(result, 2, TEXTOID, -1, false, 'i');
    
    pfree(priv_hex);
    pfree(pub_hex);
    sm2_free(&ctx);
    
    PG_RETURN_ARRAYTYPE_P(arr);
}

/*
 * sm2_get_pubkey(private_key text) -> text
 * 从私钥导出公钥
 */
extern "C" Datum
sm2_get_pubkey(PG_FUNCTION_ARGS)
{
    text *priv_key_text = PG_GETARG_TEXT_PP(0);
    uint8_t priv_key[32];
    uint8_t pub_key[64];
    char *pub_hex;
    sm2_context ctx;
    text *result;
    
    if (get_private_key_bytes(priv_key_text, priv_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 private key must be 32 bytes or 64 hex characters")));
    }
    
    sm2_init(&ctx);
    if (sm2_set_private_key(&ctx, priv_key) != 0) {
        sm2_free(&ctx);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid SM2 private key")));
    }
    
    sm2_derive_public_key(&ctx);
    sm2_get_public_key(&ctx, pub_key);
    
    pub_hex = (char *)palloc(129);
    bytes_to_hex(pub_key, 64, pub_hex);
    
    result = cstring_to_text(pub_hex);
    pfree(pub_hex);
    sm2_free(&ctx);
    
    PG_RETURN_TEXT_P(result);
}

/*
 * sm2_encrypt_hex(plaintext text, public_key text) -> text
 * SM2公钥加密，返回十六进制
 */
extern "C" Datum
sm2_encrypt_hex(PG_FUNCTION_ARGS)
{
    text *plaintext = PG_GETARG_TEXT_PP(0);
    text *pub_key_text = PG_GETARG_TEXT_PP(1);
    uint8_t pub_key[64];
    char *plain_str;
    size_t plain_len;
    uint8_t *cipher;
    size_t cipher_len;
    char *hex_str;
    text *result;
    
    if (get_public_key_bytes(pub_key_text, pub_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 public key must be 64 bytes or 128/130 hex characters")));
    }
    
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);
    
    cipher_len = plain_len + 200;  /* 预估密文长度 */
    cipher = (uint8_t *)palloc(cipher_len);
    
    if (sm2_encrypt(pub_key, (uint8_t *)plain_str, plain_len, cipher, &cipher_len) != 0) {
        pfree(plain_str);
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM2 encryption failed")));
    }
    
    hex_str = (char *)palloc(cipher_len * 2 + 1);
    bytes_to_hex(cipher, cipher_len, hex_str);
    
    result = cstring_to_text(hex_str);
    pfree(plain_str);
    pfree(cipher);
    pfree(hex_str);
    
    PG_RETURN_TEXT_P(result);
}

/*
 * sm2_decrypt_hex(ciphertext text, private_key text) -> text
 * SM2私钥解密十六进制密文
 */
extern "C" Datum
sm2_decrypt_hex(PG_FUNCTION_ARGS)
{
    text *ciphertext = PG_GETARG_TEXT_PP(0);
    text *priv_key_text = PG_GETARG_TEXT_PP(1);
    uint8_t priv_key[32];
    char *cipher_str;
    uint8_t *cipher;
    size_t cipher_len;
    uint8_t *plain;
    size_t plain_len;
    text *result;
    
    if (get_private_key_bytes(priv_key_text, priv_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 private key must be 32 bytes or 64 hex characters")));
    }
    
    cipher_str = text_to_cstring(ciphertext);
    cipher_len = strlen(cipher_str) / 2;
    cipher = (uint8_t *)palloc(cipher_len);
    
    if (hex_to_bytes(cipher_str, strlen(cipher_str), cipher, &cipher_len) != 0) {
        pfree(cipher_str);
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid hex ciphertext")));
    }
    
    /* SM2 最大明文长度 255 字节，分配 256 字节缓冶区 (+1 为结束符) */
    plain_len = 256;
    plain = (uint8_t *)palloc(plain_len + 1);
    
    if (sm2_decrypt(priv_key, cipher, cipher_len, plain, &plain_len) != 0) {
        pfree(cipher_str);
        pfree(cipher);
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM2 decryption failed")));
    }
    
    plain[plain_len] = '\0';  /* 现在安全了 */
    result = cstring_to_text((char *)plain);
    pfree(cipher_str);
    pfree(cipher);
    pfree(plain);
    
    PG_RETURN_TEXT_P(result);
}

/*
 * sm2_encrypt_base64(plaintext text, public_key text) -> text
 * SM2公钥加密，返回Base64
 */
extern "C" Datum
sm2_encrypt_base64(PG_FUNCTION_ARGS)
{
    text *plaintext = PG_GETARG_TEXT_PP(0);
    text *pub_key_text = PG_GETARG_TEXT_PP(1);
    uint8_t pub_key[64];
    char *plain_str;
    size_t plain_len;
    uint8_t *cipher;
    size_t cipher_len;
    char *b64_str;
    text *result;
    
    if (get_public_key_bytes(pub_key_text, pub_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 public key must be 64 bytes or 128/130 hex characters")));
    }
    
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);
    
    cipher_len = plain_len + 200;
    cipher = (uint8_t *)palloc(cipher_len);
    
    if (sm2_encrypt(pub_key, (uint8_t *)plain_str, plain_len, cipher, &cipher_len) != 0) {
        pfree(plain_str);
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM2 encryption failed")));
    }
    
    b64_str = base64_encode_ext(cipher, cipher_len);
    result = cstring_to_text(b64_str);
    
    pfree(plain_str);
    pfree(cipher);
    pfree(b64_str);
    
    PG_RETURN_TEXT_P(result);
}

/*
 * sm2_decrypt_base64(ciphertext text, private_key text) -> text
 * SM2私钥解密Base64密文
 */
extern "C" Datum
sm2_decrypt_base64(PG_FUNCTION_ARGS)
{
    text *ciphertext = PG_GETARG_TEXT_PP(0);
    text *priv_key_text = PG_GETARG_TEXT_PP(1);
    uint8_t priv_key[32];
    char *cipher_str;
    uint8_t *cipher;
    size_t cipher_len;
    uint8_t *plain;
    size_t plain_len;
    text *result;
    
    if (get_private_key_bytes(priv_key_text, priv_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 private key must be 32 bytes or 64 hex characters")));
    }
    
    cipher_str = text_to_cstring(ciphertext);
    cipher = base64_decode_ext(cipher_str, &cipher_len);
    
    if (!cipher) {
        pfree(cipher_str);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid base64 ciphertext")));
    }
    
    /* SM2 最大明文长度 255 字节，分配 256 字节缓冶区 (+1 为结束符) */
    plain_len = 256;
    plain = (uint8_t *)palloc(plain_len + 1);
    
    if (sm2_decrypt(priv_key, cipher, cipher_len, plain, &plain_len) != 0) {
        pfree(cipher_str);
        pfree(cipher);
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM2 decryption failed")));
    }
    
    plain[plain_len] = '\0';  /* 现在安全了 */
    result = cstring_to_text((char *)plain);
    pfree(cipher_str);
    pfree(cipher);
    pfree(plain);
    
    PG_RETURN_TEXT_P(result);
}

/*
 * sm2_encrypt_func(plaintext text, public_key text) -> bytea
 * SM2公钥加密，返回bytea
 */
extern "C" Datum
sm2_encrypt_func(PG_FUNCTION_ARGS)
{
    text *plaintext = PG_GETARG_TEXT_PP(0);
    text *pub_key_text = PG_GETARG_TEXT_PP(1);
    uint8_t pub_key[64];
    char *plain_str;
    size_t plain_len;
    uint8_t *cipher;
    size_t cipher_len;
    bytea *result;
    
    if (get_public_key_bytes(pub_key_text, pub_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 public key must be 64 bytes or 128/130 hex characters")));
    }
    
    plain_str = text_to_cstring(plaintext);
    plain_len = strlen(plain_str);
    
    cipher_len = plain_len + 200;
    cipher = (uint8_t *)palloc(cipher_len);
    
    if (sm2_encrypt(pub_key, (uint8_t *)plain_str, plain_len, cipher, &cipher_len) != 0) {
        pfree(plain_str);
        pfree(cipher);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM2 encryption failed")));
    }
    
    result = (bytea *)palloc(VARHDRSZ + cipher_len);
    SET_VARSIZE(result, VARHDRSZ + cipher_len);
    memcpy(VARDATA(result), cipher, cipher_len);
    
    pfree(plain_str);
    pfree(cipher);
    
    PG_RETURN_BYTEA_P(result);
}

/*
 * sm2_decrypt_func(ciphertext bytea, private_key text) -> text
 * SM2私钥解密bytea密文
 */
extern "C" Datum
sm2_decrypt_func(PG_FUNCTION_ARGS)
{
    bytea *ciphertext = PG_GETARG_BYTEA_PP(0);
    text *priv_key_text = PG_GETARG_TEXT_PP(1);
    uint8_t priv_key[32];
    uint8_t *cipher;
    size_t cipher_len;
    uint8_t *plain;
    size_t plain_len;
    text *result;
    
    if (get_private_key_bytes(priv_key_text, priv_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 private key must be 32 bytes or 64 hex characters")));
    }
    
    cipher_len = VARSIZE(ciphertext) - VARHDRSZ;
    cipher = (uint8_t *)VARDATA(ciphertext);
    
    /* SM2 最大明文长度 255 字节，分配 256 字节缓冶区 (+1 为结束符) */
    plain_len = 256;
    plain = (uint8_t *)palloc(plain_len + 1);
    
    if (sm2_decrypt(priv_key, cipher, cipher_len, plain, &plain_len) != 0) {
        pfree(plain);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM2 decryption failed")));
    }
    
    plain[plain_len] = '\0';  /* 现在安全了 */
    result = cstring_to_text((char *)plain);
    pfree(plain);
    
    PG_RETURN_TEXT_P(result);
}

/*
 * sm2_sign_func(message text, private_key text, id text) -> bytea
 * SM2数字签名，返回bytea
 */
extern "C" Datum
sm2_sign_func(PG_FUNCTION_ARGS)
{
    text *message = PG_GETARG_TEXT_PP(0);
    text *priv_key_text = PG_GETARG_TEXT_PP(1);
    text *id_text = PG_ARGISNULL(2) ? NULL : PG_GETARG_TEXT_PP(2);
    uint8_t priv_key[32];
    char *msg_str;
    size_t msg_len;
    char *id_str = NULL;
    size_t id_len = 16;
    uint8_t signature[64];
    bytea *result;
    
    if (get_private_key_bytes(priv_key_text, priv_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 private key must be 32 bytes or 64 hex characters")));
    }
    
    msg_str = text_to_cstring(message);
    msg_len = strlen(msg_str);
    
    if (id_text) {
        id_str = text_to_cstring(id_text);
        id_len = strlen(id_str);
    } else {
        id_str = (char *)"1234567812345678";
        id_len = 16;
    }
    
    /* 注意：当前实现使用默认 ID，传入的 id 参数被忽略 */
    if (sm2_sign(priv_key, (uint8_t *)msg_str, msg_len, signature) != 0) {
        pfree(msg_str);
        if (id_text) pfree(id_str);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM2 signature failed")));
    }
    
    result = (bytea *)palloc(VARHDRSZ + 64);
    SET_VARSIZE(result, VARHDRSZ + 64);
    memcpy(VARDATA(result), signature, 64);
    
    pfree(msg_str);
    if (id_text) pfree(id_str);
    
    PG_RETURN_BYTEA_P(result);
}

/*
 * sm2_verify_func(message text, public_key text, signature bytea, id text) -> boolean
 * SM2签名验证
 */
extern "C" Datum
sm2_verify_func(PG_FUNCTION_ARGS)
{
    text *message = PG_GETARG_TEXT_PP(0);
    text *pub_key_text = PG_GETARG_TEXT_PP(1);
    bytea *signature_bytea = PG_GETARG_BYTEA_PP(2);
    text *id_text = PG_ARGISNULL(3) ? NULL : PG_GETARG_TEXT_PP(3);
    uint8_t pub_key[64];
    char *msg_str;
    size_t msg_len;
    char *id_str = NULL;
    size_t id_len = 16;
    uint8_t *signature;
    size_t sig_len;
    int verify_result;
    
    if (get_public_key_bytes(pub_key_text, pub_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 public key must be 64 bytes or 128/130 hex characters")));
    }
    
    sig_len = VARSIZE(signature_bytea) - VARHDRSZ;
    if (sig_len != 64) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 signature must be 64 bytes")));
    }
    
    signature = (uint8_t *)VARDATA(signature_bytea);
    msg_str = text_to_cstring(message);
    msg_len = strlen(msg_str);
    
    if (id_text) {
        id_str = text_to_cstring(id_text);
        id_len = strlen(id_str);
    } else {
        id_str = (char *)"1234567812345678";
        id_len = 16;
    }
    
    /* 注意：当前实现使用默认 ID，传入的 id 参数被忽略 */
    verify_result = sm2_verify(pub_key, (uint8_t *)msg_str, msg_len, signature);
    
    pfree(msg_str);
    if (id_text) pfree(id_str);
    
    PG_RETURN_BOOL(verify_result == 0);
}

/*
 * sm2_sign_hex(message text, private_key text, id text) -> text
 * SM2数字签名，返回十六进制
 */
extern "C" Datum
sm2_sign_hex(PG_FUNCTION_ARGS)
{
    text *message = PG_GETARG_TEXT_PP(0);
    text *priv_key_text = PG_GETARG_TEXT_PP(1);
    text *id_text = PG_ARGISNULL(2) ? NULL : PG_GETARG_TEXT_PP(2);
    uint8_t priv_key[32];
    char *msg_str;
    size_t msg_len;
    char *id_str = NULL;
    size_t id_len = 16;
    uint8_t signature[64];
    char *hex_str;
    text *result;
    
    if (get_private_key_bytes(priv_key_text, priv_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 private key must be 32 bytes or 64 hex characters")));
    }
    
    msg_str = text_to_cstring(message);
    msg_len = strlen(msg_str);
    
    if (id_text) {
        id_str = text_to_cstring(id_text);
        id_len = strlen(id_str);
    } else {
        id_str = (char *)"1234567812345678";
        id_len = 16;
    }
    
    /* 注意：当前实现使用默认 ID，传入的 id 参数被忽略 */
    if (sm2_sign(priv_key, (uint8_t *)msg_str, msg_len, signature) != 0) {
        pfree(msg_str);
        if (id_text) pfree(id_str);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("SM2 signature failed")));
    }
    
    hex_str = (char *)palloc(129);
    bytes_to_hex(signature, 64, hex_str);
    result = cstring_to_text(hex_str);
    
    pfree(msg_str);
    if (id_text) pfree(id_str);
    pfree(hex_str);
    
    PG_RETURN_TEXT_P(result);
}

/*
 * sm2_verify_hex(message text, public_key text, signature_hex text, id text) -> boolean
 * SM2签名验证（十六进制签名）
 */
extern "C" Datum
sm2_verify_hex(PG_FUNCTION_ARGS)
{
    text *message = PG_GETARG_TEXT_PP(0);
    text *pub_key_text = PG_GETARG_TEXT_PP(1);
    text *signature_hex_text = PG_GETARG_TEXT_PP(2);
    text *id_text = PG_ARGISNULL(3) ? NULL : PG_GETARG_TEXT_PP(3);
    uint8_t pub_key[64];
    char *msg_str;
    size_t msg_len;
    char *id_str = NULL;
    size_t id_len = 16;
    char *sig_hex_str;
    uint8_t signature[64];
    size_t sig_len;
    int verify_result;
    
    if (get_public_key_bytes(pub_key_text, pub_key) != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 public key must be 64 bytes or 128/130 hex characters")));
    }
    
    sig_hex_str = text_to_cstring(signature_hex_text);
    if (strlen(sig_hex_str) != 128) {
        pfree(sig_hex_str);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("SM2 signature must be 128 hex characters")));
    }
    
    if (hex_to_bytes(sig_hex_str, 128, signature, &sig_len) != 0) {
        pfree(sig_hex_str);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("Invalid hex signature")));
    }
    
    msg_str = text_to_cstring(message);
    msg_len = strlen(msg_str);
    
    if (id_text) {
        id_str = text_to_cstring(id_text);
        id_len = strlen(id_str);
    } else {
        id_str = (char *)"1234567812345678";
        id_len = 16;
    }
    
    /* 注意：当前实现使用默认 ID，传入的 id 参数被忽略 */
    verify_result = sm2_verify(pub_key, (uint8_t *)msg_str, msg_len, signature);
    
    pfree(msg_str);
    pfree(sig_hex_str);
    if (id_text) pfree(id_str);
    
    PG_RETURN_BOOL(verify_result == 0);
}
