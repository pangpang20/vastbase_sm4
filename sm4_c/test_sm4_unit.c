/*
 * SM4 单元测试
 * 不依赖 PostgreSQL，独立编译运行
 * 编译: g++ -O2 -Wall -std=c++11 -DUSE_OPENSSL_KDF -o test_sm4_unit test_sm4_unit.c sm4.c -lssl -lcrypto
 * 运行: ./test_sm4_unit
 */

#include "sm4.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (cond) { tests_passed++; } \
    else { tests_failed++; printf("FAIL: %s\n", msg); } \
} while(0)

/* 测试 SM4 基本加解密往返 (ECB 单块) */
static void test_sm4_ecb_block_roundtrip(void)
{
    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t input[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                         0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t encrypted[16];
    uint8_t decrypted[16];
    sm4_context ctx;

    sm4_setkey(&ctx, key);
    sm4_encrypt_block(&ctx, input, encrypted);
    sm4_decrypt_block(&ctx, encrypted, decrypted);
    sm4_context_clean(&ctx);

    TEST_ASSERT(memcmp(input, decrypted, 16) == 0,
                "ECB block encrypt/decrypt roundtrip");
}

/* 测试 ECB 模式加解密往返 */
static void test_sm4_ecb_roundtrip(void)
{
    uint8_t key[16] = {0};
    const char *plaintext = "Hello SM4 ECB!";
    size_t plain_len = strlen(plaintext);
    uint8_t cipher[64];
    uint8_t decrypted[64];
    size_t cipher_len, plain_out_len;
    int ret;

    ret = sm4_ecb_encrypt(key, (const uint8_t *)plaintext, plain_len, cipher, &cipher_len);
    TEST_ASSERT(ret == 0, "ECB encrypt returns 0");
    TEST_ASSERT(cipher_len > plain_len, "ECB cipher longer than plaintext (PKCS7 padding)");
    TEST_ASSERT(cipher_len % SM4_BLOCK_SIZE == 0, "ECB cipher length is block-aligned");

    ret = sm4_ecb_decrypt(key, cipher, cipher_len, decrypted, &plain_out_len);
    TEST_ASSERT(ret == 0, "ECB decrypt returns 0");
    TEST_ASSERT(plain_out_len == plain_len, "ECB decrypted length matches original");
    TEST_ASSERT(memcmp(plaintext, decrypted, plain_len) == 0,
                "ECB roundtrip produces original plaintext");
}

/* 测试 CBC 模式加解密往返 */
static void test_sm4_cbc_roundtrip(void)
{
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    const char *plaintext = "Hello SM4 CBC mode test!";
    size_t plain_len = strlen(plaintext);
    uint8_t cipher[64];
    uint8_t decrypted[64];
    size_t cipher_len, plain_out_len;
    int ret;

    ret = sm4_cbc_encrypt(key, iv, (const uint8_t *)plaintext, plain_len, cipher, &cipher_len);
    TEST_ASSERT(ret == 0, "CBC encrypt returns 0");
    TEST_ASSERT(cipher_len % SM4_BLOCK_SIZE == 0, "CBC cipher length is block-aligned");

    ret = sm4_cbc_decrypt(key, iv, cipher, cipher_len, decrypted, &plain_out_len);
    TEST_ASSERT(ret == 0, "CBC decrypt returns 0");
    TEST_ASSERT(plain_out_len == plain_len, "CBC decrypted length matches original");
    TEST_ASSERT(memcmp(plaintext, decrypted, plain_len) == 0,
                "CBC roundtrip produces original plaintext");
}

/* 测试 GCM 模式加解密往返 */
static void test_sm4_gcm_roundtrip(void)
{
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    const char *plaintext = "Hello SM4 GCM!";
    const char *aad = "additional data";
    size_t plain_len = strlen(plaintext);
    size_t aad_len = strlen(aad);
    uint8_t cipher[64];
    uint8_t decrypted[64];
    uint8_t tag[SM4_GCM_TAG_SIZE];
    int ret;

    ret = sm4_gcm_encrypt(key, iv, 12,
                          (const uint8_t *)aad, aad_len,
                          (const uint8_t *)plaintext, plain_len,
                          cipher, tag);
    TEST_ASSERT(ret == 0, "GCM encrypt returns 0");

    ret = sm4_gcm_decrypt(key, iv, 12,
                          (const uint8_t *)aad, aad_len,
                          cipher, plain_len,
                          tag, decrypted);
    TEST_ASSERT(ret == 0, "GCM decrypt returns 0");
    TEST_ASSERT(memcmp(plaintext, decrypted, plain_len) == 0,
                "GCM roundtrip produces original plaintext");
}

/* 测试 GCM 认证失败检测 */
static void test_sm4_gcm_auth_failure(void)
{
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    const char *plaintext = "Secret data";
    size_t plain_len = strlen(plaintext);
    uint8_t cipher[64];
    uint8_t decrypted[64];
    uint8_t tag[SM4_GCM_TAG_SIZE];
    int ret;

    sm4_gcm_encrypt(key, iv, 12, NULL, 0,
                    (const uint8_t *)plaintext, plain_len, cipher, tag);

    /* 篡改 Tag */
    tag[0] ^= 0xff;

    ret = sm4_gcm_decrypt(key, iv, 12, NULL, 0,
                          cipher, plain_len, tag, decrypted);
    TEST_ASSERT(ret == -1, "GCM decrypt fails with tampered tag");

    /* 篡改密文 */
    tag[0] ^= 0xff;  /* 恢复 tag */
    cipher[0] ^= 0xff;

    ret = sm4_gcm_decrypt(key, iv, 12, NULL, 0,
                          cipher, plain_len, tag, decrypted);
    TEST_ASSERT(ret == -1, "GCM decrypt fails with tampered ciphertext");
}

/* 测试 GCM 大数据量 (Feature-2: 缓冲区溢出修复验证) */
static void test_sm4_gcm_large_data(void)
{
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    size_t data_len = 2048;  /* 超过旧的 1024 字节限制 */
    uint8_t *data = (uint8_t *)malloc(data_len);
    uint8_t *cipher = (uint8_t *)malloc(data_len);
    uint8_t *decrypted = (uint8_t *)malloc(data_len);
    uint8_t tag[SM4_GCM_TAG_SIZE];
    int ret;

    memset(data, 0xAB, data_len);

    ret = sm4_gcm_encrypt(key, iv, 12, NULL, 0, data, data_len, cipher, tag);
    TEST_ASSERT(ret == 0, "GCM encrypt 2048 bytes (buffer overflow test)");

    ret = sm4_gcm_decrypt(key, iv, 12, NULL, 0, cipher, data_len, tag, decrypted);
    TEST_ASSERT(ret == 0, "GCM decrypt 2048 bytes");
    TEST_ASSERT(memcmp(data, decrypted, data_len) == 0,
                "GCM large data roundtrip matches");

    free(data);
    free(cipher);
    free(decrypted);
}

/* 测试 GCM 超大数据量 */
static void test_sm4_gcm_very_large_data(void)
{
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    size_t data_len = 65536;  /* 64KB */
    uint8_t *data = (uint8_t *)malloc(data_len);
    uint8_t *cipher = (uint8_t *)malloc(data_len);
    uint8_t *decrypted = (uint8_t *)malloc(data_len);
    uint8_t tag[SM4_GCM_TAG_SIZE];
    int ret;

    RAND_bytes(data, data_len);

    ret = sm4_gcm_encrypt(key, iv, 12, NULL, 0, data, data_len, cipher, tag);
    TEST_ASSERT(ret == 0, "GCM encrypt 64KB");

    ret = sm4_gcm_decrypt(key, iv, 12, NULL, 0, cipher, data_len, tag, decrypted);
    TEST_ASSERT(ret == 0, "GCM decrypt 64KB");
    TEST_ASSERT(memcmp(data, decrypted, data_len) == 0,
                "GCM 64KB roundtrip matches");

    free(data);
    free(cipher);
    free(decrypted);
}

/* 测试空输入处理 */
static void test_sm4_empty_input(void)
{
    uint8_t key[16] = {0};
    uint8_t cipher[64];
    size_t cipher_len;
    int ret;

    ret = sm4_ecb_encrypt(key, (const uint8_t *)"", 0, cipher, &cipher_len);
    /* 空输入仍会产生一个块的 PKCS7 填充，这是预期行为 */
    TEST_ASSERT(ret == 0, "ECB encrypt empty input returns 0");
    TEST_ASSERT(cipher_len == SM4_BLOCK_SIZE, "ECB empty input produces one block");
}

/* 测试 NULL 参数检查 */
static void test_sm4_null_params(void)
{
    uint8_t key[16] = {0};
    uint8_t buf[32];
    size_t len;
    int ret;

    ret = sm4_ecb_encrypt(NULL, buf, 16, buf, &len);
    TEST_ASSERT(ret == -1, "ECB encrypt with NULL key returns -1");

    ret = sm4_ecb_encrypt(key, NULL, 16, buf, &len);
    TEST_ASSERT(ret == -1, "ECB encrypt with NULL input returns -1");

    ret = sm4_ecb_encrypt(key, buf, 16, NULL, &len);
    TEST_ASSERT(ret == -1, "ECB encrypt with NULL output returns -1");

    ret = sm4_ecb_encrypt(key, buf, 16, buf, NULL);
    TEST_ASSERT(ret == -1, "ECB encrypt with NULL output_len returns -1");
}

/* 测试 sm4_context_clean */
static void test_sm4_context_clean(void)
{
    uint8_t key[16] = {0xff};
    sm4_context ctx;
    int i;

    sm4_setkey(&ctx, key);
    /* 轮密钥不应全为零 */
    int all_zero = 1;
    for (i = 0; i < SM4_NUM_ROUNDS; i++) {
        if (ctx.rk[i] != 0) { all_zero = 0; break; }
    }
    TEST_ASSERT(!all_zero, "Context has non-zero round keys after setkey");

    sm4_context_clean(&ctx);
    all_zero = 1;
    for (i = 0; i < SM4_NUM_ROUNDS; i++) {
        if (ctx.rk[i] != 0) { all_zero = 0; break; }
    }
    TEST_ASSERT(all_zero, "Context is zeroed after clean");
}

/* 测试 GCM 不同 IV 长度 */
static void test_sm4_gcm_iv_lengths(void)
{
    uint8_t key[16] = {0};
    const char *plaintext = "test";
    size_t plain_len = 4;
    uint8_t cipher[32];
    uint8_t decrypted[32];
    uint8_t tag[SM4_GCM_TAG_SIZE];
    int ret;

    /* 12字节 IV (推荐) */
    uint8_t iv12[12] = {0};
    ret = sm4_gcm_encrypt(key, iv12, 12, NULL, 0,
                          (const uint8_t *)plaintext, plain_len, cipher, tag);
    TEST_ASSERT(ret == 0, "GCM encrypt with 12-byte IV");
    ret = sm4_gcm_decrypt(key, iv12, 12, NULL, 0,
                          cipher, plain_len, tag, decrypted);
    TEST_ASSERT(ret == 0, "GCM decrypt with 12-byte IV");

    /* 16字节 IV */
    uint8_t iv16[16] = {0};
    ret = sm4_gcm_encrypt(key, iv16, 16, NULL, 0,
                          (const uint8_t *)plaintext, plain_len, cipher, tag);
    TEST_ASSERT(ret == 0, "GCM encrypt with 16-byte IV");
    ret = sm4_gcm_decrypt(key, iv16, 16, NULL, 0,
                          cipher, plain_len, tag, decrypted);
    TEST_ASSERT(ret == 0, "GCM decrypt with 16-byte IV");
}

/* 测试 ECB 不同密文长度的解密 */
static void test_sm4_ecb_various_lengths(void)
{
    uint8_t key[16] = {0};
    int lengths[] = {1, 15, 16, 17, 31, 32, 33, 100, 255};
    int n = sizeof(lengths) / sizeof(lengths[0]);
    int i;

    for (i = 0; i < n; i++) {
        uint8_t *data = (uint8_t *)malloc(lengths[i]);
        uint8_t cipher[300];
        uint8_t decrypted[300];
        size_t cipher_len, plain_len;

        memset(data, 'A' + (i % 26), lengths[i]);

        int ret = sm4_ecb_encrypt(key, data, lengths[i], cipher, &cipher_len);
        TEST_ASSERT(ret == 0, "ECB encrypt various lengths");

        ret = sm4_ecb_decrypt(key, cipher, cipher_len, decrypted, &plain_len);
        TEST_ASSERT(ret == 0, "ECB decrypt various lengths");
        TEST_ASSERT(plain_len == (size_t)lengths[i], "ECB roundtrip length matches");

        free(data);
    }
}

int main(void)
{
    printf("SM4 Unit Tests\n");
    printf("==============\n\n");

    test_sm4_ecb_block_roundtrip();
    test_sm4_ecb_roundtrip();
    test_sm4_cbc_roundtrip();
    test_sm4_gcm_roundtrip();
    test_sm4_gcm_auth_failure();
    test_sm4_gcm_large_data();
    test_sm4_gcm_very_large_data();
    test_sm4_empty_input();
    test_sm4_null_params();
    test_sm4_context_clean();
    test_sm4_gcm_iv_lengths();
    test_sm4_ecb_various_lengths();

    printf("\n==============\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
