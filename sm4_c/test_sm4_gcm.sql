-- SM4 GCM模式测试
-- 测试基本的GCM加密和解密功能

\echo '=== SM4 GCM模式测试 ==='

-- 测试1: 基本的GCM加密和解密（无AAD）
\echo '测试1: 基本GCM加密和解密（无AAD）'
WITH encrypted AS (
    SELECT sm4_c_encrypt_gcm('Hello World!', '1234567890123456', '123456789012') AS enc
)
SELECT 
    encode(enc, 'hex') AS encrypted_hex,
    sm4_c_decrypt_gcm(enc, '1234567890123456', '123456789012') AS decrypted
FROM encrypted;

-- 测试2: GCM加密和解密（带AAD）
\echo '测试2: GCM加密和解密（带AAD）'
WITH encrypted AS (
    SELECT sm4_c_encrypt_gcm('Secret Message', '1234567890123456', '123456789012', 'additional data') AS enc
)
SELECT 
    encode(enc, 'hex') AS encrypted_hex,
    sm4_c_decrypt_gcm(enc, '1234567890123456', '123456789012', 'additional data') AS decrypted
FROM encrypted;

-- 测试3: 使用十六进制密钥和IV
\echo '测试3: 使用十六进制密钥和IV'
WITH encrypted AS (
    SELECT sm4_c_encrypt_gcm('Test Data', '31323334353637383930313233343536', '313233343536373839303132') AS enc
)
SELECT 
    encode(enc, 'hex') AS encrypted_hex,
    sm4_c_decrypt_gcm(enc, '31323334353637383930313233343536', '313233343536373839303132') AS decrypted
FROM encrypted;

-- 测试4: 长文本加密
\echo '测试4: 长文本加密'
WITH encrypted AS (
    SELECT sm4_c_encrypt_gcm(
        'This is a longer message that spans multiple blocks to test GCM mode encryption and decryption with SM4 algorithm.', 
        '1234567890123456', 
        '123456789012'
    ) AS enc
)
SELECT 
    length(enc) AS encrypted_length,
    sm4_c_decrypt_gcm(enc, '1234567890123456', '123456789012') AS decrypted
FROM encrypted;

-- 测试5: 空明文
\echo '测试5: 空明文'
WITH encrypted AS (
    SELECT sm4_c_encrypt_gcm('', '1234567890123456', '123456789012') AS enc
)
SELECT 
    length(enc) AS encrypted_length,
    sm4_c_decrypt_gcm(enc, '1234567890123456', '123456789012') AS decrypted
FROM encrypted;

-- 测试6: 16字节IV支持（兼容CBC模式IV长度）
\echo '测试6: 16字节IV支持'
WITH encrypted AS (
    SELECT sm4_c_encrypt_gcm('Test 16-byte IV', '1234567890123456', '1234567890123456') AS enc
)
SELECT 
    encode(enc, 'hex') AS encrypted_hex,
    sm4_c_decrypt_gcm(enc, '1234567890123456', '1234567890123456') AS decrypted
FROM encrypted;

-- 测试7: Base64版本 - 加密解密
\echo '测试7: Base64版本加密解密'
WITH encrypted AS (
    SELECT sm4_c_encrypt_gcm_base64('Hello Base64!', '1234567890123456', '123456789012') AS enc_b64
)
SELECT 
    enc_b64 AS encrypted_base64,
    sm4_c_decrypt_gcm_base64(enc_b64, '1234567890123456', '123456789012') AS decrypted
FROM encrypted;

-- 测试8: Base64版本 - 带AAD
\echo '测试8: Base64版本（带AAD）'
WITH encrypted AS (
    SELECT sm4_c_encrypt_gcm_base64('Secret Data', '1234567890123456', '123456789012', 'user_id:12345') AS enc_b64
)
SELECT 
    enc_b64 AS encrypted_base64,
    sm4_c_decrypt_gcm_base64(enc_b64, '1234567890123456', '123456789012', 'user_id:12345') AS decrypted
FROM encrypted;

-- 测试9: 认证失败测试（使用错误的AAD应该失败）
\echo '测试9: 认证失败测试（应该报错）'
\echo '尝试使用错误的AAD解密...'
DO $$
DECLARE
    encrypted bytea;
BEGIN
    encrypted := sm4_c_encrypt_gcm('Test', '1234567890123456', '123456789012', 'correct aad');
    BEGIN
        PERFORM sm4_c_decrypt_gcm(encrypted, '1234567890123456', '123456789012', 'wrong aad');
        RAISE NOTICE '错误: AAD验证应该失败但成功了';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE '✓ 正确: AAD验证失败，错误信息: %', SQLERRM;
    END;
END $$;

-- 测试10: 使用错误的密钥（应该失败）
\echo '测试10: 使用错误的密钥解密（应该报错）'
\echo '尝试使用错误的密钥解密...'
DO $$
DECLARE
    encrypted bytea;
BEGIN
    encrypted := sm4_c_encrypt_gcm('Test', '1234567890123456', '123456789012');
    BEGIN
        PERFORM sm4_c_decrypt_gcm(encrypted, 'wrongkey12345678', '123456789012');
        RAISE NOTICE '错误: 密钥验证应该失败但成功了';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE '✓ 正确: 密钥验证失败，错误信息: %', SQLERRM;
    END;
END $$;

-- 测试11: 完整的加解密验证
\echo '测试11: 完整加解密验证'
SELECT 
    CASE 
        WHEN sm4_c_decrypt_gcm(
            sm4_c_encrypt_gcm('测试数据123', '1234567890123456', '123456789012', 'test'),
            '1234567890123456',
            '123456789012',
            'test'
        ) = '测试数据123' 
        THEN '✓ 通过' 
        ELSE '✗ 失败' 
    END AS test_result;

\echo '=== 测试完成 ==='
