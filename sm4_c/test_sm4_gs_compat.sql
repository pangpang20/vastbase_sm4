-- SM4 GS格式兼容性测试脚本
-- 测试与VastBase gs_encrypt格式的兼容性

\echo '========================================='
\echo 'SM4 GS格式兼容性测试'
\echo '========================================='

\echo ''
\echo '1. 测试 gs_encrypt 格式加密（SHA256）'
\echo '-----------------------------------------'

-- 使用兼容格式加密
SELECT sm4_c_encrypt_cbc_gs('Hello World!', '1234567890123456', 'sha256') AS gs_format_encrypted;

\echo ''
\echo '2. 测试 gs_encrypt 格式加解密验证（SHA256）'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_gs(
    sm4_c_encrypt_cbc_gs('Hello World!', '1234567890123456', 'sha256'),
    '1234567890123456'
) AS decrypted_result;

\echo ''
\echo '3. 测试 SHA384 格式'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_gs(
    sm4_c_encrypt_cbc_gs('Secret Message', '1234567890123456', 'sha384'),
    '1234567890123456'
) AS sha384_result;

\echo ''
\echo '4. 测试 SHA512 格式'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_gs(
    sm4_c_encrypt_cbc_gs('Confidential Data', '1234567890123456', 'sha512'),
    '1234567890123456'
) AS sha512_result;

\echo ''
\echo '5. 测试 SM3 格式（需要 OpenSSL 3.0+）'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_gs(
    sm4_c_encrypt_cbc_gs('国密加密测试', '1234567890123456', 'sm3'),
    '1234567890123456'
) AS sm3_result;

\echo ''
\echo '6. 测试解密 VastBase gs_encrypt 的数据'
\echo '-----------------------------------------'
\echo '注意：这里需要你提供实际的 gs_encrypt 加密结果'
\echo ''

-- 示例：解密你提供的 gs_encrypt 数据
-- SELECT sm4_c_decrypt_cbc_gs(
--     'AwAAAAAAAAChP0tyh4nwLniN0WHlBFRMPD0qMvXaiNiZbvg/scBf48YKuse1HhuqmUy91ZVEGGzWBt1D1IHRHRTgSjbgCDG7s8lBRwo06umf4qKLufbp0Q==',
--     '1234567890123456'
-- ) AS gs_encrypt_decrypted;

\echo ''
\echo '7. 对比三种格式的输出'
\echo '-----------------------------------------'

-- 标准 KDF 格式（bytea）
SELECT encode(sm4_c_encrypt_cbc_kdf('Test Data', '1234567890123456', 'sha256'), 'hex') AS kdf_format_hex;

-- 标准 KDF 格式（base64）
SELECT encode(sm4_c_encrypt_cbc_kdf('Test Data', '1234567890123456', 'sha256'), 'base64') AS kdf_format_base64;

-- GS 兼容格式（base64）
SELECT sm4_c_encrypt_cbc_gs('Test Data', '1234567890123456', 'sha256') AS gs_format_base64;

\echo ''
\echo '8. 测试长文本加密'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_gs(
    sm4_c_encrypt_cbc_gs(
        'This is a longer text with multiple sentences to test the encryption and decryption compatibility with VastBase gs_encrypt format.',
        'test_password_123',
        'sha256'
    ),
    'test_password_123'
) AS long_text_result;

\echo ''
\echo '9. 测试中文内容'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_gs(
    sm4_c_encrypt_cbc_gs(
        '这是一段中文测试内容，用于验证与VastBase gs_encrypt的兼容性！',
        '测试密码123',
        'sha256'
    ),
    '测试密码123'
) AS chinese_content_result;

\echo ''
\echo '10. 测试错误密码（应该失败）'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_gs(
    sm4_c_encrypt_cbc_gs('Secret', 'correct_password', 'sha256'),
    'wrong_password'
) AS wrong_password_test;

\echo ''
\echo '========================================='
\echo '测试完成！'
\echo '========================================='
\echo ''
\echo '格式说明：'
\echo '1. sm4_c_encrypt_cbc_kdf: 简洁格式（salt+密文）'
\echo '2. sm4_c_encrypt_cbc_gs: gs_encrypt兼容格式（版本+算法+保留+salt+密文）'
\echo ''
\echo 'GS格式结构：'
\echo '  - Byte 0: 版本号 (0x03)'
\echo '  - Byte 1: 哈希算法 (0=SHA256, 1=SHA384, 2=SHA512, 3=SM3)'
\echo '  - Bytes 2-7: 保留字段'
\echo '  - Bytes 8-23: 盐值 (16字节)'
\echo '  - Bytes 24+: 密文'
\echo '  - 全部使用 Base64 编码'
\echo ''
