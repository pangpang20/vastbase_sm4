-- SM4 CBC KDF（密钥派生）功能测试脚本
-- 测试使用PBKDF2派生密钥的CBC加密/解密

\echo '========================================='
\echo 'SM4 CBC KDF 功能测试'
\echo '========================================='

\echo ''
\echo '1. 测试 SHA256 密钥派生加解密'
\echo '-----------------------------------------'

-- 加密
SELECT encode(sm4_c_encrypt_cbc_kdf('Hello World!', 'mypassword', 'sha256'), 'hex') AS sha256_encrypted;

-- 加解密验证
SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf('Hello World!', 'mypassword', 'sha256'),
    'mypassword',
    'sha256'
) AS sha256_result;

\echo ''
\echo '2. 测试 SHA384 密钥派生加解密'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf('Secret Message', 'strongpass123', 'sha384'),
    'strongpass123',
    'sha384'
) AS sha384_result;

\echo ''
\echo '3. 测试 SHA512 密钥派生加解密'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf('Confidential Data', 'p@ssw0rd!', 'sha512'),
    'p@ssw0rd!',
    'sha512'
) AS sha512_result;

\echo ''
\echo '4. 测试 SM3 密钥派生加解密（需要OpenSSL 3.0+）'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf('国密加密测试', '中文密码', 'sm3'),
    '中文密码',
    'sm3'
) AS sm3_result;

\echo ''
\echo '5. 测试多次加密结果不同（盐值随机）'
\echo '-----------------------------------------'

SELECT 
    encode(sm4_c_encrypt_cbc_kdf('Same Text', 'password', 'sha256'), 'hex') AS encryption_1;

SELECT 
    encode(sm4_c_encrypt_cbc_kdf('Same Text', 'password', 'sha256'), 'hex') AS encryption_2;

\echo ''
\echo '说明：两次加密结果应该不同（因为盐值随机生成）'

\echo ''
\echo '6. 测试长文本加解密'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf(
        'This is a longer text with multiple words and sentences. It should be encrypted and decrypted correctly using PBKDF2 key derivation.',
        'long_password_test',
        'sha256'
    ),
    'long_password_test',
    'sha256'
) AS long_text_result;

\echo ''
\echo '7. 测试中文内容加解密'
\echo '-----------------------------------------'

SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf(
        '这是一段中文测试内容，包含了中文字符和标点符号！',
        '测试密码123',
        'sha384'
    ),
    '测试密码123',
    'sha384'
) AS chinese_text_result;

\echo ''
\echo '8. 测试错误密码解密（应该失败）'
\echo '-----------------------------------------'

-- 这个应该返回错误或乱码
SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf('Secret', 'correct_password', 'sha256'),
    'wrong_password',
    'sha256'
) AS wrong_password_test;

\echo ''
\echo '9. 测试不支持的哈希算法（应该报错）'
\echo '-----------------------------------------'

-- 这个应该返回错误
SELECT sm4_c_encrypt_cbc_kdf('Test', 'password', 'md5');

\echo ''
\echo '10. 性能对比：标准CBC vs KDF CBC'
\echo '-----------------------------------------'

\timing on

-- 标准CBC（需要手动提供IV）
SELECT encode(sm4_c_encrypt_cbc('Performance Test', '1234567890123456', '1234567890123456'), 'hex') AS standard_cbc;

-- KDF CBC（自动派生密钥和IV）
SELECT encode(sm4_c_encrypt_cbc_kdf('Performance Test', 'password', 'sha256'), 'hex') AS kdf_cbc;

\timing off

\echo ''
\echo '========================================='
\echo '测试完成！'
\echo '========================================='
\echo ''
\echo '说明：'
\echo '1. KDF版本自动生成随机盐值，每次加密结果不同'
\echo '2. 使用PBKDF2进行10000次迭代，增强安全性'
\echo '3. 支持sha256, sha384, sha512, sm3四种哈希算法'
\echo '4. SM3需要OpenSSL 3.0+支持'
\echo '5. 密文格式：16字节salt + CBC密文'
\echo ''
