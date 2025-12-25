-- SM4 GCM模式测试
-- 测试基本的GCM加密和解密功能

\echo '=== SM4 GCM模式测试 ==='

-- 测试1: 基本的GCM加密和解密（无AAD）
\echo '测试1: 基本GCM加密和解密（无AAD）'
SELECT sm4_c_encrypt_gcm('Hello World!', '1234567890123456', '123456789012') AS encrypted \gset
SELECT sm4_c_decrypt_gcm(:'encrypted', '1234567890123456', '123456789012') AS decrypted;

-- 测试2: GCM加密和解密（带AAD）
\echo '测试2: GCM加密和解密（带AAD）'
SELECT sm4_c_encrypt_gcm('Secret Message', '1234567890123456', '123456789012', 'additional data') AS encrypted_with_aad \gset
SELECT sm4_c_decrypt_gcm(:'encrypted_with_aad', '1234567890123456', '123456789012', 'additional data') AS decrypted_with_aad;

-- 测试3: 使用十六进制密钥和IV
\echo '测试3: 使用十六进制密钥和IV'
SELECT sm4_c_encrypt_gcm('Test Data', '31323334353637383930313233343536', '313233343536373839303132') AS encrypted_hex \gset
SELECT sm4_c_decrypt_gcm(:'encrypted_hex', '31323334353637383930313233343536', '313233343536373839303132') AS decrypted_hex;

-- 测试4: 长文本加密
\echo '测试4: 长文本加密'
SELECT sm4_c_encrypt_gcm('This is a longer message that spans multiple blocks to test GCM mode encryption and decryption with SM4 algorithm.', 
                          '1234567890123456', 
                          '123456789012') AS encrypted_long \gset
SELECT sm4_c_decrypt_gcm(:'encrypted_long', '1234567890123456', '123456789012') AS decrypted_long;

-- 测试5: 空明文
\echo '测试5: 空明文'
SELECT sm4_c_encrypt_gcm('', '1234567890123456', '123456789012') AS encrypted_empty \gset
SELECT sm4_c_decrypt_gcm(:'encrypted_empty', '1234567890123456', '123456789012') AS decrypted_empty;

-- 测试6: 认证失败测试（使用错误的AAD应该失败）
\echo '测试6: 认证失败测试（应该报错）'
SELECT sm4_c_encrypt_gcm('Test', '1234567890123456', '123456789012', 'correct aad') AS encrypted_fail \gset
-- 下面这行应该失败，因为AAD不匹配
-- SELECT sm4_c_decrypt_gcm(:'encrypted_fail', '1234567890123456', '123456789012', 'wrong aad');

-- 测试7: 使用错误的密钥（应该失败）
\echo '测试7: 使用错误的密钥解密（应该报错）'
SELECT sm4_c_encrypt_gcm('Test', '1234567890123456', '123456789012') AS encrypted_key_test \gset
-- 下面这行应该失败，因为密钥不正确
-- SELECT sm4_c_decrypt_gcm(:'encrypted_key_test', '6543210987654321', '123456789012');

\echo '=== 测试完成 ==='
