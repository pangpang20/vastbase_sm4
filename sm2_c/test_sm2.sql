-- SM2 Extension Test Script
-- 国密SM2扩展测试脚本

\echo '================================================='
\echo 'SM2 国密椭圆曲线公钥密码算法测试'
\echo '================================================='

-- ========================================
-- 测试1: 密钥生成
-- ========================================
\echo ''
\echo '--- 测试1: 密钥生成 ---'

-- 生成密钥对
SELECT '生成SM2密钥对:' AS test;
SELECT sm2_c_generate_key() AS keypair;

-- 使用固定私钥进行后续测试
\echo ''
\echo '使用测试私钥:'
\set test_priv_key '3f49c0e88e8e3c9e4c3e3f8a9e5d6c7b8a9e3f4c5d6e7f8a9b0c1d2e3f4a5b6c'

-- 从私钥导出公钥
SELECT sm2_c_get_pubkey('3f49c0e88e8e3c9e4c3e3f8a9e5d6c7b8a9e3f4c5d6e7f8a9b0c1d2e3f4a5b6c') AS public_key;

-- ========================================
-- 测试2: 加密解密 (十六进制)
-- ========================================
\echo ''
\echo '--- 测试2: 加密解密 (十六进制格式) ---'

-- 生成新密钥对用于测试
DO $$
DECLARE
    keypair text[];
    priv_key text;
    pub_key text;
    plain_text text := 'Hello SM2!';
    cipher_hex text;
    decrypted text;
BEGIN
    -- 生成密钥对
    keypair := sm2_c_generate_key();
    priv_key := keypair[1];
    pub_key := keypair[2];
    
    RAISE NOTICE '私钥: %', priv_key;
    RAISE NOTICE '公钥: %', pub_key;
    RAISE NOTICE '明文: %', plain_text;
    
    -- 加密
    cipher_hex := sm2_c_encrypt_hex(plain_text, pub_key);
    RAISE NOTICE '密文(hex): %', cipher_hex;
    
    -- 解密
    decrypted := sm2_c_decrypt_hex(cipher_hex, priv_key);
    RAISE NOTICE '解密结果: %', decrypted;
    
    -- 验证
    IF decrypted = plain_text THEN
        RAISE NOTICE '✓ 加解密测试通过!';
    ELSE
        RAISE NOTICE '✗ 加解密测试失败!';
    END IF;
END $$;

-- ========================================
-- 测试3: 加密解密 (Base64)
-- ========================================
\echo ''
\echo '--- 测试3: 加密解密 (Base64格式) ---'

DO $$
DECLARE
    keypair text[];
    priv_key text;
    pub_key text;
    plain_text text := '中文测试消息';
    cipher_base64 text;
    decrypted text;
BEGIN
    keypair := sm2_c_generate_key();
    priv_key := keypair[1];
    pub_key := keypair[2];
    
    RAISE NOTICE '明文: %', plain_text;
    
    -- Base64加密
    cipher_base64 := sm2_c_encrypt_base64(plain_text, pub_key);
    RAISE NOTICE '密文(Base64): %', cipher_base64;
    
    -- Base64解密
    decrypted := sm2_c_decrypt_base64(cipher_base64, priv_key);
    RAISE NOTICE '解密结果: %', decrypted;
    
    IF decrypted = plain_text THEN
        RAISE NOTICE '✓ Base64加解密测试通过!';
    ELSE
        RAISE NOTICE '✗ Base64加解密测试失败!';
    END IF;
END $$;

-- ========================================
-- 测试4: 数字签名
-- ========================================
\echo ''
\echo '--- 测试4: 数字签名 (十六进制) ---'

DO $$
DECLARE
    keypair text[];
    priv_key text;
    pub_key text;
    message text := '待签名的重要文件内容';
    sig_hex text;
    verify_result boolean;
BEGIN
    keypair := sm2_c_generate_key();
    priv_key := keypair[1];
    pub_key := keypair[2];
    
    RAISE NOTICE '消息: %', message;
    
    -- 签名
    sig_hex := sm2_c_sign_hex(message, priv_key);
    RAISE NOTICE '签名(hex): %', sig_hex;
    
    -- 验签
    verify_result := sm2_c_verify_hex(message, pub_key, sig_hex);
    RAISE NOTICE '验签结果: %', verify_result;
    
    IF verify_result THEN
        RAISE NOTICE '✓ 签名验证测试通过!';
    ELSE
        RAISE NOTICE '✗ 签名验证测试失败!';
    END IF;
    
    -- 测试篡改消息后的验签
    verify_result := sm2_c_verify_hex('被篡改的消息', pub_key, sig_hex);
    RAISE NOTICE '篡改消息后验签结果: %', verify_result;
    
    IF NOT verify_result THEN
        RAISE NOTICE '✓ 篡改检测测试通过!';
    ELSE
        RAISE NOTICE '✗ 篡改检测测试失败!';
    END IF;
END $$;

-- ========================================
-- 测试5: 带用户标识的签名
-- ========================================
\echo ''
\echo '--- 测试5: 带用户标识的签名 ---'

DO $$
DECLARE
    keypair text[];
    priv_key text;
    pub_key text;
    message text := '合同文件';
    user_id text := 'user@example.com';
    sig_hex text;
    verify_result boolean;
BEGIN
    keypair := sm2_c_generate_key();
    priv_key := keypair[1];
    pub_key := keypair[2];
    
    RAISE NOTICE '消息: %', message;
    RAISE NOTICE '用户ID: %', user_id;
    
    -- 带ID签名
    sig_hex := sm2_c_sign_hex(message, priv_key, user_id);
    RAISE NOTICE '签名(带ID): %', sig_hex;
    
    -- 使用相同ID验签
    verify_result := sm2_c_verify_hex(message, pub_key, sig_hex, user_id);
    RAISE NOTICE '相同ID验签: %', verify_result;
    
    -- 使用不同ID验签
    verify_result := sm2_c_verify_hex(message, pub_key, sig_hex, 'other@example.com');
    RAISE NOTICE '不同ID验签: %', verify_result;
    
    IF NOT verify_result THEN
        RAISE NOTICE '✓ 用户ID绑定测试通过!';
    ELSE
        RAISE NOTICE '✗ 用户ID绑定测试失败!';
    END IF;
END $$;

-- ========================================
-- 测试6: bytea格式
-- ========================================
\echo ''
\echo '--- 测试6: bytea格式加密解密 ---'

DO $$
DECLARE
    keypair text[];
    priv_key text;
    pub_key text;
    plain_text text := 'Binary format test';
    cipher_bytea bytea;
    decrypted text;
BEGIN
    keypair := sm2_c_generate_key();
    priv_key := keypair[1];
    pub_key := keypair[2];
    
    RAISE NOTICE '明文: %', plain_text;
    
    -- bytea加密
    cipher_bytea := sm2_c_encrypt(plain_text, pub_key);
    RAISE NOTICE '密文(bytea)长度: %', length(cipher_bytea);
    
    -- bytea解密
    decrypted := sm2_c_decrypt(cipher_bytea, priv_key);
    RAISE NOTICE '解密结果: %', decrypted;
    
    IF decrypted = plain_text THEN
        RAISE NOTICE '✓ bytea格式测试通过!';
    ELSE
        RAISE NOTICE '✗ bytea格式测试失败!';
    END IF;
END $$;

-- ========================================
-- 测试7: bytea格式签名
-- ========================================
\echo ''
\echo '--- 测试7: bytea格式签名验证 ---'

DO $$
DECLARE
    keypair text[];
    priv_key text;
    pub_key text;
    message text := '测试消息';
    sig_bytea bytea;
    verify_result boolean;
BEGIN
    keypair := sm2_c_generate_key();
    priv_key := keypair[1];
    pub_key := keypair[2];
    
    -- bytea签名
    sig_bytea := sm2_c_sign(message, priv_key);
    RAISE NOTICE '签名(bytea)长度: %', length(sig_bytea);
    
    -- bytea验签
    verify_result := sm2_c_verify(message, pub_key, sig_bytea);
    RAISE NOTICE '验签结果: %', verify_result;
    
    IF verify_result THEN
        RAISE NOTICE '✓ bytea签名测试通过!';
    ELSE
        RAISE NOTICE '✗ bytea签名测试失败!';
    END IF;
END $$;

-- ========================================
-- 测试完成
-- ========================================
\echo ''
\echo '================================================='
\echo 'SM2 扩展测试完成'
\echo '================================================='
