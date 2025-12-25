-- SM4扩展测试脚本 (C扩展版本)
-- 用法: vsql -d postgres -f test_sm4.sql

-- 显示可用函数
\echo '========================================='
\echo 'SM4 C扩展函数列表:'
\echo '========================================='
\df sm4_c*

\echo ''
\echo '========================================='
\echo 'SM4加解密测试'
\echo '========================================='

-- 测试1: ECB模式 (十六进制输出)
\echo ''
\echo '测试1: ECB模式加解密 (十六进制)'
SELECT '原文' AS 类型, 'Hello VastBase!' AS 内容
UNION ALL
SELECT '密钥', '1234567890abcdef'
UNION ALL
SELECT '密文(hex)', sm4_c_encrypt_hex('Hello VastBase!', '1234567890abcdef')
UNION ALL
SELECT '解密结果', sm4_c_decrypt_hex(sm4_c_encrypt_hex('Hello VastBase!', '1234567890abcdef'), '1234567890abcdef');

-- 测试2: ECB模式 (bytea输出)
\echo ''
\echo '测试2: ECB模式加解密 (bytea)'
SELECT sm4_c_decrypt(sm4_c_encrypt('测试中文加密', '1234567890abcdef'), '1234567890abcdef') AS 解密结果;

-- 测试3: CBC模式
\echo ''
\echo '测试3: CBC模式加解密'
SELECT sm4_c_decrypt_cbc(
    sm4_c_encrypt_cbc('CBC模式测试数据', '1234567890abcdef', 'abcdef1234567890'),
    '1234567890abcdef',
    'abcdef1234567890'
) AS CBC解密结果;

-- 测试4: 使用32位十六进制密钥
\echo ''
\echo '测试4: 32位十六进制密钥'
SELECT sm4_c_decrypt_hex(
    sm4_c_encrypt_hex('使用Hex密钥', '0123456789abcdef0123456789abcdef'),
    '0123456789abcdef0123456789abcdef'
) AS 解密结果;

-- 测试5: 长文本加密
\echo ''
\echo '测试5: 长文本加密'
SELECT sm4_c_decrypt_hex(
    sm4_c_encrypt_hex('这是一段较长的测试文本，用于验证SM4加密算法对多个数据块的处理能力。SM4是中国国家密码管理局发布的分组密码标准。', '1234567890abcdef'),
    '1234567890abcdef'
) AS 长文本解密结果;

-- 测试6: 验证加密结果一致性
\echo ''
\echo '测试6: 加密一致性验证'
SELECT 
    CASE WHEN 
        sm4_c_encrypt_hex('test', 'key1234567890123') = sm4_c_encrypt_hex('test', 'key1234567890123')
    THEN '通过: 相同输入产生相同输出'
    ELSE '失败: 加密结果不一致'
    END AS 一致性测试;

\echo ''
\echo '========================================='
\echo '所有测试完成!'
\echo '========================================='
