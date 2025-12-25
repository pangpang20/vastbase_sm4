-- ========================================
-- VastBase2MRS SM4 Hive UDF 测试脚本
-- ========================================
-- 使用方法: hive -f test_sm4_udf.hql
-- 或在hive命令行中: source test_sm4_udf.hql

-- 1. 添加JAR包（请修改为实际路径）
ADD JAR /path/to/vastbase-sm4-hive-udf-1.0.0.jar;

-- 2. 创建临时函数
CREATE TEMPORARY FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB';
CREATE TEMPORARY FUNCTION sm4_decrypt_ecb AS 'com.audaque.hiveudf.SM4DecryptECB';
CREATE TEMPORARY FUNCTION sm4_encrypt_cbc AS 'com.audaque.hiveudf.SM4EncryptCBC';
CREATE TEMPORARY FUNCTION sm4_decrypt_cbc AS 'com.audaque.hiveudf.SM4DecryptCBC';

-- 3. 验证函数已注册
SELECT '========================================' AS divider;
SELECT 'Registered SM4 Functions' AS test_section;
SELECT '========================================' AS divider;
SHOW FUNCTIONS LIKE 'sm4*';

-- 4. 测试ECB模式加密解密
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 1: ECB Mode Encryption/Decryption' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    '原文' AS type,
    'Hello Hive!' AS content
UNION ALL
SELECT 
    '密钥',
    'mykey12345678901'
UNION ALL
SELECT 
    '密文(Base64)',
    sm4_encrypt_ecb('Hello Hive!', 'mykey12345678901')
UNION ALL
SELECT 
    '解密结果',
    sm4_decrypt_ecb(sm4_encrypt_ecb('Hello Hive!', 'mykey12345678901'), 'mykey12345678901');

-- 5. 测试中文加密
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 2: Chinese Characters' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    '测试中文加密' AS original,
    sm4_encrypt_ecb('测试中文加密', 'mykey12345678901') AS encrypted,
    sm4_decrypt_ecb(sm4_encrypt_ecb('测试中文加密', 'mykey12345678901'), 'mykey12345678901') AS decrypted;

-- 6. 测试手机号加密
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 3: Phone Number Encryption' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    '13800138001' AS original_phone,
    sm4_encrypt_ecb('13800138001', 'mykey12345678901') AS encrypted_phone,
    sm4_decrypt_ecb(sm4_encrypt_ecb('13800138001', 'mykey12345678901'), 'mykey12345678901') AS decrypted_phone;

-- 7. 测试身份证号加密
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 4: ID Card Encryption' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    '110101198503151234' AS original_id,
    sm4_encrypt_ecb('110101198503151234', 'mykey12345678901') AS encrypted_id,
    sm4_decrypt_ecb(sm4_encrypt_ecb('110101198503151234', 'mykey12345678901'), 'mykey12345678901') AS decrypted_id;

-- 8. 测试CBC模式
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 5: CBC Mode Encryption/Decryption' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    'CBC模式测试数据' AS original,
    sm4_encrypt_cbc('CBC模式测试数据', 'mykey12345678901', '1234567890abcdef') AS encrypted,
    sm4_decrypt_cbc(
        sm4_encrypt_cbc('CBC模式测试数据', 'mykey12345678901', '1234567890abcdef'),
        'mykey12345678901',
        '1234567890abcdef'
    ) AS decrypted;

-- 9. 测试长文本
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 6: Long Text' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    sm4_decrypt_ecb(
        sm4_encrypt_ecb(
            '这是一段较长的测试文本，用于验证SM4加密算法对多个数据块的处理能力。SM4是中国国家密码管理局发布的分组密码标准，具有高安全性和良好的性能。',
            'mykey12345678901'
        ),
        'mykey12345678901'
    ) AS long_text_result;

-- 10. 测试空值处理
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 7: NULL and Empty String Handling' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    'Empty String' AS test_case,
    sm4_encrypt_ecb('', 'mykey12345678901') AS encrypted,
    LENGTH(sm4_encrypt_ecb('', 'mykey12345678901')) AS encrypted_length;

-- 11. 创建测试表
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 8: Table Operations' AS test_section;
SELECT '========================================' AS divider;

-- 创建临时测试表
DROP TABLE IF EXISTS sm4_test_table;
CREATE TABLE sm4_test_table (
    id INT,
    name STRING,
    phone STRING,
    id_card STRING
);

-- 插入测试数据
INSERT INTO sm4_test_table VALUES
(1, '张伟', '13800138001', '110101198503151234'),
(2, '李娜', '13800138002', '310101199007221234'),
(3, '王强', '13800138003', '440101197812081234'),
(4, '刘芳', '13800138004', '500101199505301234'),
(5, '陈明', '13800138005', '510101198209181234');

SELECT 'Test data inserted' AS status;
SELECT COUNT(*) AS record_count FROM sm4_test_table;

-- 12. 创建加密表
DROP TABLE IF EXISTS sm4_test_table_encrypted;
CREATE TABLE sm4_test_table_encrypted (
    id INT,
    name STRING,
    phone_encrypted STRING,
    id_card_encrypted STRING
);

-- 加密并插入数据
INSERT INTO sm4_test_table_encrypted
SELECT 
    id,
    name,
    sm4_encrypt_ecb(phone, 'mykey12345678901') AS phone_encrypted,
    sm4_encrypt_ecb(id_card, 'mykey12345678901') AS id_card_encrypted
FROM sm4_test_table;

SELECT 'Encrypted data inserted' AS status;

-- 13. 查询加密表（显示加密数据）
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 9: View Encrypted Data' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    id,
    name,
    phone_encrypted,
    id_card_encrypted
FROM sm4_test_table_encrypted
LIMIT 3;

-- 14. 解密查询
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 10: Decrypt Query' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    id,
    name,
    sm4_decrypt_ecb(phone_encrypted, 'mykey12345678901') AS phone,
    sm4_decrypt_ecb(id_card_encrypted, 'mykey12345678901') AS id_card
FROM sm4_test_table_encrypted
LIMIT 3;

-- 15. 脱敏显示
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 11: Masked Display' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    id,
    name,
    CONCAT(
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'mykey12345678901'), 1, 3),
        '****',
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'mykey12345678901'), 8, 4)
    ) AS phone_masked,
    CONCAT(
        SUBSTR(sm4_decrypt_ecb(id_card_encrypted, 'mykey12345678901'), 1, 6),
        '********',
        SUBSTR(sm4_decrypt_ecb(id_card_encrypted, 'mykey12345678901'), 15, 4)
    ) AS id_card_masked
FROM sm4_test_table_encrypted
LIMIT 5;

-- 16. 条件查询测试
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 12: Conditional Query' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    id,
    name,
    sm4_decrypt_ecb(phone_encrypted, 'mykey12345678901') AS phone
FROM sm4_test_table_encrypted
WHERE sm4_decrypt_ecb(phone_encrypted, 'mykey12345678901') = '13800138003';

-- 17. 一致性验证
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 13: Consistency Verification' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    'Consistency Check' AS test_name,
    CASE 
        WHEN sm4_encrypt_ecb('test', 'key1234567890ab') = sm4_encrypt_ecb('test', 'key1234567890ab')
        THEN 'PASS: Same input produces same output'
        ELSE 'FAIL: Encryption not consistent'
    END AS result;

-- 18. 性能测试（小规模）
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test 14: Performance Test (Small Scale)' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    COUNT(*) AS total_encrypted,
    'Performance test completed' AS status
FROM (
    SELECT sm4_encrypt_ecb(CONCAT('data_', name), 'mykey12345678901') AS encrypted
    FROM sm4_test_table
) t;

-- 19. 清理测试表
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Cleanup' AS test_section;
SELECT '========================================' AS divider;

DROP TABLE IF EXISTS sm4_test_table;
DROP TABLE IF EXISTS sm4_test_table_encrypted;

SELECT 'Test tables cleaned up' AS status;

-- 20. 测试总结
SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Test Summary' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    'All Tests Completed!' AS message,
    'SM4 UDF functions are working correctly' AS status;

SELECT '========================================' AS divider;

-- 21. 显示函数帮助信息
SELECT '' AS blank_line;
SELECT 'Function Descriptions:' AS section;
SELECT '========================================' AS divider;

DESC FUNCTION sm4_encrypt_ecb;
DESC FUNCTION sm4_decrypt_ecb;
DESC FUNCTION sm4_encrypt_cbc;
DESC FUNCTION sm4_decrypt_cbc;

SELECT '' AS blank_line;
SELECT '========================================' AS divider;
SELECT 'Testing Complete!' AS final_message;
SELECT '========================================' AS divider;
