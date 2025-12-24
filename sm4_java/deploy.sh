#!/bin/bash

# ========================================
# VastBase SM4 Hive UDF 快速部署脚本
# ========================================

set -e

echo "========================================"
echo "VastBase SM4 Hive UDF 部署脚本"
echo "========================================"

# 配置参数
JAR_FILE="target/vastbase-sm4-hive-udf-1.0.0.jar"
HDFS_PATH="/user/hive/udf/"
HIVE_DATABASE="default"

# 检查JAR文件是否存在
if [ ! -f "$JAR_FILE" ]; then
    echo "错误: JAR文件不存在: $JAR_FILE"
    echo "请先运行: mvn clean package"
    exit 1
fi

echo ""
echo "步骤 1: 检查JAR文件"
echo "JAR文件: $JAR_FILE"
ls -lh $JAR_FILE

# 上传到HDFS
echo ""
echo "步骤 2: 上传JAR到HDFS"
echo "目标路径: hdfs://$HDFS_PATH"

read -p "是否上传到HDFS? (y/n): " upload_choice
if [ "$upload_choice" == "y" ]; then
    hdfs dfs -mkdir -p $HDFS_PATH
    hdfs dfs -put -f $JAR_FILE $HDFS_PATH
    echo "上传完成!"
    hdfs dfs -ls $HDFS_PATH$(basename $JAR_FILE)
fi

# 生成Hive注册SQL
echo ""
echo "步骤 3: 生成Hive函数注册SQL"
cat > register_functions.sql << EOF
-- ========================================
-- VastBase SM4 Hive UDF 函数注册脚本
-- 自动生成于: $(date)
-- ========================================

-- 使用数据库
USE $HIVE_DATABASE;

-- 删除旧函数（如果存在）
DROP FUNCTION IF EXISTS sm4_encrypt_ecb;
DROP FUNCTION IF EXISTS sm4_decrypt_ecb;
DROP FUNCTION IF EXISTS sm4_encrypt_cbc;
DROP FUNCTION IF EXISTS sm4_decrypt_cbc;

-- 创建永久函数
CREATE FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB'
USING JAR 'hdfs://$HDFS_PATH$(basename $JAR_FILE)';

CREATE FUNCTION sm4_decrypt_ecb AS 'com.audaque.hiveudf.SM4DecryptECB'
USING JAR 'hdfs://$HDFS_PATH$(basename $JAR_FILE)';

CREATE FUNCTION sm4_encrypt_cbc AS 'com.audaque.hiveudf.SM4EncryptCBC'
USING JAR 'hdfs://$HDFS_PATH$(basename $JAR_FILE)';

CREATE FUNCTION sm4_decrypt_cbc AS 'com.audaque.hiveudf.SM4DecryptCBC'
USING JAR 'hdfs://$HDFS_PATH$(basename $JAR_FILE)';

-- 验证函数已注册
SHOW FUNCTIONS LIKE 'sm4*';

-- 查看函数详情
DESC FUNCTION sm4_encrypt_ecb;
DESC FUNCTION sm4_decrypt_ecb;

-- 简单测试
SELECT '========================================' AS divider;
SELECT 'SM4 UDF Function Test' AS test_section;
SELECT '========================================' AS divider;

SELECT 
    'Test ECB Mode' AS test_name,
    sm4_decrypt_ecb(
        sm4_encrypt_ecb('Hello Hive!', 'mykey1234567890'),
        'mykey1234567890'
    ) AS result;

SELECT '========================================' AS divider;
SELECT 'Registration completed successfully!' AS status;
SELECT '========================================' AS divider;
EOF

echo "SQL脚本已生成: register_functions.sql"

# 注册函数
echo ""
echo "步骤 4: 注册Hive函数"
read -p "是否立即注册函数到Hive? (y/n): " register_choice
if [ "$register_choice" == "y" ]; then
    echo "执行注册..."
    hive -f register_functions.sql
    echo "注册完成!"
fi

# 完成
echo ""
echo "========================================"
echo "部署完成!"
echo "========================================"
echo ""
echo "下一步操作:"
echo "1. 如果未注册函数，运行: hive -f register_functions.sql"
echo "2. 测试函数: hive -f test_sm4_udf.hql"
echo "3. 查看使用文档: cat README.md"
echo ""
echo "可用函数:"
echo "  - sm4_encrypt_ecb(plaintext, key)"
echo "  - sm4_decrypt_ecb(ciphertext, key)"
echo "  - sm4_encrypt_cbc(plaintext, key, iv)"
echo "  - sm4_decrypt_cbc(ciphertext, key, iv)"
echo ""
