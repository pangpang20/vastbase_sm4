@echo off
REM ========================================
REM VastBase SM4 Hive UDF Windows部署脚本
REM ========================================

echo ========================================
echo VastBase SM4 Hive UDF Windows部署脚本
echo ========================================

set JAR_FILE=target\vastbase-sm4-hive-udf-1.0.0.jar

REM 检查JAR文件
if not exist %JAR_FILE% (
    echo 错误: JAR文件不存在: %JAR_FILE%
    echo 请先运行: mvn clean package
    pause
    exit /b 1
)

echo.
echo [✓] JAR文件检查通过
dir %JAR_FILE%

echo.
echo ========================================
echo 部署说明
echo ========================================
echo.
echo 1. 上传JAR到HDFS:
echo    hdfs dfs -mkdir -p /user/hive/udf/
echo    hdfs dfs -put -f %JAR_FILE% /user/hive/udf/
echo.
echo 2. 在Hive中注册函数（临时）:
echo    ADD JAR hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar;
echo    CREATE TEMPORARY FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB';
echo    CREATE TEMPORARY FUNCTION sm4_decrypt_ecb AS 'com.audaque.hiveudf.SM4DecryptECB';
echo    CREATE TEMPORARY FUNCTION sm4_encrypt_cbc AS 'com.audaque.hiveudf.SM4EncryptCBC';
echo    CREATE TEMPORARY FUNCTION sm4_decrypt_cbc AS 'com.audaque.hiveudf.SM4DecryptCBC';
echo.
echo 3. 在Hive中注册函数（永久）:
echo    CREATE FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB'
echo    USING JAR 'hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar';
echo.
echo 4. 测试函数:
echo    SELECT sm4_encrypt_ecb('Hello!', 'mykey1234567890');
echo    SELECT sm4_decrypt_ecb(sm4_encrypt_ecb('Hello!', 'mykey1234567890'), 'mykey1234567890');
echo.
echo 5. 运行完整测试:
echo    hive -f test_sm4_udf.hql
echo.
echo ========================================
echo 详细文档请查看: README.md
echo ========================================

pause
