# VastBase2MRS SM4 Hive UDF

基于Java 17的SM4国密加解密Hive UDF函数，支持ECB和CBC两种加密模式，与VastBase数据库SM4扩展完全兼容。

## 📋 项目信息

- **项目名称**: vastbase-sm4-hive-udf
- **版本**: 1.0.0
- **JDK版本**: 17
- **构建工具**: Maven
- **加密算法**: SM4（国密算法）
- **支持模式**: ECB、CBC

## 🚀 快速开始

### 1. 环境要求

- **JDK**: 17+
- **Maven**: 3.6+
- **Hive**: 3.1.3+
- **Hadoop**: 3.1.3+

### 2. 编译打包

```bash
# 进入项目目录
cd sm4_java

# 清理并编译
mvn clean compile

# 运行测试
mvn test

# 打包（生成jar文件）
mvn clean package

# 打包成功后，jar文件位于: target/vastbase-sm4-hive-udf-1.0.0.jar
```

**编译成功标志**:
```
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  XX.XXX s
[INFO] Finished at: YYYY-MM-DDTHH:MM:SS+08:00
[INFO] ------------------------------------------------------------------------
```

### 3. 部署到Hive

#### 方法1: 临时注册（会话级别）

```sql
-- 1. 添加JAR包到Hive
ADD JAR /path/to/vastbase-sm4-hive-udf-1.0.0.jar;

-- 2. 创建临时函数
CREATE TEMPORARY FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB';
CREATE TEMPORARY FUNCTION sm4_decrypt_ecb AS 'com.audaque.hiveudf.SM4DecryptECB';
CREATE TEMPORARY FUNCTION sm4_encrypt_cbc AS 'com.audaque.hiveudf.SM4EncryptCBC';
CREATE TEMPORARY FUNCTION sm4_decrypt_cbc AS 'com.audaque.hiveudf.SM4DecryptCBC';

-- 3. 验证函数已注册
SHOW FUNCTIONS LIKE 'sm4*';
```

#### 方法2: 永久注册（推荐）

```sql
-- 1. 将JAR包上传到HDFS
hdfs dfs -put vastbase-sm4-hive-udf-1.0.0.jar /user/hive/udf/

-- 2. 在Hive中创建永久函数
CREATE FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB'
USING JAR 'hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar';

CREATE FUNCTION sm4_decrypt_ecb AS 'com.audaque.hiveudf.SM4DecryptECB'
USING JAR 'hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar';

CREATE FUNCTION sm4_encrypt_cbc AS 'com.audaque.hiveudf.SM4EncryptCBC'
USING JAR 'hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar';

CREATE FUNCTION sm4_decrypt_cbc AS 'com.audaque.hiveudf.SM4DecryptCBC'
USING JAR 'hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar';

-- 3. 验证永久函数
SHOW FUNCTIONS LIKE 'sm4*';
DESC FUNCTION sm4_encrypt_ecb;
DESC FUNCTION EXTENDED sm4_encrypt_ecb;
```

## 📖 函数使用说明

### 1. sm4_encrypt_ecb - ECB模式加密

**语法**:
```sql
sm4_encrypt_ecb(plaintext STRING, key STRING) RETURNS STRING
```

**参数**:
- `plaintext`: 明文字符串
- `key`: 加密密钥（16字节字符串或32位十六进制）

**返回**: Base64编码的密文字符串

**示例**:
```sql
-- 基本加密
SELECT sm4_encrypt_ecb('13800138001', 'mykey1234567890') AS encrypted_phone;

-- 批量加密用户手机号
SELECT 
    user_id,
    name,
    sm4_encrypt_ecb(phone, 'mykey1234567890') AS encrypted_phone
FROM user_table;

-- 加密身份证号
SELECT 
    citizen_id,
    name,
    sm4_encrypt_ecb(id_card, 'gov2024secret123') AS encrypted_id_card
FROM citizen_info;
```

### 2. sm4_decrypt_ecb - ECB模式解密

**语法**:
```sql
sm4_decrypt_ecb(ciphertext STRING, key STRING) RETURNS STRING
```

**参数**:
- `ciphertext`: Base64编码的密文字符串
- `key`: 解密密钥（必须与加密时的密钥一致）

**返回**: 解密后的明文字符串

**示例**:
```sql
-- 基本解密
SELECT sm4_decrypt_ecb('base64_encrypted_data', 'mykey1234567890') AS phone;

-- 解密查询
SELECT 
    user_id,
    name,
    sm4_decrypt_ecb(encrypted_phone, 'mykey1234567890') AS phone
FROM user_table_encrypted;

-- 条件查询（解密后匹配）
SELECT *
FROM user_table_encrypted
WHERE sm4_decrypt_ecb(encrypted_phone, 'mykey1234567890') = '13800138001';
```

### 3. sm4_encrypt_cbc - CBC模式加密

**语法**:
```sql
sm4_encrypt_cbc(plaintext STRING, key STRING, iv STRING) RETURNS STRING
```

**参数**:
- `plaintext`: 明文字符串
- `key`: 加密密钥（16字节）
- `iv`: 初始向量（16字节，增强安全性）

**返回**: Base64编码的密文字符串

**示例**:
```sql
-- CBC模式加密
SELECT sm4_encrypt_cbc(
    'sensitive data', 
    'mykey1234567890', 
    '1234567890abcdef'
) AS encrypted_data;
```

### 4. sm4_decrypt_cbc - CBC模式解密

**语法**:
```sql
sm4_decrypt_cbc(ciphertext STRING, key STRING, iv STRING) RETURNS STRING
```

**示例**:
```sql
-- CBC模式解密
SELECT sm4_decrypt_cbc(
    encrypted_data, 
    'mykey1234567890', 
    '1234567890abcdef'
) AS original_data
FROM encrypted_table;
```

## 💡 完整使用示例

### 场景1: 创建加密表

```sql
-- 创建原始表
CREATE TABLE user_info (
    user_id INT,
    name STRING,
    phone STRING,
    id_card STRING,
    email STRING,
    created_at TIMESTAMP
);

-- 插入测试数据
INSERT INTO user_info VALUES
(1, '张伟', '13800138001', '110101198503151234', 'zhangwei@example.com', CURRENT_TIMESTAMP),
(2, '李娜', '13800138002', '310101199007221234', 'lina@example.com', CURRENT_TIMESTAMP),
(3, '王强', '13800138003', '440101197812081234', 'wangqiang@example.com', CURRENT_TIMESTAMP);

-- 创建加密表
CREATE TABLE user_info_encrypted (
    user_id INT,
    name STRING,
    phone_encrypted STRING,
    id_card_encrypted STRING,
    email STRING,
    created_at TIMESTAMP
);

-- 将数据加密后插入
INSERT INTO user_info_encrypted
SELECT 
    user_id,
    name,
    sm4_encrypt_ecb(phone, 'mykey1234567890') AS phone_encrypted,
    sm4_encrypt_ecb(id_card, 'mykey1234567890') AS id_card_encrypted,
    email,
    created_at
FROM user_info;
```

### 场景2: 查询解密

```sql
-- 完整解密查询
SELECT 
    user_id,
    name,
    sm4_decrypt_ecb(phone_encrypted, 'mykey1234567890') AS phone,
    sm4_decrypt_ecb(id_card_encrypted, 'mykey1234567890') AS id_card,
    email
FROM user_info_encrypted;

-- 脱敏显示（只解密前3位和后4位）
SELECT 
    user_id,
    name,
    CONCAT(
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'mykey1234567890'), 1, 3),
        '****',
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'mykey1234567890'), 8, 4)
    ) AS phone_masked,
    email
FROM user_info_encrypted;

-- 身份证脱敏（显示前6位和后4位）
SELECT 
    user_id,
    name,
    CONCAT(
        SUBSTR(sm4_decrypt_ecb(id_card_encrypted, 'mykey1234567890'), 1, 6),
        '********',
        SUBSTR(sm4_decrypt_ecb(id_card_encrypted, 'mykey1234567890'), 15, 4)
    ) AS id_card_masked
FROM user_info_encrypted;
```

### 场景3: 根据加密字段查询

```sql
-- 方法1: 解密后匹配（性能较低）
SELECT *
FROM user_info_encrypted
WHERE sm4_decrypt_ecb(phone_encrypted, 'mykey1234567890') = '13800138001';

-- 方法2: 先加密查询条件（推荐，性能更好）
-- 注意：需要在应用层先加密查询条件
SELECT *
FROM user_info_encrypted
WHERE phone_encrypted = 'xYzAbc123...'; -- 预先加密的值
```

### 场景4: 创建解密视图

```sql
-- 创建解密视图（简化查询）
CREATE VIEW user_info_decrypted AS
SELECT 
    user_id,
    name,
    sm4_decrypt_ecb(phone_encrypted, 'mykey1234567890') AS phone,
    sm4_decrypt_ecb(id_card_encrypted, 'mykey1234567890') AS id_card,
    email,
    created_at
FROM user_info_encrypted;

-- 使用视图查询
SELECT * FROM user_info_decrypted WHERE phone = '13800138001';

-- 创建脱敏视图
CREATE VIEW user_info_masked AS
SELECT 
    user_id,
    name,
    CONCAT(
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'mykey1234567890'), 1, 3),
        '****',
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'mykey1234567890'), 8, 4)
    ) AS phone,
    CONCAT(
        SUBSTR(sm4_decrypt_ecb(id_card_encrypted, 'mykey1234567890'), 1, 6),
        '********',
        SUBSTR(sm4_decrypt_ecb(id_card_encrypted, 'mykey1234567890'), 15, 4)
    ) AS id_card,
    email,
    created_at
FROM user_info_encrypted;
```

### 场景5: 数据迁移（加密历史数据）

```sql
-- 将历史明文数据加密
CREATE TABLE legacy_data_encrypted AS
SELECT 
    id,
    name,
    sm4_encrypt_ecb(ssn, 'migration_key_2024') AS ssn_encrypted,
    sm4_encrypt_ecb(credit_card, 'migration_key_2024') AS credit_card_encrypted,
    address,
    created_at
FROM legacy_data;

-- 验证加密结果
SELECT 
    id,
    name,
    sm4_decrypt_ecb(ssn_encrypted, 'migration_key_2024') AS ssn,
    sm4_decrypt_ecb(credit_card_encrypted, 'migration_key_2024') AS credit_card
FROM legacy_data_encrypted
LIMIT 10;
```

## 🔐 安全最佳实践

### 1. 密钥管理

```sql
-- ❌ 不要硬编码密钥
SELECT sm4_encrypt_ecb(phone, 'hardcoded_key') FROM user_table;

-- ✅ 使用Hive变量
SET hivevar:encryption_key=mykey1234567890;
SELECT sm4_encrypt_ecb(phone, '${hivevar:encryption_key}') FROM user_table;

-- ✅ 从配置文件读取（在应用层）
-- 或使用密钥管理系统（KMS）
```

### 2. 访问控制

```sql
-- 限制对解密视图的访问
GRANT SELECT ON TABLE user_info_masked TO ROLE data_analyst;
REVOKE SELECT ON TABLE user_info_encrypted FROM ROLE data_analyst;

-- 只允许管理员访问完整解密数据
GRANT SELECT ON VIEW user_info_decrypted TO ROLE admin;
```

### 3. 审计日志

```sql
-- 记录敏感数据访问
CREATE TABLE audit_log (
    access_time TIMESTAMP,
    user_name STRING,
    table_name STRING,
    operation STRING,
    record_count INT
);

-- 在查询中添加审计记录
INSERT INTO audit_log VALUES (
    CURRENT_TIMESTAMP,
    CURRENT_USER(),
    'user_info_decrypted',
    'SELECT',
    (SELECT COUNT(*) FROM user_info_encrypted)
);
```

## ⚡ 性能优化

### 1. 避免在WHERE子句中解密

```sql
-- ❌ 低效：每行都需要解密
SELECT *
FROM user_info_encrypted
WHERE sm4_decrypt_ecb(phone_encrypted, 'key') = '13800138001';

-- ✅ 高效：使用加密后的值查询
-- 在应用层先加密查询条件
SELECT *
FROM user_info_encrypted
WHERE phone_encrypted = 'precomputed_encrypted_value';
```

### 2. 批量处理

```sql
-- ✅ 批量加密插入
INSERT INTO user_info_encrypted
SELECT 
    user_id,
    name,
    sm4_encrypt_ecb(phone, 'key') AS phone_encrypted
FROM user_info
WHERE dt = '2024-12-24';  -- 增量处理
```

### 3. 分区表优化

```sql
-- 创建分区表
CREATE TABLE user_info_encrypted_partitioned (
    user_id INT,
    name STRING,
    phone_encrypted STRING
)
PARTITIONED BY (dt STRING);

-- 按分区加密
INSERT INTO user_info_encrypted_partitioned PARTITION(dt='2024-12-24')
SELECT 
    user_id,
    name,
    sm4_encrypt_ecb(phone, 'key')
FROM user_info
WHERE dt = '2024-12-24';
```

## 🧪 测试验证

### 单元测试

```bash
# 运行所有测试
mvn test

# 运行特定测试类
mvn test -Dtest=SM4UtilsTest

# 查看测试报告
# target/surefire-reports/
```

### Hive集成测试

```sql
-- 测试脚本: test_sm4_udf.hql

-- 1. 添加JAR
ADD JAR /path/to/vastbase-sm4-hive-udf-1.0.0.jar;

-- 2. 创建函数
CREATE TEMPORARY FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB';
CREATE TEMPORARY FUNCTION sm4_decrypt_ecb AS 'com.audaque.hiveudf.SM4DecryptECB';

-- 3. 测试加密解密
SELECT '========== ECB Test ==========' AS test_name;
SELECT sm4_encrypt_ecb('Hello Hive!', 'mykey1234567890') AS encrypted;
SELECT sm4_decrypt_ecb(sm4_encrypt_ecb('Hello Hive!', 'mykey1234567890'), 'mykey1234567890') AS decrypted;

-- 4. 测试中文
SELECT '========== Chinese Test ==========' AS test_name;
SELECT sm4_decrypt_ecb(sm4_encrypt_ecb('测试中文', 'mykey1234567890'), 'mykey1234567890') AS result;

-- 5. 测试长文本
SELECT '========== Long Text Test ==========' AS test_name;
SELECT sm4_decrypt_ecb(
    sm4_encrypt_ecb('这是一段很长的测试文本，用于验证SM4加密算法对长文本的处理能力。', 'mykey1234567890'),
    'mykey1234567890'
) AS result;

-- 6. 性能测试
SELECT '========== Performance Test ==========' AS test_name;
SELECT COUNT(*) AS total_encrypted
FROM (
    SELECT sm4_encrypt_ecb(CONCAT('phone_', CAST(id AS STRING)), 'mykey1234567890') AS enc
    FROM (SELECT EXPLODE(SPLIT(SPACE(1000), ' ')) AS id) t
) t;
```

运行测试:
```bash
hive -f test_sm4_udf.hql
```

## 📁 项目结构

```
sm4_java/
├── pom.xml                                 # Maven配置文件
├── README.md                               # 项目文档（本文件）
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── audaque/
│   │               └── hiveudf/
│   │                   ├── SM4Utils.java          # SM4加解密工具类
│   │                   ├── SM4EncryptECB.java     # ECB加密UDF
│   │                   ├── SM4DecryptECB.java     # ECB解密UDF
│   │                   ├── SM4EncryptCBC.java     # CBC加密UDF
│   │                   └── SM4DecryptCBC.java     # CBC解密UDF
│   └── test/
│       └── java/
│           └── com/
│               └── audaque/
│                   └── hiveudf/
│                       └── SM4UtilsTest.java      # 单元测试
└── target/
    └── vastbase-sm4-hive-udf-1.0.0.jar    # 打包后的JAR文件
```

## 🔧 常见问题

### Q1: 编译失败 - 找不到Hadoop/Hive类

**A**: 确保Maven配置了正确的仓库，或者使用华为云镜像：
```bash
# 如果编译失败，尝试清理并重新下载依赖
mvn clean
mvn dependency:purge-local-repository
mvn package
```

### Q2: Hive中注册函数失败

**A**: 检查以下几点：
1. JAR包路径是否正确
2. Hive版本是否兼容（建议3.1.3+）
3. 类名是否完整（包含包名）

```sql
-- 查看当前已加载的JAR
LIST JARS;

-- 删除旧JAR重新添加
DELETE JAR /path/to/old.jar;
ADD JAR /path/to/new.jar;
```

### Q3: 解密结果为乱码

**A**: 可能原因：
1. 密钥不一致
2. 加密模式不匹配（ECB vs CBC）
3. 字符编码问题

```sql
-- 验证密钥是否一致
SELECT 
    original_text,
    sm4_decrypt_ecb(sm4_encrypt_ecb(original_text, 'key1'), 'key1') AS correct,
    sm4_decrypt_ecb(sm4_encrypt_ecb(original_text, 'key1'), 'key2') AS wrong
FROM test_table;
```

### Q4: 性能问题

**A**: 优化建议：
1. 避免在WHERE条件中解密
2. 使用分区表
3. 批量处理而非逐行处理
4. 考虑创建解密视图

### Q5: 如何卸载函数

```sql
-- 删除临时函数
DROP TEMPORARY FUNCTION IF EXISTS sm4_encrypt_ecb;
DROP TEMPORARY FUNCTION IF EXISTS sm4_decrypt_ecb;

-- 删除永久函数
DROP FUNCTION IF EXISTS sm4_encrypt_ecb;
DROP FUNCTION IF EXISTS sm4_decrypt_ecb;
```

## 📞 技术支持

- **问题反馈**: 提交Issue到项目仓库
- **文档**: 查看本README或源码注释
- **兼容性**: 与VastBase数据库SM4扩展完全兼容

## 📄 许可证

本项目遵循与VastBase SM4扩展相同的许可证。

---

**最后更新**: 2025-12-24  
**版本**: 1.0.0  
**作者**: 陈云亮 <676814828@qq.com>
