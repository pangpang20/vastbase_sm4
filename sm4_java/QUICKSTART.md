# VastBase2MRS SM4 Hive UDF - 快速开始指南

## MRS中部署指南

### 1. 编译状态

```bash
✓ 编译成功: mvn clean compile
✓ 打包成功: mvn clean package
✓ JAR文件: target/vastbase-sm4-hive-udf-1.0.0.jar (4.1 MB)
```

### 2. 项目信息

- **项目名称**: vastbase-sm4-hive-udf
- **版本**: 1.0.0
- **JDK**: 17
- **构建工具**: Maven
- **Hive版本**: 3.1.3
- **Hadoop版本**: 3.1.3

### 3. 包含的UDF函数

1. **sm4_encrypt_ecb** - ECB模式加密
2. **sm4_decrypt_ecb** - ECB模式解密
3. **sm4_encrypt_cbc** - CBC模式加密
4. **sm4_decrypt_cbc** - CBC模式解密

---

## 🚀 5分钟快速部署

### 步骤1: 编译项目（已完成）

```bash
cd sm4_java
mvn clean package
```

### 步骤2: 上传JAR到HDFS

```bash
# Linux/Mac
hdfs dfs -mkdir -p /user/hive/udf/
hdfs dfs -put -f target/vastbase-sm4-hive-udf-1.0.0.jar /user/hive/udf/

# 验证上传
hdfs dfs -ls /user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar
```

### 步骤3: 在Hive中注册函数

#### 方法A: 临时函数（快速测试）

```sql
-- 启动Hive
hive

-- 添加JAR
ADD JAR hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar;

-- 创建临时函数
CREATE TEMPORARY FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB';
CREATE TEMPORARY FUNCTION sm4_decrypt_ecb AS 'com.audaque.hiveudf.SM4DecryptECB';
CREATE TEMPORARY FUNCTION sm4_encrypt_cbc AS 'com.audaque.hiveudf.SM4EncryptCBC';
CREATE TEMPORARY FUNCTION sm4_decrypt_cbc AS 'com.audaque.hiveudf.SM4DecryptCBC';

-- 测试
SELECT sm4_encrypt_ecb('Hello Hive!', 'mykey1234567890');
```

#### 方法B: 永久函数（生产环境推荐）

```sql
CREATE FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB'
USING JAR 'hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar';

CREATE FUNCTION sm4_decrypt_ecb AS 'com.audaque.hiveudf.SM4DecryptECB'
USING JAR 'hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar';

CREATE FUNCTION sm4_encrypt_cbc AS 'com.audaque.hiveudf.SM4EncryptCBC'
USING JAR 'hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar';

CREATE FUNCTION sm4_decrypt_cbc AS 'com.audaque.hiveudf.SM4DecryptCBC'
USING JAR 'hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar';
```

### 步骤4: 验证函数

```sql
-- 查看已注册的SM4函数
SHOW FUNCTIONS LIKE 'sm4*';

-- 查看函数详情
DESC FUNCTION sm4_encrypt_ecb;
DESC FUNCTION EXTENDED sm4_encrypt_ecb;

-- 简单测试
SELECT 
    sm4_decrypt_ecb(
        sm4_encrypt_ecb('Test Data', 'mykey1234567890'),
        'mykey1234567890'
    ) AS result;
```

---

## 使用示例

### 示例1: 加密用户手机号

```sql
-- 创建原始表
CREATE TABLE users (
    user_id INT,
    name STRING,
    phone STRING,
    email STRING
);

-- 插入测试数据
INSERT INTO users VALUES
(1, '张三', '13800138001', 'zhangsan@example.com'),
(2, '李四', '13800138002', 'lisi@example.com'),
(3, '王五', '13800138003', 'wangwu@example.com');

-- 创建加密表
CREATE TABLE users_encrypted (
    user_id INT,
    name STRING,
    phone_encrypted STRING,
    email STRING
);

-- 加密并插入
INSERT INTO users_encrypted
SELECT 
    user_id,
    name,
    sm4_encrypt_ecb(phone, 'prod_key_2024') AS phone_encrypted,
    email
FROM users;

-- 查询解密
SELECT 
    user_id,
    name,
    sm4_decrypt_ecb(phone_encrypted, 'prod_key_2024') AS phone,
    email
FROM users_encrypted;
```

### 示例2: 数据脱敏显示

```sql
-- 手机号脱敏（显示前3位和后4位）
SELECT 
    user_id,
    name,
    CONCAT(
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'prod_key_2024'), 1, 3),
        '****',
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'prod_key_2024'), 8, 4)
    ) AS phone_masked
FROM users_encrypted;

-- 输出示例: 138****8001
```

### 示例3: CBC模式加密（更安全）

```sql
-- CBC模式需要额外的IV参数
SELECT 
    sm4_encrypt_cbc('敏感数据', 'mykey1234567890', '1234567890abcdef') AS encrypted;

-- CBC模式解密
SELECT 
    sm4_decrypt_cbc(
        encrypted_data, 
        'mykey1234567890', 
        '1234567890abcdef'
    ) AS decrypted
FROM sensitive_table;
```

---

## 🧪 运行完整测试

```bash
# 运行提供的测试脚本
hive -f test_sm4_udf.hql

# 测试脚本包含:
# - 基本加密解密测试
# - 中文字符测试
# - 长文本测试
# - 表操作测试
# - 脱敏显示测试
# - 性能测试
```

---

## 📂 项目文件说明

```bash
sm4_java/
├── pom.xml                    # Maven配置（JDK 17）
├── README.md                  # 详细文档
├── QUICKSTART.md              # 快速开始（本文件）
├── .gitignore                 # Git忽略文件
├── deploy.sh                  # Linux部署脚本
├── deploy.bat                 # Windows部署脚本（已验证✓）
├── test_sm4_udf.hql          # Hive测试脚本
├── src/
│   ├── main/java/com/audaque/hiveudf/
│   │   ├── SM4Utils.java         # SM4加密工具类
│   │   ├── SM4EncryptECB.java    # ECB加密UDF
│   │   ├── SM4DecryptECB.java    # ECB解密UDF
│   │   ├── SM4EncryptCBC.java    # CBC加密UDF
│   │   └── SM4DecryptCBC.java    # CBC解密UDF
│   └── test/java/com/audaque/hiveudf/
│       └── SM4UtilsTest.java     # 单元测试
└── target/
    └── vastbase-sm4-hive-udf-1.0.0.jar  # 编译后的JAR（4.1 MB）
```

---

## ⚙️ 密钥说明

### 密钥格式

支持两种密钥格式：

1. **16字节字符串**: `"mykey1234567890"` （16个字符）
2. **32位十六进制**: `"6d796b657931323334353637383930"`

### 密钥管理建议

```sql
--  不推荐：硬编码密钥
SELECT sm4_encrypt_ecb(phone, 'hardcoded_key') FROM users;

--  推荐：使用Hive变量
SET hivevar:sm4_key=mykey1234567890;
SELECT sm4_encrypt_ecb(phone, '${hivevar:sm4_key}') FROM users;

--  最佳：从密钥管理系统获取（在应用层）
```

---

## 🔍 故障排查

### 问题1: 函数注册失败

```bash
错误: ClassNotFoundException: com.audaque.hiveudf.SM4EncryptECB
```

**解决**:

- 确认JAR已上传到HDFS
- 检查类名是否正确（包含完整包名）
- 重新添加JAR: `ADD JAR hdfs://...`

### 问题2: 解密结果为乱码

```bash
原因: 密钥不一致
```

**解决**:

- 确保加密和解密使用相同的密钥
- 检查密钥长度（必须是16字节）

### 问题3: 编译失败

```bash
# 清理并重新编译
mvn clean
mvn dependency:purge-local-repository
mvn clean package
```

---


**最后更新**: 2025-12-24  
**版本**: 1.0.0  
**维护者**: 陈云亮 <676814828@qq.com>
