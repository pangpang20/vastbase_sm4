# VastBase SM4 国密加密解决方案

本项目提供了VastBase数据库和Hive的SM4国密加解密完整解决方案，包含C语言数据库扩展和Java Hive UDF两个实现。

## 📁 项目结构

```
vastbase_sm4/
├── sm4_c/          # C语言实现 - VastBase数据库扩展
└── sm4_java/       # Java实现 - Hive UDF函数
```

---

## 📦 sm4_c - VastBase数据库扩展

**技术栈**: C语言 + PostgreSQL扩展框架  
**目标平台**: VastBase数据库 / PostgreSQL  
**加密算法**: SM4国密算法（GB/T 32907-2016标准）

### 主要功能

- ✅ SM4 ECB模式加解密
- ✅ SM4 CBC模式加解密
- ✅ 支持bytea和十六进制字符串格式
- ✅ 完整的SQL函数接口
- ✅ PKCS7填充支持

### 核心文件

| 文件           | 说明               |
| -------------- | ------------------ |
| `sm4.c`        | SM4算法核心实现    |
| `sm4_ext.c`    | PostgreSQL扩展接口 |
| `sm4.h`        | 头文件定义         |
| `sm4--1.0.sql` | SQL函数定义        |
| `sm4.control`  | 扩展控制文件       |
| `Makefile`     | 编译配置           |
| `test_sm4.sql` | 测试脚本           |

### 提供的SQL函数

```sql
-- ECB模式
sm4_encrypt(text, text) RETURNS bytea
sm4_decrypt(bytea, text) RETURNS text
sm4_encrypt_hex(text, text) RETURNS text
sm4_decrypt_hex(text, text) RETURNS text

-- CBC模式
sm4_encrypt_cbc(text, text, text) RETURNS bytea
sm4_decrypt_cbc(bytea, text, text) RETURNS text
```

### 快速开始

```bash
cd sm4_c

# 编译
make

# 安装（需要管理员权限）
sudo make install

# 在数据库中创建扩展
psql -d your_database -c "CREATE EXTENSION sm4;"

# 测试
psql -d your_database -f test_sm4.sql
```

### 使用示例

```sql
-- ECB模式加密
SELECT sm4_encrypt_hex('13800138001', 'mykey1234567890') AS encrypted_phone;

-- ECB模式解密
SELECT sm4_decrypt_hex('encrypted_hex_string', 'mykey1234567890') AS phone;

-- CBC模式加密（更安全）
SELECT sm4_encrypt_cbc('sensitive data', 'mykey1234567890', '1234567890abcdef');
```

### 应用场景

- ✅ 数据库字段加密存储
- ✅ 敏感信息保护（手机号、身份证等）
- ✅ 数据脱敏查询
- ✅ 政务系统数据安全

📖 **详细文档**: 查看 [sm4_c/README_SM4_C.md](sm4_c/README_SM4_C.md)

---

## ☕ sm4_java - Hive UDF函数

**技术栈**: Java 17 + Maven + BouncyCastle  
**目标平台**: Apache Hive 3.1.3+  
**加密算法**: SM4国密算法（与数据库扩展完全兼容）

### 主要功能

- ✅ 4个Hive UDF函数（ECB/CBC加密解密）
- ✅ Base64编码输出（便于Hive存储）
- ✅ 支持16字节密钥和32位十六进制密钥
- ✅ 完整的单元测试
- ✅ 自动化部署脚本

### 核心组件

| 组件                 | 说明                |
| -------------------- | ------------------- |
| `SM4Utils.java`      | SM4加解密工具类     |
| `SM4EncryptECB.java` | ECB加密UDF          |
| `SM4DecryptECB.java` | ECB解密UDF          |
| `SM4EncryptCBC.java` | CBC加密UDF          |
| `SM4DecryptCBC.java` | CBC解密UDF          |
| `pom.xml`            | Maven配置（JDK 17） |

### Hive UDF函数

```sql
-- ECB模式
sm4_encrypt_ecb(plaintext STRING, key STRING) RETURNS STRING
sm4_decrypt_ecb(ciphertext STRING, key STRING) RETURNS STRING

-- CBC模式
sm4_encrypt_cbc(plaintext STRING, key STRING, iv STRING) RETURNS STRING
sm4_decrypt_cbc(ciphertext STRING, key STRING, iv STRING) RETURNS STRING
```

### 快速开始

```bash
cd sm4_java

# 编译打包
mvn clean package

# 上传到HDFS
hdfs dfs -put target/vastbase-sm4-hive-udf-1.0.0.jar /user/hive/udf/

# 在Hive中注册（临时）
hive
ADD JAR hdfs:///user/hive/udf/vastbase-sm4-hive-udf-1.0.0.jar;
CREATE TEMPORARY FUNCTION sm4_encrypt_ecb AS 'com.audaque.hiveudf.SM4EncryptECB';
CREATE TEMPORARY FUNCTION sm4_decrypt_ecb AS 'com.audaque.hiveudf.SM4DecryptECB';

# 测试
SELECT sm4_encrypt_ecb('Hello Hive!', 'mykey1234567890');
```

### 使用示例

```sql
-- 加密用户表
CREATE TABLE users_encrypted AS
SELECT 
    user_id,
    name,
    sm4_encrypt_ecb(phone, 'prod_key_2024') AS phone_encrypted,
    sm4_encrypt_ecb(id_card, 'prod_key_2024') AS id_card_encrypted
FROM users;

-- 解密查询
SELECT 
    user_id,
    name,
    sm4_decrypt_ecb(phone_encrypted, 'prod_key_2024') AS phone
FROM users_encrypted;

-- 脱敏显示
SELECT 
    user_id,
    CONCAT(
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'prod_key_2024'), 1, 3),
        '****',
        SUBSTR(sm4_decrypt_ecb(phone_encrypted, 'prod_key_2024'), 8, 4)
    ) AS phone_masked
FROM users_encrypted;
```

### 应用场景

- ✅ Hive数据仓库敏感数据加密
- ✅ 大数据平台数据脱敏
- ✅ 数据迁移加密处理
- ✅ 批量数据加解密

📖 **详细文档**: 查看 [sm4_java/README.md](sm4_java/README.md)  
🚀 **快速开始**: 查看 [sm4_java/QUICKSTART.md](sm4_java/QUICKSTART.md)

---

## 🔗 两个实现的关系

### 兼容性

✅ **完全兼容** - 两个实现使用相同的SM4算法和PKCS7填充方式，可以互相解密对方加密的数据。

### 典型应用架构

```
┌─────────────────────────────────────────┐
│         业务应用层                        │
│  ┌──────────┐      ┌──────────┐         │
│  │ Java应用 │      │ Web应用  │         │
│  └────┬─────┘      └────┬─────┘         │
└───────┼─────────────────┼───────────────┘
        │                 │
        │                 │
┌───────▼─────────────────▼───────────────┐
│           数据处理层                      │
│  ┌──────────────┐  ┌─────────────────┐  │
│  │  Hive数据仓库 │  │ VastBase数据库  │  │
│  │  (sm4_java)  │  │   (sm4_c)       │  │
│  └──────────────┘  └─────────────────┘  │
│       UDF加解密        扩展函数加解密      │
└─────────────────────────────────────────┘
```

### 使用场景选择

| 场景                      | 推荐方案 | 原因               |
| ------------------------- | -------- | ------------------ |
| VastBase/PostgreSQL数据库 | sm4_c    | 性能最优，原生支持 |
| Hive数据仓库              | sm4_java | 大数据平台标准     |
| Java应用集成              | sm4_java | 开发语言一致       |
| 高性能要求                | sm4_c    | C实现性能更好      |
| 跨平台数据交换            | 两者皆可 | 完全兼容           |

---

## 🔐 安全最佳实践

### 1. 密钥管理

```bash
# ❌ 不要硬编码密钥
SELECT sm4_encrypt('data', 'hardcoded_key');

# ✅ 使用环境变量
export SM4_KEY="your_secret_key"

# ✅ 使用密钥管理系统（KMS）
# AWS KMS, Azure Key Vault, HashiCorp Vault等
```

### 2. 密钥格式

支持两种密钥格式：
- **16字节字符串**: `"mykey1234567890"` (推荐)
- **32位十六进制**: `"6d796b657931323334353637383930"`

### 3. 加密模式选择

- **ECB模式**: 简单快速，适合独立字段加密
- **CBC模式**: 更安全，适合大数据或高安全要求场景

### 4. 访问控制

```sql
-- VastBase: 限制函数执行权限
REVOKE EXECUTE ON FUNCTION sm4_decrypt FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sm4_decrypt TO trusted_role;

-- Hive: 使用脱敏视图
CREATE VIEW users_masked AS
SELECT id, name, phone_masked FROM users_encrypted;
GRANT SELECT ON users_masked TO analyst_role;
```

---

## 📊 性能对比

| 指标     | sm4_c      | sm4_java  |
| -------- | ---------- | --------- |
| 加密速度 | ⭐⭐⭐⭐⭐ 极快 | ⭐⭐⭐⭐ 快   |
| 内存占用 | ⭐⭐⭐⭐⭐ 极小 | ⭐⭐⭐ 中等  |
| 并发性能 | ⭐⭐⭐⭐⭐ 优秀 | ⭐⭐⭐⭐ 良好 |
| 部署难度 | ⭐⭐⭐ 中等   | ⭐⭐⭐⭐ 简单 |
| 跨平台性 | ⭐⭐⭐ 需编译 | ⭐⭐⭐⭐⭐ JVM |

---

## 🧪 测试验证

### sm4_c测试

```bash
cd sm4_c
psql -d testdb -f test_sm4.sql
```

### sm4_java测试

```bash
cd sm4_java
mvn test
hive -f test_sm4_udf.hql
```

### 互操作性测试

```sql
-- 在VastBase中加密
SELECT sm4_encrypt_hex('test data', 'mykey1234567890') AS encrypted;
-- 输出: a1b2c3d4e5f6...

-- 在Hive中解密（转换为Base64）
SELECT sm4_decrypt_ecb('base64_of_a1b2c3d4e5f6...', 'mykey1234567890');
-- 输出: test data
```

---

## 📚 文档导航

- **sm4_c详细文档**: [sm4_c/README_SM4_C.md](sm4_c/README_SM4_C.md)
- **sm4_java详细文档**: [sm4_java/README.md](sm4_java/README.md)
- **sm4_java快速开始**: [sm4_java/QUICKSTART.md](sm4_java/QUICKSTART.md)
- **数据库使用示例**: [sm4_c/demo_citizen_data.sql](sm4_c/demo_citizen_data.sql)

---

## 🛠️ 环境要求

### sm4_c

- PostgreSQL/VastBase 开发包
- GCC/Clang 编译器
- Make 构建工具
- Linux/Unix 系统（推荐）

### sm4_java

- JDK 17+
- Maven 3.6+
- Hive 3.1.3+
- Hadoop 3.3.4+

---

## 📄 许可证

本项目遵循开源许可证，详见 [sm4_c/LICENSE](sm4_c/LICENSE)

---

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

1. Fork本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

---

## 📞 技术支持

如有问题，请：
1. 查看对应子目录的详细文档
2. 运行测试脚本验证环境
3. 提交Issue描述问题

---

**最后更新**: 2024-12-24  
**版本**: 1.0.0  
**维护者**: VastBase SM4 Team
