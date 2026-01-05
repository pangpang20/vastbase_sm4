# VastBase2MRS 国密加密解决方案

本项目提供了VastBase数据库和Hive的国密加解密完整解决方案，支持SM2非对称加密、SM4对称加密，包含C语言数据库扩展和Java Hive UDF实现。

## 项目结构

```bash
vastbase_sm4/
├── sm2_c/          # C语言实现 - SM2国密非对称加密扩展 (NEW)
├── sm4_c/          # C语言实现 - SM4国密对称加密扩展
└── sm4_java/       # Java实现 - MRS Hive UDF函数
```

---

## sm2_c - VastBase SM2数据库扩展 (NEW)

**技术栈**: C语言 + PostgreSQL扩展框架

**目标平台**: VastBase数据库

**加密算法**: SM2国密椭圆曲线公钥密码算法（GB/T 32918-2016标准）

### 主要功能

- ✅ SM2密钥对生成
- ✅ SM2公钥加密/私钥解密
- ✅ SM2数字签名/验签
- ✅ 支持bytea、十六进制、Base64多种格式
- ✅ 支持自定义用户标识(ID)
- ✅ 内置SM3哈希算法

### 核心文件

| 文件 | 说明 |
|------|------|
| `sm2.c` | SM2算法核心实现（椭圆曲线、SM3、KDF） |
| `sm2_ext.c` | PostgreSQL扩展接口 |
| `sm2.h` | 头文件定义 |
| `sm2--1.0.sql` | SQL函数定义 |
| `sm2.control` | 扩展控制文件 |
| `Makefile` | 编译配置 |
| `test_sm2.sql` | 测试脚本 |

### 提供的SQL函数

```sql
-- 密钥管理
sm2_c_generate_key() RETURNS text[]           -- 生成密钥对 [私钥, 公钥]
sm2_c_get_pubkey(private_key) RETURNS text    -- 从私钥导出公钥

-- 加密解密
sm2_c_encrypt(text, public_key) RETURNS bytea
sm2_c_decrypt(bytea, private_key) RETURNS text
sm2_c_encrypt_hex(text, public_key) RETURNS text
sm2_c_decrypt_hex(text, private_key) RETURNS text
sm2_c_encrypt_base64(text, public_key) RETURNS text
sm2_c_decrypt_base64(text, private_key) RETURNS text

-- 数字签名
sm2_c_sign(message, private_key, id) RETURNS bytea
sm2_c_verify(message, public_key, signature, id) RETURNS boolean
sm2_c_sign_hex(message, private_key, id) RETURNS text
sm2_c_verify_hex(message, public_key, signature_hex, id) RETURNS boolean
```

### SM2使用示例

```sql
-- 生成密钥对
SELECT sm2_c_generate_key() AS keypair;
-- 结果: {私钥hex, 公钥hex}

-- 加密解密
DO $$
DECLARE
    keypair text[];
    cipher text;
BEGIN
    keypair := sm2_c_generate_key();
    cipher := sm2_c_encrypt_hex('敏感数据', keypair[2]);  -- 公钥加密
    RAISE NOTICE '解密: %', sm2_c_decrypt_hex(cipher, keypair[1]);  -- 私钥解密
END $$;

-- 数字签名
DO $$
DECLARE
    keypair text[];
    signature text;
BEGIN
    keypair := sm2_c_generate_key();
    signature := sm2_c_sign_hex('合同文件', keypair[1]);  -- 私钥签名
    RAISE NOTICE '验签: %', sm2_c_verify_hex('合同文件', keypair[2], signature);  -- 公钥验签
END $$;
```

**详细文档**: 查看 [sm2_c/README.md](sm2_c/README.md)

---

## sm4_c - VastBase数据库扩展

**技术栈**: C语言 + PostgreSQL扩展框架

**目标平台**: VastBase数据库

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

**重要提示**: 为避免与VastBase系统函数冲突，C扩展函数使用 `sm4_c_` 前缀。

```sql
-- ECB模式
sm4_c_encrypt(text, text) RETURNS bytea
sm4_c_decrypt(bytea, text) RETURNS text
sm4_c_encrypt_hex(text, text) RETURNS text
sm4_c_decrypt_hex(text, text) RETURNS text

-- CBC模式
sm4_c_encrypt_cbc(text, text, text) RETURNS bytea
sm4_c_decrypt_cbc(bytea, text, text) RETURNS text
```

### C扩展使用示例

```sql
-- ECB模式加密
SELECT sm4_c_encrypt_hex('13800138001', 'mykey12345678901') AS encrypted_phone;

-- ECB模式解密
SELECT sm4_c_decrypt_hex('encrypted_hex_string', 'mykey12345678901') AS phone;

-- CBC模式加密（更安全）
SELECT sm4_c_encrypt_cbc('sensitive data', 'mykey12345678901', '1234567890abcdef');
```

### C扩展应用场景

- ✅ 数据库字段加密存储
- ✅ 敏感信息保护（手机号、身份证等）
- ✅ 数据脱敏查询
- ✅ 政务系统数据安全

**详细文档**: 查看 [sm4_c/README.md](sm4_c/README.md)

---

## sm4_java - MRS Hive UDF函数

**技术栈**: Java 17 + Maven + BouncyCastle  
**目标平台**: MRS Hive 3.1.3+  
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

### Hive UDF使用示例

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

### Hive UDF应用场景

- ✅ Hive数据仓库敏感数据加密
- ✅ 大数据平台数据脱敏
- ✅ 数据迁移加密处理
- ✅ 批量数据加解密

**详细文档**: 查看 [sm4_java/README.md](sm4_java/README.md)  
**快速开始**: 查看 [sm4_java/QUICKSTART.md](sm4_java/QUICKSTART.md)

---

## 两个实现的关系

### 兼容性

✅ **完全兼容** - 两个实现使用相同的SM4算法和PKCS7填充方式，可以互相解密对方加密的数据。

### 典型应用架构

```text
┌─────────────────────────────────────────┐
│         业务应用层                       │
│  ┌──────────┐      ┌──────────┐         │
│  │ Java应用 │      │ Web应用  │          │
│  └────┬─────┘      └────┬─────┘         │
└───────┼─────────────────┼───────────────┘
        │                 │
        │                 │
┌───────▼─────────────────▼───────────────┐
│           数据处理层                     │
│  ┌──────────────┐  ┌─────────────────┐  │
│  │  Hive数据仓库 │  │ VastBase数据库  │  │
│  │  (sm4_java)  │  │   (sm4_c)       │  │
│  └──────────────┘  └─────────────────┘  │
│       UDF加解密        扩展函数加解密     │
└─────────────────────────────────────────┘
```

### 使用场景选择

| 场景                      | 推荐方案 | 原因               |
| ------------------------- | -------- | ------------------ |
| VastBase/PostgreSQL数据库 | sm2_c/sm4_c | 性能最优，原生支持 |
| Hive数据仓库              | sm4_java | 大数据平台标准     |
| Java应用集成              | sm4_java | 开发语言一致       |
| 高性能要求                | sm4_c    | C实现性能更好      |
| 数字签名场景              | sm2_c    | SM2支持签名       |
| 跨平台数据交换            | 两者皆可 | 完全兼容           |

### SM2 vs SM4 对比

| 特性 | SM2 | SM4 |
|------|-----|-----|
| 算法类型 | 非对称加密 | 对称加密 |
| 密钥 | 公钥/私钥对 | 单一密钥 |
| 性能 | 较慢 | 较快 |
| 密钥分发 | 公钥可公开 | 需安全传输 |
| 适用场景 | 数字签名、密钥交换、少量数据加密 | 大量数据加密 |
| 密钥长度 | 256位(私钥) | 128位 |
| 数字签名 | ✅ 支持 | ✗ 不支持 |

---

## 安全最佳实践

### 1. 密钥管理

```bash
# ❌ 不要硬编码密钥
SELECT sm4_c_encrypt('data', 'hardcoded_key');

# 使用环境变量
export SM4_KEY="your_secret_key"

# 使用密钥管理系统（KMS）
# AWS KMS, Azure Key Vault, HashiCorp Vault等
```

### 2. 密钥格式

支持两种密钥格式：

- **16字节字符串**: `"mykey12345678901"` (推荐)
- **32位十六进制**: `"6d796b657931323334353637383930"`

### 3. 加密模式选择

- **ECB模式**: 简单快速，适合独立字段加密
- **CBC模式**: 更安全，适合大数据或高安全要求场景

### 4. 访问控制

```sql
-- VastBase: 限制函数执行权限（使用sm4_c_*函数）
REVOKE EXECUTE ON FUNCTION sm4_c_decrypt FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sm4_c_decrypt TO trusted_role;

-- Hive: 使用脱敏视图
CREATE VIEW users_masked AS
SELECT id, name, phone_masked FROM users_encrypted;
GRANT SELECT ON users_masked TO analyst_role;
```

### 互操作性测试

```sql
-- 在VastBase中加密（使用C扩展）
SELECT sm4_c_encrypt_hex('test data', 'mykey12345678901') AS encrypted;
-- 输出: a1b2c3d4e5f6...

-- 在Hive中解密（转换为Base64）
SELECT sm4_decrypt_ecb('base64_of_a1b2c3d4e5f6...', 'mykey12345678901');
-- 输出: test data
```

---

**最后更新**: 2026-01-05  
**版本**: 1.1.0  
**维护者**: 陈云亮 <676814828@qq.com>

