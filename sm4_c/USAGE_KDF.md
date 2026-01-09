# SM4 CBC KDF 扩展使用指南

## 新增功能说明

在原有 SM4 加密功能基础上，新增了**带密钥派生功能的 CBC 模式加解密**，支持：

- **密钥派生函数（KDF）**: 使用 PBKDF2 从密码派生加密密钥和 IV
- **多种哈希算法**: 支持 SHA256、SHA384、SHA512、SM3
- **自动盐值管理**: 每次加密自动生成随机盐值，增强安全性
- **无需手动管理 IV**: 系统自动派生 IV，简化使用

## 编译安装

### 前置条件

确保已安装 OpenSSL 开发库（需要 OpenSSL 1.1.1+ 或 3.0+）：

```bash
# 检查 OpenSSL 版本
openssl version

# 如果需要安装（CentOS/RHEL）
sudo yum install openssl-devel

# Ubuntu/Debian
sudo apt-get install libssl-dev
```

### 编译步骤

```bash
# 切换到数据库用户
su - vastbase

# 进入代码目录
cd /home/vastbase/vastbase_sm4/sm4_c

# 设置环境变量
export VBHOME=/home/vastbase/vasthome
export PATH=$VBHOME/bin:$PATH
export LD_LIBRARY_PATH=$VBHOME/lib:$LD_LIBRARY_PATH

# 清理旧编译
make clean

# 编译（新版本已启用 USE_OPENSSL_KDF）
make

# 安装
make install

# 复制 .so 到 proc_srclib 目录
mkdir -p /home/vastbase/vasthome/lib/postgresql/proc_srclib
cp /home/vastbase/vasthome/lib/postgresql/sm4.so \
   /home/vastbase/vasthome/lib/postgresql/proc_srclib/

# 重启数据库
vb_ctl restart
```

### 在数据库中创建函数

```bash
# 在需要使用的数据库中执行
vsql -d postgres -f /home/vastbase/vasthome/share/postgresql/extension/sm4--1.0.sql

# 或在其他数据库中
vsql -d test01 -f /home/vastbase/vasthome/share/postgresql/extension/sm4--1.0.sql
```

## 函数说明

### 1. sm4_c_encrypt_cbc_kdf

**加密函数（带密钥派生）**

```sql
sm4_c_encrypt_cbc_kdf(plaintext text, password text, hash_algo text) -> bytea
```

**参数：**
- `plaintext`: 明文（text）
- `password`: 密码（text，任意长度）
- `hash_algo`: 哈希算法（'sha256'、'sha384'、'sha512'、'sm3'）

**返回：** bytea（包含 16 字节盐值 + CBC 密文）

### 2. sm4_c_decrypt_cbc_kdf

**解密函数（带密钥派生）**

```sql
sm4_c_decrypt_cbc_kdf(ciphertext bytea, password text, hash_algo text) -> text
```

**参数：**
- `ciphertext`: 密文（bytea，包含盐值+密文）
- `password`: 密码（text，必须与加密时相同）
- `hash_algo`: 哈希算法（必须与加密时相同）

**返回：** text（明文）

## 使用示例

### 基本加解密

```sql
-- SHA256 加密
SELECT encode(sm4_c_encrypt_cbc_kdf('Hello World!', 'mypassword', 'sha256'), 'hex');

-- SHA256 解密
SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf('Hello World!', 'mypassword', 'sha256'),
    'mypassword',
    'sha256'
);
```

### 使用不同哈希算法

```sql
-- SHA384
SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf('Secret Message', 'password123', 'sha384'),
    'password123',
    'sha384'
);

-- SHA512
SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf('Confidential', 'strongpass', 'sha512'),
    'strongpass',
    'sha512'
);

-- SM3（国密哈希，需要 OpenSSL 3.0+）
SELECT sm4_c_decrypt_cbc_kdf(
    sm4_c_encrypt_cbc_kdf('国密测试', '中文密码', 'sm3'),
    '中文密码',
    'sm3'
);
```

### 表数据加密示例

```sql
-- 创建测试表
CREATE TABLE sensitive_data (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    email_encrypted BYTEA,
    phone_encrypted BYTEA
);

-- 插入加密数据
INSERT INTO sensitive_data (username, email_encrypted, phone_encrypted)
VALUES (
    'user001',
    sm4_c_encrypt_cbc_kdf('user@example.com', 'db_encryption_key', 'sha256'),
    sm4_c_encrypt_cbc_kdf('13800138000', 'db_encryption_key', 'sha256')
);

-- 查询并解密
SELECT 
    username,
    sm4_c_decrypt_cbc_kdf(email_encrypted, 'db_encryption_key', 'sha256') AS email,
    sm4_c_decrypt_cbc_kdf(phone_encrypted, 'db_encryption_key', 'sha256') AS phone
FROM sensitive_data;
```

## 运行测试

```bash
vsql -d test01 -f test_sm4_cbc_kdf.sql
```

## 技术细节

### 密钥派生过程

1. **生成随机盐值**: 16 字节随机盐（使用 OpenSSL RAND_bytes）
2. **PBKDF2 派生**: 
   - 输入：密码 + 盐值
   - 迭代次数：10,000 次
   - 输出：32 字节（16 字节密钥 + 16 字节 IV）
3. **SM4 加密**: 使用派生的密钥和 IV 进行 CBC 加密
4. **输出格式**: 盐值（16 字节）+ 密文

### 数据格式

```
输出结构:
+---------------+------------------+
| Salt (16字节) | Ciphertext (变长) |
+---------------+------------------+
```

### 安全特性

- ✅ 每次加密使用不同的随机盐值
- ✅ PBKDF2 10,000 次迭代增强密码强度
- ✅ 支持多种安全哈希算法
- ✅ 自动内存清理（敏感数据）
- ✅ 符合国密 SM4 标准

## 与标准 CBC 的区别

| 特性 | 标准 CBC (`sm4_c_encrypt_cbc`) | KDF CBC (`sm4_c_encrypt_cbc_kdf`) |
|------|-------------------------------|-----------------------------------|
| 密钥输入 | 16 字节固定密钥 | 任意长度密码 |
| IV 管理 | 手动提供 16 字节 IV | 自动派生 |
| 盐值 | 无 | 自动生成并包含在输出中 |
| 密钥强化 | 无 | PBKDF2 10,000 次迭代 |
| 适用场景 | 密钥已安全管理 | 基于密码的加密 |

## 注意事项

1. **OpenSSL 版本要求**:
   - SHA256/384/512: OpenSSL 1.1.1+
   - SM3: OpenSSL 3.0+（或 GmSSL）

2. **性能考虑**:
   - KDF 版本因 PBKDF2 迭代会比标准版本慢
   - 建议在应用层缓存派生密钥（如果密码不变）

3. **兼容性**:
   - 保留了所有原有函数，完全向后兼容
   - 新函数命名为 `*_kdf` 以示区别

4. **密码管理**:
   - 请使用强密码
   - 在生产环境中，密码应从配置文件或密钥管理系统读取
   - 不要在 SQL 脚本中硬编码密码

## 故障排查

### 编译错误：找不到 OpenSSL

```bash
# 检查 OpenSSL 安装
rpm -qa | grep openssl-devel  # CentOS/RHEL
dpkg -l | grep libssl-dev     # Ubuntu/Debian

# 如果未安装
sudo yum install openssl-devel
```

### 运行时错误：函数未找到

```bash
# 确认 .so 文件存在
ls -l /home/vastbase/vasthome/lib/postgresql/sm4.so
ls -l /home/vastbase/vasthome/lib/postgresql/proc_srclib/sm4.so

# 确认 SQL 函数已创建
vsql -d test01 -c "\df sm4_c_encrypt_cbc_kdf"
```

### SM3 不支持

```
错误: Hash algorithm must be one of: sha256, sha384, sha512, sm3
```

解决方法：
- 升级到 OpenSSL 3.0+ 或使用 GmSSL
- 或使用 SHA256/384/512 替代

## 卸载

```sql
-- 删除 KDF 函数
DROP FUNCTION IF EXISTS sm4_c_encrypt_cbc_kdf(text, text, text);
DROP FUNCTION IF EXISTS sm4_c_decrypt_cbc_kdf(bytea, text, text);
```

## 参考资料

- [GB/T 32907-2016 SM4 分组密码算法](https://www.gb688.cn/bzgk/gb/newGbInfo?hcno=7803DE42D3BC5E80B0C3E5D8E873D56A)
- [RFC 8018 PKCS #5: PBKDF2](https://www.rfc-editor.org/rfc/rfc8018)
- [OpenSSL EVP KDF Functions](https://www.openssl.org/docs/man3.0/man7/EVP_KDF-PBKDF2.html)
