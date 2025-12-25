# SM4 Extension for VastBase

国密SM4分组密码算法扩展，基于GB/T 32907-2016标准实现。

## 文件结构

```text
├── sm4.h               # SM4算法头文件
├── sm4.c               # SM4算法实现
├── sm4_ext.c           # VastBase扩展接口
├── sm4.control         # 扩展控制文件
├── sm4--1.0.sql        # SQL函数定义
├── Makefile            # 编译配置
├── test_sm4.sql        # 测试脚本
├── test_sm4_gcm.sql    # GCM模式测试脚本
├── demo_citizen_data.sql # 示例数据
└── README.md           # 使用文档（包含GCM模式详细说明）
```

## 编译安装

```bash
# 进入代码目录(根据实际调整用户和目录)
# 把vastbase_sm4上传到Vastbase数据库服务器，并授权所有者为数据库用户

su - vastbase
cd /home/vastbase/vastbase_sm4/sm4_c

# 设置环境变量
export VBHOME=/home/vastbase/vasthome # 根据实际调整
export PATH=$VBHOME/bin:$PATH
export LD_LIBRARY_PATH=$VBHOME/lib:$LD_LIBRARY_PATH

# 编译
make clean
make

# 安装
make install

# 复制.so到proc_srclib目录
mkdir -p /home/vastbase/vasthome/lib/postgresql/proc_srclib
cp /home/vastbase/vasthome/lib/postgresql/sm4.so /home/vastbase/vasthome/lib/postgresql/proc_srclib/

# 重启数据库加载新扩展
vb_ctl restart
```

## 启用扩展

VastBase不支持EXTENSION语法，需直接执行SQL创建函数。

**注意**: 函数是数据库级别对象，需在每个要使用的数据库中单独创建。.so文件是共享的，只需安装一次。

```bash
# 在postgres库中创建函数
vsql -d postgres -f /home/vastbase/vasthome/share/postgresql/extension/sm4--1.0.sql

# 在vastbase库中创建函数
vsql -d vastbase -f /home/vastbase/vasthome/share/postgresql/extension/sm4--1.0.sql

# 在其他库中创建...
vsql -d test01 -f /home/vastbase/vasthome/share/postgresql/extension/sm4--1.0.sql
```

或手动执行（可选）：

```sql
-- 连接数据库
vsql -d test01 -r

-- 创建SM4函数 (使用sm4_c_前缀避免与Java UDF冲突)
CREATE OR REPLACE FUNCTION sm4_c_encrypt(plaintext text, key text)
RETURNS bytea AS 'sm4', 'sm4_encrypt' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_c_decrypt(ciphertext bytea, key text)
RETURNS text AS 'sm4', 'sm4_decrypt' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_c_encrypt_hex(plaintext text, key text)
RETURNS text AS 'sm4', 'sm4_encrypt_hex' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_c_decrypt_hex(ciphertext_hex text, key text)
RETURNS text AS 'sm4', 'sm4_decrypt_hex' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_c_encrypt_cbc(plaintext text, key text, iv text)
RETURNS bytea AS 'sm4', 'sm4_encrypt_cbc' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_c_decrypt_cbc(ciphertext bytea, key text, iv text)
RETURNS text AS 'sm4', 'sm4_decrypt_cbc' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_c_encrypt_gcm(plaintext text, key text, iv text, aad text DEFAULT NULL)
RETURNS bytea AS 'sm4', 'sm4_encrypt_gcm' LANGUAGE C IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_c_decrypt_gcm(ciphertext_with_tag bytea, key text, iv text, aad text DEFAULT NULL)
RETURNS text AS 'sm4', 'sm4_decrypt_gcm' LANGUAGE C IMMUTABLE;
```

## 停用扩展

如果需要删除SM4扩展函数，执行以下命令：

```sql
-- 连接数据库
vsql -d test01 -r

-- 删除所有SM4 C扩展函数
DROP FUNCTION IF EXISTS sm4_c_encrypt(text, text);
DROP FUNCTION IF EXISTS sm4_c_decrypt(bytea, text);
DROP FUNCTION IF EXISTS sm4_c_encrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm4_c_decrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm4_c_encrypt_cbc(text, text, text);
DROP FUNCTION IF EXISTS sm4_c_decrypt_cbc(bytea, text, text);
DROP FUNCTION IF EXISTS sm4_c_encrypt_gcm(text, text, text, text);
DROP FUNCTION IF EXISTS sm4_c_decrypt_gcm(bytea, text, text, text);
```

**注意**：

- 删除函数不会删除.so文件，只是在当前数据库中移除函数定义
- 如需在多个数据库中删除，需要分别连接每个数据库执行删除命令
- 如果要完全卸载扩展，还需要删除.so文件：

  ```bash
  rm -f /home/vastbase/vasthome/lib/postgresql/sm4.so
  rm -f /home/vastbase/vasthome/lib/postgresql/proc_srclib/sm4.so
  ```

## 查看已安装的函数

```sql
vsql -d test01

-- 查看所有SM4 C扩展函数
\df sm4_c*

-- 查看函数详细信息
\df+ sm4_c_encrypt
```

## 函数说明

**重要提示**: 为避免VastBase中与Java UDF函数名冲突，所有C扩展函数均使用 `sm4_c_` 前缀。

| 函数                                     | 说明                             |
| ---------------------------------------- | -------------------------------- |
| `sm4_c_encrypt(text, key)`               | ECB模式加密，返回bytea           |
| `sm4_c_decrypt(bytea, key)`              | ECB模式解密，返回text            |
| `sm4_c_encrypt_hex(text, key)`           | ECB模式加密，返回十六进制字符串  |
| `sm4_c_decrypt_hex(hex, key)`            | ECB模式解密，输入十六进制密文    |
| `sm4_c_encrypt_cbc(text, key, iv)`       | CBC模式加密，返回bytea           |
| `sm4_c_decrypt_cbc(bytea, key, iv)`      | CBC模式解密，返回text            |
| `sm4_c_encrypt_gcm(text, key, iv, aad)`  | GCM模式加密，返回密文+Tag(bytea) |
| `sm4_c_decrypt_gcm(bytea, key, iv, aad)` | GCM模式解密，返回text            |
| `sm4_c_encrypt_gcm_base64(text, key, iv, aad)`  | GCM模式加密，返回Base64编码(text) |
| `sm4_c_decrypt_gcm_base64(text, key, iv, aad)` | GCM模式解密，接收Base64编码(text)            |

**密钥格式**: 16字节字符串 或 32位十六进制字符串

**IV格式**:

- CBC模式: 16字节字符串 或 32位十六进制字符串
- GCM模式: 12或16字节字符串 或 24/32位十六进制字符串（推荐12字节）

## 运行示例

```bash
# 进入数据库
vsql -d test01

```

```sql
-- ECB模式加密 (返回十六进制)
SELECT sm4_c_encrypt_hex('Hello VastBase!', '12345678901abcdef');

-- ECB模式解密
SELECT sm4_c_decrypt_hex(sm4_c_encrypt_hex('Hello VastBase!', '1234567890abcdef'), '1234567890abcdef');

-- 加解密验证
SELECT sm4_c_decrypt_hex(
    sm4_c_encrypt_hex('测试数据', '1234567890abcdef'),
    '1234567890abcdef'
);

-- bytea格式加解密
SELECT sm4_c_decrypt(
    sm4_c_encrypt('中文测试', '1234567890abcdef'),
    '1234567890abcdef'
);

-- CBC模式 (需要IV)
SELECT sm4_c_decrypt_cbc(
    sm4_c_encrypt_cbc('明文数据', 'key1234567890123', 'iv12345678901234'),
    'key1234567890123',
    'iv12345678901234'
);

-- 使用32位十六进制密钥
SELECT sm4_c_encrypt_hex('敏感数据', '0123456789abcdef0123456789abcdef');

-- GCM模式加密（无AAD）
SELECT encode(sm4_c_encrypt_gcm('Hello GCM!', '1234567890123456', '123456789012'), 'hex');

-- GCM模式加密（带AAD）
SELECT sm4_c_encrypt_gcm('Secret Message', '1234567890123456', '123456789012', 'additional data');

-- GCM模式解密
SELECT sm4_c_decrypt_gcm(
    sm4_c_encrypt_gcm('Test Data', '1234567890123456', '123456789012', 'aad'),
    '1234567890123456',
    '123456789012',
    'aad'
);

-- 运行测试脚本
vsql -d postgres -f test_sm4.sql

vsql -d postgres -f test_sm4_gcm.sql

vsql -d postgres -f demo_citizen_data.sql
```

测试结果1：

![测试结果1](image.png)

测试结果2：

![测试结果2](image-1.png)

---

# SM4-GCM 模式详细说明

## 概述

GCM (Galois/Counter Mode) 是一种认证加密模式，提供数据的保密性和完整性保护。与 ECB 和 CBC 模式相比，GCM 模式具有以下特点:

- **认证加密**: 同时提供加密和认证功能
- **并行处理**: 可以并行加密/解密，性能更好
- **防篡改**: 任何对密文的修改都会被检测出来
- **AAD支持**: 可以对附加数据进行认证而不加密

## 核心特性

### 1. 认证标签 (Authentication Tag)

- GCM 模式会生成一个 16 字节的认证标签
- 该标签附加在密文后面一起返回
- 解密时会验证标签，如果不匹配则解密失败

### 2. 附加认证数据 (AAD)

- AAD 是需要认证但不需要加密的数据
- 常用于存储元数据、协议头等信息
- AAD 是可选的，可以为 NULL

### 3. 初始向量 (IV/Nonce)

- **推荐使用 12 字节的 IV**（96位）：性能最优，无需额外 GHASH 计算
- **支持 16 字节的 IV**（128位）：用于与某些系统兼容或与 CBC 模式保持一致
- 每次加密都应使用不同的 IV
- IV 不需要保密，但必须是唯一的
- **重要**：同一密钥下每个 IV 只能使用一次

**IV 长度选择建议：**
- ✅ **12 字节**（推荐）：符合 NIST SP 800-38D 推荐，性能最佳
- ✅ **16 字节**（兼容）：与 CBC 模式 IV 长度一致，便于统一管理
- ❌ 其他长度：虽然 GCM 标准支持，但本实现暂未开放

## GCM 函数接口

### 加密函数

**二进制版本（返回 bytea）**

```sql
sm4_c_encrypt_gcm(
    plaintext text,      -- 明文
    key text,            -- 密钥 (16字节或32位十六进制)
    iv text,             -- 初始向量 (12或16字节，或24/32位十六进制，推荐12字节)
    aad text DEFAULT NULL -- 附加认证数据 (可选)
) RETURNS bytea          -- 返回: 密文 + 16字节认证标签
```

**Base64版本（返回 text）**

```sql
sm4_c_encrypt_gcm_base64(
    plaintext text,      -- 明文
    key text,            -- 密钥 (16字节或32位十六进制)
    iv text,             -- 初始向量 (12或16字节，或24/32位十六进制，推荐12字节)
    aad text DEFAULT NULL -- 附加认证数据 (可选)
) RETURNS text           -- 返回: Base64编码的密文 + 16字节认证标签
```

### 解密函数

**二进制版本（接收 bytea）**

```sql
sm4_c_decrypt_gcm(
    ciphertext_with_tag bytea, -- 密文+标签
    key text,                   -- 密钥
    iv text,                    -- 初始向量 (12或16字节，或24/32位十六进制，必须与加密时相同)
    aad text DEFAULT NULL       -- 附加认证数据 (必须与加密时相同)
) RETURNS text                  -- 返回: 明文 (如果认证失败则报错)
```

**Base64版本（接收 text）**

```sql
sm4_c_decrypt_gcm_base64(
    ciphertext_base64 text,     -- Base64编码的密文+标签
    key text,                   -- 密钥
    iv text,                    -- 初始向量 (12或16字节，或24/32位十六进制，必须与加密时相同)
    aad text DEFAULT NULL       -- 附加认证数据 (必须与加密时相同)
) RETURNS text                  -- 返回: 明文 (如果认证失败则报错)
```

## GCM 使用示例

### 1. 基本加密解密（无 AAD）

**二进制版本：**

```sql
-- 加密
SELECT sm4_c_encrypt_gcm(
    'Hello World!',        -- 明文
    '1234567890123456',    -- 密钥
    '123456789012'         -- IV
) AS encrypted \gset

-- 解密
SELECT sm4_c_decrypt_gcm(
    :'encrypted',          -- 密文+标签
    '1234567890123456',    -- 密钥
    '123456789012'         -- IV
);
```

**Base64版本：**

```sql
-- 加密
SELECT sm4_c_encrypt_gcm_base64(
    'Hello World!',        -- 明文
    '1234567890123456',    -- 密钥
    '123456789012'         -- IV
) AS encrypted_base64 \gset

-- 结果例: l7KTjHKuvrP6cAY4J6FofBmzHej8IHeeiSOApA==

-- 解密
SELECT sm4_c_decrypt_gcm_base64(
    :'encrypted_base64',   -- Base64密文
    '1234567890123456',    -- 密钥
    '123456789012'         -- IV
);
-- 返回: Hello World!
```

### 2. 使用 AAD 的加密解密

```sql
-- 加密（带 AAD）
SELECT sm4_c_encrypt_gcm(
    'Secret Message',      -- 明文
    '1234567890123456',    -- 密钥
    '123456789012',        -- IV
    'user_id:12345'        -- AAD（例如：用户ID）
) AS encrypted_with_aad \gset

-- 解密（需要提供相同的 AAD）
SELECT sm4_c_decrypt_gcm(
    :'encrypted_with_aad',
    '1234567890123456',
    '123456789012',
    'user_id:12345'        -- AAD 必须与加密时一致
);
```

### 3. 实际应用场景

#### 场晩1: 加密用户敏感数据

```sql
-- 创建用户表
CREATE TABLE users (
    user_id INT PRIMARY KEY,
    username VARCHAR(50),
    encrypted_ssn BYTEA,  -- 加密的身份证号
    gcm_iv VARCHAR(24)    -- 存储每次加密使用的IV
);

-- 插入加密数据
INSERT INTO users VALUES (
    1,
    'alice',
    sm4_c_encrypt_gcm(
        '123456789012345678',      -- 身份证号
        'my-secret-key16',         -- 密钥（实际应从密钥管理系统获取）
        'random-iv-12',            -- 随机IV
        'user_id:1'                -- AAD包含用户ID
    ),
    'random-iv-12'
);

-- 查询并解密
SELECT 
    user_id,
    username,
    sm4_c_decrypt_gcm(
        encrypted_ssn,
        'my-secret-key16',
        gcm_iv,
        'user_id:' || user_id      -- 构造AAD
    ) AS ssn
FROM users
WHERE user_id = 1;
```

## 安全最佳实践

### 1. IV 管理

```sql
-- ✅ 正确：每次加密使用不同的随机IV
SELECT sm4_c_encrypt_gcm(
    'data',
    'key',
    substring(md5(random()::text || clock_timestamp()::text), 1, 12)  -- 随机IV
);

-- ❌ 错误：重复使用相同的IV会严重降低安全性
SELECT sm4_c_encrypt_gcm('data', 'key', 'same-iv-123');
```

### 2. AAD 的使用

```sql
-- ✅ 推荐：使用AAD绑定上下文信息
SELECT sm4_c_encrypt_gcm(
    'sensitive_data',
    'key',
    'iv',
    'user_id:' || user_id || ',timestamp:' || now()::text
);

-- 这样可以防止密文被用于其他用户或时间点
```

## 输出格式选择

项目提供了两种输出格式：

### 1. 二进制版本 (bytea)

**函数**：`sm4_c_encrypt_gcm` / `sm4_c_decrypt_gcm`

**优点**：
- ✅ 存储空间最小（原始二进制）
- ✅ 数据库原生支持
- ✅ 性能最优，无需编解码

**适用场景**：
- 数据直接存储在数据库中
- 内部系统使用
- 对存储空间敏感

### 2. Base64版本 (text)

**函数**：`sm4_c_encrypt_gcm_base64` / `sm4_c_decrypt_gcm_base64`

**优点**：
- ✅ 易于传输（HTTP/JSON/XML）
- ✅ 可读性更好
- ✅ 无特殊字符，兼容性强
- ✅ 与外部系统集成方便

**缺点**：
- ❌ 存储空间增加约 33%
- ❌ 需要编解码开销

**适用场景**：
- API 接口返回
- 前后端数据交换
- 命令行工具输出
- 与第三方系统集成

```sql
-- 场晩1：数据库存储 - 使用二进制版本
CREATE TABLE users (
    id INT,
    encrypted_data BYTEA  -- 使用 sm4_c_encrypt_gcm
);

-- 场晩2：API 返回 - 使用 Base64 版本
CREATE OR REPLACE FUNCTION get_user_data(uid INT)
RETURNS JSON AS $$
SELECT json_build_object(
    'user_id', uid,
    'encrypted_token', sm4_c_encrypt_gcm_base64(token, key, iv)
) FROM tokens WHERE user_id = uid;
$$ LANGUAGE SQL;
```

## 与其他模式的比较

| 特性     | ECB       | CBC            | GCM        |
| -------- | --------- | -------------- | ---------- |
| 加密模式 | 块加密    | 块加密（链式） | 计数器模式 |
| 需要IV   | ❌         | ✅              | ✅          |
| 数据认证 | ❌         | ❌              | ✅          |
| 并行处理 | ✅         | ❌              | ✅          |
| 填充需求 | ✅ (PKCS7) | ✅ (PKCS7)      | ❌          |
| 安全性   | 低        | 中             | 高         |
| 推荐使用 | ❌         | 部分场景       | ✅          |

## 注意事项

1. **IV 唯一性**: 使用相同的密钥和IV加密不同数据会严重降低安全性
2. **AAD 一致性**: 解密时必须提供与加密时相同的AAD
3. **标签验证**: GCM 会自动验证标签，验证失败会抛出错误
4. **数据长度**: GCM 不需要填充，密文长度等于明文长度（不含标签）
5. **密钥重用**: 同一密钥下每个IV只能使用一次

## 故障排查

### 问题1: 解密失败 "authentication failed"

**原因**: 
- AAD 不匹配
- 密文被篡改
- 密钥错误
- IV 错误

**解决**:
```sql
-- 确保所有参数与加密时一致
SELECT sm4_c_decrypt_gcm(
    ciphertext,
    correct_key,    -- ✓ 正确的密钥
    correct_iv,     -- ✓ 正确的IV
    correct_aad     -- ✓ 正确的AAD（或NULL）
);
```

### 问题2: IV 长度错误

**错误信息**: "SM4 GCM IV must be 12 or 16 bytes (or 24/32 hex characters)"

**解决**:
```sql
-- ✅ 正确：12字节字符串（推荐）
SELECT sm4_c_encrypt_gcm('data', 'key', '123456789012');

-- ✅ 正确：16字节字符串
SELECT sm4_c_encrypt_gcm('data', 'key', '1234567890123456');

-- ✅ 正确：24位十六进制（12字节）
SELECT sm4_c_encrypt_gcm('data', 'key', '313233343536373839303132');

-- ✅ 正确：32位十六进制（16字节）
SELECT sm4_c_encrypt_gcm('data', 'key', '31323334353637383930313233343536');

-- ❌ 错误：长度不对
SELECT sm4_c_encrypt_gcm('data', 'key', '12345');
```

## 技术实现

本实现基于以下标准：

- **NIST SP 800-38D**: GCM模式规范
- **GB/T 32907-2016**: SM4算法标准
- **RFC 4106**: GCM在IPsec中的应用（参考）

核心算法组件：

1. **GHASH**: 伽罗瓦域哈希函数，用于生成认证标签
2. **GCTR**: 计数器模式加密
3. **GF(2^128)**: 伽罗瓦域乘法运算
