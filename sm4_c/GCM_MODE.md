# SM4-GCM 模式说明

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

## 函数接口

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

## 使用示例

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

**二进制版本：**

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

**Base64版本：**

```sql
-- 加密（带 AAD）
SELECT sm4_c_encrypt_gcm_base64(
    'Secret Message',      -- 明文
    '1234567890123456',    -- 密钥
    '123456789012',        -- IV
    'user_id:12345'        -- AAD
) AS encrypted_base64_aad \gset

-- 解密
SELECT sm4_c_decrypt_gcm_base64(
    :'encrypted_base64_aad',
    '1234567890123456',
    '123456789012',
    'user_id:12345'        -- AAD 必须与加密时一致
);
```

### 3. 使用十六进制格式的密钥和 IV

```sql
-- 使用十六进制密钥和 12 字节 IV
SELECT sm4_c_encrypt_gcm(
    'Test Data',
    '31323334353637383930313233343536',  -- 32位十六进制密钥
    '313233343536373839303132'           -- 24位十六进制IV (12字节)
) AS encrypted_hex \gset

SELECT sm4_c_decrypt_gcm(
    :'encrypted_hex',
    '31323334353637383930313233343536',
    '313233343536373839303132'
);
```

### 4. 使用 16 字节 IV（与 CBC 模式保持一致）

```sql
-- 使用 16 字节 IV（与 SM4 块大小相同）
SELECT sm4_c_encrypt_gcm(
    'Compatible Data',
    '1234567890123456',    -- 16字节密钥
    '1234567890123456'     -- 16字节IV
) AS encrypted_16 \gset

SELECT sm4_c_decrypt_gcm(
    :'encrypted_16',
    '1234567890123456',
    '1234567890123456'
);

-- 使用 32 位十六进制 IV（16 字节）
SELECT sm4_c_encrypt_gcm(
    'Hex IV Test',
    'mykey1234567890',
    '31323334353637383930313233343536'  -- 32位十六进制 = 16字节
) AS encrypted_hex_16 \gset

SELECT sm4_c_decrypt_gcm(
    :'encrypted_hex_16',
    'mykey1234567890',
    '31323334353637383930313233343536'
);
```

### 4. 实际应用场景

#### 场景1: 加密用户敏感数据

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

#### 场景2: API 令牌加密

```sql
-- 创建令牌表
CREATE TABLE api_tokens (
    token_id SERIAL PRIMARY KEY,
    user_id INT,
    encrypted_token BYTEA,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 生成并存储加密令牌
INSERT INTO api_tokens (user_id, encrypted_token)
SELECT 
    123,  -- 用户ID
    sm4_c_encrypt_gcm(
        'secret-api-token-xyz',
        'token-key-1234567',
        substring(md5(random()::text), 1, 12),  -- 随机IV
        'api_token'
    );
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

### 3. 密钥管理

```sql
-- ❌ 不要在代码中硬编码密钥
SELECT sm4_c_encrypt_gcm('data', 'hardcoded-key', 'iv');

-- ✅ 从环境变量或密钥管理系统获取
SELECT sm4_c_encrypt_gcm(
    'data',
    current_setting('app.encryption_key'),  -- 从配置获取
    'iv'
);
```

### 4. 错误处理

```sql
-- GCM解密失败会抛出错误
DO $$
BEGIN
    PERFORM sm4_c_decrypt_gcm(
        encrypted_data,
        'key',
        'iv',
        'wrong_aad'  -- AAD不匹配会导致认证失败
    );
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Decryption failed: %', SQLERRM;
END;
$$;
```

## 性能考虑

### 1. 批量操作

```sql
-- 批量加密
UPDATE sensitive_data
SET encrypted_column = sm4_c_encrypt_gcm(
    plain_column,
    'key',
    substring(md5(random()::text || id::text), 1, 12),
    'table:sensitive_data,id:' || id
);
```

### 2. 索引支持

```sql
-- GCM密文是二进制数据，可以建立索引
CREATE INDEX idx_encrypted ON users USING hash(encrypted_ssn);
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

```sql
-- 返回 bytea: \x97b2938c72aebeb3fa70063827a1687c19b31de8fc20779e892380a4
SELECT sm4_c_encrypt_gcm('hello world!', 'key', 'iv');
```

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
-- 返回 text: l7KTjHKuvrP6cAY4J6FofBmzHej8IHeeiSOApA==
SELECT sm4_c_encrypt_gcm_base64('hello world!', 'key', 'iv');
```

### 选择建议

```sql
-- 场景1：数据库存储 - 使用二进制版本
CREATE TABLE users (
    id INT,
    encrypted_data BYTEA  -- 使用 sm4_c_encrypt_gcm
);

-- 场景2：API 返回 - 使用 Base64 版本
CREATE OR REPLACE FUNCTION get_user_data(uid INT)
RETURNS JSON AS $$
SELECT json_build_object(
    'user_id', uid,
    'encrypted_token', sm4_c_encrypt_gcm_base64(token, key, iv)
) FROM tokens WHERE user_id = uid;
$$ LANGUAGE SQL;
```

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

### 问题3: 12 字节 vs 16 字节 IV 的选择

**建议**:
- **默认使用 12 字节**：符合 NIST 推荐，性能最优
- **16 字节适用场景**：
  - 需要与使用 16 字节 IV 的旧系统兼容
  - 希望 GCM 和 CBC 模式使用相同长度的 IV，便于统一管理
  - 应用程序已经存在大量 16 字节 IV 的生成逻辑

```sql
-- 性能比较（理论上 12 字节略快）
-- 12 字节：直接使用，无需 GHASH 计算
-- 16 字节：需要额外的 GHASH 计算，但差异微乎其微
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

## 参考资源

- [NIST SP 800-38D: GCM规范](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [GB/T 32907-2016: SM4分组密码算法](http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html)
- [VastBase 文档](https://www.vastdata.com.cn/)
