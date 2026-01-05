# SM2 Extension for VastBase

国密SM2椭圆曲线公钥密码算法扩展，基于 **OpenSSL** 高性能实现，符合 GB/T 32918-2016 标准。

## ⚠️ 重要: OpenSSL 版本要求

**必须满足以下条件之一**:
- ✅ **OpenSSL >= 3.0** (推荐)
- ✅ **GmSSL** (国密专用)
- ❌ OpenSSL 1.1.1 **不支持**

### 检查当前版本

```bash
openssl version
# 应该显示: OpenSSL 3.x.x
```

**如果版本为 1.1.1**，请先安装 OpenSSL 3.0：

```bash
# 步骤 1: 下载 OpenSSL 3.0.18 源码包
# 在本地或有网络的机器上下载（选择任一镜像）：

# 清华镜像（推荐）
wget https://mirrors.tuna.tsinghua.edu.cn/openssl/source/openssl-3.0.18.tar.gz

# 中科大镜像
wget https://mirrors.ustc.edu.cn/openssl/source/openssl-3.0.18.tar.gz

# 阿里云镜像
wget https://mirrors.aliyun.com/openssl/source/openssl-3.0.18.tar.gz

# 步骤 2: 将源码包上传到服务器
# 使用 scp 或 WinSCP 等工具，上传到：
#   /path/to/vastbase_sm4/sm2_c/openssl_source/openssl-3.0.18.tar.gz

# 步骤 3: 使用离线安装脚本
cd /path/to/vastbase_sm4/sm2_c
sudo bash install_openssl3.sh

# 或查看详细指南
cat OPENSSL_UPGRADE_GUIDE.md
```

## 功能特性

- ✅ SM2密钥对生成
- ✅ SM2公钥加密/私钥解密
- ✅ SM2数字签名/验签
- ✅ 支持bytea、十六进制、Base64多种格式
- ✅ 支持自定义用户标识(ID)
- ✅ 完整的SQL函数接口
- ✅ 符合GB/T 32918-2016国家标准

## 文件结构

```text
sm2_c/
├── sm2_openssl.h           # SM2算法头文件 (OpenSSL版本)
├── sm2_openssl.c           # SM2算法实现 (OpenSSL高性能)
├── sm2_ext_openssl.c       # VastBase扩展接口
├── sm2.control             # 扩展控制文件
├── sm2--1.0.sql            # SQL函数定义
├── Makefile                # 编译配置 (OpenSSL 3.0)
├── test_sm2.sql            # 测试脚本
├── install_openssl3.sh     # OpenSSL 3.0 一键安装脚本
├── OPENSSL_UPGRADE_GUIDE.md # OpenSSL 升级指南
└── README.md               # 使用文档
```

## 编译安装

### 前置条件

1. **安装 OpenSSL 3.0** (如果未安装)

```bash
# 使用一键安装脚本
cd /path/to/vastbase_sm4/sm2_c
sudo bash install_openssl3.sh

# 脚本将自动安装 OpenSSL 3.0 到 /usr/local/openssl-3.0
```

2. **编译 SM2 扩展**

```bash
# 进入代码目录
su - vastbase
cd /home/vastbase/vastbase_sm4/sm2_c

# 设置环境变量
export VBHOME=/home/vastbase/vasthome
export PATH=$VBHOME/bin:$PATH
export LD_LIBRARY_PATH=$VBHOME/lib:$LD_LIBRARY_PATH

# 编译 (指定 OpenSSL 路径)
make clean
make OPENSSL_HOME=/usr/local/openssl-3.0

# 检查编译结果
ldd sm2.so | grep ssl
# 应该显示:
# libssl.so.3 => /usr/local/openssl-3.0/lib64/libssl.so.3
# libcrypto.so.3 => /usr/local/openssl-3.0/lib64/libcrypto.so.3

# 安装
make install OPENSSL_HOME=/usr/local/openssl-3.0

# 复制.so到proc_srclib目录
mkdir -p /home/vastbase/vasthome/lib/postgresql/proc_srclib
cp /home/vastbase/vasthome/lib/postgresql/sm2.so /home/vastbase/vasthome/lib/postgresql/proc_srclib/

# 重启数据库加载新扩展
vb_ctl restart
```

### 快捷命令 (已安装 OpenSSL 3.0)

```bash
# 如果已经安装了 OpenSSL 3.0，直接编译
make clean
make OPENSSL_HOME=/usr/local/openssl-3.0
make install OPENSSL_HOME=/usr/local/openssl-3.0
```

## 启用扩展

VastBase不支持EXTENSION语法，需直接执行SQL创建函数。

```bash
# 在目标数据库中创建函数
vsql -d postgres -f /home/vastbase/vasthome/share/postgresql/extension/sm2--1.0.sql

vsql -d vastbase -f /home/vastbase/vasthome/share/postgresql/extension/sm2--1.0.sql

# 在其他库中创建...
vsql -d test01 -f /home/vastbase/vasthome/share/postgresql/extension/sm2--1.0.sql
```

## 函数说明

**重要提示**: 所有C扩展函数使用 `sm2_c_` 前缀以避免命名冲突。

### 密钥管理函数

| 函数 | 说明 |
|------|------|
| `sm2_c_generate_key()` | 生成SM2密钥对，返回text数组[私钥hex, 公钥hex] |
| `sm2_c_get_pubkey(private_key)` | 从私钥导出公钥 |

### 加密解密函数

| 函数 | 说明 |
|------|------|
| `sm2_c_encrypt(plaintext, public_key)` | 公钥加密，返回bytea |
| `sm2_c_decrypt(ciphertext, private_key)` | 私钥解密，输入bytea |
| `sm2_c_encrypt_hex(plaintext, public_key)` | 公钥加密，返回十六进制 |
| `sm2_c_decrypt_hex(ciphertext_hex, private_key)` | 私钥解密，输入十六进制 |
| `sm2_c_encrypt_base64(plaintext, public_key)` | 公钥加密，返回Base64 |
| `sm2_c_decrypt_base64(ciphertext_base64, private_key)` | 私钥解密，输入Base64 |

### 数字签名函数

| 函数 | 说明 |
|------|------|
| `sm2_c_sign(message, private_key, id)` | 签名，返回bytea(64字节) |
| `sm2_c_verify(message, public_key, signature, id)` | 验签，返回boolean |
| `sm2_c_sign_hex(message, private_key, id)` | 签名，返回十六进制 |
| `sm2_c_verify_hex(message, public_key, signature_hex, id)` | 验签，输入十六进制签名 |

### 参数格式

**私钥格式**:
- 32字节原始字符串
- 64字符十六进制字符串

**公钥格式**:
- 64字节原始字符串 (X || Y)
- 128字符十六进制字符串
- 130字符十六进制字符串 (04 || X || Y)

**密文格式** (GB/T 32918.4):
- C1 (65字节): 椭圆曲线点 (04 || X || Y)
- C3 (32字节): SM3哈希值
- C2 (可变): 加密后的数据

**签名格式**:
- r (32字节) || s (32字节)，共64字节

## 使用示例

### 1. 生成密钥对

```sql
-- 生成SM2密钥对
SELECT sm2_c_generate_key() AS keypair;

-- 结果示例:
-- {3f49c0e88e8e3c9e4c3e3f8a9e5d6c7b8a9e3f4c5d6e7f8a9b0c1d2e3f4a5b6c, a1b2c3d4...128字符公钥...}

-- 从私钥导出公钥
SELECT sm2_c_get_pubkey('3f49c0e88e8e3c9e4c3e3f8a9e5d6c7b8a9e3f4c5d6e7f8a9b0c1d2e3f4a5b6c');
```

### 2. 加密解密

```sql
-- 十六进制格式加解密
DO $$
DECLARE
    keypair text[];
    priv_key text;
    pub_key text;
    cipher text;
    plain text;
BEGIN
    keypair := sm2_c_generate_key();
    priv_key := keypair[1];
    pub_key := keypair[2];
    
    -- 加密
    cipher := sm2_c_encrypt_hex('Hello SM2!', pub_key);
    RAISE NOTICE '密文: %', cipher;
    
    -- 解密
    plain := sm2_c_decrypt_hex(cipher, priv_key);
    RAISE NOTICE '明文: %', plain;
END $$;

-- Base64格式加解密
SELECT sm2_c_decrypt_base64(
    sm2_c_encrypt_base64('敏感数据', (sm2_c_generate_key())[2]),
    (sm2_c_generate_key())[1]
);
```

### 3. 数字签名

```sql
DO $$
DECLARE
    keypair text[];
    priv_key text;
    pub_key text;
    signature text;
    verified boolean;
BEGIN
    keypair := sm2_c_generate_key();
    priv_key := keypair[1];
    pub_key := keypair[2];
    
    -- 签名
    signature := sm2_c_sign_hex('合同内容', priv_key);
    RAISE NOTICE '签名: %', signature;
    
    -- 验签
    verified := sm2_c_verify_hex('合同内容', pub_key, signature);
    RAISE NOTICE '验签结果: %', verified;
    
    -- 带用户ID签名
    signature := sm2_c_sign_hex('合同内容', priv_key, 'user@example.com');
    verified := sm2_c_verify_hex('合同内容', pub_key, signature, 'user@example.com');
END $$;
```

### 4. 实际应用场景

```sql
-- 创建加密用户表
CREATE TABLE users_sm2 (
    id SERIAL PRIMARY KEY,
    name TEXT,
    phone_encrypted TEXT,      -- SM2加密的手机号
    id_card_encrypted TEXT,    -- SM2加密的身份证
    public_key TEXT,           -- 用户公钥
    created_at TIMESTAMP DEFAULT NOW()
);

-- 插入加密数据
DO $$
DECLARE
    keypair text[];
    priv_key text;
    pub_key text;
BEGIN
    keypair := sm2_c_generate_key();
    priv_key := keypair[1];
    pub_key := keypair[2];
    
    INSERT INTO users_sm2 (name, phone_encrypted, id_card_encrypted, public_key)
    VALUES (
        '张三',
        sm2_c_encrypt_hex('13800138000', pub_key),
        sm2_c_encrypt_hex('110101199001011234', pub_key),
        pub_key
    );
    
    -- 保存私钥到安全存储 (不要存数据库!)
    RAISE NOTICE '请安全保存私钥: %', priv_key;
END $$;

-- 查询解密数据 (需要私钥)
SELECT 
    name,
    sm2_c_decrypt_hex(phone_encrypted, '私钥') AS phone,
    sm2_c_decrypt_hex(id_card_encrypted, '私钥') AS id_card
FROM users_sm2;
```

## 停用扩展

```sql
-- 删除所有SM2 C扩展函数
DROP FUNCTION IF EXISTS sm2_c_generate_key();
DROP FUNCTION IF EXISTS sm2_c_get_pubkey(text);
DROP FUNCTION IF EXISTS sm2_c_encrypt(text, text);
DROP FUNCTION IF EXISTS sm2_c_decrypt(bytea, text);
DROP FUNCTION IF EXISTS sm2_c_encrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm2_c_decrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm2_c_encrypt_base64(text, text);
DROP FUNCTION IF EXISTS sm2_c_decrypt_base64(text, text);
DROP FUNCTION IF EXISTS sm2_c_sign(text, text, text);
DROP FUNCTION IF EXISTS sm2_c_verify(text, text, bytea, text);
DROP FUNCTION IF EXISTS sm2_c_sign_hex(text, text, text);
DROP FUNCTION IF EXISTS sm2_c_verify_hex(text, text, text, text);
```

## 安全建议

### 1. 密钥管理

```bash
# ❌ 不要硬编码私钥
SELECT sm2_c_decrypt_hex(cipher, 'hardcoded_private_key');

# ✅ 使用环境变量或密钥管理系统
export SM2_PRIV_KEY="your_private_key"
```

### 2. 私钥存储

- **永远不要**将私钥存储在数据库中
- 使用硬件安全模块(HSM)或密钥管理服务(KMS)
- 私钥应加密存储，并限制访问权限

### 3. 用户标识

SM2签名支持用户标识(ID)，建议使用：
- 用户邮箱
- 用户UUID
- 组织标识

### 4. 访问控制

```sql
-- 限制函数执行权限
REVOKE EXECUTE ON FUNCTION sm2_c_decrypt FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION sm2_c_decrypt_hex FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sm2_c_decrypt TO trusted_role;
```

## 技术规范

### 椭圆曲线参数 (sm2p256v1)

| 参数 | 值 |
|------|-----|
| p | FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF |
| a | FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC |
| b | 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93 |
| n | FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123 |
| Gx | 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7 |
| Gy | BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0 |

### 相关标准

- GB/T 32918.1-2016: SM2椭圆曲线公钥密码算法 第1部分：总则
- GB/T 32918.2-2016: SM2椭圆曲线公钥密码算法 第2部分：数字签名算法
- GB/T 32918.3-2016: SM2椭圆曲线公钥密码算法 第3部分：密钥交换协议
- GB/T 32918.4-2016: SM2椭圆曲线公钥密码算法 第4部分：公钥加密算法
- GB/T 32918.5-2017: SM2椭圆曲线公钥密码算法 第5部分：参数定义
- GB/T 32905-2016: SM3密码杂凑算法

## 运行测试

```bash
vsql -d test01 -f test_sm2.sql
```

## SM2 vs SM4 对比

| 特性 | SM2 | SM4 |
|------|-----|-----|
| 算法类型 | 非对称加密 | 对称加密 |
| 密钥 | 公钥/私钥对 | 单一密钥 |
| 性能 | 较慢 | 较快 |
| 密钥分发 | 公钥可公开 | 需安全传输 |
| 适用场景 | 数字签名、密钥交换、少量数据加密 | 大量数据加密 |
| 密钥长度 | 256位(私钥) | 128位 |

## 常见问题

### Q: SM2加密的数据比原文大多少？
A: SM2密文 = C1(65字节) + C3(32字节) + C2(原文长度) = 原文 + 97字节

### Q: 为什么解密失败？
A: 检查以下几点：
1. 公钥和私钥是否匹配
2. 密文格式是否正确
3. 密文是否被篡改

### Q: 签名验证失败？
A: 检查以下几点：
1. 消息内容是否完全一致
2. 公钥是否正确
3. 用户ID是否与签名时相同

---

**最后更新**: 2025-12-24  
**版本**: 1.0.0  
**基于标准**: GB/T 32918-2016
