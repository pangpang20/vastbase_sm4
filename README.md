# SM4 Extension for VastBase/OpenGauss

国密SM4分组密码算法扩展，基于GB/T 32907-2016标准实现。

## 文件结构

```
├── sm4.h          # SM4算法头文件
├── sm4.c          # SM4算法实现
├── sm4_ext.c      # VastBase扩展接口
├── sm4.control    # 扩展控制文件
├── sm4--1.0.sql   # SQL函数定义
├── Makefile       # 编译配置
├── install.sh     # 安装脚本
└── test_sm4.sql   # 测试脚本
```

## 编译安装

```bash
# 进入代码目录
cd /home/vastbase/vastbase_sm4

# 设置环境变量
export VBHOME=/home/vastbase/vasthome
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

VastBase不支持EXTENSION语法，需直接执行SQL创建函数：

```bash
# 连接数据库并执行SQL文件
vsql -d postgres -f /home/vastbase/vasthome/share/postgresql/extension/sm4--1.0.sql
```

或手动执行：

```sql
-- 连接数据库
vsql -d postgres

-- 创建SM4函数
CREATE OR REPLACE FUNCTION sm4_encrypt(plaintext text, key text)
RETURNS bytea AS 'sm4', 'sm4_encrypt' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_decrypt(ciphertext bytea, key text)
RETURNS text AS 'sm4', 'sm4_decrypt' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_encrypt_hex(plaintext text, key text)
RETURNS text AS 'sm4', 'sm4_encrypt_hex' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_decrypt_hex(ciphertext_hex text, key text)
RETURNS text AS 'sm4', 'sm4_decrypt_hex' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_encrypt_cbc(plaintext text, key text, iv text)
RETURNS bytea AS 'sm4', 'sm4_encrypt_cbc' LANGUAGE C STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION sm4_decrypt_cbc(ciphertext bytea, key text, iv text)
RETURNS text AS 'sm4', 'sm4_decrypt_cbc' LANGUAGE C STRICT IMMUTABLE;

-- 删除函数
DROP FUNCTION IF EXISTS sm4_encrypt(text, text);
DROP FUNCTION IF EXISTS sm4_decrypt(bytea, text);
DROP FUNCTION IF EXISTS sm4_encrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm4_decrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm4_encrypt_cbc(text, text, text);
DROP FUNCTION IF EXISTS sm4_decrypt_cbc(bytea, text, text);
```

## 函数说明

| 函数                              | 说明                            |
| --------------------------------- | ------------------------------- |
| `sm4_encrypt(text, key)`          | ECB模式加密，返回bytea          |
| `sm4_decrypt(bytea, key)`         | ECB模式解密，返回text           |
| `sm4_encrypt_hex(text, key)`      | ECB模式加密，返回十六进制字符串 |
| `sm4_decrypt_hex(hex, key)`       | ECB模式解密，输入十六进制密文   |
| `sm4_encrypt_cbc(text, key, iv)`  | CBC模式加密，返回bytea          |
| `sm4_decrypt_cbc(bytea, key, iv)` | CBC模式解密，返回text           |

**密钥格式**: 16字节字符串 或 32位十六进制字符串

## 运行示例

```sql
-- ECB模式加密 (返回十六进制)
SELECT sm4_encrypt_hex('Hello VastBase!', '1234567890abcdef');

-- ECB模式解密
SELECT sm4_decrypt_hex('密文hex', '1234567890abcdef');

-- 加解密验证
SELECT sm4_decrypt_hex(
    sm4_encrypt_hex('测试数据', '1234567890abcdef'),
    '1234567890abcdef'
);

-- bytea格式加解密
SELECT sm4_decrypt(
    sm4_encrypt('中文测试', '1234567890abcdef'),
    '1234567890abcdef'
);

-- CBC模式 (需要IV)
SELECT sm4_decrypt_cbc(
    sm4_encrypt_cbc('明文数据', 'key1234567890123', 'iv12345678901234'),
    'key1234567890123',
    'iv12345678901234'
);

-- 使用32位十六进制密钥
SELECT sm4_encrypt_hex('敏感数据', '0123456789abcdef0123456789abcdef');

-- 运行测试脚本
vsql -d postgres -f test_sm4.sql
```
