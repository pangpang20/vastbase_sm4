# MRS Hive 与 VastBase SM4 加密互操作指南

本文档介绍如何在 MRS Hive 和 VastBase 数据库之间使用 SM4/SM2 加密算法进行数据加密和解密，实现跨系统的加密数据互操作。

## 目录

- [前置条件](#前置条件)
- [第一步：生成加密密钥](#第一步生成加密密钥)
- [第二步：MRS Hive UDF 部署](#第二步mrs-hive-udf-部署)
- [第三步：VastBase 加解密操作](#第三步vastbase-加解密操作)
- [密钥格式转换说明](#密钥格式转换说明)
- [常见问题](#常见问题)

---

## 前置条件

### MRS 环境要求

- MRS 集群已正常运行
- 已配置 Kerberos 认证
- 已部署 dcf_etl 工具
- 已准备好 SM 算法 UDF JAR 包：`adq-sm-algorithm-1.0.0.jar`

### VastBase 环境要求

- VastBase 数据库已安装并运行
- 已安装 SM4 C 扩展（参考 [README.md](README.md)）
- 已创建测试数据库（如 `test01`）

---

## 第一步：生成加密密钥

使用 OpenSSL 生成 16 字节（128 位）的随机密钥。

### 1.1 生成 Base64 编码密钥

```bash
# 生成 16 字节随机密钥并进行 Base64 编码
encrypt_key=$(openssl rand 16 | base64)

# 查看生成的密钥
echo $encrypt_key
```

**示例输出**:
```
jH54J9X5Ywztmc/UMDXTbw==
```

> **说明**: 此 Base64 格式密钥用于 MRS Hive UDF。

### 1.2 转换为 16 进制格式

VastBase/GaussDB 数据库需要使用 16 进制格式的密钥。

```bash
# 将 Base64 密钥还原并转换为 16 进制
echo "$encrypt_key" | base64 -d | xxd -p -c 256
```

**示例输出**:
```
8c7e7827d5f9630ced99cfd43035d36f
```

> **说明**: 此 16 进制格式密钥用于 VastBase SM4 加密函数。

### 1.3 密钥格式对照表

| 用途 | 密钥格式 | 示例 |
|------|---------|------|
| MRS Hive UDF | Base64 编码 | `jH54J9X5Ywztmc/UMDXTbw==` |
| VastBase SM4 | 16 进制（32 字符） | `8c7e7827d5f9630ced99cfd43035d36f` |

---

## 第二步：MRS Hive UDF 部署

### 2.1 登录 MRS 节点

```bash
# 切换到指定用户
su - cyl

# 加载 MRS 环境变量
source /opt/mrs_client_new/bigdata_env

# Kerberos 认证
kinit chenyunliang
# 输入密码: Audaque@123

# 进入部署脚本目录
cd /opt/dcf_etl/shell
```

### 2.2 创建 SM4 加解密函数

#### 创建 SM4 加密函数

```bash
./mrs_hive_udf.sh \
  --config_path "/opt/dcf_etl/config/hadoop_cluster_config_mrs" \
  --jar_local_path "/opt/dcf_etl/jars/adq-sm-algorithm-1.0.0.jar" \
  --db_name "cyl" \
  --func_name "mysm4_encrypt" \
  --class_name "com.audaque.hiveudf.SM4Encrypt" \
  --action "create"
```

#### 创建 SM4 解密函数

```bash
./mrs_hive_udf.sh \
  --config_path "/opt/dcf_etl/config/hadoop_cluster_config_mrs" \
  --jar_local_path "/opt/dcf_etl/jars/adq-sm-algorithm-1.0.0.jar" \
  --db_name "cyl" \
  --func_name "mysm4_decrypt" \
  --class_name "com.audaque.hiveudf.SM4Decrypt" \
  --action "create"
```

### 2.3 创建 SM2 加解密函数

#### 创建 SM2 加密函数

```bash
./mrs_hive_udf.sh \
  --config_path "/opt/dcf_etl/config/hadoop_cluster_config_mrs" \
  --jar_local_path "/opt/dcf_etl/jars/adq-sm-algorithm-1.0.0.jar" \
  --db_name "cyl" \
  --func_name "mysm2_encrypt" \
  --class_name "com.audaque.hiveudf.SM2Encrypt" \
  --action "create"
```

#### 创建 SM2 解密函数

```bash
./mrs_hive_udf.sh \
  --config_path "/opt/dcf_etl/config/hadoop_cluster_config_mrs" \
  --jar_local_path "/opt/dcf_etl/jars/adq-sm-algorithm-1.0.0.jar" \
  --db_name "cyl" \
  --func_name "mysm2_decrypt" \
  --class_name "com.audaque.hiveudf.SM2Decrypt" \
  --action "create"
```

### 2.4 验证函数创建

登录 Hive 并查看已创建的函数：

```bash
# 启动 Beeline 客户端
beeline
```

```sql
-- 切换到目标数据库
use cyl;

-- 查看所有 SM 相关的自定义函数
show functions like '*sm*';
```

**预期输出**:
```
cyl.mysm4_encrypt
cyl.mysm4_decrypt
cyl.mysm2_encrypt
cyl.mysm2_decrypt
```

### 2.5 测试 SM4 加解密

```sql
-- 设置 SM4 密钥（Base64 格式，128 位）
-- 注意：sm4_key= 后面不要加单引号或双引号
SET hivevar:sm4_key=jH54J9X5Ywztmc/UMDXTbw==;

-- 测试 SM4 加密
SELECT cyl.mysm4_encrypt('敏感信息', '${hivevar:sm4_key}') AS encrypted;
```

**示例输出**:
```
Z5+I+POSSeCKgEYliRThY9qTpzPfnpuqgvZJCw==
```

```sql
-- 测试 SM4 解密
SELECT cyl.mysm4_decrypt('Z5+I+POSSeCKgEYliRThY9qTpzPfnpuqgvZJCw==', '${hivevar:sm4_key}') AS decrypted;
```

**示例输出**:
```
敏感信息
```

### 2.6 删除自定义函数（可选）

如需删除已创建的函数，执行以下命令：

```bash
# 删除 SM4 加密函数
./mrs_hive_udf.sh \
  --config_path "/opt/dcf_etl/config/hadoop_cluster_config_mrs" \
  --db_name "cyl" \
  --func_name "mysm4_encrypt" \
  --action "delete"

# 删除 SM4 解密函数
./mrs_hive_udf.sh \
  --config_path "/opt/dcf_etl/config/hadoop_cluster_config_mrs" \
  --db_name "cyl" \
  --func_name "mysm4_decrypt" \
  --action "delete"

# 删除 SM2 加密函数
./mrs_hive_udf.sh \
  --config_path "/opt/dcf_etl/config/hadoop_cluster_config_mrs" \
  --db_name "cyl" \
  --func_name "mysm2_encrypt" \
  --action "delete"

# 删除 SM2 解密函数
./mrs_hive_udf.sh \
  --config_path "/opt/dcf_etl/config/hadoop_cluster_config_mrs" \
  --db_name "cyl" \
  --func_name "mysm2_decrypt" \
  --action "delete"
```

---

## 第三步：VastBase 加解密操作

### 3.1 登录 VastBase 数据库

```bash
# 切换到 VastBase 用户
su - vastbase

# 登录数据库
vsql -d test01 -r
```

### 3.2 查看已安装的 SM4 函数

```sql
-- 查看所有 SM4 C 扩展函数
\df sm4_c_*
```

**预期输出**:
```
sm4_c_encrypt
sm4_c_decrypt
sm4_c_encrypt_hex
sm4_c_decrypt_hex
sm4_c_encrypt_cbc
sm4_c_decrypt_cbc
sm4_c_encrypt_gcm
sm4_c_decrypt_gcm
sm4_c_encrypt_gcm_base64
sm4_c_decrypt_gcm_base64
```

### 3.3 SM4-GCM 模式加密（推荐）

VastBase 使用 GCM 模式提供更高的安全性（带认证）。

#### 加密示例

```sql
-- SM4-GCM 加密（返回 Base64 格式）
-- 参数说明：明文, 密钥(16进制), IV(16进制)
SELECT sm4_c_encrypt_gcm_base64(
    '敏感信息',
    '8c7e7827d5f9630ced99cfd43035d36f',
    '8c7e7827d5f9630ced99cfd43035d36f'
);
```

**示例输出**:
```
iuc7UvJ4zEwGwpJ/YMzqsSsAqcocqOm2WTMlMw==
```

#### 解密示例

```sql
-- SM4-GCM 解密（输入 Base64 格式密文）
SELECT sm4_c_decrypt_gcm_base64(
    'iuc7UvJ4zEwGwpJ/YMzqsSsAqcocqOm2WTMlMw==',
    '8c7e7827d5f9630ced99cfd43035d36f',
    '8c7e7827d5f9630ced99cfd43035d36f'
);
```

**示例输出**:
```
敏感信息
```

### 3.4 完整加解密验证

```sql
-- 加密后立即解密，验证数据完整性
SELECT sm4_c_decrypt_gcm_base64(
    sm4_c_encrypt_gcm_base64(
        '测试数据123',
        '8c7e7827d5f9630ced99cfd43035d36f',
        '8c7e7827d5f9630ced99cfd43035d36f'
    ),
    '8c7e7827d5f9630ced99cfd43035d36f',
    '8c7e7827d5f9630ced99cfd43035d36f'
) AS decrypted_text;
```

**预期输出**:
```
测试数据123
```

---

## 密钥格式转换说明

### MRS Hive → VastBase

如果已有 MRS Hive 使用的 Base64 密钥，需要转换为 VastBase 的 16 进制格式：

```bash
# 示例：将 Base64 密钥转换为 16 进制
echo "jH54J9X5Ywztmc/UMDXTbw==" | base64 -d | xxd -p -c 256
```

**输出**:
```
8c7e7827d5f9630ced99cfd43035d36f
```

### VastBase → MRS Hive

如果已有 VastBase 使用的 16 进制密钥，需要转换为 MRS Hive 的 Base64 格式：

```bash
# 示例：将 16 进制密钥转换为 Base64
echo "8c7e7827d5f9630ced99cfd43035d36f" | xxd -r -p | base64
```

**输出**:
```
jH54J9X5Ywztmc/UMDXTbw==
```

---

## 常见问题

### Q1: MRS Hive 和 VastBase 使用的加密算法一致吗？

**A**: 是的，两者都使用国密 SM4 算法，但加密模式不同：

- **MRS Hive UDF**: 默认使用 SM4-CBC 或 SM4-ECB 模式
- **VastBase C 扩展**: 支持 ECB、CBC、GCM 模式（推荐使用 GCM）

> **注意**: 不同加密模式的密文无法互相解密。如需跨系统互操作，需使用相同的加密模式和参数。

### Q2: 为什么 VastBase 和 Hive 的密钥格式不同？

**A**: 
- **VastBase SM4 C 扩展**: 接受 16 进制字符串（32 字符），更直观地表示二进制密钥
- **MRS Hive UDF**: 接受 Base64 编码字符串，减少传输和存储空间

两种格式本质上表示的是相同的 16 字节二进制密钥，可通过命令行工具相互转换。

### Q3: GCM 模式的 IV 参数如何选择？

**A**: 
- **长度**: 推荐使用 12 字节（96 位），也可使用 16 字节
- **随机性**: IV 必须是随机生成的，且不能重复使用
- **示例生成**:
  ```bash
  # 生成 12 字节 IV（16 进制）
  openssl rand 12 | xxd -p -c 256
  
  # 生成 16 字节 IV（16 进制）
  openssl rand 16 | xxd -p -c 256
  ```

### Q4: 如何确保 Hive 和 VastBase 之间的加密互操作？

**A**: 需要满足以下条件：

1. **使用相同的密钥**（注意格式转换）
2. **使用相同的加密模式**（ECB、CBC 或 GCM）
3. **CBC/GCM 模式需要相同的 IV**
4. **字符编码一致**（建议使用 UTF-8）

### Q5: 密钥应该如何安全管理？

**A**: 

- ❌ **不要**将密钥硬编码在代码或配置文件中
- ✅ **建议**使用专业的密钥管理系统（KMS）
- ✅ **建议**使用环境变量或加密配置文件
- ✅ **建议**定期轮换密钥
- ✅ **建议**对密钥进行访问控制和审计

### Q6: 函数命名为什么使用 `sm4_c_` 前缀？

**A**: VastBase 同时支持 Java UDF 和 C 扩展。为避免与 Java UDF 中的 SM4 函数名冲突，C 扩展统一使用 `sm4_c_` 前缀进行区分。

---

## 参考文档

- [SM4 C 扩展 README](README.md) - VastBase SM4 C 扩展的详细说明
- [VastBase 与 MRS 集成指南](../vastbase2mrs.md) - VastBase 与 MRS Hive 的集成方案
- GB/T 32907-2016 - 国密 SM4 分组密码算法标准

---

## 版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| 1.0 | 2026-01-09 | 初始版本，包含密钥生成、MRS UDF 部署、VastBase 操作指南 |
