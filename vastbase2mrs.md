# VastBase SM4 扩展部署与 MRS Hive 集成指南

## 前提条件

切换到 VastBase 安装用户:

```bash
su - vastbase
```

---

## Step 1: 设置环境变量

> **注意**: 根据实际情况调整 `VBHOME` 的路径，其他变量保持不变。

```bash
export VBHOME=/home/vastbase/vasthome
export PATH=$VBHOME/bin:$PATH
export LD_LIBRARY_PATH=$VBHOME/lib:$LD_LIBRARY_PATH
```

---

## Step 2: 复制文件到目标目录

```bash
mkdir -p $VBHOME/lib/postgresql/proc_srclib
cp sm4.so $VBHOME/lib/postgresql/
cp sm4.control $VBHOME/share/postgresql/extension/
cp sm4--1.0.sql $VBHOME/share/postgresql/extension/
cp $VBHOME/lib/postgresql/sm4.so $VBHOME/lib/postgresql/proc_srclib/
```

---

## Step 3: 重启数据库加载新扩展

### 单机模式

```bash
vb_ctl restart
```

### 集群模式

```bash
cm_ctl stop
cm_ctl start
```

---

## Step 4: 创建扩展函数

> **重要**: 函数是数据库级别对象，需在每个要使用的数据库中单独创建。`.so` 文件是共享的，只需安装一次。

以下示例在 `test01` 库中创建函数，其他数据库需根据实际情况修改 `-d` 参数:

```bash
vsql -d test01 -f /home/vastbase/vasthome/share/postgresql/extension/sm4--1.0.sql
```

---

## Step 5: 停用扩展（可选）

如需停用扩展，可执行以下操作:

### 5.1 连接数据库

```bash
vsql -d test01 -r
```

### 5.2 删除所有 SM4 C 扩展函数

```sql
DROP FUNCTION IF EXISTS sm4_c_encrypt(text, text);
DROP FUNCTION IF EXISTS sm4_c_decrypt(bytea, text);
DROP FUNCTION IF EXISTS sm4_c_encrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm4_c_decrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm4_c_encrypt_cbc(text, text, text);
DROP FUNCTION IF EXISTS sm4_c_decrypt_cbc(bytea, text, text);
DROP FUNCTION IF EXISTS sm4_c_encrypt_gcm(text, text, text, text);
DROP FUNCTION IF EXISTS sm4_c_decrypt_gcm(bytea, text, text, text);
```

### 5.3 删除 .so 文件

```bash
rm -f $VBHOME/lib/postgresql/sm4.so
rm -f $VBHOME/lib/postgresql/proc_srclib/sm4.so
```

---

## Step 6: 查看函数

### 6.1 登录数据库

```bash
vsql -d test01
```

### 6.2 查看所有 SM4 C 扩展函数

```sql
\df sm4_c*
```

### 6.3 查看函数详细信息

```sql
\df+ sm4_c_encrypt_gcm_base64
```

### 6.4 测试 GCM 模式加解密（Base64 版本）

```sql
SELECT sm4_c_decrypt_gcm_base64(
    sm4_c_encrypt_gcm_base64('Hello World!', '12345678901234561234567890123456', '12345678901234561234567890123456'),
    '12345678901234561234567890123456',
    '12345678901234561234567890123456'
);
```

**返回结果**: `Hello World!`

---

## Step 7: 验证函数

执行测试脚本:

```bash
vsql -d test01 -f test_sm4_gcm.sql
```

---

## Step 8: 与 MRS Hive UDF 集成

### 8.1 在 VastBase 中加密数据

> **注意**: Key 和 IV 参数需要保持一致，因为 Hive UDF 使用相同的值。

```sql
SELECT sm4_c_encrypt_gcm_base64(
    'Hello World!', 
    '12345678901234561234567890123456', 
    '12345678901234561234567890123456'
);
```

**加密结果**:
```
ls6vj8Wh9w/HRiFuxpPVFjAgRczy2i2A28HOrg==
```

### 8.2 将 Key 转换为 Base64 格式

Hive UDF 需要使用 Base64 编码的 Key:

```bash
echo "12345678901234561234567890123456" | xxd -r -p | base64
```

**转换结果**:
```
EjRWeJASNFYSNFZ4kBI0Vg==
```

### 8.3 在 Hive 中解密数据

```sql
SELECT default.sm4_decrypt(
    'ls6vj8Wh9w/HRiFuxpPVFjAgRczy2i2A28HOrg==', 
    'EjRWeJASNFYSNFZ4kBI0Vg=='
);
```

**解密结果**:
```
Hello World!
```

---

## 总结

本文档介绍了 VastBase SM4 扩展的完整部署流程，以及与 MRS Hive UDF 的集成方法。关键点:

- ✅ 环境变量配置
- ✅ 扩展文件部署
- ✅ 数据库重启与函数创建
- ✅ VastBase 与 Hive 之间的加解密互通
- ✅ Key 格式转换（HEX → Base64）
