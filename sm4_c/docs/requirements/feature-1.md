# Feature-1: 空值/空字符串输入跳过加密解密

## 优先级: 高

## 问题描述

**注意**: SQL 函数已声明为 `STRICT`，PostgreSQL/VastBase 在参数为 NULL 时会自动返回 NULL，不会调用 C 函数。因此 NULL 处理已由数据库层面解决。

当前需要修复的核心问题是**空字符串("")输入**：当数据库字段值为空字符串时，函数仍尝试执行加密/解密操作，导致：

- 空字符串加密后产生无意义的填充密文（16字节PKCS7填充）
- 浪费计算资源，增加不必要的性能开销

C 层的 NULL 指针检查作为防御性编程保留，防止非 SQL 调用路径中的空指针问题。

## 影响范围

- `sm4_ext.c` 中所有 10 个 PG_FUNCTION_INFO_V1 函数
- `sm4_encrypt`, `sm4_decrypt`
- `sm4_encrypt_cbc`, `sm4_decrypt_cbc`
- `sm4_encrypt_hex`, `sm4_decrypt_hex`
- `sm4_encrypt_gcm`, `sm4_decrypt_gcm`
- `sm4_encrypt_gcm_base64`, `sm4_decrypt_gcm_base64`

## 需求描述

### 加密场景
- 如果输入明文为 NULL，直接返回 NULL
- 如果输入明文为空字符串("")，直接返回 NULL 或空字符串（不执行加密）

### 解密场景
- 如果输入密文为 NULL，直接返回 NULL
- 如果输入密文为空（长度为0），直接返回 NULL 或空字符串（不执行解密）

### SQL 函数签名兼容
- 使用 `PG_ARGISNULL()` 检查参数是否为 NULL
- 使用 `VARSIZE_ANY_EXHDR()` 检查实际数据长度是否为 0

## 参考代码位置

- `sm4_ext.c:92-136` — sm4_encrypt 函数
- `sm4_ext.c:142-183` — sm4_decrypt 函数
- `sm4_ext.c:455-556` — sm4_encrypt_gcm 函数

## 验收标准

1. `SELECT sm4_c_encrypt(NULL, '1234567890abcdef');` 返回 NULL（由 STRICT 属性保证）
2. `SELECT sm4_c_encrypt('', '1234567890abcdef');` 返回 NULL（C 层空字符串检查）
3. `SELECT sm4_c_decrypt(NULL, '1234567890abcdef');` 返回 NULL（由 STRICT 属性保证）
4. 所有模式（ECB/CBC/GCM）的加密解密函数均需支持空字符串检查
5. C 层 NULL 指针检查作为防御性编程保留
