# Feature-1: 空值/NULL 输入跳过加密解密

## 优先级: 高

## 问题描述

当前所有加密/解密函数（ECB、CBC、GCM模式）均未对空值、NULL 输入做特殊处理。当数据库字段值为空字符串("")、NULL 或字面量 "NULL" 时，函数仍尝试执行加密/解密操作，导致：

- 空字符串加密后产生无意义的填充密文（16字节PKCS7填充）
- NULL 值传入时可能触发空指针异常
- 浪费计算资源，增加不必要的性能开销

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

1. `SELECT sm4_c_encrypt(NULL, '1234567890abcdef');` 返回 NULL
2. `SELECT sm4_c_encrypt('', '1234567890abcdef');` 返回 NULL 或空
3. `SELECT sm4_c_decrypt(NULL, '1234567890abcdef');` 返回 NULL
4. 所有模式（ECB/CBC/GCM）的加密解密函数均需支持此行为
