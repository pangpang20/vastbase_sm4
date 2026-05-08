# Feature-12: 密钥中间载体内存清零

## 优先级: 高

## 问题描述

`get_key_bytes()` 函数（sm4_ext.c:63-85）通过 `text_to_cstring()` 分配密钥字符串，复制到 `key_bytes` 后仅调用 `pfree()` 释放，未清零内存。`pfree` 不保证清零已释放内存，密钥明文残留在堆中。

此外，`text_to_cstring()` 在 IV 解析（sm4_ext.c:213, 289, 484, 593 等多处）中分配的 `iv_str` 也存在同样问题。

### 具体位置

1. `sm4_ext.c:65` — `key_str = text_to_cstring(key_text)` 后仅 pfree
2. `sm4_ext.c:213` — `iv_str = text_to_cstring(iv_text)` 后仅 pfree
3. `sm4_ext.c:289` — CBC 解密中的 iv_str
4. `sm4_ext.c:484` — GCM 加密中的 iv_str
5. `sm4_ext.c:521` — `aad_str = text_to_cstring(aad_text)` 后仅 pfree
6. 所有 GCM 变体中的 aad_str

## 需求描述

1. 在 `pfree()` 前使用 `OPENSSL_cleanse()` 或 `memset_s()` 清零所有包含密钥/IV/AAD 的中间字符串
2. 使用 volatile 函数指针或 `OPENSSL_cleanse` 防止编译器优化掉清零操作
3. 统一在 `get_key_bytes` 函数内完成清零（密钥场景）
4. IV 和 AAD 的清零在各 PG 函数中就近处理

## 参考代码位置

- `sm4_ext.c:63-85` — get_key_bytes 函数
- `sm4_ext.c:189-258` — sm4_encrypt_cbc 函数
- `sm4_ext.c:455-556` — sm4_encrypt_gcm 函数

## 验收标准

1. 所有 `text_to_cstring` 返回的密钥/IV/AAD 字符串在释放前被清零
2. 使用 Valgrind 或 AddressSanitizer 验证无密钥残留
3. 清零操作未被编译器优化掉
