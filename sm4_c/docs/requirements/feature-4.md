# Feature-4: 敏感数据内存清零

## 优先级: 高

## 问题描述

多个函数在使用完密钥、明文、轮密钥等敏感数据后未清零，导致敏感信息残留在内存中，可能通过内存转储、core dump 或冷启动攻击泄露。

### 具体位置

1. **sm4_context 轮密钥未清零**：`sm4_setkey()` 生成的 32 个轮密钥（`ctx->rk[32]`）在使用后从未被清零
2. **sm4_ext.c 中 key_bytes 未清零**：所有 PG 函数中的 `uint8_t key_bytes[SM4_KEY_SIZE]` 在函数返回前未清零
3. **sm4.c 中临时缓冲区未清零**：`padded`、`block`、`prev`、`counter`、`encrypted_counter` 等临时缓冲区未清零
4. **KDF 派生的密钥材料**：`derive_key_and_iv()` 中的 `derived[32]` 虽然有清零，但调用方的 `key` 和 `iv` 未清零

## 影响范围

- `sm4.c:113-129` — sm4_setkey 函数
- `sm4.c:219-251` — sm4_ecb_encrypt 函数
- `sm4.c:284-323` — sm4_cbc_encrypt 函数
- `sm4.c:326-362` — sm4_cbc_decrypt 函数
- `sm4.c:471-566` — sm4_gcm_encrypt 函数
- `sm4_ext.c` 中所有 PG 函数

## 需求描述

1. 在每个加密/解密函数结束前，使用 `OPENSSL_cleanse()` 或 `memset_s()` 清零所有敏感栈变量
2. 提供 `sm4_context_clean()` 函数清零上下文中的轮密钥
3. 对于 palloc 分配的内存，清零后再 pfree
4. 避免编译器优化掉清零操作（使用 volatile 或专用函数）

## 参考代码位置

- `sm4.h:18-20` — sm4_context 结构体定义
- `sm4.c:113-129` — sm4_setkey 函数
- `sm4_ext.c:63-85` — get_key_bytes 函数

## 验收标准

1. 使用 Valgrind 或 AddressSanitizer 验证无敏感数据残留
2. 函数返回后栈内存中的密钥数据已被清零
3. 所有模式（ECB/CBC/GCM）的函数均需实现清零
