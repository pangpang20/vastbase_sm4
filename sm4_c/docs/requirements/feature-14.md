# Feature-14: 密钥扩展中间状态清零

## 优先级: 高

## 问题描述

`sm4_setkey()` 函数（sm4.c:113-129）中的 `k[36]` 数组包含密钥扩展的中间计算结果。该数组在栈上分配，函数返回后未清零，导致密钥材料残留在栈内存中。

虽然 Feature-4 已覆盖 `sm4_context` 中的轮密钥清零，但 `k[36]` 是独立的中间状态，需要单独处理。

### 漏洞代码

```c
void sm4_setkey(sm4_context *ctx, const uint8_t *key)
{
    uint32_t k[36];  // 包含密钥扩展中间值，函数返回后残留在栈上
    // ...
    // 函数结束，k[36] 未清零
}
```

## 影响范围

- `sm4.c:115` — k[36] 数组声明
- `sm4.c:113-129` — sm4_setkey 函数整体

## 需求描述

1. 在 `sm4_setkey` 函数返回前，使用 `OPENSSL_cleanse(k, sizeof(k))` 清零 k 数组
2. 同样处理 `sm4_encrypt_block` 和 `sm4_decrypt_block` 中的 `x[36]` 数组

## 验收标准

1. sm4_setkey 返回后栈上的 k[36] 已被清零
2. sm4_encrypt_block/sm4_decrypt_block 返回后栈上的 x[36] 已被清零
3. 清零操作未被编译器优化掉
