# Feature-15: 输入长度整数溢出防护

## 优先级: 中

## 问题描述

多个加密函数中，输入长度的算术运算存在整数溢出风险：

1. `sm4_ecb_encrypt`（sm4.c:232）：`padded_len = input_len + SM4_BLOCK_SIZE - (input_len % SM4_BLOCK_SIZE)` — 当 `input_len` 接近 `SIZE_MAX` 时溢出
2. `sm4_cbc_encrypt`（sm4.c:299）：同上
3. `sm4_ext.c` 中所有 `palloc(plain_len + SM4_BLOCK_SIZE)` 调用 — 当 `plain_len` 极大时溢出导致分配过小的缓冲区

溢出后果：分配的缓冲区小于实际需要，后续 `memcpy`/`pkcs7_pad` 写入越界。

## 影响范围

- `sm4.c:232` — sm4_ecb_encrypt 中的 padded_len 计算
- `sm4.c:299` — sm4_cbc_encrypt 中的 padded_len 计算
- `sm4_ext.c` 中所有 palloc 调用中的长度计算

## 需求描述

1. 在加密函数入口处检查 `input_len` 是否超过合理上限（建议 1GB = 1073741824 字节）
2. 在长度计算前进行溢出检查：若 `input_len > SIZE_MAX - SM4_BLOCK_SIZE` 则拒绝
3. 在 `palloc` 调用前验证长度未溢出

## 验收标准

1. 超大输入被拒绝并返回明确错误
2. 不发生整数溢出导致的缓冲区分配不足
3. 错误消息指示输入长度超限
