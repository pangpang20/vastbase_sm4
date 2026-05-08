# Feature-9: 内存分配失败检查

## 优先级: 中

## 问题描述

多处代码使用 `palloc()` 分配内存但未检查返回值。虽然 PostgreSQL 的 `palloc` 在内存不足时默认抛出错误，但在某些配置下可能返回 NULL，导致空指针解引用。

## 影响范围

- `sm4_ext.c` 中所有使用 `palloc()` 的位置
- `sm4.c` 中使用 `malloc()` 的位置

### 具体位置
- `sm4_ext.c:116` — cipher = palloc(cipher_len)
- `sm4_ext.c:128` — result = palloc(VARHDRSZ + cipher_len)
- `sm4_ext.c:166` — plain = palloc(cipher_len + 1)
- `sm4_ext.c:239` — cipher = palloc(cipher_len)
- `sm4_ext.c:251` — result = palloc(VARHDRSZ + cipher_len)
- `sm4_ext.c:314` — plain = palloc(cipher_len + 1)
- `sm4_ext.c:362-363` — cipher = palloc(cipher_len), hex_str = palloc(...)
- `sm4_ext.c:417-418` — cipher = palloc(hex_len / 2), plain = palloc(...)
- `sm4_ext.c:530` — cipher = palloc(plain_len)
- `sm4_ext.c:546` — result = palloc(...)
- `sm4_ext.c:651` — plain = palloc(cipher_len + 1)
- `sm4_ext.c:681` — out = palloc(out_len + 1) (base64_encode)
- `sm4_ext.c:731` — out = palloc(*out_len) (base64_decode)
- `sm4_ext.c:826` — cipher = palloc(plain_len)
- `sm4_ext.c:842` — cipher_with_tag = palloc(...)
- `sm4_ext.c:960` — plain = palloc(cipher_len + 1)
- `sm4.c:235` — padded = malloc(padded_len)
- `sm4.c:301` — padded = malloc(padded_len)

## 需求描述

1. 对所有 `palloc()` 和 `malloc()` 调用添加返回值检查
2. 内存分配失败时执行清理（释放已分配的资源）
3. 返回适当的错误码或抛出 PostgreSQL 错误

## 验收标准

1. 所有内存分配调用都有返回值检查
2. 内存分配失败时正确清理资源
3. 无内存泄漏（通过 Valgrind 验证）
