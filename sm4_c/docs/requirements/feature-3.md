# Feature-3: GCM Tag 比较时序侧信道攻击修复

## 优先级: 高

## 问题描述

`sm4_gcm_decrypt()` 中的 Tag 验证使用逐字节比较，遇到不匹配时立即返回：

```c
for (i = 0; i < 16; i++) {
    if (computed_tag[i] != tag[i]) {
        return -1;  /* 认证失败 */
    }
}
```

这种实现存在时序侧信道攻击风险：攻击者可以通过测量响应时间推断 Tag 的正确字节数，逐字节伪造有效 Tag。

## 影响范围

- `sm4.c:654-658` — sm4_gcm_decrypt 中的 Tag 比较
- 所有使用 GCM 解密的 SQL 函数

## 需求描述

1. 使用常量时间比较函数替代逐字节比较
2. 可使用 OpenSSL 的 `CRYPTO_memcmp()` 或自行实现常量时间比较
3. 确保无论匹配程度如何，比较时间恒定

## 参考实现

```c
static int constant_time_memcmp(const void *a, const void *b, size_t len)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t result = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        result |= x[i] ^ y[i];
    }
    return result;
}
```

## 参考代码位置

- `sm4.c:650-658` — Tag 验证逻辑

## 验收标准

1. Tag 比较使用常量时间实现
2. 伪造 Tag 的响应时间与正确 Tag 的响应时间无统计学差异
3. GCM 认证失败功能正常（错误 Tag 仍返回失败）
