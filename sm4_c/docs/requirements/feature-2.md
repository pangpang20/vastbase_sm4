# Feature-2: GCM 模式栈缓冲区溢出修复

## 优先级: 严重

## 问题描述

`sm4_gcm_encrypt()` 和 `sm4_gcm_decrypt()` 中，`ghash_input` 声明为固定 1024 字节的栈缓冲区：

```c
uint8_t ghash_input[1024]; // 栈上固定 1024 字节
```

用于构造 GHASH 输入的缓冲区只有 1024 字节。当 `AAD + 密文 + 16字节长度字段` 的总填充后长度超过 1024 时：
- `memcpy(ghash_input + ghash_len, output, input_len)` 会越界写入栈
- 例如 `aad_len=500, input_len=500` → 填充后总长 = 512 + 512 + 16 = 1040 > 1024

风险: 栈溢出可导致崩溃或远程代码执行。

### 漏洞代码

```c
// 填充计算：
ghash_len = aad_len;
if (ghash_len % 16 != 0) {
    ghash_len += 16 - (ghash_len % 16); // 只增加计数，不分配内存！
}
// 然后：
memcpy(ghash_input + ghash_len, output, input_len); // ⚠️ 无边界检查
```

## 影响范围

- `sm4.c:480` — sm4_gcm_encrypt 中的 ghash_input 声明
- `sm4.c:577` — sm4_gcm_decrypt 中的 ghash_input 声明
- `sm4.c:528-557` — GHASH 输入构造逻辑（加密端）
- `sm4.c:618-645` — GHASH 输入构造逻辑（解密端）

## 需求描述

1. 将 `ghash_input` 从固定 1024 字节改为动态分配，大小为 `aad_len_padded + input_len_padded + 16`
2. 或者将固定大小增大到足够容纳最大可能输入（如 64KB+）
3. 添加长度校验，拒绝超出合理范围的输入
4. 使用 `palloc()` 动态分配并检查返回值

## 参考代码位置

- `sm4.c:471-566` — sm4_gcm_encrypt 函数
- `sm4.c:568-667` — sm4_gcm_decrypt 函数

## 验收标准

1. 加密/解密超过 1008 字节的数据不发生栈溢出
2. 使用 AddressSanitizer 编译测试无内存错误
3. 大数据量 GCM 加密解密往返测试通过
