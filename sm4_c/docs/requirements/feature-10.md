# Feature-10: C 单元测试框架

## 优先级: 中

## 状态: 已完成

## 问题描述

当前项目只有 SQL 层面的集成测试（test_sm4.sql、test_sm4_gcm.sql），缺少 C 语言层面的单元测试。SQL 测试无法覆盖：

1. 边界条件（空输入、超大输入、非法参数）
2. 内存安全问题（缓冲区溢出、内存泄漏）
3. 错误处理路径
4. 加密算法的正确性验证

## 已完成实现

已创建 `test_sm4_unit.c`，使用轻量级自定义测试框架（assert 宏 + 计数器），不依赖外部库。

### 编译运行

```bash
make test
# 或手动编译:
gcc -O2 -Wall -std=c11 -DUSE_OPENSSL_KDF -o test_sm4_unit test_sm4_unit.c sm4.c -lssl -lcrypto
./test_sm4_unit
```

### 已实现的测试用例 (62 个)

| 测试 | 覆盖内容 |
|------|----------|
| test_sm4_ecb_block_roundtrip | 单块加解密往返 |
| test_sm4_ecb_roundtrip | ECB 模式完整往返 |
| test_sm4_cbc_roundtrip | CBC 模式完整往返 |
| test_sm4_gcm_roundtrip | GCM 模式完整往返 (含 AAD) |
| test_sm4_gcm_auth_failure | GCM Tag/密文篡改检测 |
| test_sm4_gcm_large_data | 2048 字节 GCM (验证缓冲区溢出修复) |
| test_sm4_gcm_very_large_data | 64KB GCM |
| test_sm4_empty_input | 空输入处理 |
| test_sm4_null_params | NULL 参数检查 |
| test_sm4_context_clean | 上下文清零验证 |
| test_sm4_gcm_iv_lengths | 不同 IV 长度 (12/16 字节) |
| test_sm4_ecb_various_lengths | 不同明文长度 (1-255 字节) |
