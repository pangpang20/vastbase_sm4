# Feature-10: C 单元测试框架

## 优先级: 中

## 问题描述

当前项目只有 SQL 层面的集成测试（test_sm4.sql、test_sm4_gcm.sql），缺少 C 语言层面的单元测试。SQL 测试无法覆盖：

1. 边界条件（空输入、超大输入、非法参数）
2. 内存安全问题（缓冲区溢出、内存泄漏）
3. 错误处理路径
4. 加密算法的正确性验证

## 影响范围

- 整个项目缺乏 C 层测试
- 安全漏洞难以通过 SQL 测试发现

## 需求描述

1. 引入 C 单元测试框架（推荐 CUnit 或 Check）
2. 为每个加密/解密函数编写测试用例：
   - 正常输入测试
   - 边界条件测试（空输入、最大长度、对齐边界）
   - 错误处理测试（无效密钥长度、无效 IV、非法输入）
   - 内存安全测试（使用 AddressSanitizer）
3. 测试用例覆盖所有加密模式（ECB、CBC、GCM）
4. 集成到 Makefile 的 test 目标

## 测试用例示例

```
test_sm4_ecb_encrypt_normal()       — 正常加密
test_sm4_ecb_encrypt_empty()        — 空输入
test_sm4_ecb_encrypt_null_key()     — NULL 密钥
test_sm4_ecb_encrypt_invalid_key()  — 无效密钥长度
test_sm4_ecb_roundtrip()            — 加密后解密验证
test_sm4_gcm_large_data()           — 大数据量 GCM
test_sm4_memory_cleanup()           — 敏感数据清零验证
```

## 验收标准

1. 单元测试框架集成到构建系统
2. 测试覆盖率达到 80% 以上
3. 所有测试通过
4. AddressSanitizer 检测无内存错误
