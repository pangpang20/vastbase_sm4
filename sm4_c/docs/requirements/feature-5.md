# Feature-5: ECB 模式安全警告或禁用

## 优先级: 中

## 问题描述

ECB（电子密码本）模式是一种不安全的加密模式，相同的明文块总是产生相同的密文块，无法提供语义安全性。攻击者可以通过模式分析推断明文结构。

当前项目提供多个 ECB 模式函数：
- `sm4_encrypt` / `sm4_decrypt`（bytea 格式）
- `sm4_encrypt_hex` / `sm4_decrypt_hex`（hex 格式）

这些函数在数据库加密场景中使用，可能导致敏感数据的模式泄露。

## 影响范围

- `sm4_ext.c:91-136` — sm4_encrypt
- `sm4_ext.c:142-183` — sm4_decrypt
- `sm4_ext.c:337-385` — sm4_encrypt_hex
- `sm4_ext.c:391-449` — sm4_decrypt_hex
- `sm4--1.0.sql` 中对应的 SQL 函数定义

## 需求描述

### 方案 A：添加安全警告（推荐）
1. 在 ECB 函数执行时输出 WARNING 级别日志，提示 ECB 模式不安全
2. 在 SQL 函数注释中标注 "不推荐用于生产环境"
3. 在 README 中明确说明 ECB 模式的安全风险

### 方案 B：禁用 ECB 模式
1. 从 SQL 函数定义中移除 ECB 模式函数
2. 保留 C 代码但不暴露为 SQL 接口

## 参考代码位置

- `sm4--1.0.sql` — SQL 函数定义
- `sm4_ext.c:91-136` — sm4_encrypt 函数
- `README.md` — 使用文档

## 验收标准

1. 如果采用方案 A：ECB 函数执行时输出警告信息
2. 如果采用方案 B：ECB 函数不再通过 SQL 可调用
3. 文档中明确标注 ECB 模式的安全风险
