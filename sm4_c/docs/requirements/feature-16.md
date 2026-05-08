# Feature-16: Feature-1 NULL 处理描述修正

## 优先级: 低

## 状态: 已完成

## 问题描述

Feature-1 描述中提到"NULL 值传入时可能触发空指针异常"，但实际上 `sm4--1.0.sql` 中所有函数均声明为 `STRICT`（或 PostgreSQL 默认行为），PostgreSQL/VastBase 在参数为 NULL 时会自动返回 NULL，不会调用 C 函数。

因此 Feature-1 的核心问题应聚焦于：
1. 空字符串("")输入的处理（当前会产生无意义的 PKCS7 填充密文）
2. C 层作为安全兜底的 NULL 指针检查（防御性编程）

## 已完成修改

- Feature-1.md 描述已修正，明确 STRICT 属性处理 NULL，核心问题是空字符串
- 验收标准已更新，区分 STRICT 自动处理和 C 层手动检查
