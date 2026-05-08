# Feature-16: Feature-1 NULL 处理描述修正

## 优先级: 低

## 问题描述

Feature-1 描述中提到"NULL 值传入时可能触发空指针异常"，但实际上 `sm4--1.0.sql` 中所有函数均声明为 `STRICT`（或 PostgreSQL 默认行为），PostgreSQL/VastBase 在参数为 NULL 时会自动返回 NULL，不会调用 C 函数。

因此 Feature-1 的核心问题应聚焦于：
1. 空字符串("")输入的处理（当前会产生无意义的 PKCS7 填充密文）
2. C 层作为安全兜底的 NULL 指针检查（防御性编程）

## 需求描述

修正 Feature-1 的问题描述，明确：
1. SQL 层的 `STRICT` 属性已处理 NULL 输入，无需额外代码
2. 真正需要修复的是空字符串("")的处理
3. C 层的 NULL 检查是防御性编程，非主要功能需求

## 验收标准

1. Feature-1 描述准确反映实际问题
2. 不重复已由 `STRICT` 属性解决的问题
