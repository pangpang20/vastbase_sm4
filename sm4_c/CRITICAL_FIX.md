# 🚨 紧急修复说明 - 数据库宕机问题

## 问题描述

调用C扩展函数时，VastBase尝试初始化JVM并加载Java JAR包，导致数据库宕机：

```
NOTICE:  SM4 JVM initializing with JAR: /home/vastbase/dis-algorithm-1.0.0.0.jar
CONTEXT:  referenced column: sm4_decrypt
```

## 根本原因

VastBase中存在**同名的Java UDF函数**（如 `sm4_encrypt`, `sm4_decrypt`），数据库在调用时混淆了C扩展函数和Java UDF函数，导致：
1. C扩展函数被错误地当作Java UDF执行
2. 触发JVM初始化
3. 内存冲突导致数据库宕机

## 解决方案

### 已实施的修复

所有C扩展函数已重命名，添加 `sm4_c_` 前缀以避免冲突：

| 旧函数名          | 新函数名            |
| ----------------- | ------------------- |
| `sm4_encrypt`     | `sm4_c_encrypt`     |
| `sm4_decrypt`     | `sm4_c_decrypt`     |
| `sm4_encrypt_hex` | `sm4_c_encrypt_hex` |
| `sm4_decrypt_hex` | `sm4_c_decrypt_hex` |
| `sm4_encrypt_cbc` | `sm4_c_encrypt_cbc` |
| `sm4_decrypt_cbc` | `sm4_c_decrypt_cbc` |

## 部署步骤

### 1. 清理旧函数（重要！）

```sql
-- 连接数据库
vsql -d vastbase

-- 删除旧的冲突函数
DROP FUNCTION IF EXISTS sm4_encrypt(text, text);
DROP FUNCTION IF EXISTS sm4_decrypt(bytea, text);
DROP FUNCTION IF EXISTS sm4_encrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm4_decrypt_hex(text, text);
DROP FUNCTION IF EXISTS sm4_encrypt_cbc(text, text, text);
DROP FUNCTION IF EXISTS sm4_decrypt_cbc(bytea, text, text);
```

### 2. 重新编译安装

```bash
# 进入C扩展目录
cd /home/vastbase/vastbase_sm4/sm4_c

# 设置环境变量
export VBHOME=/home/vastbase/vasthome
export PATH=$VBHOME/bin:$PATH
export LD_LIBRARY_PATH=$VBHOME/lib:$LD_LIBRARY_PATH

# 清理并重新编译
make clean
make
make install

# 复制.so到proc_srclib目录
mkdir -p /home/vastbase/vasthome/lib/postgresql/proc_srclib
cp /home/vastbase/vasthome/lib/postgresql/sm4.so /home/vastbase/vasthome/lib/postgresql/proc_srclib/

# 重启数据库
vb_ctl restart
```

### 3. 创建新函数

```bash
# 在需要的数据库中执行
vsql -d vastbase -f /home/vastbase/vasthome/share/postgresql/extension/sm4--1.0.sql
vsql -d postgres -f /home/vastbase/vasthome/share/postgresql/extension/sm4--1.0.sql
```

### 4. 验证

```sql
-- 查看新函数
\df sm4_c*

-- 测试加解密
SELECT sm4_c_decrypt(
    sm4_c_encrypt('测试数据', '1234567890abcdef'),
    '1234567890abcdef'
);

-- 运行完整测试
vsql -d vastbase -f /home/vastbase/vastbase_sm4/sm4_c/test_sm4.sql
```

## 注意事项

### ⚠️ 重要警告

1. **函数名冲突会导致数据库宕机**：切勿在同一数据库中同时存在同名的C扩展函数和Java UDF函数
2. **必须清理旧函数**：部署前务必删除所有 `sm4_*` 函数（不带 `_c_` 前缀的）
3. **影响现有代码**：如果已有SQL代码使用了旧函数名，需要全部更新

### 函数命名规范

- **C扩展函数**: 使用 `sm4_c_*` 前缀（本项目）
- **Java UDF函数**: 使用 `sm4_*` 或其他前缀（避免 `sm4_c_`）
- **原则**: 不同语言实现的函数必须使用不同的名称

## 迁移指南

如果您已经在生产环境使用旧函数名，需要：

1. **备份数据**
2. **更新应用SQL代码**：
   ```sql
   -- 旧代码
   SELECT sm4_encrypt('data', 'key');
   
   -- 新代码
   SELECT sm4_c_encrypt('data', 'key');
   ```
3. **测试验证**
4. **部署新版本**

## 技术细节

### 为什么会宕机？

1. VastBase支持多种UDF类型（C、Java、Python等）
2. 函数调度器根据函数名和签名查找实现
3. 当存在同名函数时，可能错误地选择Java实现
4. C扩展进程试图初始化JVM会导致：
   - 内存分配冲突
   - 信号处理冲突
   - 进程崩溃

### 日志分析

如果再次遇到宕机，检查日志：

```bash
# VastBase日志位置
tail -f $VBHOME/log/postgresql-*.log

# 查找关键词
grep -i "SM4 JVM" $VBHOME/log/*.log
grep -i "crash" $VBHOME/log/*.log
```

## 联系支持

- **问题报告**: 提交Issue到项目仓库
- **紧急支持**: 联系数据库管理员
- **技术讨论**: 查看项目文档

---

**修复时间**: 2025-12-25  
**影响版本**: SM4 C Extension 1.0  
**严重程度**: 🔴 严重（导致数据库宕机）  
**状态**: ✅ 已修复
