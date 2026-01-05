# SM2 快速开始指南

基于 OpenSSL 3.0 的高性能 SM2 国密算法扩展。

## 为什么选择 OpenSSL 版本？

**性能对比**:
- 密钥生成: 纯C实现 >60秒 → OpenSSL **<5ms** (提升12000倍!)
- 加解密: 纯C实现 ~500ms → OpenSSL **<1ms** (提升500倍)

## 一键安装 OpenSSL 3.0

### 在 VastBase 服务器上操作

```bash
# 1. 进入目录
cd /path/to/vastbase_sm4/sm2_c

# 2. 运行一键安装脚本 (root 权限)
sudo bash install_openssl3.sh

# 脚本将自动完成:
# - 下载 OpenSSL 3.0.12
# - 编译安装到 /usr/local/openssl-3.0
# - 配置动态链接库
# - 验证 SM2 支持
# 全程约 10-15 分钟
```

## 编译 SM2 扩展

```bash
# 1. 进入目录
cd /path/to/vastbase_sm4/sm2_c

# 2. 清理旧文件
make clean

# 3. 编译 (指定 OpenSSL 3.0 路径)
make OPENSSL_HOME=/usr/local/openssl-3.0

# 4. 检查编译结果
ls -lh sm2.so
# 应该看到 sm2.so 文件 (约 50-100KB)

# 5. 检查动态链接
ldd sm2.so | grep ssl
# 应该能看到指向 /usr/local/openssl-3.0 的库

# 6. 安装
sudo make install OPENSSL_HOME=/usr/local/openssl-3.0
```

## 测试使用

```sql
-- 连接数据库
\c your_database

-- 加载扩展
CREATE EXTENSION sm2;

-- 测试1: 生成密钥对 (应该在毫秒级完成!)
\timing on
SELECT sm2_c_generate_key() as keypair;
\timing off

-- 测试2: 加密解密
WITH keys AS (
    SELECT 
        (sm2_c_generate_key())[1] as privkey,
        (sm2_c_generate_key())[2] as pubkey
)
SELECT 
    sm2_c_encrypt_hex('Hello SM2!', pubkey) as ciphertext,
    privkey
FROM keys;

-- 测试3: 完整流程
WITH keys AS (
    SELECT 
        (sm2_c_generate_key())[1] as privkey,
        (sm2_c_generate_key())[2] as pubkey
),
encrypted AS (
    SELECT 
        sm2_c_encrypt_hex('敏感数据123', pubkey) as cipher,
        privkey
    FROM keys
)
SELECT 
    sm2_c_decrypt_hex(cipher, privkey) as decrypted
FROM encrypted;
```

## 如果 OpenSSL 版本过低

### 方案A: 升级系统 OpenSSL (推荐)

```bash
# RHEL/CentOS 8+
sudo yum install openssl-devel

# Ubuntu 22.04+
sudo apt install libssl-dev
```

### 方案B: 编译安装 OpenSSL 3.x

```bash
# 下载
cd /tmp
wget https://www.openssl.org/source/openssl-3.0.12.tar.gz
tar -xzf openssl-3.0.12.tar.gz
cd openssl-3.0.12

# 编译 (约5-10分钟)
./config --prefix=/usr/local/openssl-3.0 \
         --openssldir=/usr/local/openssl-3.0 \
         shared zlib
make -j$(nproc)
sudo make install

# 配置动态库路径
echo "/usr/local/openssl-3.0/lib64" | sudo tee -a /etc/ld.so.conf.d/openssl3.conf
sudo ldconfig

# 修改 Makefile.openssl
# 将 OPENSSL_HOME = /usr 改为:
# OPENSSL_HOME = /usr/local/openssl-3.0

# 重新编译
cd /path/to/vastbase_sm4/sm2_c
make -f Makefile.openssl clean
make -f Makefile.openssl OPENSSL_HOME=/usr/local/openssl-3.0
```

### 方案C: 使用 GmSSL (国密专用)

```bash
# 克隆代码
cd /tmp
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL

# 编译安装
./config --prefix=/usr/local/gmssl
make -j$(nproc)
sudo make install

# 配置
echo "/usr/local/gmssl/lib" | sudo tee -a /etc/ld.so.conf.d/gmssl.conf
sudo ldconfig

# 使用 GmSSL 编译
cd /path/to/vastbase_sm4/sm2_c
make -f Makefile.openssl clean
make -f Makefile.openssl OPENSSL_HOME=/usr/local/gmssl
```

## 性能基准测试

```bash
# 在 VastBase 中运行性能测试
cat > /tmp/sm2_benchmark.sql <<'EOF'
-- 密钥生成性能 (100次)
\timing on
SELECT count(*) FROM (
    SELECT sm2_c_generate_key() 
    FROM generate_series(1, 100)
) t;
\timing off

-- 加密性能 (1000次)
WITH keys AS (
    SELECT (sm2_c_generate_key())[2] as pubkey
)
\timing on
SELECT count(*) FROM (
    SELECT sm2_c_encrypt_hex('test data', pubkey)
    FROM generate_series(1, 1000), keys
) t;
\timing off
EOF

# 运行测试
vsql -U vastbase -d postgres -f /tmp/sm2_benchmark.sql
```

**预期性能**:
- 密钥生成 100次: < 500ms (平均 <5ms/次)
- 加密 1000次: < 1秒 (平均 <1ms/次)

## 故障排查

### 问题1: 找不到 libssl.so

```bash
# 检查
ldd sm2.so

# 解决
export LD_LIBRARY_PATH=/usr/local/openssl-3.0/lib64:$LD_LIBRARY_PATH

# 或永久配置
echo "/usr/local/openssl-3.0/lib64" | sudo tee -a /etc/ld.so.conf
sudo ldconfig
```

### 问题2: 编译时找不到 openssl/evp.h

```bash
# 检查 OpenSSL 安装
pkg-config --cflags --libs openssl

# 手动指定路径
make -f Makefile.openssl OPENSSL_HOME=/usr/local/openssl-3.0
```

### 问题3: OpenSSL 不支持 SM2

```bash
# 检查 SM2 支持
openssl list -public-key-algorithms | grep -i sm2

# 如果没有输出,说明:
# 1. OpenSSL 版本 < 3.0 (需要升级)
# 2. 或使用 GmSSL
```

## 与 Java 版本对比

| 特性 | Java (BouncyCastle) | C (OpenSSL) | 胜者 |
|------|-------------------|------------|------|
| 性能 | 毫秒级 | **微秒级** | ✅ C |
| 内存占用 | ~100MB (JVM) | **<1MB** | ✅ C |
| 部署复杂度 | 中等 | 简单 | ✅ C |
| 适用场景 | Hive批处理 | 数据库实时查询 | - |

## 生产环境建议

1. **优先使用 OpenSSL 3.0+**: 官方支持,性能最优
2. **备选 GmSSL**: 国密专用,完全兼容
3. **避免纯C实现**: 仅作学习参考

## 下一步

- ✅ 完成编译和测试
- ✅ 部署到生产环境
- ✅ 与应用系统集成
- ✅ 监控性能指标

## 技术支持

遇到问题? 检查:
1. `IMPLEMENTATION_NOTES.md` - 详细技术说明
2. OpenSSL 官方文档: https://www.openssl.org/docs/
3. GmSSL 项目: https://github.com/guanzhi/GmSSL
