# OpenSSL 版本不兼容问题解决方案

## ❌ 当前问题

您的系统 OpenSSL 版本: **1.1.1k** (2021年)

```
OpenSSL 1.1.1k  25 Mar 2021
```

**问题**: OpenSSL 1.1.1 不完全支持 SM2 算法的高级 API

## ✅ 解决方案

### 方案A: 升级到 OpenSSL 3.0+ (推荐)

**优点**: 
- 官方最新版本
- 性能最优
- 完整的 SM2 支持

#### 方法 1: 使用一键安装脚本 (推荐)

```bash
cd /path/to/vastbase_sm4/sm2_c
sudo bash install_openssl3.sh

# 脚本会自动尝试多个国内镜像源:
# 1. 清华大学 TUNA 镜像
# 2. 中科大 USTC 镜像
# 3. 阿里云镜像
# 4. OpenSSL 官方源
# 5. GitHub Releases
```

#### 方法 2: 手动下载安装 (网络受限时)

**步骤 1**: 在有网络的机器上下载

```bash
# 选择以下任一镜像源下载

# 清华 TUNA 镜像 (推荐)
wget https://mirrors.tuna.tsinghua.edu.cn/openssl/source/openssl-3.0.12.tar.gz

# 中科大 USTC 镜像
wget https://mirrors.ustc.edu.cn/openssl/source/openssl-3.0.12.tar.gz

# 阿里云镜像
wget https://mirrors.aliyun.com/openssl/source/openssl-3.0.12.tar.gz

# 或使用迅雷/百度网盘下载后上传
```

**步骤 2**: 上传到目标服务器

```bash
# 使用 scp 上传
scp openssl-3.0.12.tar.gz vastbase@server:/tmp/openssl-install/

# 或使用 WinSCP / FileZilla 等工具
```

**步骤 3**: 在服务器上手动安装

```bash
# 1. 安装编译依赖
sudo yum install -y gcc make perl zlib-devel

# 2. 解压
cd /tmp/openssl-install
tar -xzf openssl-3.0.12.tar.gz
cd openssl-3.0.12

# 3. 配置
./config --prefix=/usr/local/openssl-3.0 \
         --openssldir=/usr/local/openssl-3.0 \
         shared zlib

# 4. 编译 (约10分钟)
make -j$(nproc)

# 5. 安装
sudo make install

# 6. 配置动态库
echo "/usr/local/openssl-3.0/lib64" | sudo tee -a /etc/ld.so.conf.d/openssl3.conf
sudo ldconfig

# 7. 验证
/usr/local/openssl-3.0/bin/openssl version
# 应该显示: OpenSSL 3.0.12
```

# 2. 配置编译选项
./config --prefix=/usr/local/openssl-3.0 \
         --openssldir=/usr/local/openssl-3.0 \
         shared zlib

# 3. 编译 (约10分钟, 使用所有CPU核心)
make -j$(nproc)

# 4. 安装
sudo make install

# 5. 配置动态链接库路径
echo "/usr/local/openssl-3.0/lib64" | sudo tee -a /etc/ld.so.conf.d/openssl3.conf
sudo ldconfig

# 6. 验证安装
/usr/local/openssl-3.0/bin/openssl version
# 应该显示: OpenSSL 3.0.12

# 7. 检查 SM2 支持
/usr/local/openssl-3.0/bin/openssl list -public-key-algorithms | grep -i sm2
# 应该有输出

# 8. 编译 SM2 扩展
cd /path/to/vastbase_sm4/sm2_c
make clean
make OPENSSL_HOME=/usr/local/openssl-3.0

# 9. 检查编译结果
ldd sm2.so | grep ssl
# 应该看到指向 /usr/local/openssl-3.0 的库

# 10. 安装
sudo make install OPENSSL_HOME=/usr/local/openssl-3.0
```

### 方案B: 使用 GmSSL (国密专用)

**优点**:
- 国密算法专用库
- 完整的 SM2/SM3/SM4 支持
- 性能优异

**步骤**:

```bash
# 1. 安装依赖
sudo yum install -y git gcc make

# 2. 克隆 GmSSL
cd /tmp
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL

# 3. 配置和编译
./config --prefix=/usr/local/gmssl
make -j$(nproc)
sudo make install

# 4. 配置动态库
echo "/usr/local/gmssl/lib" | sudo tee -a /etc/ld.so.conf.d/gmssl.conf
sudo ldconfig

# 5. 验证
/usr/local/gmssl/bin/gmssl version

# 6. 编译 SM2 扩展
cd /path/to/vastbase_sm4/sm2_c
make clean
make OPENSSL_HOME=/usr/local/gmssl

# 7. 安装
sudo make install OPENSSL_HOME=/usr/local/gmssl
```

### 方案C: 修改 Makefile 指定路径

如果已经手动安装了 OpenSSL 3.0 或 GmSSL，修改 Makefile:

```bash
cd /path/to/vastbase_sm4/sm2_c

# 编辑 Makefile，修改这行:
# OPENSSL_HOME ?= /usr
# 改为:
# OPENSSL_HOME ?= /usr/local/openssl-3.0
# 或
# OPENSSL_HOME ?= /usr/local/gmssl

# 然后编译
make clean
make
```

## 编译测试

```bash
# 完整的编译和测试流程
cd /path/to/vastbase_sm4/sm2_c

# 1. 清理
make clean

# 2. 检查 OpenSSL
make check-openssl

# 3. 编译 (指定路径)
make OPENSSL_HOME=/usr/local/openssl-3.0

# 4. 检查动态链接
ldd sm2.so

# 5. 查看文件大小
ls -lh sm2.so

# 6. 安装
sudo make install OPENSSL_HOME=/usr/local/openssl-3.0
```

## 性能对比

| OpenSSL 版本 | SM2 支持 | 性能 |
|-------------|---------|------|
| 1.1.1k | ❌ 不完整 | - |
| 3.0.12 | ✅ 完整 | ⭐⭐⭐⭐⭐ |
| GmSSL | ✅ 专用 | ⭐⭐⭐⭐⭐ |

## 常见问题

### Q1: 编译时找不到 openssl/core_names.h

**A**: 这是 OpenSSL 3.0+ 的头文件，说明你的 OpenSSL 版本过低，需要升级。

### Q2: 运行时找不到 libssl.so.3

**A**: 需要配置动态库路径:
```bash
echo "/usr/local/openssl-3.0/lib64" | sudo tee -a /etc/ld.so.conf
sudo ldconfig
```

### Q3: 不想升级系统 OpenSSL

**A**: 可以安装到独立目录 (/usr/local/openssl-3.0)，不影响系统原有的 OpenSSL。

### Q4: 编译成功但运行时报错

**A**: 检查 VastBase 进程的 LD_LIBRARY_PATH:
```bash
# 在启动 VastBase 前设置
export LD_LIBRARY_PATH=/usr/local/openssl-3.0/lib64:$LD_LIBRARY_PATH
```

## 推荐配置

**生产环境推荐**:
1. 使用 OpenSSL 3.0.12 (官方最新稳定版)
2. 安装到 /usr/local/openssl-3.0 (不影响系统)
3. 配置 LD_LIBRARY_PATH 环境变量

**性能要求高**:
- 使用 GmSSL (国密专用优化)

## 联系支持

如果遇到其他问题，请提供:
1. OpenSSL 版本: `openssl version`
2. 编译错误信息
3. 系统版本: `cat /etc/redhat-release`
