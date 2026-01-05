#!/bin/bash
#
# OpenSSL 3.0 一键安装脚本
# 用于 SM2 扩展编译
#
# 使用方法: sudo bash install_openssl3.sh
#

set -e  # 遇到错误立即退出

echo "=========================================="
echo "OpenSSL 3.0 一键安装脚本"
echo "=========================================="
echo ""

# 检查是否为 root 用户
if [ "$EUID" -ne 0 ]; then 
    echo "错误: 请使用 root 权限运行此脚本"
    echo "使用: sudo bash $0"
    exit 1
fi

# 配置变量
OPENSSL_VERSION="3.0.12"
# 使用多个镜像源（按优先级尝试）
OPENSSL_URLS=(
    "https://mirrors.tuna.tsinghua.edu.cn/openssl/source/openssl-${OPENSSL_VERSION}.tar.gz"
    "https://mirrors.ustc.edu.cn/openssl/source/openssl-${OPENSSL_VERSION}.tar.gz"
    "https://mirrors.aliyun.com/openssl/source/openssl-${OPENSSL_VERSION}.tar.gz"
    "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
    "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
)
INSTALL_PREFIX="/usr/local/openssl-3.0"
TEMP_DIR="/tmp/openssl-install"

echo "安装配置:"
echo "  版本: OpenSSL ${OPENSSL_VERSION}"
echo "  安装路径: ${INSTALL_PREFIX}"
echo ""

# 检查是否已安装
if [ -f "${INSTALL_PREFIX}/bin/openssl" ]; then
    EXISTING_VERSION=$(${INSTALL_PREFIX}/bin/openssl version | awk '{print $2}')
    echo "检测到已安装的 OpenSSL: ${EXISTING_VERSION}"
    read -p "是否重新安装? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "取消安装"
        exit 0
    fi
fi

# 1. 安装编译依赖
echo "[1/7] 安装编译依赖..."
yum install -y gcc make perl zlib-devel wget || {
    echo "错误: 安装依赖失败"
    exit 1
}

# 2. 创建临时目录
echo "[2/7] 准备工作目录..."
mkdir -p ${TEMP_DIR}
cd ${TEMP_DIR}

# 3. 下载 OpenSSL
echo "[3/7] 下载 OpenSSL ${OPENSSL_VERSION}..."
if [ ! -f "openssl-${OPENSSL_VERSION}.tar.gz" ]; then
    DOWNLOADED=0
    for url in "${OPENSSL_URLS[@]}"; do
        echo "尝试从: ${url}"
        if wget --timeout=30 --tries=2 "${url}" -O "openssl-${OPENSSL_VERSION}.tar.gz" 2>/dev/null; then
            DOWNLOADED=1
            echo "✓ 下载成功"
            break
        else
            echo "✗ 下载失败，尝试下一个源..."
            rm -f "openssl-${OPENSSL_VERSION}.tar.gz"
        fi
    done
    
    if [ ${DOWNLOADED} -eq 0 ]; then
        echo ""
        echo "错误: 所有下载源均失败"
        echo ""
        echo "手动下载方案:"
        echo "1. 在有网络的机器上下载:"
        echo "   wget https://mirrors.tuna.tsinghua.edu.cn/openssl/source/openssl-${OPENSSL_VERSION}.tar.gz"
        echo ""
        echo "2. 上传到服务器 ${TEMP_DIR} 目录"
        echo ""
        echo "3. 重新运行此脚本"
        exit 1
    fi
else
    echo "使用已下载的文件"
fi

# 4. 解压
echo "[4/7] 解压源码..."
tar -xzf openssl-${OPENSSL_VERSION}.tar.gz
cd openssl-${OPENSSL_VERSION}

# 5. 配置和编译
echo "[5/7] 配置编译选项..."
./config --prefix=${INSTALL_PREFIX} \
         --openssldir=${INSTALL_PREFIX} \
         shared zlib || {
    echo "错误: 配置失败"
    exit 1
}

echo "[6/7] 编译 OpenSSL (可能需要10-15分钟)..."
CPU_COUNT=$(nproc)
echo "使用 ${CPU_COUNT} 个CPU核心加速编译..."
make -j${CPU_COUNT} || {
    echo "错误: 编译失败"
    exit 1
}

# 6. 安装
echo "[7/7] 安装到 ${INSTALL_PREFIX}..."
make install || {
    echo "错误: 安装失败"
    exit 1
}

# 7. 配置动态链接库
echo ""
echo "配置动态链接库..."
LDCONF_FILE="/etc/ld.so.conf.d/openssl3.conf"
echo "${INSTALL_PREFIX}/lib64" > ${LDCONF_FILE}
ldconfig

# 8. 验证安装
echo ""
echo "验证安装..."
if [ -f "${INSTALL_PREFIX}/bin/openssl" ]; then
    VERSION=$(${INSTALL_PREFIX}/bin/openssl version)
    echo "✓ OpenSSL 安装成功: ${VERSION}"
    
    # 检查 SM2 支持
    echo ""
    echo "检查 SM2 支持..."
    if ${INSTALL_PREFIX}/bin/openssl list -public-key-algorithms | grep -qi sm2; then
        echo "✓ SM2 算法支持: 已启用"
    else
        echo "⚠ 警告: SM2 算法未检测到"
    fi
else
    echo "✗ 安装失败"
    exit 1
fi

# 9. 清理临时文件
echo ""
read -p "是否清理临时文件? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd /
    rm -rf ${TEMP_DIR}
    echo "✓ 临时文件已清理"
fi

# 10. 显示后续步骤
echo ""
echo "=========================================="
echo "安装完成!"
echo "=========================================="
echo ""
echo "OpenSSL 3.0 已安装到: ${INSTALL_PREFIX}"
echo ""
echo "下一步操作:"
echo ""
echo "1. 编译 SM2 扩展:"
echo "   cd /path/to/vastbase_sm4/sm2_c"
echo "   make clean"
echo "   make OPENSSL_HOME=${INSTALL_PREFIX}"
echo ""
echo "2. 检查编译结果:"
echo "   ldd sm2.so | grep ssl"
echo ""
echo "3. 安装扩展:"
echo "   sudo make install OPENSSL_HOME=${INSTALL_PREFIX}"
echo ""
echo "4. 在 VastBase 中加载:"
echo "   CREATE EXTENSION sm2;"
echo ""
echo "=========================================="
