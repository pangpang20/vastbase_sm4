#!/bin/bash
#
# OpenSSL 3.0 离线编译安装脚本
# 用于 SM2 扩展编译
#
# 使用方法: sudo bash install_openssl3.sh
# 前置条件: 请将 openssl-3.0.18.tar.gz 放置在 openssl_source 目录中
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
OPENSSL_VERSION="3.0.18"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}/openssl_source"
INSTALL_PREFIX="/usr/local/openssl-3.0"
TEMP_DIR="/tmp/openssl-install"

# 检查源码包是否存在
if [ ! -f "${SOURCE_DIR}/openssl-${OPENSSL_VERSION}.tar.gz" ]; then
    echo "错误: 未找到源码包"
    echo "请将 openssl-${OPENSSL_VERSION}.tar.gz 放置在以下目录:"
    echo "  ${SOURCE_DIR}/"
    echo ""
    echo "下载地址（选择其一）:"
    echo "  清华镜像: https://mirrors.tuna.tsinghua.edu.cn/openssl/source/openssl-${OPENSSL_VERSION}.tar.gz"
    echo "  中科大镜像: https://mirrors.ustc.edu.cn/openssl/source/openssl-${OPENSSL_VERSION}.tar.gz"
    echo "  阿里云镜像: https://mirrors.aliyun.com/openssl/source/openssl-${OPENSSL_VERSION}.tar.gz"
    exit 1
fi

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
echo "[1/6] 安装编译依赖..."
yum install -y gcc make perl zlib-devel || {
    echo "错误: 安装依赖失败"
    exit 1
}

# 2. 创建临时目录并复制源码
echo "[2/6] 准备工作目录..."
mkdir -p ${TEMP_DIR}
cd ${TEMP_DIR}

echo "从 ${SOURCE_DIR} 复制源码包..."
cp "${SOURCE_DIR}/openssl-${OPENSSL_VERSION}.tar.gz" . || {
    echo "错误: 复制源码包失败"
    exit 1
}
echo "✓ 源码包准备完成"

# 3. 解压源码
echo "[3/6] 解压源码..."

tar -xzf openssl-${OPENSSL_VERSION}.tar.gz || {
    echo "错误: 解压失败"
    exit 1
}
cd openssl-${OPENSSL_VERSION}
echo "✓ 解压完成"

# 4. 配置编译选项
echo "[4/6] 配置编译选项..."
echo "安装路径: ${INSTALL_PREFIX}"
echo "配置选项: 独立安装，不影响系统 OpenSSL"
./config --prefix=${INSTALL_PREFIX} \
         --openssldir=${INSTALL_PREFIX} \
         shared zlib \
         no-idea no-mdc2 no-rc5 || {
    echo "错误: 配置失败"
    exit 1
}
echo "✓ 配置完成"

# 5. 编译
echo "[5/6] 编译 OpenSSL (可能需要10-15分钟)..."
CPU_COUNT=$(nproc)
echo "使用 ${CPU_COUNT} 个CPU核心加速编译..."
make -j${CPU_COUNT} || {
    echo "错误: 编译失败"
    exit 1
}
echo "✓ 编译完成"

# 6. 安装
echo "[6/6] 安装到 ${INSTALL_PREFIX}..."
make install || {
    echo "错误: 安装失败"
    exit 1
}
echo "✓ 安装完成"

# 7. 配置动态链接库（独立配置，不影响系统 OpenSSL）
echo ""
echo "配置动态链接库..."
LDCONF_FILE="/etc/ld.so.conf.d/openssl3.conf"

# 只有当配置文件不存在或内容不同时才写入
if [ ! -f "${LDCONF_FILE}" ] || ! grep -q "${INSTALL_PREFIX}/lib64" "${LDCONF_FILE}"; then
    echo "${INSTALL_PREFIX}/lib64" > ${LDCONF_FILE}
    ldconfig
    echo "✓ 动态库配置完成"
else
    echo "✓ 动态库配置已存在"
fi

# 验证系统 OpenSSL 未被影响
echo ""
echo "验证系统 OpenSSL..."
SYSTEM_OPENSSL=$(which openssl)
if [ -n "${SYSTEM_OPENSSL}" ] && [ "${SYSTEM_OPENSSL}" != "${INSTALL_PREFIX}/bin/openssl" ]; then
    SYSTEM_VERSION=$(openssl version 2>/dev/null || echo "未安装")
    echo "✓ 系统 OpenSSL: ${SYSTEM_VERSION}"
    echo "✓ 系统 OpenSSL 未受影响"
fi

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
