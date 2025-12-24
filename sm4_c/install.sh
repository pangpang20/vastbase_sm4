#!/bin/bash
# SM4扩展编译安装脚本
# 用法: ./install.sh

set -e

# VastBase安装路径
VBHOME=${VBHOME:-/home/vastbase/vasthome}

echo "========================================="
echo "SM4 Extension Installer for VastBase"
echo "========================================="
echo "VastBase路径: $VBHOME"
echo ""

# 检查pg_config是否存在
if [ ! -f "$VBHOME/bin/pg_config" ]; then
    echo "错误: 未找到 $VBHOME/bin/pg_config"
    echo "请设置正确的VBHOME环境变量"
    exit 1
fi

# 设置环境变量
export PATH=$VBHOME/bin:$PATH
export LD_LIBRARY_PATH=$VBHOME/lib:$LD_LIBRARY_PATH

# 获取安装目录
LIBDIR=$($VBHOME/bin/pg_config --pkglibdir)
SHAREDIR=$($VBHOME/bin/pg_config --sharedir)
EXTDIR=$SHAREDIR/extension

echo "库目录: $LIBDIR"
echo "扩展目录: $EXTDIR"
echo ""

# 编译
echo "[1/3] 编译SM4扩展..."
make clean 2>/dev/null || true
make VBHOME=$VBHOME

if [ ! -f "sm4.so" ]; then
    echo "错误: 编译失败，未生成sm4.so"
    exit 1
fi

echo "编译成功!"
echo ""

# 安装
echo "[2/3] 安装SM4扩展..."
cp sm4.so $LIBDIR/
cp sm4.control $EXTDIR/
cp sm4--1.0.sql $EXTDIR/

echo "文件已复制:"
echo "  - $LIBDIR/sm4.so"
echo "  - $EXTDIR/sm4.control"
echo "  - $EXTDIR/sm4--1.0.sql"
echo ""

# 验证安装
echo "[3/3] 验证安装..."
if [ -f "$LIBDIR/sm4.so" ] && [ -f "$EXTDIR/sm4.control" ]; then
    echo "========================================="
    echo "安装成功!"
    echo "========================================="
    echo ""
    echo "使用方法:"
    echo "  1. 连接数据库: vsql -d postgres"
    echo "  2. 创建扩展: CREATE EXTENSION sm4;"
    echo "  3. 使用函数:"
    echo "     - sm4_encrypt('明文', '密钥')"
    echo "     - sm4_decrypt(密文, '密钥')"
    echo "     - sm4_encrypt_hex('明文', '密钥')"
    echo "     - sm4_decrypt_hex('十六进制密文', '密钥')"
    echo ""
else
    echo "警告: 安装可能不完整，请检查文件权限"
    exit 1
fi
