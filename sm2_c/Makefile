# SM2 Extension Makefile for VastBase/OpenGauss
# 基于 OpenSSL 高性能实现

# VastBase安装路径
VBHOME ?= /home/vastbase/vasthome

# OpenSSL路径 (根据系统调整)
# 方式1: 系统OpenSSL 3.0+ (推荐)
OPENSSL_HOME ?= /usr

# 方式2: 自定义OpenSSL
# OPENSSL_HOME ?= /usr/local/openssl

# 编译器
CXX = g++
CXXFLAGS = -O3 -Wall -fPIC -std=c++11 -march=native

# 包含路径
INCLUDES = -I$(VBHOME)/include/postgresql/server \
           -I$(VBHOME)/include/postgresql/internal \
           -I$(VBHOME)/include \
           -I$(OPENSSL_HOME)/include

# 链接库
LDFLAGS = -L$(OPENSSL_HOME)/lib64 -L$(OPENSSL_HOME)/lib \
          -lssl -lcrypto -lpthread

# 目标文件
OBJS = sm2_openssl.o sm2_ext_openssl.o
TARGET = sm2.so

# 安装路径
LIBDIR = $(VBHOME)/lib/postgresql
EXTDIR = $(VBHOME)/share/postgresql/extension

.PHONY: all clean install test check-openssl

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -shared -o $@ $(OBJS) $(LDFLAGS)

sm2_openssl.o: sm2_openssl.c sm2_openssl.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

sm2_ext_openssl.o: sm2_ext_openssl.c sm2_openssl.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

install: $(TARGET)
	cp $(TARGET) $(LIBDIR)/
	cp sm2.control $(EXTDIR)/
	cp sm2--1.0.sql $(EXTDIR)/
	@echo "安装完成! OpenSSL 高性能版本"
	@echo "请确保 OpenSSL 版本 >= 3.0 或使用 GmSSL"

clean:
	rm -f $(OBJS) $(TARGET)

# 检查OpenSSL版本
check-openssl:
	@echo "检查 OpenSSL 版本..."
	@openssl version || echo "OpenSSL 未找到"
	@echo "SM2 支持需要 OpenSSL >= 3.0 或 GmSSL"

# 性能测试
test: $(TARGET)
	@echo "编译成功! 文件大小:"
	@ls -lh $(TARGET)
	@echo ""
	@echo "性能优化:"
	@echo "- 使用 -O3 优化"
	@echo "- 使用 -march=native CPU指令优化"
	@echo "- OpenSSL 硬件加速支持"
