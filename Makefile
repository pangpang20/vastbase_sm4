# SM4 Extension Makefile for VastBase/OpenGauss
# 用法: make && make install

MODULES = sm4_ext
EXTENSION = sm4
DATA = sm4--1.0.sql
OBJS = sm4.o sm4_ext.o

# VastBase/OpenGauss 安装路径
VBHOME ?= /home/vastbase/vasthome

# pg_config 路径
PG_CONFIG = $(VBHOME)/bin/pg_config

# 获取PostgreSQL构建配置
PGXS := $(shell $(PG_CONFIG) --pgxs)

# 编译选项 (强制使用gcc)
CC = gcc
CXX = gcc
LD = gcc
override CXXFLAGS := $(filter-out -std=c++14 -std=c++11,$(CXXFLAGS))
PG_CPPFLAGS = -I$(VBHOME)/include/postgresql/server
SHLIB_LINK =

# 目标库名
MODULE_big = sm4

include $(PGXS)

# 自定义编译规则
sm4.o: sm4.c sm4.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(PG_CPPFLAGS) -fPIC -c -o $@ $<

sm4_ext.o: sm4_ext.c sm4.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(PG_CPPFLAGS) -fPIC -c -o $@ $<

# 清理
clean-local:
	rm -f *.o *.so
