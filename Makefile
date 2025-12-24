# SM4 Extension Makefile for VastBase/OpenGauss
# 独立编译，不依赖PGXS

# VastBase安装路径
VBHOME ?= /home/vastbase/vasthome

# 编译器
CC = gcc
CFLAGS = -O2 -Wall -fPIC

# 包含路径
INCLUDES = -I$(VBHOME)/include/postgresql/server \
           -I$(VBHOME)/include/postgresql/internal \
           -I$(VBHOME)/include

# 目标文件
OBJS = sm4.o sm4_ext.o
TARGET = sm4.so

# 安装路径
LIBDIR = $(VBHOME)/lib/postgresql
EXTDIR = $(VBHOME)/share/postgresql/extension

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -shared -o $@ $(OBJS)

sm4.o: sm4.c sm4.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

sm4_ext.o: sm4_ext.c sm4.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

install: $(TARGET)
	cp $(TARGET) $(LIBDIR)/
	cp sm4.control $(EXTDIR)/
	cp sm4--1.0.sql $(EXTDIR)/
	@echo "安装完成!"
	@echo "  $(LIBDIR)/$(TARGET)"
	@echo "  $(EXTDIR)/sm4.control"
	@echo "  $(EXTDIR)/sm4--1.0.sql"

clean:
	rm -f $(OBJS) $(TARGET)
