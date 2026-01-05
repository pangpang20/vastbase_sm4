# SM2 Extension Makefile for VastBase/OpenGauss

# VastBase安装路径
VBHOME ?= /home/vastbase/vasthome

# 编译器 (必须用g++)
CXX = g++
CXXFLAGS = -O2 -Wall -fPIC -std=c++11

# 包含路径
INCLUDES = -I$(VBHOME)/include/postgresql/server \
           -I$(VBHOME)/include/postgresql/internal \
           -I$(VBHOME)/include

# 目标文件
OBJS = sm2.o sm2_ext.o
TARGET = sm2.so

# 安装路径
LIBDIR = $(VBHOME)/lib/postgresql
EXTDIR = $(VBHOME)/share/postgresql/extension

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -shared -o $@ $(OBJS)

sm2.o: sm2.c sm2.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

sm2_ext.o: sm2_ext.c sm2.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

install: $(TARGET)
	cp $(TARGET) $(LIBDIR)/
	cp sm2.control $(EXTDIR)/
	cp sm2--1.0.sql $(EXTDIR)/
	@echo "安装完成!"
	@echo "请执行以下命令完成安装:"
	@echo "  1. mkdir -p $(LIBDIR)/proc_srclib"
	@echo "  2. cp $(LIBDIR)/sm2.so $(LIBDIR)/proc_srclib/"
	@echo "  3. vb_ctl restart"
	@echo "  4. vsql -d <database> -f $(EXTDIR)/sm2--1.0.sql"

uninstall:
	rm -f $(LIBDIR)/sm2.so
	rm -f $(LIBDIR)/proc_srclib/sm2.so
	rm -f $(EXTDIR)/sm2.control
	rm -f $(EXTDIR)/sm2--1.0.sql
	@echo "卸载完成!"

clean:
	rm -f $(OBJS) $(TARGET)
