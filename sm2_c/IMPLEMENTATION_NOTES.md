# SM2 C扩展实现说明

## 当前状态

当前纯C实现存在**性能问题**：
- 手工实现的大整数运算和椭圆曲线算法执行缓慢
- `sm2_generate_key()` 函数卡住，原因是复杂的椭圆曲线点乘运算

## 对比 Java 实现

Java版本（`adq-sm-decrypt`）使用 **BouncyCastle 库**：
```java
// 使用成熟的加密库
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
```

优势：
- 性能优化充分
- 经过安全审计
- 维护成本低

## 推荐解决方案

### 方案1：使用 GmSSL 库（推荐）

GmSSL 是支持国密算法的 OpenSSL 分支。

**安装 GmSSL：**
```bash
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL
./config --prefix=/usr/local/gmssl
make && make install
```

**修改 Makefile：**
```makefile
GMSSL_HOME = /usr/local/gmssl
INCLUDES = -I$(VBHOME)/include/postgresql/server \
           -I$(GMSSL_HOME)/include
LDFLAGS = -L$(GMSSL_HOME)/lib -lgmssl -lcrypto
```

**简化代码：**
使用 GmSSL 的 SM2 API 替代手工实现。

### 方案2：使用 OpenSSL 3.0+

OpenSSL 3.0+ 原生支持 SM2/SM3/SM4。

```bash
# 检查版本
openssl version  # 需要 >= 3.0

# 编译时链接
LDFLAGS = -lssl -lcrypto
```

### 方案3：保持当前实现但优化算法

如果必须纯C实现，需要优化：
1. 使用蒙哥马利模乘算法
2. 实现窗口法椭圆曲线点乘
3. 使用预计算表加速基点乘法

**工作量大，不推荐**。

## 当前建议

**临时方案**：
如果当前纯C实现无法快速修复，建议：
1. 使用 Java 版本（已验证可用）
2. C 版本作为未来优化目标

**长期方案**：
重构 C 扩展，基于 GmSSL 或 OpenSSL 3.0+ 实现。

## 参考资料

- GmSSL: https://github.com/guanzhi/GmSSL
- OpenSSL SM2: https://www.openssl.org/docs/man3.0/man7/SM2.html
- BouncyCastle: https://www.bouncycastle.org/
