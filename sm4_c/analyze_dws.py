#!/usr/bin/env python3
# 分析 DWS gs_encrypt 数据格式

import base64

# DWS 加密 'TESTDATA' 的结果
dws_data = 'AwAAAAAAAAD8wqc5ck20CaP2DqsR2dnbHX1WKb7MccybJySHX5yPoIRE1TNh1Fxr+RPKAbQWmvZmXbQ8mea5IDnD/zvsknoQMDzVImgtN+Lvge7uOeSvfw=='

# Base64 解码
binary = base64.b64decode(dws_data)
print(f"总长度: {len(binary)} 字节")
print(f"Hex: {binary.hex()}")
print()

# 解析结构
header = binary[0:8]
salt = binary[8:24]
remaining = binary[24:]

print(f"Header (8字节): {header.hex()}")
print(f"Salt (16字节): {salt.hex()}")
print(f"剩余 ({len(remaining)}字节): {remaining.hex()}")
print()

# 如果假设是 HMAC(32) + 密文
if len(remaining) >= 32:
    hmac = remaining[0:32]
    ciphertext = remaining[32:]
    print(f"假设 HMAC (32字节): {hmac.hex()}")
    print(f"假设密文 ({len(ciphertext)}字节): {ciphertext.hex()}")
    print()
    print(f"密文长度: {len(ciphertext)} 字节 = {len(ciphertext)//16} 个 SM4 块")
    print()

# 分析密文长度
plaintext = b'TESTDATA'  # 8字节
print(f"明文: {plaintext} ({len(plaintext)} 字节)")
print(f"如果直接加密 8字节 + PKCS7填充 → 16字节（1个块）")
print(f"但实际密文是 {len(ciphertext)} 字节 = {len(ciphertext)//16} 个块")
print(f"推测：DWS 添加了 {len(ciphertext) - 16} 字节额外数据")
print()

# 尝试不同的数据分布
print("可能的格式:")
print(f"1. header(8) + salt(16) + HMAC(32) + ciphertext({len(ciphertext)})")
print(f"2. header(8) + salt(16) + metadata + HMAC + ciphertext")
print()

# 多个示例对比
examples = [
    ('TESTDATA', 'AwAAAAAAAAD8wqc5ck20CaP2DqsR2dnbHX1WKb7MccybJySHX5yPoIRE1TNh1Fxr+RPKAbQWmvZmXbQ8mea5IDnD/zvsknoQMDzVImgtN+Lvge7uOeSvfw=='),
    ('TESTDATA', 'AwAAAAAAAAD8wqc5ck20CaP2DqsR2dnbDkf2FLipWPpGcJQ1JOAgwdmISe8JeHQ+EttycqRlhKFItvatQN9U+Q/f5NdXhk8qHleimwMbhILO3bGp24ZSug=='),
]

print("多个示例分析:")
for plaintext, b64 in examples:
    binary = base64.b64decode(b64)
    remaining = binary[24:]
    print(f"明文: {plaintext:20s} → 总长度: {len(binary):3d}, 剩余(HMAC+密文): {len(remaining):2d}")
