#!/usr/bin/env python3
"""测试 DWS PBKDF2 密钥派生"""
import hashlib
import base64
from Crypto.Cipher import SM4
from Crypto.Util.Padding import unpad

# DWS 加密的数据
ciphertext_b64 = "AwAAAAAAAACYmZIZhPO2kFzBIAyjK/I7PRTt0GkKqNzSD/6gHJDHeQ=="
password = b"1234567890123456"

# 解码 Base64
ciphertext_bin = base64.b64decode(ciphertext_b64)
print(f"Total length: {len(ciphertext_bin)} bytes")
print(f"Hex: {ciphertext_bin.hex()}")

# 解析格式
version = ciphertext_bin[0]
header = ciphertext_bin[0:8]
salt = ciphertext_bin[8:24]
encrypted = ciphertext_bin[24:]

print(f"\nVersion: {version:02x}")
print(f"Header: {header.hex()}")
print(f"Salt: {salt.hex()}")
print(f"Encrypted: {encrypted.hex()}")

# 尝试不同的迭代次数
for iterations in [1000, 2048, 4096, 8192, 10000, 16384]:
    print(f"\n=== Testing iterations={iterations} ===")
    
    # PBKDF2 派生
    derived = hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=32)
    key = derived[0:16]
    iv = derived[16:32]
    
    print(f"Key: {key.hex()}")
    print(f"IV:  {iv.hex()}")
    
    try:
        # SM4 CBC 解密
        cipher = SM4.new(key, SM4.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        # 尝试去除填充
        try:
            plaintext = unpad(decrypted, 16)
            print(f"✅ SUCCESS: {plaintext.decode('utf-8', errors='ignore')}")
        except:
            print(f"❌ Invalid padding: {decrypted.hex()}")
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
