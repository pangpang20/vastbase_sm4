-- SM4 Extension SQL Definitions
-- 国密SM4加解密函数定义

-- ECB模式加密 (返回bytea)
CREATE OR REPLACE FUNCTION sm4_encrypt(plaintext text, key text)
RETURNS bytea
AS '/home/vastbase/vasthome/lib/postgresql/sm4', 'sm4_encrypt'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_encrypt(text, text) IS 
'SM4 ECB模式加密。参数: plaintext-明文, key-密钥(16字节或32位十六进制)。返回二进制密文。';

-- ECB模式解密
CREATE OR REPLACE FUNCTION sm4_decrypt(ciphertext bytea, key text)
RETURNS text
AS '/home/vastbase/vasthome/lib/postgresql/sm4', 'sm4_decrypt'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_decrypt(bytea, text) IS 
'SM4 ECB模式解密。参数: ciphertext-密文(bytea), key-密钥。返回明文。';

-- CBC模式加密
CREATE OR REPLACE FUNCTION sm4_encrypt_cbc(plaintext text, key text, iv text)
RETURNS bytea
AS '/home/vastbase/vasthome/lib/postgresql/sm4', 'sm4_encrypt_cbc'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_encrypt_cbc(text, text, text) IS 
'SM4 CBC模式加密。参数: plaintext-明文, key-密钥, iv-初始向量(16字节或32位十六进制)。';

-- CBC模式解密
CREATE OR REPLACE FUNCTION sm4_decrypt_cbc(ciphertext bytea, key text, iv text)
RETURNS text
AS '/home/vastbase/vasthome/lib/postgresql/sm4', 'sm4_decrypt_cbc'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_decrypt_cbc(bytea, text, text) IS 
'SM4 CBC模式解密。参数: ciphertext-密文, key-密钥, iv-初始向量。';

-- ECB模式加密 (返回十六进制字符串)
CREATE OR REPLACE FUNCTION sm4_encrypt_hex(plaintext text, key text)
RETURNS text
AS '/home/vastbase/vasthome/lib/postgresql/sm4', 'sm4_encrypt_hex'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_encrypt_hex(text, text) IS 
'SM4 ECB模式加密，返回十六进制字符串。便于存储和传输。';

-- ECB模式解密 (输入十六进制字符串)
CREATE OR REPLACE FUNCTION sm4_decrypt_hex(ciphertext_hex text, key text)
RETURNS text
AS '/home/vastbase/vasthome/lib/postgresql/sm4', 'sm4_decrypt_hex'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_decrypt_hex(text, text) IS 
'SM4 ECB模式解密，输入为十六进制密文字符串。';
