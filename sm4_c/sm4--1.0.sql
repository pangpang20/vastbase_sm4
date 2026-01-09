-- SM4 Extension SQL Definitions
-- 国密SM4加解密函数定义

-- ECB模式加密 (返回bytea) - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_encrypt(plaintext text, key text)
RETURNS bytea
AS 'sm4', 'sm4_encrypt'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_encrypt(text, text) IS 
'SM4 ECB模式加密(C扩展)。参数: plaintext-明文, key-密钥(16字节或32位十六进制)。返回二进制密文。';

-- ECB模式解密 - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_decrypt(ciphertext bytea, key text)
RETURNS text
AS 'sm4', 'sm4_decrypt'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_decrypt(bytea, text) IS 
'SM4 ECB模式解密(C扩展)。参数: ciphertext-密文(bytea), key-密钥。返回明文。';

-- CBC模式加密 - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_encrypt_cbc(plaintext text, key text, iv text)
RETURNS bytea
AS 'sm4', 'sm4_encrypt_cbc'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_encrypt_cbc(text, text, text) IS 
'SM4 CBC模式加密(C扩展)。参数: plaintext-明文, key-密钥, iv-初始向量(16字节或32位十六进制)。';

-- CBC模式解密 - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_decrypt_cbc(ciphertext bytea, key text, iv text)
RETURNS text
AS 'sm4', 'sm4_decrypt_cbc'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_decrypt_cbc(bytea, text, text) IS 
'SM4 CBC模式解密(C扩展)。参数: ciphertext-密文, key-密钥, iv-初始向量。';

-- ECB模式加密 (返回十六进制字符串) - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_encrypt_hex(plaintext text, key text)
RETURNS text
AS 'sm4', 'sm4_encrypt_hex'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_encrypt_hex(text, text) IS 
'SM4 ECB模式加密(C扩展)，返回十六进制字符串。便于存储和传输。';

-- ECB模式解密 (输入十六进制字符串) - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_decrypt_hex(ciphertext_hex text, key text)
RETURNS text
AS 'sm4', 'sm4_decrypt_hex'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_decrypt_hex(text, text) IS 
'SM4 ECB模式解密(C扩展)，输入为十六进制密文字符串。';

-- GCM模式加密 - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_encrypt_gcm(plaintext text, key text, iv text, aad text DEFAULT NULL)
RETURNS bytea
AS 'sm4', 'sm4_encrypt_gcm'
LANGUAGE C IMMUTABLE;

COMMENT ON FUNCTION sm4_c_encrypt_gcm(text, text, text, text) IS 
'SM4 GCM模式加密(C扩展)。参数: plaintext-明文, key-密钥(16字节或32位十六进制), iv-初始向量(12或16字节，或24/32位十六进制，推荐12字节), aad-附加认证数据(可选)。返回密文+Tag(16字节)。';

-- GCM模式解密 - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_decrypt_gcm(ciphertext_with_tag bytea, key text, iv text, aad text DEFAULT NULL)
RETURNS text
AS 'sm4', 'sm4_decrypt_gcm'
LANGUAGE C IMMUTABLE;

COMMENT ON FUNCTION sm4_c_decrypt_gcm(bytea, text, text, text) IS 
'SM4 GCM模式解密(C扩展)。参数: ciphertext_with_tag-密文+Tag, key-密钥, iv-初始向量(12或16字节，或24/32位十六进制，必须与加密时相同), aad-附加认证数据(可选)。返回明文。';

-- GCM模式加密 (Base64版本) - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_encrypt_gcm_base64(plaintext text, key text, iv text, aad text DEFAULT NULL)
RETURNS text
AS 'sm4', 'sm4_encrypt_gcm_base64'
LANGUAGE C IMMUTABLE;

COMMENT ON FUNCTION sm4_c_encrypt_gcm_base64(text, text, text, text) IS 
'SM4 GCM模式加密(C扩展)，返回Base64编码。参数: plaintext-明文, key-密钥(16字节或32位十六进制), iv-初始向量(12或16字节，或24/32位十六进制，推荐12字节), aad-附加认证数据(可选)。返回Base64编码的密文+Tag。';

-- GCM模式解密 (Base64版本) - C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_decrypt_gcm_base64(ciphertext_base64 text, key text, iv text, aad text DEFAULT NULL)
RETURNS text
AS 'sm4', 'sm4_decrypt_gcm_base64'
LANGUAGE C IMMUTABLE;

COMMENT ON FUNCTION sm4_c_decrypt_gcm_base64(text, text, text, text) IS 
'SM4 GCM模式解密(C扩展)，接收Base64编码。参数: ciphertext_base64-Base64编码的密文+Tag, key-密钥, iv-初始向量(12或16字节，或24/32位十六进制，必须与加密时相同), aad-附加认证数据(可选)。返回明文。';

-- CBC模式加密（带密钥派生）- C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_encrypt_cbc_kdf(plaintext text, password text, hash_algo text)
RETURNS bytea
AS 'sm4', 'sm4_encrypt_cbc_kdf'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_encrypt_cbc_kdf(text, text, text) IS 
'SM4 CBC模式加密(C扩展)，带密钥派生。参数: plaintext-明文, password-密码, hash_algo-哈希算法(sha256/sha384/sha512/sm3)。返回salt+密文(bytea)。使用PBKDF2派生密钥和IV，盐值随机生成。';

-- CBC模式解密（带密钥派生）- C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_decrypt_cbc_kdf(ciphertext bytea, password text, hash_algo text)
RETURNS text
AS 'sm4', 'sm4_decrypt_cbc_kdf'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_decrypt_cbc_kdf(bytea, text, text) IS 
'SM4 CBC模式解密(C扩展)，带密钥派生。参数: ciphertext-密文(包含salt+密文的bytea), password-密码, hash_algo-哈希算法(sha256/sha384/sha512/sm3)。返回明文。使用PBKDF2从密码和盐值派生密钥和IV。';

-- CBC模式加密（兼容gs_encrypt格式）- C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_encrypt_cbc_gs(plaintext text, password text, hash_algo text)
RETURNS text
AS 'sm4', 'sm4_encrypt_cbc_gs'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_encrypt_cbc_gs(text, text, text) IS 
'SM4 CBC模式加密(C扩展)，兼容gs_encrypt格式。参数: plaintext-明文, password-密码, hash_algo-哈希算法(sha256/sha384/sha512/sm3)。返回Base64编码的加密数据，格式与DWS gs_encrypt兼容。包含版本号+算法标识+盐值+密文。';

-- CBC模式解密（兼容gs_encrypt格式）- C扩展版本
CREATE OR REPLACE FUNCTION sm4_c_decrypt_cbc_gs(ciphertext text, password text, hash_algo text)
RETURNS text
AS 'sm4', 'sm4_decrypt_cbc_gs'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm4_c_decrypt_cbc_gs(text, text, text) IS 
'SM4 CBC模式解密(C扩展)，兼容gs_encrypt格式。参数: ciphertext-Base64编码的密文(gs_encrypt格式), password-密码, hash_algo-哈希算法(sha256/sha384/sha512/sm3)。返回明文。兼容DWS gs_encrypt加密的数据。';
