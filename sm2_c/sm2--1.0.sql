-- SM2 Extension SQL Definitions
-- 国密SM2椭圆曲线公钥密码算法函数定义

-- ========================================
-- 密钥生成与管理
-- ========================================

-- 生成SM2密钥对 (返回数组: [私钥hex, 公钥hex])
CREATE OR REPLACE FUNCTION sm2_c_generate_key()
RETURNS text[]
AS 'sm2', 'sm2_generate_key'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION sm2_c_generate_key() IS 
'生成SM2密钥对(C扩展)。返回text数组: [私钥hex(64字符), 公钥hex(128字符)]。';

-- 从私钥导出公钥
CREATE OR REPLACE FUNCTION sm2_c_get_pubkey(private_key text)
RETURNS text
AS 'sm2', 'sm2_get_pubkey'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm2_c_get_pubkey(text) IS 
'从SM2私钥导出公钥(C扩展)。参数: private_key-私钥(32字节或64位十六进制)。返回公钥hex(128字符)。';

-- ========================================
-- 加密解密函数
-- ========================================

-- SM2公钥加密 (返回bytea)
CREATE OR REPLACE FUNCTION sm2_c_encrypt(plaintext text, public_key text)
RETURNS bytea
AS 'sm2', 'sm2_encrypt_func'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm2_c_encrypt(text, text) IS 
'SM2公钥加密(C扩展)。参数: plaintext-明文, public_key-公钥(64字节或128位十六进制)。返回bytea格式密文。密文格式: C1(65字节) || C3(32字节) || C2(明文长度)。';

-- SM2私钥解密 (输入bytea)
CREATE OR REPLACE FUNCTION sm2_c_decrypt(ciphertext bytea, private_key text)
RETURNS text
AS 'sm2', 'sm2_decrypt_func'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm2_c_decrypt(bytea, text) IS 
'SM2私钥解密(C扩展)。参数: ciphertext-密文(bytea), private_key-私钥(32字节或64位十六进制)。返回明文。';

-- SM2公钥加密 (返回十六进制)
CREATE OR REPLACE FUNCTION sm2_c_encrypt_hex(plaintext text, public_key text)
RETURNS text
AS 'sm2', 'sm2_encrypt_hex'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm2_c_encrypt_hex(text, text) IS 
'SM2公钥加密(C扩展)，返回十六进制密文字符串。便于存储和传输。';

-- SM2私钥解密 (输入十六进制)
CREATE OR REPLACE FUNCTION sm2_c_decrypt_hex(ciphertext_hex text, private_key text)
RETURNS text
AS 'sm2', 'sm2_decrypt_hex'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm2_c_decrypt_hex(text, text) IS 
'SM2私钥解密(C扩展)，输入为十六进制密文字符串。';

-- SM2公钥加密 (返回Base64)
CREATE OR REPLACE FUNCTION sm2_c_encrypt_base64(plaintext text, public_key text)
RETURNS text
AS 'sm2', 'sm2_encrypt_base64'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm2_c_encrypt_base64(text, text) IS 
'SM2公钥加密(C扩展)，返回Base64编码密文。便于JSON传输和跨平台兼容。';

-- SM2私钥解密 (输入Base64)
CREATE OR REPLACE FUNCTION sm2_c_decrypt_base64(ciphertext_base64 text, private_key text)
RETURNS text
AS 'sm2', 'sm2_decrypt_base64'
LANGUAGE C STRICT IMMUTABLE;

COMMENT ON FUNCTION sm2_c_decrypt_base64(text, text) IS 
'SM2私钥解密(C扩展)，输入为Base64编码密文。';

-- ========================================
-- 数字签名函数
-- ========================================

-- SM2签名 (返回bytea)
CREATE OR REPLACE FUNCTION sm2_c_sign(message text, private_key text, id text DEFAULT NULL)
RETURNS bytea
AS 'sm2', 'sm2_sign_func'
LANGUAGE C IMMUTABLE;

COMMENT ON FUNCTION sm2_c_sign(text, text, text) IS 
'SM2数字签名(C扩展)。参数: message-待签名消息, private_key-私钥, id-用户标识(可选，默认"1234567812345678")。返回64字节签名(r || s)。';

-- SM2验签
CREATE OR REPLACE FUNCTION sm2_c_verify(message text, public_key text, signature bytea, id text DEFAULT NULL)
RETURNS boolean
AS 'sm2', 'sm2_verify_func'
LANGUAGE C IMMUTABLE;

COMMENT ON FUNCTION sm2_c_verify(text, text, bytea, text) IS 
'SM2签名验证(C扩展)。参数: message-原始消息, public_key-公钥, signature-签名(64字节), id-用户标识(可选)。返回验证结果。';

-- SM2签名 (返回十六进制)
CREATE OR REPLACE FUNCTION sm2_c_sign_hex(message text, private_key text, id text DEFAULT NULL)
RETURNS text
AS 'sm2', 'sm2_sign_hex'
LANGUAGE C IMMUTABLE;

COMMENT ON FUNCTION sm2_c_sign_hex(text, text, text) IS 
'SM2数字签名(C扩展)，返回十六进制签名字符串(128字符)。';

-- SM2验签 (输入十六进制签名)
CREATE OR REPLACE FUNCTION sm2_c_verify_hex(message text, public_key text, signature_hex text, id text DEFAULT NULL)
RETURNS boolean
AS 'sm2', 'sm2_verify_hex'
LANGUAGE C IMMUTABLE;

COMMENT ON FUNCTION sm2_c_verify_hex(text, text, text, text) IS 
'SM2签名验证(C扩展)，输入十六进制签名字符串。';
