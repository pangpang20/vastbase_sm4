package com.audaque.hiveudf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

/**
 * SM4国密加解密工具类
 * 支持ECB和CBC模式，与VastBase数据库SM4扩展完全兼容
 * 
 * @author VastBase SM4 Team
 * @version 1.0.0
 * @date 2024-12-24
 */
public class SM4Utils {

    static {
        // 添加BouncyCastle安全提供者
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String ALGORITHM_NAME = "SM4";

    // ECB模式 - 与数据库sm4_encrypt/sm4_decrypt函数对应
    private static final String ALGORITHM_ECB = "SM4/ECB/PKCS7Padding";

    // CBC模式 - 与数据库sm4_encrypt_cbc/sm4_decrypt_cbc函数对应
    private static final String ALGORITHM_CBC = "SM4/CBC/PKCS7Padding";

    /**
     * 将十六进制字符串转换为字节数组
     */
    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int index = i * 2;
            bytes[i] = (byte) Integer.parseInt(hexString.substring(index, index + 2), 16);
        }
        return bytes;
    }

    /**
     * 将字节数组转换为十六进制字符串
     */
    public static String bytesToHexString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 处理密钥：支持16字节字符串或32位十六进制字符串
     */
    public static byte[] processKey(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        // 如果是32位十六进制字符串
        if (key.length() == 32 && key.matches("[0-9a-fA-F]+")) {
            return hexStringToBytes(key);
        }

        // 如果是16字节的普通字符串
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes or 32-char hex string, got: " + keyBytes.length);
        }

        return keyBytes;
    }

    // ==================== ECB模式 ====================

    /**
     * ECB模式加密（返回字节数组）
     * 
     * @param plaintext 明文字符串
     * @param key       密钥（16字节字符串或32位十六进制）
     * @return 加密后的字节数组
     */
    public static byte[] encryptECB(String plaintext, String key) throws Exception {
        if (plaintext == null || plaintext.isEmpty()) {
            return new byte[0];
        }

        byte[] keyBytes = processKey(key);
        byte[] inputBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance(ALGORITHM_ECB, BouncyCastleProvider.PROVIDER_NAME);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        return cipher.doFinal(inputBytes);
    }

    /**
     * ECB模式解密（输入字节数组）
     * 
     * @param ciphertext 密文字节数组
     * @param key        密钥
     * @return 解密后的明文字符串
     */
    public static String decryptECB(byte[] ciphertext, String key) throws Exception {
        if (ciphertext == null || ciphertext.length == 0) {
            return "";
        }

        byte[] keyBytes = processKey(key);

        Cipher cipher = Cipher.getInstance(ALGORITHM_ECB, BouncyCastleProvider.PROVIDER_NAME);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM_NAME);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * ECB模式加密（返回十六进制字符串）
     */
    public static String encryptECBHex(String plaintext, String key) throws Exception {
        byte[] cipherBytes = encryptECB(plaintext, key);
        return bytesToHexString(cipherBytes);
    }

    /**
     * ECB模式解密（输入十六进制字符串）
     */
    public static String decryptECBHex(String ciphertextHex, String key) throws Exception {
        if (ciphertextHex == null || ciphertextHex.isEmpty()) {
            return "";
        }
        byte[] cipherBytes = hexStringToBytes(ciphertextHex);
        return decryptECB(cipherBytes, key);
    }

    /**
     * ECB模式加密（返回Base64字符串）
     */
    public static String encryptECBBase64(String plaintext, String key) throws Exception {
        byte[] cipherBytes = encryptECB(plaintext, key);
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    /**
     * ECB模式解密（输入Base64字符串）
     */
    public static String decryptECBBase64(String ciphertextBase64, String key) throws Exception {
        if (ciphertextBase64 == null || ciphertextBase64.isEmpty()) {
            return "";
        }
        byte[] cipherBytes = Base64.getDecoder().decode(ciphertextBase64);
        return decryptECB(cipherBytes, key);
    }

    // ==================== CBC模式 ====================

    /**
     * CBC模式加密（返回字节数组）
     * 
     * @param plaintext 明文字符串
     * @param key       密钥
     * @param iv        初始向量（16字节字符串或32位十六进制）
     * @return 加密后的字节数组
     */
    public static byte[] encryptCBC(String plaintext, String key, String iv) throws Exception {
        if (plaintext == null || plaintext.isEmpty()) {
            return new byte[0];
        }

        byte[] keyBytes = processKey(key);
        byte[] ivBytes = processKey(iv);
        byte[] inputBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance(ALGORITHM_CBC, BouncyCastleProvider.PROVIDER_NAME);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM_NAME);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(inputBytes);
    }

    /**
     * CBC模式解密（输入字节数组）
     * 
     * @param ciphertext 密文字节数组
     * @param key        密钥
     * @param iv         初始向量
     * @return 解密后的明文字符串
     */
    public static String decryptCBC(byte[] ciphertext, String key, String iv) throws Exception {
        if (ciphertext == null || ciphertext.length == 0) {
            return "";
        }

        byte[] keyBytes = processKey(key);
        byte[] ivBytes = processKey(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM_CBC, BouncyCastleProvider.PROVIDER_NAME);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM_NAME);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * CBC模式加密（返回十六进制字符串）
     */
    public static String encryptCBCHex(String plaintext, String key, String iv) throws Exception {
        byte[] cipherBytes = encryptCBC(plaintext, key, iv);
        return bytesToHexString(cipherBytes);
    }

    /**
     * CBC模式解密（输入十六进制字符串）
     */
    public static String decryptCBCHex(String ciphertextHex, String key, String iv) throws Exception {
        if (ciphertextHex == null || ciphertextHex.isEmpty()) {
            return "";
        }
        byte[] cipherBytes = hexStringToBytes(ciphertextHex);
        return decryptCBC(cipherBytes, key, iv);
    }

    /**
     * CBC模式加密（返回Base64字符串）
     */
    public static String encryptCBCBase64(String plaintext, String key, String iv) throws Exception {
        byte[] cipherBytes = encryptCBC(plaintext, key, iv);
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    /**
     * CBC模式解密（输入Base64字符串）
     */
    public static String decryptCBCBase64(String ciphertextBase64, String key, String iv) throws Exception {
        if (ciphertextBase64 == null || ciphertextBase64.isEmpty()) {
            return "";
        }
        byte[] cipherBytes = Base64.getDecoder().decode(ciphertextBase64);
        return decryptCBC(cipherBytes, key, iv);
    }
}
