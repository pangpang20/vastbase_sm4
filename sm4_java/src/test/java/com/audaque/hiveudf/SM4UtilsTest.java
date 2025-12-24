package com.audaque.hiveudf;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * SM4工具类单元测试
 * 
 * @author VastBase SM4 Team
 */
public class SM4UtilsTest {

    private static final String TEST_KEY = "mykey12345678901"; // 16字节
    private static final String TEST_IV = "1234567890abcdef"; // 16字节

    @Test
    public void testECBEncryptDecrypt() throws Exception {
        String plaintext = "13800138001";

        // 测试加密解密
        String encrypted = SM4Utils.encryptECBBase64(plaintext, TEST_KEY);
        assertNotNull(encrypted);
        assertFalse(encrypted.isEmpty());

        String decrypted = SM4Utils.decryptECBBase64(encrypted, TEST_KEY);
        assertEquals(plaintext, decrypted);

        System.out.println("ECB Test:");
        System.out.println("  Plaintext: " + plaintext);
        System.out.println("  Encrypted: " + encrypted);
        System.out.println("  Decrypted: " + decrypted);
    }

    @Test
    public void testCBCEncryptDecrypt() throws Exception {
        String plaintext = "110101198503151234";

        String encrypted = SM4Utils.encryptCBCBase64(plaintext, TEST_KEY, TEST_IV);
        assertNotNull(encrypted);
        assertFalse(encrypted.isEmpty());

        String decrypted = SM4Utils.decryptCBCBase64(encrypted, TEST_KEY, TEST_IV);
        assertEquals(plaintext, decrypted);

        System.out.println("\nCBC Test:");
        System.out.println("  Plaintext: " + plaintext);
        System.out.println("  Encrypted: " + encrypted);
        System.out.println("  Decrypted: " + decrypted);
    }

    @Test
    public void testHexKeySupport() throws Exception {
        String plaintext = "Test with hex key";
        String hexKey = "6d796b65793132333435363738393031"; // "mykey12345678901" in hex (32位)

        String encrypted = SM4Utils.encryptECBBase64(plaintext, hexKey);
        String decrypted = SM4Utils.decryptECBBase64(encrypted, hexKey);
        assertEquals(plaintext, decrypted);

        System.out.println("\nHex Key Test:");
        System.out.println("  Hex Key: " + hexKey);
        System.out.println("  Result: PASS");
    }

    @Test
    public void testChineseCharacters() throws Exception {
        String plaintext = "测试中文加密";

        String encrypted = SM4Utils.encryptECBBase64(plaintext, TEST_KEY);
        String decrypted = SM4Utils.decryptECBBase64(encrypted, TEST_KEY);
        assertEquals(plaintext, decrypted);

        System.out.println("\nChinese Characters Test:");
        System.out.println("  Plaintext: " + plaintext);
        System.out.println("  Decrypted: " + decrypted);
    }

    @Test
    public void testEmptyString() throws Exception {
        String plaintext = "";

        String encrypted = SM4Utils.encryptECBBase64(plaintext, TEST_KEY);
        assertEquals("", encrypted);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidKey() throws Exception {
        SM4Utils.encryptECBBase64("test", "short");
    }
}
