package com.audaque.hiveudf;

import java.nio.charset.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;

import org.bouncycastle.jce.provider.*;

import java.security.*;

public class SM4Utils {
    private static final String ALGORITHM_NAME = "SM4";
    private static final String ALGORITHM_NAME_GCM_PADDING = "SM4/GCM/NoPadding";
    private static final int DEFAULT_KEY_SIZE = 128;
    public static final int DEFAULT_DATA_BLOCK_SIZE = 1024;
    public static final int ENCRYPT_DATA_BLOCK_SIZE = 2080;

    public static byte[] generateKey() throws Exception {
        return generateKey(128);
    }

    private static byte[] generateKey(final int keySize) throws Exception {
        final KeyGenerator kg = KeyGenerator.getInstance("SM4", "BC");
        final SecureRandom random = SecureRandomUtils.getInstance();
        kg.init(keySize, random);
        return kg.generateKey().getEncoded();
    }

    public static String encryptGcmKeyHexResultHex(final String hexKey, final String paramStr) throws Exception {
        final byte[] keyData = DataConvertUtil.fromHexString(hexKey);
        final byte[] srcData = paramStr.getBytes(StandardCharsets.UTF_8);
        final byte[] cipherArray = encrypt_Gcm_Padding(keyData, srcData);
        final String cipherText = DataConvertUtil.toHexString(cipherArray);
        return cipherText;
    }

    public static byte[] encryptGcmKeyHex(final String hexKey, final byte[] srcData) throws Exception {
        final byte[] keyData = DataConvertUtil.fromHexString(hexKey);
        return encrypt_Gcm_Padding(keyData, srcData);
    }

    public static String encryptKey64Result64(final String base64Key, final String paramStr) throws Exception {
        final byte[] keyData = Base64Utils.decodeFromString(base64Key);
        final byte[] srcData = paramStr.getBytes(StandardCharsets.UTF_8);
        final byte[] cipherArray = encrypt_Gcm_Padding(keyData, srcData);
        final String cipherText = Base64Utils.encodeToString(cipherArray);
        return cipherText;
    }

    private static byte[] encrypt_Gcm_Padding(final byte[] key, final byte[] data) throws Exception {
        final Cipher cipher = generateCbcCipher("SM4/GCM/NoPadding", 1, key);
        return cipher.doFinal(data);
    }

    public static String decryptGcmKeyHexValueHex(final String hexKey, final String cipherText) throws Exception {
        final byte[] keyData = DataConvertUtil.fromHexString(hexKey);
        final byte[] cipherData = DataConvertUtil.fromHexString(cipherText);
        final byte[] srcData = decrypt_Gcm_Padding(keyData, cipherData);
        final String decryptStr = new String(srcData, StandardCharsets.UTF_8);
        return decryptStr;
    }

    public static String decryptKeyBase64Value64(final String base64Key, final String cipherText) throws Exception {
        final byte[] keyData = Base64Utils.decodeFromString(base64Key);
        final byte[] cipherData = Base64Utils.decodeFromString(cipherText);
        final byte[] srcData = decrypt_Gcm_Padding(keyData, cipherData);
        final String decryptStr = new String(srcData, StandardCharsets.UTF_8);
        return decryptStr;
    }

    public static byte[] decryptKeyHex(final String hexKey, final byte[] cipherData) throws Exception {
        final byte[] keyData = DataConvertUtil.fromHexString(hexKey);
        return decrypt_Gcm_Padding(keyData, cipherData);
    }

    private static byte[] decrypt_Gcm_Padding(final byte[] key, final byte[] cipherText) throws Exception {
        final Cipher cipher = generateCbcCipher("SM4/GCM/NoPadding", 2, key);
        return cipher.doFinal(cipherText);
    }

    private static Cipher generateCbcCipher(final String algorithmName, final int mode, final byte[] key) throws Exception {
        final Cipher cipher = Cipher.getInstance(algorithmName, "BC");
        final Key sm4Key = new SecretKeySpec(key, "SM4");
        cipher.init(mode, sm4Key, generateIV(key));
        return cipher;
    }

    private static AlgorithmParameters generateIV(final byte[] key) throws Exception {
        final AlgorithmParameters params = AlgorithmParameters.getInstance("SM4");
        params.init(new IvParameterSpec(key));
        return params;
    }

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.addProvider(new BouncyCastleProvider());
    }
}
