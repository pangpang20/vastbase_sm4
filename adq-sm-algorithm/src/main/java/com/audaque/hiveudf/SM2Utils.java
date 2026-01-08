package com.audaque.hiveudf;

import org.bouncycastle.asn1.x9.*;
import org.bouncycastle.jce.provider.*;

import java.security.*;
import java.security.spec.*;

import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.*;
import org.bouncycastle.crypto.params.*;

import java.math.*;

import org.bouncycastle.asn1.gm.*;

public class SM2Utils {
    public static final int DEFAULT_DATA_BLOCK_SIZE = 1024;
    public static final int ENCRYPT_DATA_BLOCK_SIZE = 2242;
    private static X9ECParameters x9ECParameters;
    private static ECParameterSpec ecDomainParameters;

    public static KeyPair createECKeyPair() {
        final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            kpg.initialize(sm2Spec, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptKeyHexResultHex(final String publicKeyHex, final String data) {
        return encryptResultHex(getECPublicKeyByPublicKeyHex(publicKeyHex), data, 1);
    }

    public static String encryptResultHex(final BCECPublicKey publicKey, final String data, final int modeType) {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        final ECParameterSpec ecParameterSpec = publicKey.getParameters();
        final ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
        final ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
        final SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        byte[] arrayOfBytes = null;
        try {
            final byte[] in = data.getBytes("utf-8");
            arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
        } catch (Exception e) {
            System.out.println("SM2\u52a0\u5bc6\u65f6\u51fa\u73b0\u5f02\u5e38:" + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
        return Hex.toHexString(arrayOfBytes);
    }

    public static byte[] encryptByte(final String publicKeyHex, final byte[] data) {
        return encryptBytes(getECPublicKeyByPublicKeyHex(publicKeyHex), data, 1);
    }

    public static byte[] encryptBytes(final BCECPublicKey publicKey, final byte[] in, final int modeType) {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        final ECParameterSpec ecParameterSpec = publicKey.getParameters();
        final ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
        final ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
        final SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        byte[] arrayOfBytes = null;
        try {
            arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
            return arrayOfBytes;
        } catch (Exception e) {
            System.out.println("SM2\u52a0\u5bc6\u65f6\u51fa\u73b0\u5f02\u5e38:" + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    public static String encryptKeyHexResultBase64(final String publicKeyBase64, final String data) {
        return encryptKeyHexResultBase64(getECPublicKeyByPublicKeyHex(publicKeyBase64), data, 1);
    }

    public static String encryptKey64ResultBase64(final String publicKeyBase64, final String data) {
        return encryptKeyHexResultBase64(getECPublicKeyByPublicKeyBase64(publicKeyBase64), data, 1);
    }

    public static String encryptKeyHexResultBase64(final BCECPublicKey publicKey, final String data, final int modeType) {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        final ECParameterSpec ecParameterSpec = publicKey.getParameters();
        final ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
        final ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
        final SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        byte[] arrayOfBytes = null;
        try {
            final byte[] in = data.getBytes("utf-8");
            arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
        } catch (Exception e) {
            System.out.println("SM2\u52a0\u5bc6\u65f6\u51fa\u73b0\u5f02\u5e38:" + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
        return Base64Utils.encodeToString(arrayOfBytes);
    }

    public static String decryptKeyHexValueHex(final String privateKeyHex, final String cipherData) {
        return decryptKeyHexValueHex(getBCECPrivateKeyByPrivateKeyHex(privateKeyHex), cipherData, 1);
    }

    public static String decryptKeyHexValueHex(final BCECPrivateKey privateKey, final String cipherData, final int modeType) {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        final byte[] cipherDataByte = Hex.decode(cipherData);
        final ECParameterSpec ecParameterSpec = privateKey.getParameters();
        final ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
        final ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(), ecDomainParameters);
        final SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(false, ecPrivateKeyParameters);
        String result = null;
        try {
            final byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
            result = new String(arrayOfBytes, "utf-8");
        } catch (Exception e) {
            System.out.println("SM2\u89e3\u5bc6\u65f6\u51fa\u73b0\u5f02\u5e38" + e.getMessage());
            e.printStackTrace();
        }
        return result;
    }

    public static byte[] decryptBytesKeyHex(final String privateKeyHex, final byte[] cipherData) {
        return decryptBytesKeyHex(getBCECPrivateKeyByPrivateKeyHex(privateKeyHex), cipherData, 1);
    }

    public static byte[] decryptBytesKeyHex(final BCECPrivateKey privateKey, final byte[] cipherDataByte, final int modeType) {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        final ECParameterSpec ecParameterSpec = privateKey.getParameters();
        final ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
        final ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(), ecDomainParameters);
        final SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(false, ecPrivateKeyParameters);
        final String result = null;
        try {
            final byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
            return arrayOfBytes;
        } catch (Exception e) {
            System.out.println("SM2\u89e3\u5bc6\u65f6\u51fa\u73b0\u5f02\u5e38" + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    public static String decryptKey64ValueBase64(final String privateKeyHex, final String cipherData) {
        return decryptKeyHexValueBase64(getBCECPrivateKeyByPrivateKey64(privateKeyHex), cipherData, 1);
    }

    public static String decryptKeyHexValueBase64(final String privateKeyHex, final String cipherData) {
        return decryptKeyHexValueBase64(getBCECPrivateKeyByPrivateKeyHex(privateKeyHex), cipherData, 1);
    }

    public static String decryptKeyHexValueBase64(final BCECPrivateKey privateKey, final String cipherData, final int modeType) {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        final byte[] cipherDataByte = Base64Utils.decodeFromString(cipherData);
        final ECParameterSpec ecParameterSpec = privateKey.getParameters();
        final ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
        final ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(), ecDomainParameters);
        final SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(false, ecPrivateKeyParameters);
        String result = null;
        try {
            final byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
            result = new String(arrayOfBytes, "utf-8");
        } catch (Exception e) {
            System.out.println("SM2\u89e3\u5bc6\u65f6\u51fa\u73b0\u5f02\u5e38" + e.getMessage());
            e.printStackTrace();
        }
        return result;
    }

    public static BCECPublicKey getECPublicKeyByPublicKeyHex(String pubKeyHex) {
        if (pubKeyHex.length() > 128) {
            pubKeyHex = pubKeyHex.substring(pubKeyHex.length() - 128);
        }
        final String stringX = pubKeyHex.substring(0, 64);
        final String stringY = pubKeyHex.substring(stringX.length());
        final BigInteger x = new BigInteger(stringX, 16);
        final BigInteger y = new BigInteger(stringY, 16);
        final ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(SM2Utils.x9ECParameters.getCurve().createPoint(x, y), SM2Utils.ecDomainParameters);
        return new BCECPublicKey("EC", ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static BCECPublicKey getECPublicKeyByPublicKeyBase64(String pubKeyBase64) {
        String pubKeyHex = DataConvertUtil.toHexString(Base64Utils.decodeFromString(pubKeyBase64));
        if (pubKeyHex.length() > 128) {
            pubKeyHex = pubKeyHex.substring(pubKeyHex.length() - 128);
        }
        final String stringX = pubKeyHex.substring(0, 64);
        final String stringY = pubKeyHex.substring(stringX.length());
        final BigInteger x = new BigInteger(stringX, 16);
        final BigInteger y = new BigInteger(stringY, 16);
        final ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(SM2Utils.x9ECParameters.getCurve().createPoint(x, y), SM2Utils.ecDomainParameters);
        return new BCECPublicKey("EC", ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static BCECPrivateKey getBCECPrivateKeyByPrivateKeyHex(final String privateKeyHex) {
        final BigInteger d = new BigInteger(privateKeyHex, 16);
        final ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, SM2Utils.ecDomainParameters);
        return new BCECPrivateKey("EC", ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
    }
    public static BCECPrivateKey getBCECPrivateKeyByPrivateKey64(final String privateKey64) {
        final String privateKeyHex = DataConvertUtil.toHexString(Base64Utils.decodeFromString(privateKey64));
        final BigInteger d = new BigInteger(privateKeyHex, 16);
        final ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, SM2Utils.ecDomainParameters);
        return new BCECPrivateKey("EC", ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    static {
        SM2Utils.x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
        SM2Utils.ecDomainParameters = new ECParameterSpec(SM2Utils.x9ECParameters.getCurve(), SM2Utils.x9ECParameters.getG(), SM2Utils.x9ECParameters.getN());
    }
}
