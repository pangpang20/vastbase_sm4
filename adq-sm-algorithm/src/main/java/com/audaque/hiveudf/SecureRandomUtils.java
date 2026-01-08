package com.audaque.hiveudf;

import java.security.*;
import java.util.*;
import java.nio.*;

public class SecureRandomUtils {
    public static SecureRandom getInstance() {
        try {
            return SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static UUID randomUUID() {
        final SecureRandom secureRandom = getInstance();
        final byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        final byte[] array = randomBytes;
        final int n = 6;
        array[n] &= 0xF;
        final byte[] array2 = randomBytes;
        final int n2 = 6;
        array2[n2] |= 0x40;
        final byte[] array3 = randomBytes;
        final int n3 = 8;
        array3[n3] &= 0x3F;
        final byte[] array4 = randomBytes;
        final int n4 = 8;
        array4[n4] |= (byte) 128;
        return new UUID(ByteBuffer.wrap(randomBytes).getLong(), ByteBuffer.wrap(randomBytes, 8, 8).getLong());
    }

    public static String getSecureRandomString(final int length) {
        final SecureRandom secureRandom = getInstance();
        final int len = length / 2;
        final byte[] values = new byte[len];
        secureRandom.nextBytes(values);
        final StringBuilder sb = new StringBuilder();
        for (final byte b : values) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String randomUUIDString(final boolean upperCase, final boolean withHyphen) {
        final UUID uuid = randomUUID();
        String uuidStr = uuid.toString();
        if (upperCase) {
            uuidStr = uuidStr.toUpperCase();
        }
        if (!withHyphen) {
            uuidStr = uuidStr.replace("-", "");
        }
        return uuidStr;
    }
}
