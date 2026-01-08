package com.audaque.hiveudf;

import java.util.*;
import java.nio.charset.*;

public abstract class Base64Utils {
    private static final Charset DEFAULT_CHARSET;

    public static byte[] encode(final byte[] src) {
        return (src.length == 0) ? src : Base64.getEncoder().encode(src);
    }

    public static byte[] decode(final byte[] src) {
        return (src.length == 0) ? src : Base64.getDecoder().decode(src);
    }

    public static byte[] encodeUrlSafe(final byte[] src) {
        return (src.length == 0) ? src : Base64.getUrlEncoder().encode(src);
    }

    public static byte[] decodeUrlSafe(final byte[] src) {
        return (src.length == 0) ? src : Base64.getUrlDecoder().decode(src);
    }

    public static String encodeToString(final byte[] src) {
        return (src.length == 0) ? "" : new String(encode(src), Base64Utils.DEFAULT_CHARSET);
    }

    public static byte[] decodeFromString(final String src) {
        return src.isEmpty() ? new byte[0] : decode(src.getBytes(Base64Utils.DEFAULT_CHARSET));
    }

    public static String encodeToUrlSafeString(final byte[] src) {
        return new String(encodeUrlSafe(src), Base64Utils.DEFAULT_CHARSET);
    }

    public static byte[] decodeFromUrlSafeString(final String src) {
        return decodeUrlSafe(src.getBytes(Base64Utils.DEFAULT_CHARSET));
    }

    static {
        DEFAULT_CHARSET = StandardCharsets.UTF_8;
    }
}
