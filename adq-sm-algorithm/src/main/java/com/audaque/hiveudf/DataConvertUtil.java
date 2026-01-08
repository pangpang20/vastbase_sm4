package com.audaque.hiveudf;

public class DataConvertUtil {
    private static final char[] DIGITS_LOWER;

    private static byte rotateLeft(final byte sourceByte, final int n) {
        final int temp = sourceByte & 0xFF;
        return (byte) (temp << n | temp >>> 8 - n);
    }

    private static byte rotateRight(final byte sourceByte, final int n) {
        final int temp = sourceByte & 0xFF;
        return (byte) (temp >>> n | temp << 8 - n);
    }

    public static byte[] rotateLeft(final byte[] sourceBytes, final int n) {
        final byte[] out = new byte[sourceBytes.length];
        for (int i = 0; i < sourceBytes.length; ++i) {
            out[i] = rotateLeft(sourceBytes[i], n);
        }
        return out;
    }

    public static byte[] rotateRight(final byte[] sourceBytes, final int n) {
        final byte[] out = new byte[sourceBytes.length];
        for (int i = 0; i < sourceBytes.length; ++i) {
            out[i] = rotateRight(sourceBytes[i], n);
        }
        return out;
    }

    public static int byteArrayToInt(final byte[] b) {
        return (b[3] & 0xFF) | (b[2] & 0xFF) << 8 | (b[1] & 0xFF) << 16 | (b[0] & 0xFF) << 24;
    }

    public static byte[] intToByteArray(final int a) {
        return new byte[]{(byte) (a >> 24 & 0xFF), (byte) (a >> 16 & 0xFF), (byte) (a >> 8 & 0xFF), (byte) (a & 0xFF)};
    }

    public static byte[] fromHexString(final String s) {
        final char[] rawChars = s.toUpperCase().toCharArray();
        int hexChars = 0;
        for (final char rawChar : rawChars) {
            if ((rawChar >= '0' && rawChar <= '9') || (rawChar >= 'A' && rawChar <= 'F')) {
                ++hexChars;
            }
        }
        final byte[] byteString = new byte[hexChars + 1 >> 1];
        int pos = hexChars & 0x1;
        for (final char rawChar2 : rawChars) {
            Label_0198:
            {
                if (rawChar2 >= '0' && rawChar2 <= '9') {
                    final byte[] array3 = byteString;
                    final int n = pos >> 1;
                    array3[n] <<= 4;
                    final byte[] array4 = byteString;
                    final int n2 = pos >> 1;
                    array4[n2] |= (byte) (rawChar2 - '0');
                } else {
                    if (rawChar2 < 'A' || rawChar2 > 'F') {
                        break Label_0198;
                    }
                    final byte[] array5 = byteString;
                    final int n3 = pos >> 1;
                    array5[n3] <<= 4;
                    final byte[] array6 = byteString;
                    final int n4 = pos >> 1;
                    array6[n4] |= (byte) (rawChar2 - 'A' + '\n');
                }
                ++pos;
            }
        }
        return byteString;
    }

    public static String toHexString(final byte[] input) {
        final StringBuilder result = new StringBuilder();
        for (final byte b : input) {
            result.append(DataConvertUtil.DIGITS_LOWER[b >>> 4 & 0xF]);
            result.append(DataConvertUtil.DIGITS_LOWER[b & 0xF]);
        }
        return result.toString();
    }

    static {
        DIGITS_LOWER = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    }
}
