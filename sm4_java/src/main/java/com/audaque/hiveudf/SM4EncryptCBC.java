package com.audaque.hiveudf;

import org.apache.hadoop.hive.ql.exec.Description;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDF;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.PrimitiveObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.StringObjectInspector;
import org.apache.hadoop.io.Text;

/**
 * SM4 CBC模式加密 Hive UDF函数
 * 
 * 用法: sm4_encrypt_cbc(plaintext, key, iv)
 * 参数:
 * - plaintext: 明文字符串
 * - key: 加密密钥（16字节字符串或32位十六进制）
 * - iv: 初始向量（16字节字符串或32位十六进制）
 * 返回: Base64编码的密文字符串
 * 
 * @author VastBase SM4 Team
 */
@Description(name = "sm4_encrypt_cbc", value = "_FUNC_(plaintext, key, iv) - SM4 CBC mode encryption", extended = "Example: SELECT sm4_encrypt_cbc('sensitive data', 'mykey1234567890', '1234567890abcdef');")
public class SM4EncryptCBC extends GenericUDF {

    private PrimitiveObjectInspector plaintextInspector;
    private PrimitiveObjectInspector keyInspector;
    private PrimitiveObjectInspector ivInspector;

    @Override
    public ObjectInspector initialize(ObjectInspector[] arguments) throws UDFArgumentException {
        if (arguments.length != 3) {
            throw new UDFArgumentException(
                    "sm4_encrypt_cbc requires exactly 3 parameters: plaintext, key, and iv");
        }

        if (!(arguments[0] instanceof PrimitiveObjectInspector) ||
                !(arguments[1] instanceof PrimitiveObjectInspector) ||
                !(arguments[2] instanceof PrimitiveObjectInspector)) {
            throw new UDFArgumentException(
                    "sm4_encrypt_cbc parameters must be primitive types");
        }

        plaintextInspector = (PrimitiveObjectInspector) arguments[0];
        keyInspector = (PrimitiveObjectInspector) arguments[1];
        ivInspector = (PrimitiveObjectInspector) arguments[2];

        return PrimitiveObjectInspectorFactory.writableStringObjectInspector;
    }

    @Override
    public Object evaluate(DeferredObject[] arguments) throws HiveException {
        String plaintext = getStringValue(arguments[0].get(), plaintextInspector);
        String key = getStringValue(arguments[1].get(), keyInspector);
        String iv = getStringValue(arguments[2].get(), ivInspector);

        if (plaintext == null || plaintext.isEmpty()) {
            return new Text("");
        }

        if (key == null || key.isEmpty()) {
            throw new HiveException("SM4 encryption key cannot be null or empty");
        }

        if (iv == null || iv.isEmpty()) {
            throw new HiveException("SM4 CBC mode requires IV (initialization vector)");
        }

        try {
            String encrypted = SM4Utils.encryptCBCBase64(plaintext, key, iv);
            return new Text(encrypted);
        } catch (Exception e) {
            throw new HiveException("SM4 CBC encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public String getDisplayString(String[] children) {
        return "sm4_encrypt_cbc(" + children[0] + ", " + children[1] + ", " + children[2] + ")";
    }

    private String getStringValue(Object obj, PrimitiveObjectInspector inspector) {
        if (obj == null) {
            return null;
        }

        if (inspector instanceof StringObjectInspector) {
            return ((StringObjectInspector) inspector).getPrimitiveJavaObject(obj);
        } else {
            Object primitiveObj = inspector.getPrimitiveJavaObject(obj);
            return primitiveObj != null ? primitiveObj.toString() : null;
        }
    }
}
