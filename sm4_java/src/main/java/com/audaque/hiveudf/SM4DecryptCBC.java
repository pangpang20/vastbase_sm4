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
 * SM4 CBC模式解密 Hive UDF函数
 * 
 * 用法: sm4_decrypt_cbc(ciphertext, key, iv)
 * 
 * @author VastBase SM4 Team
 */
@Description(name = "sm4_decrypt_cbc", value = "_FUNC_(ciphertext, key, iv) - SM4 CBC mode decryption", extended = "Example: SELECT sm4_decrypt_cbc(encrypted_data, 'mykey1234567890', '1234567890abcdef');")
public class SM4DecryptCBC extends GenericUDF {

    private PrimitiveObjectInspector ciphertextInspector;
    private PrimitiveObjectInspector keyInspector;
    private PrimitiveObjectInspector ivInspector;

    @Override
    public ObjectInspector initialize(ObjectInspector[] arguments) throws UDFArgumentException {
        if (arguments.length != 3) {
            throw new UDFArgumentException(
                    "sm4_decrypt_cbc requires exactly 3 parameters: ciphertext, key, and iv");
        }

        if (!(arguments[0] instanceof PrimitiveObjectInspector) ||
                !(arguments[1] instanceof PrimitiveObjectInspector) ||
                !(arguments[2] instanceof PrimitiveObjectInspector)) {
            throw new UDFArgumentException(
                    "sm4_decrypt_cbc parameters must be primitive types");
        }

        ciphertextInspector = (PrimitiveObjectInspector) arguments[0];
        keyInspector = (PrimitiveObjectInspector) arguments[1];
        ivInspector = (PrimitiveObjectInspector) arguments[2];

        return PrimitiveObjectInspectorFactory.writableStringObjectInspector;
    }

    @Override
    public Object evaluate(DeferredObject[] arguments) throws HiveException {
        String ciphertext = getStringValue(arguments[0].get(), ciphertextInspector);
        String key = getStringValue(arguments[1].get(), keyInspector);
        String iv = getStringValue(arguments[2].get(), ivInspector);

        if (ciphertext == null || ciphertext.isEmpty()) {
            return new Text("");
        }

        if (key == null || key.isEmpty()) {
            throw new HiveException("SM4 decryption key cannot be null or empty");
        }

        if (iv == null || iv.isEmpty()) {
            throw new HiveException("SM4 CBC mode requires IV (initialization vector)");
        }

        try {
            String decrypted = SM4Utils.decryptCBCBase64(ciphertext, key, iv);
            return new Text(decrypted);
        } catch (Exception e) {
            throw new HiveException("SM4 CBC decryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public String getDisplayString(String[] children) {
        return "sm4_decrypt_cbc(" + children[0] + ", " + children[1] + ", " + children[2] + ")";
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
