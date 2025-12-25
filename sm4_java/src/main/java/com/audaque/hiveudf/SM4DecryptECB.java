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
 * SM4 ECB模式解密 Hive UDF函数
 * 
 * 用法: sm4_decrypt_ecb(ciphertext, key)
 * 参数:
 * - ciphertext: Base64编码的密文字符串
 * - key: 解密密钥（16字节字符串或32位十六进制）
 * 返回: 解密后的明文字符串
 * 
 * 示例:
 * SELECT sm4_decrypt_ecb(encrypted_phone, 'mykey12345678901') AS phone FROM
 * user_table;
 * 
 * @author VastBase SM4 Team
 */
@Description(name = "sm4_decrypt_ecb", value = "_FUNC_(ciphertext, key) - SM4 ECB mode decryption, input is Base64 encoded ciphertext", extended = "Example: SELECT sm4_decrypt_ecb(encrypted_data, 'mykey12345678901');")
public class SM4DecryptECB extends GenericUDF {

    private PrimitiveObjectInspector ciphertextInspector;
    private PrimitiveObjectInspector keyInspector;

    @Override
    public ObjectInspector initialize(ObjectInspector[] arguments) throws UDFArgumentException {
        if (arguments.length != 2) {
            throw new UDFArgumentException(
                    "sm4_decrypt_ecb requires exactly 2 parameters: ciphertext and key");
        }

        if (!(arguments[0] instanceof PrimitiveObjectInspector) ||
                !(arguments[1] instanceof PrimitiveObjectInspector)) {
            throw new UDFArgumentException(
                    "sm4_decrypt_ecb parameters must be primitive types (string/varchar)");
        }

        ciphertextInspector = (PrimitiveObjectInspector) arguments[0];
        keyInspector = (PrimitiveObjectInspector) arguments[1];

        return PrimitiveObjectInspectorFactory.writableStringObjectInspector;
    }

    @Override
    public Object evaluate(DeferredObject[] arguments) throws HiveException {
        String ciphertext = getStringValue(arguments[0].get(), ciphertextInspector);
        String key = getStringValue(arguments[1].get(), keyInspector);

        if (ciphertext == null || ciphertext.isEmpty()) {
            return new Text("");
        }

        if (key == null || key.isEmpty()) {
            throw new HiveException("SM4 decryption key cannot be null or empty");
        }

        try {
            String decrypted = SM4Utils.decryptECBBase64(ciphertext, key);
            return new Text(decrypted);
        } catch (Exception e) {
            throw new HiveException("SM4 ECB decryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public String getDisplayString(String[] children) {
        return "sm4_decrypt_ecb(" + children[0] + ", " + children[1] + ")";
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
