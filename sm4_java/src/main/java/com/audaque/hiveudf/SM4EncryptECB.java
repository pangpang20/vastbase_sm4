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
 * SM4 ECB模式加密 Hive UDF函数
 * 
 * 用法: sm4_encrypt_ecb(plaintext, key)
 * 参数:
 * - plaintext: 明文字符串
 * - key: 加密密钥（16字节字符串或32位十六进制）
 * 返回: Base64编码的密文字符串
 * 
 * 示例:
 * SELECT sm4_encrypt_ecb('13800138001', 'mykey12345678901') AS encrypted_phone;
 * 
 * @author VastBase SM4 Team
 */
@Description(name = "sm4_encrypt_ecb", value = "_FUNC_(plaintext, key) - SM4 ECB mode encryption, returns Base64 encoded ciphertext", extended = "Example: SELECT sm4_encrypt_ecb('13800138001', 'mykey12345678901');")
public class SM4EncryptECB extends GenericUDF {

    private PrimitiveObjectInspector plaintextInspector;
    private PrimitiveObjectInspector keyInspector;

    @Override
    public ObjectInspector initialize(ObjectInspector[] arguments) throws UDFArgumentException {
        // 检查参数数量
        if (arguments.length != 2) {
            throw new UDFArgumentException(
                    "sm4_encrypt_ecb requires exactly 2 parameters: plaintext and key");
        }

        // 检查参数类型
        if (!(arguments[0] instanceof PrimitiveObjectInspector) ||
                !(arguments[1] instanceof PrimitiveObjectInspector)) {
            throw new UDFArgumentException(
                    "sm4_encrypt_ecb parameters must be primitive types (string/varchar)");
        }

        plaintextInspector = (PrimitiveObjectInspector) arguments[0];
        keyInspector = (PrimitiveObjectInspector) arguments[1];

        // 返回类型为String
        return PrimitiveObjectInspectorFactory.writableStringObjectInspector;
    }

    @Override
    public Object evaluate(DeferredObject[] arguments) throws HiveException {
        // 获取参数值
        String plaintext = getStringValue(arguments[0].get(), plaintextInspector);
        String key = getStringValue(arguments[1].get(), keyInspector);

        // 处理null或空值
        if (plaintext == null || plaintext.isEmpty()) {
            return new Text("");
        }

        if (key == null || key.isEmpty()) {
            throw new HiveException("SM4 encryption key cannot be null or empty");
        }

        try {
            // 加密并返回Base64编码的结果
            String encrypted = SM4Utils.encryptECBBase64(plaintext, key);
            return new Text(encrypted);
        } catch (Exception e) {
            throw new HiveException("SM4 ECB encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public String getDisplayString(String[] children) {
        return "sm4_encrypt_ecb(" + children[0] + ", " + children[1] + ")";
    }

    /**
     * 从ObjectInspector获取字符串值
     */
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
