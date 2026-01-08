package com.audaque.hiveudf;

import org.apache.hadoop.hive.common.type.HiveVarchar;
import org.apache.hadoop.hive.ql.exec.Description;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDF;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.PrimitiveObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.StringObjectInspector;
import org.apache.hadoop.io.Text;

@Description(name = "sm2_hexdecrypt", value = "Decrypts SM2 encrypted data and returns a UTF-8 encoded string")
public class SM2HexDecrypt extends GenericUDF {
    private PrimitiveObjectInspector dataInspector;
    private PrimitiveObjectInspector keyInspector;

    @Override
    public ObjectInspector initialize(final ObjectInspector[] arguments) throws UDFArgumentException {
        if (arguments.length != 2) {
            throw new UDFArgumentException("sm2_decrypt requires 2 parameters: encrypted data and key");
        }
        if (!(arguments[0] instanceof PrimitiveObjectInspector) || !(arguments[1] instanceof PrimitiveObjectInspector)) {
            throw new UDFArgumentException("sm2_decrypt parameters must be primitive types");
        }
        this.dataInspector = (PrimitiveObjectInspector) arguments[0];
        this.keyInspector = (PrimitiveObjectInspector) arguments[1];
        return PrimitiveObjectInspectorFactory.writableStringObjectInspector;
    }

    private String getStringValue(final Object obj, final PrimitiveObjectInspector inspector) {
        if (obj == null) {
            return null;
        }
        if (inspector instanceof StringObjectInspector) {
            return ((StringObjectInspector) inspector).getPrimitiveJavaObject(obj);
        }
        final Object primitiveObj = inspector.getPrimitiveJavaObject(obj);
        if (primitiveObj instanceof HiveVarchar) {
            return ((HiveVarchar) primitiveObj).getValue();
        }
        return primitiveObj.toString();
    }

    @Override
    public Object evaluate(final DeferredObject[] arguments) throws HiveException {
        if (arguments[0] == null || arguments[1] == null) {
            return null;
        }
        final String encryptedData = this.getStringValue(arguments[0].get(), this.dataInspector);
        final String privateKeyStr = this.getStringValue(arguments[1].get(), this.keyInspector);
        if (encryptedData == null || encryptedData.isEmpty() || privateKeyStr == null || privateKeyStr.isEmpty()) {
            return null;
        }
        try {
            return new Text(SM2Utils.decryptKeyHexValueHex(privateKeyStr, encryptedData));
        } catch (Exception e) {
            throw new HiveException("SM2 decryption failed");
        }
    }

    @Override
    public String getDisplayString(final String[] children) {
        return "sm2_hexdecrypt(" + children[0] + ", " + children[1] + ")";
    }
}
