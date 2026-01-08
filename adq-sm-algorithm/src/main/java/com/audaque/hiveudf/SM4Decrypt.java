package com.audaque.hiveudf;

import org.apache.hadoop.hive.ql.udf.generic.*;
import org.apache.hadoop.hive.serde2.objectinspector.*;
import org.apache.hadoop.hive.ql.exec.*;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.*;
import org.apache.hadoop.hive.common.type.*;
import org.apache.hadoop.io.*;
import org.apache.hadoop.hive.ql.metadata.*;

@Description(name = "sm4_decrypt", value = "SM4 Decrypt")
public class SM4Decrypt extends GenericUDF {
    private PrimitiveObjectInspector dataInspector;
    private PrimitiveObjectInspector keyInspector;

    public ObjectInspector initialize(final ObjectInspector[] arguments) throws UDFArgumentException {
        if (arguments.length != 2) {
            throw new UDFArgumentException("sm4_decrypt requires 2 parameters: encrypted data and key");
        }
        if (!(arguments[0] instanceof PrimitiveObjectInspector) || !(arguments[1] instanceof PrimitiveObjectInspector)) {
            throw new UDFArgumentException("sm4_decrypt parameters must be primitive types");
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

    public Object evaluate(final GenericUDF.DeferredObject[] arguments) throws HiveException {
        final String data = this.getStringValue(arguments[0].get(), this.dataInspector);
        final String key = this.getStringValue(arguments[1].get(), this.keyInspector);
        if (data == null || data.isEmpty() || key == null || key.isEmpty()) {
            return new Text(data);
        }
        try {
            return new Text(SM4Utils.decryptKeyBase64Value64(key, data));
        } catch (Exception e) {
            throw new HiveException("SM4 decryption failed");
        }
    }

    public String getDisplayString(final String[] children) {
        return "sm4_decrypt(" + children[0] + ", " + children[1] + ")";
    }
}
