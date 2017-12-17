package org.szwj.ca.helper.utils;

import java.io.IOException;

public class Base64Util {

    /**
     * base64编码
     */
    public static String encode(byte[] sIndata) {
        return new sun.misc.BASE64Encoder().encode(sIndata);
    }

    /**
     * base64解码
     */
    public static byte[] decode(String strBase64) throws IOException {
        byte[] decodedData = null;
        sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
        decodedData = decoder.decodeBuffer(strBase64);
        return decodedData;
    }
}
