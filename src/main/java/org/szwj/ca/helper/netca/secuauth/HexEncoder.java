package org.szwj.ca.helper.netca.secuauth;

public class HexEncoder {

    private static final byte[] hexTable =
        {
            (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6',
            (byte) '7',
            (byte) '8', (byte) '9', (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e',
            (byte) 'f'
        };

    public static String encode(byte[] bData) {
        byte[] bStr = new byte[bData.length * 2];
        for (int i = 0; i < bData.length; i++) {
            bStr[i * 2] = hexTable[(bData[i] >>> 4) & 0x0f];
            bStr[i * 2 + 1] = hexTable[bData[i] & 0x0f];
        }

        return new String(bStr);
    }

    public static byte[] decode(String strHex) {
        strHex = strHex.replaceAll("\\s", "");    //去除所有空格 "[ \t\n\x0B\f\r]"
        byte bytes[] = new byte[strHex.length() / 2];
        strHex = strHex.toLowerCase();
        for (int i = 0; i < strHex.length(); i += 2) {
            char left = strHex.charAt(i);
            char right = strHex.charAt(i + 1);
            int index = i / 2;
            if (left < 'a') {
                bytes[index] = (byte) (left - 48 << 4);
            } else {
                bytes[index] = (byte) ((left - 97) + 10 << 4);
            }
            if (right < 'a') {
                bytes[index] += (byte) (right - 48);
            } else {
                bytes[index] += (byte) ((right - 97) + 10);
            }
        }

        return bytes;
    }
}

