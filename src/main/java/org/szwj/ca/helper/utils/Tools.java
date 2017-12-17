package org.szwj.ca.helper.utils;

/*
import org.apache.batik.transcoder.Transcoder;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.image.PNGTranscoder;

import java.io.*;
*/

/**
 * Created by maxm on 2017/6/10.
 */
public class Tools {

    /**
     * ip地址校验正则表达式
     */
    private static final String IPADDRESS_PATTERN = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";

    /**
     * 校验输入ip地址是否有效
     *
     * @param ip ip地址
     * @return 判断结果
     */
    public static boolean isIPAddressValid(String ip) {
        return ip.matches(IPADDRESS_PATTERN);
    }

    /**
     * 判断字符串是否为空
     *
     * @param string 输入字符串
     * @return 判断结果
     */
    public static boolean isStringEmpty(String string) {
        return (null == string) || (string.length() <= 0);
    }

    /**
     * 对象转数组
     * @param obj
     * @return
     */
    /*
    public static byte[] toByteArray (Object obj) {
        byte[] bytes = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(obj);
            oos.flush();
            bytes = bos.toByteArray ();
            oos.close();
            bos.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return bytes;
    }
    */

    /**
     * 数组转对象
     * @param bytes
     * @return
     */
    /*
    public static Object toObject (byte[] bytes) {
        Object obj = null;
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream (bytes);
            ObjectInputStream ois = new ObjectInputStream (bis);
            obj = ois.readObject();
            ois.close();
            bis.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        } catch (ClassNotFoundException ex) {
            ex.printStackTrace();
        }
        return obj;
    }
    */

    /*
    public static void svg2PNG(InputStream in, OutputStream out) throws IOException {
        Transcoder tr = new PNGTranscoder();
        try {
            TranscoderInput input = new TranscoderInput(in);
            try {
                TranscoderOutput output = new TranscoderOutput(out);
                tr.transcode(input, output);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                out.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            in.close();
        }
    }
    */
}
