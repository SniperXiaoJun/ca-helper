package org.szwj.ca.helper.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import sun.misc.BASE64Encoder;

public class FileUtil {

    public FileUtil() {

    }

    public static byte[] ReadFileToByteArray(File file) throws IOException {
        FileInputStream in = null;

        byte[] var3;
        try {
            if (!file.exists()) {
                throw new FileNotFoundException("File '" + file + "' does not exist");
            }

            if (file.isDirectory()) {
                throw new IOException("File '" + file + "' exists but is a directory");
            }

            if (!file.canRead()) {
                throw new IOException("File '" + file + "' cannot be read");
            }

            in = new FileInputStream(file);
            var3 = toByteArray(in, file.length());
        } finally {
            if (in != null) {
                in.close();
            }

        }

        return var3;
    }

    private static byte[] toByteArray(InputStream input, long fileSize) throws IOException {
        if (fileSize > 2147483647L) {
            throw new IllegalArgumentException(
                "Size cannot be greater than Integer max value: " + fileSize);
        } else {
            int size = (int) fileSize;
            if (size < 0) {
                throw new IllegalArgumentException(
                    "Size must be equal or greater than zero: " + size);
            } else if (size == 0) {
                return new byte[0];
            } else {
                byte[] data = new byte[size];

                int offset;
                int readed;
                for (offset = 0;
                    offset < size && (readed = input.read(data, offset, size - offset)) != -1;
                    offset += readed) {
                    ;
                }

                if (offset != size) {
                    throw new IOException(
                        "Unexpected readed size. current: " + offset + ", excepted: " + size);
                } else {
                    return data;
                }
            }
        }
    }

    public static void WriteByteArrayToFile(File file, byte[] data) throws IOException {
        FileOutputStream out = null;

        try {
            out = openOutputStream(file, false);
            out.write(data);
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }

    private static FileOutputStream openOutputStream(File file, boolean append) throws IOException {
        if (file.exists()) {
            if (file.isDirectory()) {
                throw new IOException("File '" + file + "' exists but is a directory");
            }

            if (!file.canWrite()) {
                throw new IOException("File '" + file + "' cannot be written to");
            }
        } else {
            File parent = file.getParentFile();
            if (parent != null && !parent.mkdirs() && !parent.isDirectory()) {
                throw new IOException("Directory '" + parent + "' could not be created");
            }
        }

        return new FileOutputStream(file, append);
    }

    public static String GenDigestSHA1(String decript) throws Exception {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update(decript.getBytes("UTF-8"));
            byte[] messageDigest = digest.digest();
            BASE64Encoder base64 = new BASE64Encoder();
            return base64.encode(messageDigest);
        } catch (NoSuchAlgorithmException var4) {
            var4.printStackTrace();
            return "";
        }
    }
}