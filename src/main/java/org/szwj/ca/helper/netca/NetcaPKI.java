package org.szwj.ca.helper.netca;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import net.netca.asn1.ASN1InputStream;
import net.netca.asn1.DERObjectIdentifier;
import net.netca.asn1.DEROctetString;
import net.netca.asn1.DERSequence;
import net.netca.pki.Base64;
import net.netca.pki.CertStore;
import net.netca.pki.Certificate;
import net.netca.pki.Cipher;
import net.netca.pki.Device;
import net.netca.pki.DeviceSet;
import net.netca.pki.EnvelopedData;
import net.netca.pki.KeyPair;
import net.netca.pki.PkiException;
import net.netca.pki.Signature;
import net.netca.pki.SignedData;
import net.netca.pki.Util;
import net.netca.util.encoders.Hex;

public class NetcaPKI {

    /**
     * 证书信息域常量解析
     */
    public static String[] CERTVALUEPARSE = {"0:证书PEM编码", "1:姆印", "2:序列号",
        "3:主题", "4:颁发者", "5:有效期开始时间", "6:有效期截止时间",
        "7:密钥用法",
        "8:证书公钥算法",
        "9:用户证书绑定值",
        "10:旧证书用户证书绑定值", // 1-10

        "11:主体名", "12:人名CN", "13:单位O", "14:地址L", "15:EmailAddress",
        "16:部门OU", "17:国家C", "18:省ST",
        "",
        "", // 11-20
        "21:CAID", "22:证书类型", "23:证书客服号", "", "", "", "", "",
        "",
        "", // 21-30
        "31:旧姆印", "32:纳税人编码", "33:企业法人代码", "34:税务登记号", "35:证书来源地",
        "36:证件号码信息扩展域值", "37:明文证件号码", "", "",
        "", // 31-40
        "", "", "", "", "", "", "", "", "",
        "", // 41-50
        "51:GDCA TrustID[1.2.86.21.1.3]",
        "52:GDCA TrustID2[1.2.86.21.1.1]", "", "", "", "", "", "", "", "" // 51

    };
    private static final String BYTE_CODE = "UTF8";
    public static String NETCAPKI_SUPPORTCA = "NETCA;GDCA";
    public static int INCLUDE_CERT_OPTION = SignedData.INCLUDE_CERT_OPTION_SELF;
    public static int NETCAPKI_ALGORITHM_HASH = 8192; // 默认哈希算法:SHA1
    public static int NETCAPKI_ALGORITHM_RSASIGN = Signature.SHA1WITHRSA;// SignedData.NETCAPKI_ALGORITHM_SHA1WITHRSA;//RSA签名算法
    public static int NETCAPKI_ALGORITHM_SM2SIGN = Signature.SM3WITHSM2;// SM2签名算法

    /**
     * ======================================================== 0 全局变量 [根据项目实际应用定制,特别注意1~4项修订]
     * ========================================================
     */
    // 定制1：字符串编码方式，特定项目需定制
    // 早期案例编码方式为：NETCAPKI_CP_UTF16LE
    // 2015年后一般采用UTF8编码方式
    public static final String NETCAPKI_CP = "UTF-16LE";

    // 定制2：证书获取方式，特定项目需定制(java中无需定制此项)
    // Device：从设备获取证书,速度更快【推荐】；
    // CSP：从获取证书，多CA支持时需采用此方式。
    public static String NETCAPKI_CERTFROM = "Device";

    // 定制3：默认的证书筛选条件，特定项目需定制
    // 多CA支持时需定制，如{ "NETCA", "GDCA","SZCA" }
    public static final String[] NETCAPKI_SUPPORTCAS = {"NETCA"};

    // 定制4：NETCA证书实体唯一标识，特定项目需定制
    // 1.3.6.1.4.1.18760.1.12.11/1.3.6.1.4.1.18760.11.12.11.1：NETCA通用定义OID；
    // 2.16.156.112548：深圳地方标准
    public static String NETCAPKI_UUID = "1.3.6.1.4.1.18760.1.12.11";
    // 定制8：RSA加密算法 AES256CBC
    public static int NETCAPKI_ENVELOPEDDATA_ALGORITHM_RSAENV = EnvelopedData.AES256CBC;

    // 定制9：SM2加密算法 SM4CBC
    public static int NETCAPKI_ENVELOPEDDATA_ALGORITHM_SM2ENV = EnvelopedData.SM4CBC;

    // 定制10：RSA对称加密算法
    public static int NETCAPKI_ALGORITHM_SYMENV = Cipher.AES_CBC;

    // 定制11：签名包含证书的选项，一般无需定制
    public static int NETCAPKI_SIGNEDDATA_INCLUDE_CERT_OPTION = SignedData.INCLUDE_CERT_OPTION_SELF;

    // 定制12：设置该项BASE64编码不换行
    public static int NETCAPKI_BASE64_ENCODE_NO_NL = Base64.ENCODE_NO_NL;

    //证书基本信息
    //证书base64编码
    public static final int NETCAPKI_CERT_INFO_BASE64 = 0;
    //证书姆印
    public static final int NETCAPKI_CERT_INFO_THUMBPRINT = 1;
    //序列号
    public static final int NETCAPKI_CERT_INFO_SERIALNUMBER = 2;
    //主体
    public static final int NETCAPKI_CERT_INFO_SUBJECT = 3;
    //颁发者
    public static final int NETCAPKI_CERT_INFO_ISSUER = 4;
    //有效开始时间
    public static final int NETCAPKI_CERT_INFO_VALIDFROMDATE = 5;
    //有效结束时间
    public static final int NETCAPKI_CERT_INFO_VALIDTODATE = 6;
    //证书的密钥用法
    public static final int NETCAPKI_CERT_INFO_KEYUSAGE = 7;
    //公共密钥算法
    public static final int NETCAPKI_CERT_INFO_PUBLICKEYALGORITHM = 8;
    // 获取证书客户服务号\取证书证件号码扩展域信息\证书姆印
    public static final int NETCAPKI_CERT_INFO_USERCERTNO = 9;
    //旧的用户证书绑定值
    public static final int NETCAPKI_CERT_INFO_OLDUSERCERTNO = 10;
    //证书主题中的名称
    public static final int NETCAPKI_CERT_INFO_SUBJECT_NAME = 11;
    //证书主题中的CN项（人名）
    public static final int NETCAPKI_CERT_INFO_SUBJECT_CN = 12;
    //Subject中的O项（人名）
    public static final int NETCAPKI_CERT_INFO_SUBJECT_O = 13;
    //Subject中的地址（L项）
    public static final int NETCAPKI_CERT_INFO_SUBJECT_L = 14;
    //证书颁发者的Email
    public static final int NETCAPKI_CERT_INFO_SUBJECT_EMAIL = 15;
    //Subject中的部门名（OU项）
    public static final int NETCAPKI_CERT_INFO_SUBJECT_OU = 16;
    //用户国家名（C项）
    public static final int NETCAPKI_CERT_INFO_SUBJECT_C = 17;
    //用户省州名（S项）
    public static final int NETCAPKI_CERT_INFO_SUBJECT_S = 18;
    //CA ID
    public static final int NETCAPKI_CERT_INFO_CA_CATITLE = 21;
    //证书类型
    public static final int NETCAPKI_CERT_INFO_TYPE = 22;
    //用户证书客服号
    public static final int NETCAPKI_CERT_INFO_CUSTOMER_NUMBER = 23;
    //深圳地标
    public static final int NETCAPKI_CERT_INFO_SZ_LANDMARK = 24;
    //证书旧姆印
    public static final int NETCAPKI_CERT_INFO_OLDTHUMBPRINT = 31;
    //纳税人编码
    public static final int NETCAPKI_CERT_INFO_RATEPAYER_NUMBER = 32;
    //组织机构代码号
    public static final int NETCAPKI_CERT_INFO_ORGANIZATION_CODE = 33;
    //税务登记号
    public static final int NETCAPKI_CERT_INFO_RATELOAD_NUMBER = 34;
    //证书来源地
    public static final int NETCAPKI_CERT_INFO_SOURCE = 35;
    //证书证件号码扩展域
    public static final int NETCAPKI_CERT_INFO_NUMBEREXTEND = 36;
    //证书证件号码扩展域
    public static final int NETCAPKI_CERT_INFO_NUMBEREXTEND_DECODE = 37;
    //GDCA的特定扩展域 51
    public static final int NETCAPKI_CERT_INFO_SPECIFICEXTEND = 51;

    // 获取任意类型设备的设备集
    private static DeviceSet getDeviceSet() throws PkiException {
        DeviceSet set = new DeviceSet(Device.ANY_DEVICE,
            Device.DEVICE_FLAG_CACHE_PIN_IN_PROCESS);
        return set;
    }

    private static Device getDevice(DeviceSet set, int index)
        throws PkiException {
        if (set == null) {
            throw new PkiException("请输入设备集!");
        }
        if (index < 0 || index > set.count()) {
            throw new PkiException("请输入正确的设备索引值:大于0且小于" + set.count() + "的整数");
        }
        Device device = set.get(index);
        return device;
    }

    /**==================================================================
     * 0.工具类
     * ==================================================================
     */
    /**
     * 字符串转byte数组，采用的编码方式在项目定制常量“NETCAPKI_CP”中定义。
     *
     * @param data 需要转byte数据的字符串
     * @return byte数组
     */
    public static byte[] convertByte(String data) throws PkiException {
        if (isEmpty(data)) {
            throw new PkiException("字符串转字节数组，字符串为空");
        }
        try {
            return data.getBytes(BYTE_CODE);
        } catch (UnsupportedEncodingException ex) {
            throw new PkiException("字符串转字节数组编码错误:" + ex.getMessage());
        }
    }

    /**
     * byte数组转字符串，采用的编码方式为项目定制常量“NETCAPKI_CP”中定义。
     *
     * @param data 需要转字符串的byte数组
     * @return 转码后的字符串
     */
    public static String convertString(byte[] data) throws PkiException {
        if (isEmpty(data)) {
            throw new PkiException("byte数组转字符串中，字节数组为空");
        }
        try {
            return new String(data, BYTE_CODE);
        } catch (UnsupportedEncodingException ex) {
            throw new PkiException("字符串转字符编码错误:" + ex.getMessage());
        }
    }

    /**
     * 两个字节数组的对比
     *
     * @param source 字节数组1
     * @param target 字节数组2
     * @return 两个数组完全相同，则返回true，反之，则false
     */
    private static boolean compareByteArrays(byte[] source, byte[] target) {

        int count = source.length;
        if (count != target.length) {
            return false;
        }
        for (int i = 0; i < count; i++) {
            if (source[i] != target[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * 使用公司工具类，将字节数组进行Base64编码，得到Base64字符串
     *
     * @param data 字节数组
     * @return Base64编码的字符串
     */
    public static String base64Encode(byte[] data) throws PkiException {
        if (isEmpty(data)) {
            throw new PkiException("在进行Base64编码的过程，字节数组为空");
        }
        try {
            return Base64.encode(NETCAPKI_CERT_INFO_BASE64, data);
        } catch (PkiException e) {
            throw new PkiException("在进行Base64编码的过程中，出错：" + e.getMessage());
        }
    }

    /**
     * 使用公司工具类，将编码的字符串进行Base64解码，获得字节数组
     *
     * @param data 需要编码的数据
     * @return Base64解码后的字节数组
     */
    public static byte[] base64Decode(String data) throws PkiException {
        if (isEmpty(data)) {
            throw new PkiException("在进行Base64解码的过程中，输入的值为空");
        }
        try {
            return Base64.decode(NETCAPKI_BASE64_ENCODE_NO_NL, data);
        } catch (PkiException e) {
            throw new PkiException("在进行Base64解码的过程中，出错：" + e.getMessage());
        }
    }

    /**
     * 获取随机数
     *
     * @param length 生产的随机数的长度
     * @return 随机数
     */
    public static byte[] getRandom(int length) throws PkiException {
        if (length < 1) {
            throw new PkiException("请输入正确的随机数位数!");
        }
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] bytes = new byte[length];
            random.nextBytes(bytes);
            return bytes;
        } catch (Exception ex) {
            throw new PkiException(ex.getMessage());
        }
    }

    /**
     * 二进制 读取文件
     *
     * @param path 文件路径
     * @return 读取文件的内容，返回一个字节数组
     */
    public static byte[] readFile(String path) throws IOException {
        if (isEmpty(path)) {
            throw new IOException("读文件的操作中，文件路径为空");
        }
        File f = new File(path);
        if (!f.exists()) {
            throw new IOException("读取的文件路径不存在");
        }

        InputStream inputStream = null;
        byte[] content = null;

        try {
            inputStream = new FileInputStream(path);
            int len = inputStream.available();
            content = new byte[len];
            len = inputStream.read(content);
            return content;
        } catch (FileNotFoundException e) {
            throw new IOException("读文件的操作中，该路径下没有对应的文件进行读取");
        } catch (IOException e) {
            throw new IOException("读文件的操作中，读取文件出现错误：" + e.getMessage());
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Exception e3) {
                    throw new IOException("读文件的操作中，关闭输入流失败");
                }
            }
        }
    }

    /**
     * 二进制写文件的操作
     *
     * @param path 文件路径
     * @param content 字节数组，需要写入文件的内容
     * @return 读取文件的内容，返回一个字节数组
     */
    public static boolean writeFile(String path, byte[] content) throws IOException {
        if (isEmpty(content)) {
            throw new IOException("写入的内容为空");
        }
        if (isEmpty(path)) {
            throw new IOException("写入的文件路径为空");
        }
        File f = new File(path);
        if (!f.exists()) {
            throw new IOException("写入的文件路径不存在");
        }
        OutputStream outputStream = null;
        try {
            outputStream = new FileOutputStream(path);
            outputStream.write(content);
            return true;
        } catch (FileNotFoundException e) {
            throw new FileNotFoundException("写文件的操作中，该路径下没有对应的文件");
        } catch (IOException e) {
            throw new IOException("写文件的操作中，写入文件出现错误：" + e.getMessage());
        } finally {
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (Exception e) {
                    throw new IOException("写文件的操作中，关闭输出流失败");
                }
            }
        }
    }

    /**
     * 5.2.1获取签名证书，多张证书取第1张
     */
    public static Certificate getSignX509Certificate() throws PkiException {
        CertStore oCertStore = null;
        try {
            oCertStore = new CertStore(CertStore.CURRENT_USER, CertStore.MY);
            int Count = oCertStore.getCertificateCount();
            for (int i = 0; i < Count; i++) {
                Certificate oCert = oCertStore.getCertificate(i);
                Date oDateEnd = oCert.getValidityEnd();
                Date oDateBegin = oCert.getValidityStart();
                Date oDateNow = new Date();
                if (oDateNow.compareTo(oDateBegin) > 0
                    && oDateNow.compareTo(oDateEnd) < 0) {// 找出有效期内证书
                    String keyUse = getX509CertificateInfo(oCert, 7);
                    if (keyUse.equals("3")) {// 找出签名证书
                        return oCert;
                    }
                }

            }
        } catch (Exception ex) {
            System.out.println(ex.getMessage());

        } finally {
            if (oCertStore != null) {
                oCertStore.close();
            }
        }

        return null;
    }

    /**=================================================================================
     *  1. 证书处理
     * =================================================================================
     */
    /**
     * 获取证书集（通过证书库、或者直接通过弹出框） 使用频率：较少用到； 使用场景： 1）证书登陆时，网页列出插入证书下拉框，需选择对应证书进行登陆； 2）证书绑定时，绑定相应证书；
     *
     * @param purpose 证书类型：签名、加密、两者兼备
     */
    @SuppressWarnings("unused")
    public static List<Certificate> getX509Certificates(int purpose)
        throws PkiException {

        List<Certificate> list = new ArrayList<Certificate>();
        int count = 0;

        // 通过设备来获取certificate
        if (NETCAPKI_CERTFROM.equals("Device")) {
            int type = Device.ANY_DEVICE;
            int flag = Device.DEVICE_FLAG_CACHE_PIN_IN_PROCESS;

            DeviceSet deviceSet = null;
            try {
                deviceSet = new DeviceSet(type, flag);
                if (deviceSet == null) {
                    throw new PkiException("获取证书集失败，系统中设备集为空");
                }
                count = deviceSet.count();
                Device device = null;
                KeyPair keyPair = null;
                try {
                    for (int i = 0; i < count; i++) { //1.遍历DeviceSet里面所有的Device
                        device = deviceSet.get(i);
                        if (device == null) {
                            continue;
                        }

                        int keyPairCount = device.getKeyPairCount();
                        for (int j = 1; j <= keyPairCount; ++j) { //2.遍历Device里面所有的KeyPair
                            keyPair = device.getKeyPair(j);
                            if (keyPair == null) {
                                continue;
                            }
                            try {
                                int certCount = keyPair.getCertificateCount(); //通常来说，一个keypair一个证书！
                                for (int k = 0; k < certCount; k++) { //3.遍历KeyPair中的每个Certificate
                                    Certificate certificate = keyPair.getCertificate(k);
                                    // 过滤证书：密钥用法(getKeyUsage)
                                    int kUsage = certificate
                                        .getKeyUsage(); //输出就是证书里面密钥用的或起来得到的结果，而不是特定的常量，因为一个证书有多个密钥用法

                                    list.add(certificate);
                                }
                            } finally {
                                if (keyPair != null) {
                                    keyPair.free();
                                }
                                keyPair = null;
                            }
                        }
                    }
                } finally {
                    if (device != null) {
                        device.free();
                        device = null;
                    }
                }
            } catch (PkiException e) {
                throw new PkiException("获取证书集过程中，创建设备集失败，请检查筛选的类型是否出错:" + e.getMessage());
            } finally {
                if (deviceSet != null) {
                    deviceSet.free();
                }
                deviceSet = null;
            }
        }

        return list;
    }

    /**
     * [常用]获取证书属性信息 使用频率：较常用，多CA支持时，需定制； 注：第9项值一般作为证书的绑定值，该项值为一个复合值；
     *
     * @param certificate 一个证书对象
     * @param iInfoType 信息类型（见5.1.2 证书中相关信息的类型编码）
     * @return 相对应的相关信息
     */
    public static String getX509CertificateInfo(Certificate certificate, int iInfoType)
        throws PkiException {

        if (null == certificate) {
            return "";
        }
        try {
            String rt = "";
            switch (iInfoType) {

                case 0:    // 获取证书BASE64格式编码字符串     NETCAPKI_CERT_INFO_BASE64
                    // return certificate.pemEncode();
                    byte[] bCert = certificate.derEncode();
                    return base64Encode(bCert);
                // 注意：其中的Constants.NETCAPKI_ALGORITHM_HASH是固定编码方式，注意旧版本调用过程hash算法中（可能为sha1）会不会与之不同（SHA256）

                //证书基本信息1-8
                case 1:        //证书姆印   	NETCAPKI_CERT_INFO_THUMBPRINT
                    return Util.HexEncode(true,
                        certificate.computeThumbprint(NETCAPKI_ALGORITHM_HASH));        //SHA256
                case 2:        //证书序列号 	NETCAPKI_CERT_INFO_SERIALNUMBER
                    return certificate.getSerialNumber();
                case 3:        //证书主题	NETCAPKI_CERT_INFO_SUBJECT
                    return certificate.getSubject();
                case 4:        //证书颁发者主题
                    return certificate.getIssuer();
                case 5:        //证书有效期起	NETCAPKI_CERT_INFO_VALIDFROMDATE 证书有效期起
                    return certificate.getValidityStart().toString();
                case 6:        //证书有效期止	NETCAPKI_CERT_INFO_VALIDTODATE
                    return certificate.getValidityEnd().toString();
                case 7:        //密钥用法	NETCAPKI_CERT_INFO_KEYUSAGE
                    return Integer.valueOf(certificate.getKeyUsage()).toString();
                case 8:    //证书的公钥的算法NETCAPKI_CERT_INFO_PUBLICKEYALGORITHM
                {
                    return Integer.valueOf(certificate.getPublicKeyAlgorithm()).toString();
                }
                case 9:    //NETCAPKI_CERT_INFO_USERCERTNO
                {
                    // 证书的唯一标识
                    rt = getX509CertificateInfo(certificate, NETCAPKI_CERT_INFO_NUMBEREXTEND);
                    if (rt != null && !rt.isEmpty()) {
                        return rt;
                    }
                    // 证书客户服务号
                    rt = getX509CertificateInfo(certificate, NETCAPKI_CERT_INFO_CUSTOMER_NUMBER);
                    if (rt != null && !rt.isEmpty()) {
                        return rt;
                    }
                    // 证书姆印
                    rt = getX509CertificateInfo(certificate, NETCAPKI_CERT_INFO_THUMBPRINT);
                    if (rt != null && !rt.isEmpty()) {
                        return rt;
                    }
                    return "";
                }
                case 10:    //旧的用户证书绑定值；(证书更新后的原有9的取值)	NETCAPKI_CERT_INFO_OLDUSERCERTNO
                {
                    if (getX509CertificateInfo(certificate, NETCAPKI_CERT_INFO_CA_CATITLE)
                        .equals("NetCA")) {
                        return getX509CertificateInfo(certificate,
                            NETCAPKI_CERT_INFO_OLDTHUMBPRINT);
                    }
                    return "";
                }
                //Subject中信息（11~18）
                case 11:    //证书主题名称；有CN项取CN项值；无CN项，取O的值	NETCAPKI_CERT_INFO_SUBJECT_NAME
                {
                    rt = getX509CertificateInfo(certificate, NETCAPKI_CERT_INFO_SUBJECT_CN);
                    if (rt != null && !rt.isEmpty()) {
                        return rt;
                    } else {
                        return getX509CertificateInfo(certificate, NETCAPKI_CERT_INFO_SUBJECT_O);
                    }
                }
                case 12: {    //Subject中的CN项（人名）	NETCAPKI_CERT_INFO_SUBJECT_CN
                    rt = certificate.getSubjectCN();
                    return ((rt != null && !rt.isEmpty()) ? rt : "");
                }
                case 13: {    //Subject中的O项（人名）	NETCAPKI_CERT_INFO_SUBJECT_O
                    rt = certificate.getSubjectO();
                    return ((rt != null && !rt.isEmpty()) ? rt : "");
                }
                case 14: {    //Subject中的地址	NETCAPKI_CERT_INFO_SUBJECT_L
                    rt = certificate.getSubjectL();
                    return ((rt != null && !rt.isEmpty()) ? rt : "");
                }
                case 15: {    //证书颁发者的EmailNETCAPKI_CERT_INFO_SUBJECT_EMAIL
                    rt = certificate.getSubjectEmail();
                    return ((rt != null && !rt.isEmpty()) ? rt : "");
                }
                case 16: {    //Subject中的部门名（OU项）	NETCAPKI_CERT_INFO_SUBJECT_OU
                    rt = certificate.getSubjectOU();
                    return ((rt != null && !rt.isEmpty()) ? rt : "");
                }
                case 17: {    ///用户国家名（C项）NETCAPKI_CERT_INFO_SUBJECT_C
                    rt = certificate.getSubjectC();
                    return ((rt != null && !rt.isEmpty()) ? rt : "");
                }
                case 18: {    //用户省州名（S项）	NETCAPKI_CERT_INFO_SUBJECT_S
                    rt = certificate.getSubjectST();
                    return ((rt != null && !rt.isEmpty()) ? rt : "");
                }
                case 21: {    //CA ID	NETCAPKI_CERT_INFO_CA_CATITLE
                    for (int i = 0; i < NETCAPKI_SUPPORTCAS.length; i++) {
                        if (getX509CertificateInfo(certificate, NETCAPKI_CERT_INFO_ISSUER)
                            .indexOf(NETCAPKI_SUPPORTCAS[i]) > 0) {
                            return NETCAPKI_SUPPORTCAS[i];
                        }
                    }
                }
                //2017年7月8日15:13:13，注：关于扩展OID的还没有实现。
                case 22: {
                    if (getX509CertificateInfo(certificate, 21).equals("NETCA")) {

                        try {
                            //netca证书类型扩展OID:NETCA OID(1.3.6.1.4.1.18760.1.12.12.2)
                            //1：服务器证书;2：个人证书;3: 机构证书;4：机构员工证书;5：机构业务证书(注：该类型国密标准待定);0：其他证书
                            String flag = null;//certificate.getStringExtension("1.3.6.1.4.1.18760.1.12.12.2");
                            byte[] extV = certificate
                                .getExtensionValue("1.3.6.1.4.1.18760.1.12.12.2");
                            flag = net.netca.pki.Util
                                .decodeDERString(net.netca.pki.Util.UTF8STRING_TYPE, extV);
                            if (flag.equals("001")) {
                                return "3";
                            } else if (flag.equals("002")) {
                                return "5";
                            } else if (flag.equals("003")) {
                                return "4";
                            } else if (flag.equals("004")) {
                                return "2";
                            } else {
                                return "0";
                            }
                        } catch (Exception e) {
                            String sCN = getX509CertificateInfo(certificate, 12);
                            String sO = getX509CertificateInfo(certificate, 13);
                            boolean hasSCN = (sCN != null && (!sCN.equals("")));
                            boolean hasSO = (sO != null && (!sO.equals("")));
                            if ((!hasSO) && hasSCN) {
                                return "2";
                            } else if ((hasSO && (!hasSCN)) ||
                                (hasSO && hasSCN && sO.equals(sCN))) {
                                return "3";
                            } else if (
                                hasSO && hasSCN && (!sO.equals(sCN))) {
                                return "4";
                            }
                        }
                        return "0";
                    } else {
                        return "0";
                    }

                }
                case 23: {        //用户证书客服号 	//底层会报错
                    if (getX509CertificateInfo(certificate, 21).equals("NETCA")) {
                        try {
                            byte[] extV = certificate.getExtensionValue("1.3.6.1.4.1.18760.1.14");
                            return net.netca.pki.Util
                                .decodeDERString(net.netca.pki.Util.UTF8STRING_TYPE, extV);
                        } catch (Exception e) {
                            return "";
                        }
                    } else if (getX509CertificateInfo(certificate, 21).equals("GDCA")) {
                        return getX509CertificateInfo(certificate, 51);
                    }
                }
                case 24: {        //深圳地标
                    try {
                        byte[] extV = certificate.getExtensionValue("2.16.156.112548");
                        return net.netca.pki.Util
                            .decodeDERString(net.netca.pki.Util.UTF8STRING_TYPE, extV);
                    } catch (Exception e) {
                        return "";
                    }
                }
                case 31: {        //证书旧姆印
                    try {
                        return "";
                    } catch (Exception e) {
                        return "";
                    }
                }
                case 32: {        //纳税人编码
                    try {
                        return "";
                    } catch (Exception e) {
                        return "";
                    }
                }
                case 33: {        //组织机构代码号
                    try {
                        return "";
                    } catch (Exception e) {
                        return "";
                    }
                }
                case 34: {        //税务登记号
                    try {
                        return "";
                    } catch (Exception e) {
                        return "";
                    }
                }
                case 35: {        //证书来源地
                    try {
                        return "";
                    } catch (Exception e) {
                        return "";
                    }
                }
                case 36: {        //证书证件号码扩展域
                    //例子：10001@0006ZZ1XXXXXw==
                    try {
                        byte[] extV = certificate.getExtensionValue(NETCAPKI_UUID);
                        return net.netca.pki.Util
                            .decodeDERString(net.netca.pki.Util.UTF8STRING_TYPE, extV);
                    } catch (Exception e) {
                        return "";
                    }
                }
                case 37: {        //证书证件号码扩展域
                    String certExtension = getX509CertificateInfo(certificate, 36);
                    if (certExtension != null && certExtension.length() > 13) {
                        int beginIndex = certExtension.indexOf("@");
                        if (beginIndex == -1) {
                            return "";        //解析内容不是合法的扩展域
                        }
                        String flag = certExtension.substring(beginIndex + 7, beginIndex + 8);
                        if (flag.equals("1")) {
                            String b64Identity = certExtension.substring(beginIndex + 8);
                            byte[] data = base64Decode(b64Identity);
                            return convertString(data);
                        } else if (flag.equals("0")) {
                            return certExtension.substring(beginIndex + 8);
                        }
                    }
                }
                case 51: {        //GDCA 证书信任号
                    String OID = "1.2.86.21.1.3";
                    if (getX509CertificateInfo(certificate, 21).equals("GDCA")) {
                        try {
                            return OID;
                        } catch (Exception e) {
                            return "";
                        }
                    }
                }
                default:
                    return "";
            }
        } catch (PkiException e) {
            throw new PkiException("获取证书的相关信息过程中出错：" + e.getMessage());
        }
    }

    /**
     * 5.3.1 用指定证书进行PKCS7签名
     */
    public static String signedDataByCertificate(Certificate certificate, String sSource,
        Boolean IsNotHasSource, String pwd) throws PkiException {
        if (isEmpty(sSource)) {
            throw new PkiException("在进行签名过程中，待签名的原文为空");
        }

        if (certificate == null) {
            throw new PkiException("证书为空!");
        }
        byte[] bSource = convertByte(sSource);
        SignedData signedData = null;
        byte[] signValue = null;
        try {
            signedData = new SignedData(true);
            signedData.setDetached(IsNotHasSource); // 是否带原文（false：带，true：不带
            if (isEmpty(pwd)) {
                signedData.setSignCertificate(certificate);
            } else {
                signedData.setSignCertificate(certificate, pwd);
            }
            String defaultAlgo = Integer.valueOf(KeyPair.RSA).toString();
            String certAlgo = getX509CertificateInfo(certificate,
                NETCAPKI_CERT_INFO_PUBLICKEYALGORITHM);

            signedData.setSignAlgorithm(0, certAlgo.equals(defaultAlgo) ? NETCAPKI_ALGORITHM_RSASIGN
                : NETCAPKI_ALGORITHM_SM2SIGN);
            signedData.setIncludeCertOption(NETCAPKI_SIGNEDDATA_INCLUDE_CERT_OPTION);
            signValue = signedData.sign(bSource);
            return base64Encode(signValue);
        } catch (PkiException ex) {
            throw new PkiException("PKCS7签名失败:" + ex.getMessage());
        } finally {
            if (signedData != null) {
                signedData.free();
            }
        }
    }

    /**
     * PKCS7签名验证并获取签名证书
     *
     * @param signValue 签名值
     * @return 签名的证书（验证成功返回一个证书）
     */
    public static Certificate verifySignedData(String sSource, String signValue)
        throws PkiException, UnsupportedEncodingException {
        try {
            byte[] data = base64Decode(signValue);
            return verifySignedData(sSource, data);
        } catch (PkiException e) {
            throw new PkiException("验证签名失败：" + e.getMessage());
        }
    }

    /**
     * PKCS7时间戳签名验证并获取证书（字节数组签名值）
     *
     * @param signValue 签名值
     * @return 签名的证书（验证成功返回一个证书）
     */
    public static Certificate verifySignedData(String sSource, byte[] signValue)
        throws PkiException, UnsupportedEncodingException {
        return (Certificate) getVerifySignedData(sSource, signValue)[1];
    }

    /**
     * 带原文PKCS#7签名,验证并获取原文。
     *
     * @param signValue 签名信息
     * @return 原文和证书的对象（0：原文，1：证书）
     */
    private static Object[] getVerifySignedData(String sSource, byte[] signValue)
        throws PkiException, UnsupportedEncodingException {
        if (isEmpty(signValue)) {
            throw new PkiException("在带原文PKCS#7签名,验证并获取原文的过程中，待验签的签名值为空");
        }
        Object[] objects = new Object[2];
        SignedData signedData = null;
        byte[] source = convertByte(sSource);

        try {
            signedData = new SignedData(false);

            //2017-8-2  是否带原文
            boolean detached = signedData.isDetachedSign(signValue);
            if (detached) {
                // 不带原文
                boolean tbs = signedData.detachedVerify(source, 0, source.length, signValue);
                if (!tbs) {
                    throw new PkiException("签名信息验签不通过");
                }
                objects[0] = null;
            } else {
                // 带原文
                // 验证原文与解析出来的原文

                source = signedData.verify(signValue);
                if (isEmpty(source)) {
                    throw new PkiException("signedData验证，签名值为空");
                }
                objects[0] = new String(source, BYTE_CODE);

                if (!((String) objects[0]).equals(sSource)) {
                    throw new PkiException("在带原文PKCS#7签名,验证并获取原文的过程中，待验签的签名值不一致");
                }
            }
            objects[1] = signedData.getSignCertificate(0);
            return objects;
        } catch (UnsupportedEncodingException e) {
            throw new UnsupportedEncodingException("signedData验证签名值中，字节数组转数字出错：" + e.getMessage());
        } catch (PkiException e) {
            throw new PkiException("signedData验证签名值出错：" + e.getMessage());
        } finally {
            if (signedData != null) {
                signedData.free();
            }
        }
    }

    /**
     * 时间戳签名核心方法
     *
     * @param certificate 签名用到的证书
     * @param source 原文，即签名内容
     * @param url 时间戳服务器URL
     * @param hasDetached 是否带原文（false：带，true：不带）
     * @return 签名值信息
     */
    public static String signedDataWithTSA(Certificate certificate, String source, String url,
        boolean hasDetached)
        throws PkiException {

        if (isEmpty(source)) {
            throw new PkiException("在对时间戳进行签名的过程中，待签名的原文为空");
        }
        if (isEmpty(url)) {
            throw new PkiException("在对时间戳进行签名的过程中，时间戳服务URL为空");
        }
        if (certificate == null) {
            throw new PkiException("在对时间戳进行签名的过程中，未选择证书");
        }
        byte[] signValue = null;
        SignedData signedData = null;

        try {
            signedData = new SignedData(true);
            signedData.setDetached(hasDetached);

            signedData.setSignCertificate(certificate);

            String defaultAlgo = Integer.valueOf(KeyPair.RSA).toString();
            String certAlgo = getX509CertificateInfo(certificate,
                NETCAPKI_CERT_INFO_PUBLICKEYALGORITHM);

            signedData.setSignAlgorithm(0, certAlgo.equals(defaultAlgo) ? NETCAPKI_ALGORITHM_RSASIGN
                : NETCAPKI_ALGORITHM_SM2SIGN);
            signValue = signedData.signWithTimeStamp(convertByte(source), url);
            return base64Encode(signValue);
        } catch (PkiException e) {
            throw new PkiException("时间戳签名出错：" + e.getMessage());
        } finally {
            if (signedData != null) {
                signedData.free();
            }
            signedData = null;
        }
    }

    /**
     * 验证时间戳签名值
     *
     * @param source 原文
     * @param signValue 签名值
     * @return 签名的证书（验证成功返回一个证书）
     */
    public static String verifySignedDataWithTSA(String source, String signValue)
        throws PkiException {

        if (isEmpty(source)) {
            throw new PkiException("在验证时间戳签名值的过程中，待验签的原文为空");
        }
        if (isEmpty(signValue)) {
            throw new PkiException("在验证时间戳签名值的过程中，待验签的签名值为空");
        }
        SignedData signedData = null;
        byte[] verifyValue = null;
        byte[] signValueArray = null;

        try {
            signValueArray = Base64.decode(NETCAPKI_BASE64_ENCODE_NO_NL, signValue);
            signedData = new SignedData(false);
            signedData.verifyInit();

            // 判断是否为SignedData编码
            if (!SignedData.isSign(signValueArray)) {
                throw new PkiException("验证时间戳签名值，签名信息验签未通过:签名数据格式不正确!");
            }
            boolean isVerifyPass = true;
            // 判断是否带原文
            if (SignedData.isDetachedSign(signValueArray)) {
                // 不带原文
                isVerifyPass = signedData.detachedVerify(convertByte(source), signValueArray);
                if (!isVerifyPass) {
                    throw new PkiException("验证时间戳签名值，签名信息验证未通过"); // 错误信息。
                }
            } else {
                // 带原文
                verifyValue = signedData.verifyUpdate(signValueArray, 0, signValueArray.length);
                signedData.verifyFinal();
                if (!compareByteArrays(convertByte(source), verifyValue)) {
                    throw new PkiException("验证时间戳签名值，签名信息验证未通过,原文与签名信息不一致!");
                }
            }

            int count = signedData.getSignerCount();

            for (int i = 0; i < count; i++) {
                if (signedData.verifyTimeStamp(i)) {
                    Date date = signedData.getTimeStampTime(i);
                    SimpleDateFormat formatter;
                    formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                    return formatter.format(date);
                }
            }
        } catch (PkiException e) {
            throw new PkiException("验证时间戳签名值，验证失败：" + e.getMessage());
        } finally {
            if (signedData != null) {
                signedData.free();
            }
            signedData = null;
        }
        return null;
    }

    // 返回密钥用法字符串
    private static String PrintKeyUsage(int keyUsage) {

        String kustr = "";
        boolean first = true;

        if ((keyUsage | Certificate.KEYUSAGE_DIGITALSIGNATURE) == keyUsage) {
            if (first) {
                kustr += "数字签名";
            } else {
                kustr += ",数字签名";
            }
            first = false;
        }

        if ((keyUsage | Certificate.KEYUSAGE_NONREPUDIATION) == keyUsage) {
            if (first) {
                kustr += "不可否认";
            } else {
                kustr += ",不可否认";
            }
            first = false;
        }

        if ((keyUsage | Certificate.KEYUSAGE_CONTENTCOMMITMENT) == keyUsage) {
            if (first) {
                kustr += "内容承诺";
            } else {
                kustr += ",内容承诺";
            }
            first = false;
        }
        if ((keyUsage | Certificate.KEYUSAGE_KEYENCIPHERMENT) == keyUsage) {
            if (first) {
                kustr += "加密密钥";
            } else {
                kustr += ",加密密钥";
            }
            first = false;
        }

        if ((keyUsage | Certificate.KEYUSAGE_DATAENCIPHERMENT) == keyUsage) {
            if (first) {
                kustr += "加密数据";
            } else {
                kustr += ",加密数据";
            }
            first = false;
        }

        if ((keyUsage | Certificate.KEYUSAGE_KEYAGREEMENT) == keyUsage) {
            if (first) {
                kustr += "密钥协商";
            } else {
                kustr += ",密钥协商";
            }
            first = false;
        }

        if ((keyUsage | Certificate.KEYUSAGE_KEYCERTSIGN) == keyUsage) {
            if (first) {
                kustr += "签证书";
            } else {
                kustr += ",签证书";
            }
            first = false;
        }

        if ((keyUsage | Certificate.KEYUSAGE_CRLSIGN) == keyUsage) {
            if (first) {
                kustr += "签CRL";
            } else {
                kustr += ",签CRL";
            }
            first = false;
        }

        if ((keyUsage | Certificate.KEYUSAGE_ENCIPHERONLY) == keyUsage) {
            if (first) {
                kustr += "只加密";
            } else {
                kustr += ",只加密";
            }
            first = false;
        }

        if ((keyUsage | Certificate.KEYUSAGE_DECIPHERONLY) == keyUsage) {
            if (first) {
                kustr += "只解密";
            } else {
                kustr += ",只解密";
            }
            first = false;
        }

        if ("".equals(kustr)) {
            return "密钥用法:没有密钥用法";
        } else {
            return "密钥用法:" + kustr;
        }
    }

    private static String hexToStr(byte pBytes[]) {
        byte NUMBER_KEY = 48;
        byte UPPER_KEY = 55;
        byte LOWER_KEY = 87;
        byte HEX_KEY = 16;
        String result = "";
        for (int i = 0; i < pBytes.length; i++) {
            int tmpInt = (new Byte(pBytes[i])).intValue();
            if (tmpInt < 0) {
                tmpInt += 256;
            }
            byte strList[] = new byte[2];
            strList[1] = (new Integer(tmpInt % 16)).byteValue();
            strList[0] = (new Integer((tmpInt / 16) % 16)).byteValue();
            if (strList[1] > 9 && strList[1] < 16) {
                strList[1] += UPPER_KEY;
            }
            if (strList[1] >= 0 && strList[1] < 10) {
                strList[1] += NUMBER_KEY;
            }
            if (strList[0] > 9 && strList[0] < 16) {
                strList[0] += UPPER_KEY;
            }
            if (strList[0] >= 0 && strList[0] < 10) {
                strList[0] += NUMBER_KEY;
            }
            result = result + new String(strList);
        }

        return result;
    }

    private static String getThumbprintStr(byte[] b, String oid)
        throws PkiException {
        try {
            String value = "";

            int byteLength = getStringLength(b);
            byte[] b0 = new byte[b.length - byteLength];
            for (int j = 0; j < b.length - byteLength; j++) {
                b0[j] = b[j + byteLength];
            }

            ASN1InputStream asn1Stream = new ASN1InputStream(
                new ByteArrayInputStream(b0));
            DERSequence deSequences = (DERSequence) asn1Stream.readObject();
            for (Enumeration e = deSequences.getObjects(); e.hasMoreElements(); ) {
                DERSequence deSequence = ((DERSequence) e.nextElement());
                Enumeration e1 = deSequence.getObjects();

                DERSequence deSq = (DERSequence) e1.nextElement();
                Enumeration e2 = deSq.getObjects();
                DERObjectIdentifier iden = (DERObjectIdentifier) e2
                    .nextElement();
                // System.out.println("11:" + iden.getId());

                if (oid.equalsIgnoreCase(iden.getId()) && e1.hasMoreElements()) {
                    DEROctetString derStr = (DEROctetString) e1.nextElement();
                    byte tt[] = derStr.getOctets();
                    // System.out.println("22:" + Hex.EncodeToString(tt));
                    value = Hex.EncodeToString(tt);
                }
            }
            return value;
        } catch (Exception ex) {
            throw new PkiException(ex.getMessage());

        }
    }

    /**
     * 得到asn1编码的头标志长度
     *
     * @param b byte[]
     * @return int
     */
    private static int getStringLength(byte[] b) {
        // byte[] b0 = null;
        int ccc[] = new int[8];
        for (int z = 0; z < 8; z++) {
            char tem = 1;
            tem <<= z;
            tem &= b[1];
            tem >>= z;
            ccc[z] = tem;
        }
        int byteLength = 2;
        if (ccc[7] == 1) {
            byteLength = 2 + ccc[0] + ccc[1] * 2 + ccc[2] * 4 + ccc[3] * 8
                + ccc[4] * 16 + ccc[5] * 32 + ccc[6] * 64;
        }
        return byteLength;
    }

    /**
     * 获得证书类型 证书类型，也可以是获取条件的JSON。可以参考《NETCA PKI API参考手册》
     *
     * @param method 证书的获取方法（设备、证书库）
     * @param purpose 证书作用类型（加密、签名）
     */
    private static String getType(String method, int purpose) {
        String type = "{\"UIFlag\":\"default\",\"InValidity\":true,";
        if (purpose == Certificate.PURPOSE_SIGN) {
            type += "\"Type\":\"signature\",";
        } else if (purpose == Certificate.PURPOSE_ENCRYPT) {
            type += "\"Type\":\"encrypt\",";
        }

        if (method.toLowerCase().equals("device")) {
            type += "\"Method\":\"device\",\"Value\":\"any\"";
            // type += "\"Method\":\"device\",\"Value\":{\"Type\":-7,\"SerialNumber\":\"00618BAF1631460B\"}";
        } else {
            type += "\"Method\":\"store\",\"Value\":{\"Type\":\"current user\",\"Value\":\"my\"}";
        }
        type += "}";
        return type;
    }

    /**
     * 获得表达式条件
     *
     * @param purpose 证书作用类型（加密、签名）
     */
    private static String getFilter(int purpose) {
        String filter = "InValidity='True'";
        if (NETCAPKI_SUPPORTCAS.length > 0) {
            filter += "&&(";
            for (int i = 0; i < NETCAPKI_SUPPORTCAS.length; i++) {
                if (i == 0) {
                    filter += "IssuerCN~'" + NETCAPKI_SUPPORTCAS[i] + "'";
                } else {
                    filter += "||IssuerCN~'" + NETCAPKI_SUPPORTCAS[i] + "'";
                }

            }
            filter += ")";
        }
        if (purpose == Certificate.PURPOSE_SIGN) {
            filter += "&&CertType='Signature'&&CheckPrivKey='True'";
        } else if (purpose == Certificate.PURPOSE_ENCRYPT) {
            filter += "&&CertType='Encrypt'";
        }
        return filter;
    }

    /**
     * 获得X509证书，返回一个证书对象 使用频率：较常用； 使用场景： 选择证书通常采用此函数。1）证书绑定时，2）证书登录时； 根据全局变量定制项2、3，可通过该函数支持多CA支持；
     *
     * @param purpose 证书作用的类型（加密、签名），参见Cetificate类有关PURPOSE字样的常量定义
     * @return 一个筛选出来的证书
     */
    public static Certificate getX509Certificate(int purpose) {
        String type = getType(NETCAPKI_CERTFROM, purpose);
        String expr = getFilter(purpose);
        System.out.println("type:" + type);
        System.out.println("expr:" + expr);
        return Certificate.select(type, expr);
    }

    /**
     * 获得X509证书，返回一个证书对象（从证书BASE64编码信息中） 使用频率：较常用
     *
     * @param base64Cert 证书的Base64编码
     * @return 一个证书对象
     * @throws PkiException 比如：采用指定人员的证书进行加密；
     */
    public static Certificate getX509Certificate(String base64Cert) throws PkiException {
        if (isEmpty(base64Cert)) {
            throw new PkiException("获得X509证书过程中，证书的Base64编码为空");
        }
        Certificate certificate = null;
        try {
            certificate = new Certificate(base64Cert);
        } catch (Exception e) {
            throw new PkiException("通过Base64编码获得X509证书过程中出错：" + e.getMessage());
        }
        return certificate;
    }

    /**===================================================================================================
     * 5.加解密操作
     * ===================================================================================================
     */
    /**
     * 数字信封加密的核心方法
     *
     * @param certificate 数字信封使用到的证书。
     * @param source 原文，待加密值
     * @return 加密值
     */
    public static String envelopedData(Certificate certificate, byte[] source) throws PkiException {

        if (isEmpty(source)) {
            throw new PkiException("数字信封加密中，待加密值为空");
        }
        byte[] envelopedValue = null;

        // 1. 对参数进行筛选
        if (certificate == null) {
            throw new PkiException("数字信封加密，未选择证书,请检查是否插入密钥!");
        }
        EnvelopedData envelopedData = null;

        try {
            envelopedData = new EnvelopedData(true);
            int algo = 0;
            String defalutAlgo = getX509CertificateInfo(certificate,
                NETCAPKI_CERT_INFO_PUBLICKEYALGORITHM);
            if (defalutAlgo.equals(Integer.valueOf(KeyPair.RSA).toString())) {
                algo = NETCAPKI_ENVELOPEDDATA_ALGORITHM_RSAENV;
            } else {
                algo = NETCAPKI_ENVELOPEDDATA_ALGORITHM_SM2ENV;
            }
            envelopedData.setEncryptAlgorithm(algo);
            envelopedData.addCertificate(certificate, true);
            envelopedValue = envelopedData.encrypt(source);

            return Base64.encode(NETCAPKI_BASE64_ENCODE_NO_NL, envelopedValue);
        } catch (PkiException e) {
            throw new PkiException("数字信封加密出错：" + e.getMessage());
        } finally {
            if (envelopedData != null) {
                envelopedData.free();
            }
            envelopedData = null;
        }
    }


    /**
     * 数字信封加密 用服务器证书加密
     *
     * @param strCertificate 数字信封使用到的证书Base64编码值。
     * @param source 原文，待加密值
     * @return 加密值
     */
    public static String envelopedData(String strCertificate, byte[] source) throws PkiException {

        Certificate certificate = null;
        try {
            certificate = getX509Certificate(strCertificate);
            return envelopedData(certificate, source);
        } catch (PkiException e) {
            throw new PkiException("数字信封签名失败：" + e.getMessage());
        } finally {
            if (certificate != null) {
                certificate.free();
            }
            certificate = null;
        }
    }

    /**
     * 数字信封解密
     *
     * @param envelopedValue 数字信封解码信息
     * @return 解码值
     */
    public static byte[] developedData(String envelopedValue)
        throws PkiException, UnsupportedEncodingException {

        EnvelopedData envelopedData = null;
        if (null == envelopedValue || envelopedValue.length() == 0) {
            throw new PkiException("数字信封解码，待加密的值为空");
        }
        byte[] envValue = base64Decode(envelopedValue);
        byte[] developedValue = null;
        try {
            envelopedData = new EnvelopedData(false);
            developedValue = envelopedData.decrypt(envValue);
            return developedValue;
        } catch (PkiException e) {
            throw new PkiException("数字信封解码过程中出错：" + e.getMessage());
        } finally {
            if (envelopedData != null) {
                envelopedData.free();
            }
            envelopedData = null;
        }
    }

    /**
     * 判断是否为空字符串
     */
    private static boolean isEmpty(String content) {
        if (content == null || content.trim().length() == 0) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 判断是否为空字节数组
     */
    private static boolean isEmpty(byte[] content) {
        if (content == null || content.length == 0) {
            return true;
        } else {
            return false;
        }
    }
}
