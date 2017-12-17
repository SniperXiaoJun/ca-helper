package org.szwj.ca.helper;

import com.google.gson.JsonObject;
import java.util.UUID;
import org.szwj.ca.helper.bjca.Bjca;
import org.szwj.ca.helper.models.CaHelperException;
import org.szwj.ca.helper.models.Dictionary;
import org.szwj.ca.helper.models.EventValue;
import org.szwj.ca.helper.models.Loginer;
import org.szwj.ca.helper.models.PDFInfo;
import org.szwj.ca.helper.models.ResponseBody;
import org.szwj.ca.helper.models.UserCert;
import org.szwj.ca.helper.netca.Netca;
import org.szwj.ca.helper.utils.Base64Util;
import org.szwj.ca.helper.utils.HttpClientUtil;
import org.szwj.ca.helper.utils.JsonHelper;
import org.szwj.ca.helper.utils.PropertiesUtil;
import org.szwj.ca.helper.utils.Tools;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by yangyaosui on 2017/8/8.
 */
public class SZWJ_CaHelper {

    public static final String NETCA_AUTHORITY = "NETCA";

    public static final String BJCA_AUTHORITY = "BJCA";

    // 深圳市 CA 业务类型编码，001表示登录
    public static final String BusinessTypeCode_Login = "001";

    private static final Logger logger = LoggerFactory.getLogger(SZWJ_CaHelper.class);

    private static SZWJ_CaHelper SZWJCaHelper = new SZWJ_CaHelper();

    private static Netca netca = new Netca();

    private static Bjca bjca = new Bjca();

    private static Map<String, ICaHelper> mSnStore = new HashMap<String, ICaHelper>();

    private static Map<String, String> propertiesMap;

    private static int remotePort;

    /**
     * Helper为工具类
     */
    private SZWJ_CaHelper() {
        try {
            String configPath = System.getProperty("user.dir") + "/config/CaHelper.properties";
            // 为儿童医院医惠系统定制
//            String configPath =
//                SZWJ_CaHelper.class.getResource("/").getPath() + "config" + "/CaHelper.properties";
            propertiesMap = PropertiesUtil.getPropertiesUtil().GetPropertiesContent(configPath);
            remotePort = Integer.parseInt(propertiesMap.get("remote.port"), 10);
            logger.info("SZWJ_CaHelper(): init successfully, remote port: {}", remotePort);
        } catch (FileNotFoundException e) {
            logger.error("SZWJ_CaHelper(): failed to read properties file, error: {}",
                e.getMessage());
            remotePort = 8087;
        } catch (IOException e) {
            logger.error("SZWJ_CaHelper(): failed to read properties file, error: {}",
                e.getMessage());
            remotePort = 8087;
        }
    }

    /**
     * 返回单例CaHelper实例
     */
    public static SZWJ_CaHelper getHelper() {
        return SZWJCaHelper;
    }

    /**
     * 根据颁发机构获取对应的接口实现类
     *
     * @return 接口实现类
     */
    public static ICaHelper getCaHelperImplByAuthority(String certAuthority) {
        if (NETCA_AUTHORITY.equals(certAuthority)) {
            return netca;
        } else if (BJCA_AUTHORITY.equals(certAuthority)) {
            return bjca;
        } else {
            return null;
        }
    }

    private static void addSnStore(List<UserCert> userCertList, ICaHelper helper) {
        for (UserCert userCert : userCertList) {
            mSnStore.put(userCert.getSn(), helper);
        }
    }

    /**
     * 获取用户列表
     *
     * @return 返回证书用户列表信息
     */
    public static String SZWJ_GetUserList() {
        logger.info("SZWJ_GetUserList(): begin to get user list.");
        List<UserCert> totalUserCerts = new ArrayList<UserCert>();

        try {
            List<UserCert> netcaUserCerts = netca.GetUserList();
            totalUserCerts.addAll(netcaUserCerts);
            addSnStore(netcaUserCerts, netca);

            List<UserCert> bjcaUserCerts = bjca.GetUserList();
            totalUserCerts.addAll(bjcaUserCerts);
            addSnStore(bjcaUserCerts, bjca);
        } catch (CaHelperException e) {
            logger.error(
                "SZWJ_GetUserList(): failed to get user list, error: " + e.getMessage() + ".");
            return JsonHelper
                .generateResponse(1,
                    String.format("failed to get user list, error: %s.", e.getMessage()),
                    null);
        }

        logger.info("SZWJ_GetUserList(): get user list successfully.");
        EventValue eventValue = new EventValue();
        eventValue.setUserCerts(totalUserCerts);
        return JsonHelper.generateResponse(0, "get user list successfully", eventValue);
    }

    private static String getRandomNumFromRemote(String server, String businessSystemCode,
        String businessTypeCode, String authority, String sn)
        throws IOException, CaHelperException {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("businessSystemCode", businessSystemCode);
        jsonObject.addProperty("businessTypeCode", businessTypeCode);
        jsonObject.addProperty("authority", authority);
        jsonObject.addProperty("sn", sn);
        String responseJson = HttpClientUtil.HttpPostWithJson(String
                .format("http://%s:%d/v1.0/login/getrandomnum", server, remotePort),
            jsonObject.toString());
        return responseJson;
    }

    public static String SZWJ_Login(String server, String businessSystemCode, String sn,
        String pwd) {
        logger.info("SZWJ_Login(): begin to login.");
        if (Tools.isStringEmpty(sn)) {
            logger.error("SZWJ_Login(): login failed, error: sn is empty.");
            return JsonHelper.generateResponse(1, "login failed, error: sn is empty.", null);
        }
        if (Tools.isStringEmpty(pwd)) {
            logger.error("SZWJ_Login(): login failed, error: pwd is empty.");
            return JsonHelper
                .generateResponse(1, "login failed, error: pwd is empty.", null);
        }

        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            logger.error("SZWJ_Login(): login failed, error: incorrect serial number.");
            return JsonHelper
                .generateResponse(-1, "login failed, error: incorrect serial number.",
                    null);
        }

        String authority = helper.GetAuthority();
        // 请求服务端生成随机数
        String randomNum = "";
        String loginInfoID = "";
        if (!Tools.isStringEmpty(server)) {
            try {
                String responseJson = getRandomNumFromRemote(server, businessSystemCode,
                    BusinessTypeCode_Login, authority, sn);
                randomNum = JsonHelper.getValueFromEventValue(responseJson, "randomNum");
                loginInfoID = JsonHelper.getValueFromEventValue(responseJson, "loginInfoID");
                logger.info("SZWJ_Login(): get random num from remote successfully.");
            } catch (IOException e) {
                logger.error("SZWJ_Login() catch IOException: " + e.getMessage());
                return JsonHelper
                    .generateResponse(2, String.format("login failed, error: %s.", e.getMessage()),
                        null);
            } catch (CaHelperException e) {
                logger.error("SZWJ_Login(): catch CaHelperException: " + e.getMessage());
                return JsonHelper
                    .generateResponse(2,
                        String.format("login failed, error: %s.", e.getMessage()),
                        null);
            }
        } else {
            randomNum = helper.GetRandomNum().replace("\r\n", "");
            logger.info("SZWJ_Login(): get random num from local successfully.");
        }

        // 使用证书签名，之后验证，以达到验证密码是否正确的目的
        // 1. 使用证书签名
        String signedRandomNum = "";
        try {
            signedRandomNum = helper.Login(sn, pwd, randomNum);
            logger.info("SZWJ_Login(): sign login random num successfully.");
        } catch (CaHelperException e) {
            logger.error("SZWJ_Login(): catch CaHelperException: " + e.getMessage());
            return JsonHelper
                .generateResponse(3, String.format("login failed, error: %s.", e.getMessage()),
                    null);
        }

        // 2. 签名验证
        if (Tools.isStringEmpty(server)) {
            // 本地验证
            try {
                helper.VerSignData(randomNum, signedRandomNum);
                logger.info("SZWJ_Login(): verify login random num successfully.");
                return JsonHelper.generateResponse(0, "local login successfully.", null);
            } catch (CaHelperException e) {
                logger.error("SZWJ_Login(): catch CaHelperException: " + e.getMessage());
                return JsonHelper
                    .generateResponse(4, String.format("login failed, error: %s.", e.getMessage()),
                        null);
            }
        }

        // 3. 获取签名证书与加密证书
        String signCert = "";
        String cryptionCert = "";
        try {
            signCert = helper.GetUserSignCert(sn);
            cryptionCert = helper.GetUserCryptionCert(sn);
        } catch (CaHelperException e) {
            logger.error("SZWJ_Login() catch CaHelperException: " + e.getMessage());
            return JsonHelper
                .generateResponse(5, String.format("login failed, error: %s.", e.getMessage()),
                    null);
        }

        // 4. 请求认证服务器验证，并获取动态口令
        try {
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("businessSystemCode", businessSystemCode);
            jsonObject.addProperty("businessTypeCode", BusinessTypeCode_Login);
            jsonObject.addProperty("authority", authority);
            jsonObject.addProperty("sn", sn);
            jsonObject.addProperty("signCert", signCert);
            jsonObject.addProperty("cryptionCert", cryptionCert);
            jsonObject.addProperty("passwd", pwd);
            jsonObject.addProperty("loginInfoID", loginInfoID);
            jsonObject.addProperty("sourceData", randomNum);
            jsonObject.addProperty("signedData", signedRandomNum.replace("\r\n", ""));

            String responseJson = HttpClientUtil.HttpPostWithJson(
                String.format("http://%s:%d/v1.0/login/gettoken", server, remotePort),
                jsonObject.toString());
            logger.info("SZWJ_Login(): verify signed random num from remote successfully.");
            return responseJson;
        } catch (IOException e) {
            logger.error("SZWJ_Login() catch IOException: " + e.getMessage());
            return JsonHelper.generateResponse(6,
                String.format("login failed, catch IOException: %s.", e.getMessage()), null);
        } catch (CaHelperException e) {
            logger.error("SZWJ_Login() catch CaHelperException: {}", e.getMessage());
            return JsonHelper.generateResponse(7,
                String.format("login failed, catch CaHelperException: %s.", e.getMessage()),
                null);
        }
    }

    public static String SZWJ_GetCheckKey(String sn) {
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            logger.error(
                "SZWJ_GetCheckKey(): failed to get check key, error: incorrect serial number.");
            return JsonHelper
                .generateResponse(-1, "failed to get check key, error: incorrect serial number.",
                    null);
        }

        String checkKey = "";
        try {
            String base64Cert = helper.GetUserSignCert(sn);
            checkKey = helper.GetCheckKey(base64Cert);
        } catch (CaHelperException e) {
            return JsonHelper.generateResponse(1,
                String.format("get check key failed, error: %s.", e.getMessage()), null);
        }

        EventValue eventValue = new EventValue();
        eventValue.setCheckKey(checkKey);
        return JsonHelper.generateResponse(0, "executed successfully", eventValue);
    }

    public static String SZWJ_SignData(String server, String sn, String data, Boolean detach,
        Boolean withTsa) {
        logger.info("SZWJ_SignData(): begin to sign data.");
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            logger.error("SZWJ_SignData(): failed to sign data, error: incorrect serial number.");
            return JsonHelper
                .generateResponse(-1, "failed to sign data, error: incorrect serial number.",
                    null);
        }

        String signCert = "";
        String signedData = "";
        String timestamp = "";
        try {
            signCert = helper.GetUserSignCert(sn);
            // 本地签名
            signedData = helper.SignData(sn, data, detach).replace("\r\n", "");
            // 本地验签
            if (Tools.isStringEmpty(server)) {
                // 本地验签
                helper.VerSignData(data, signedData);
                if (withTsa) {
                    // TODO: 本地连接时间戳服务器签时间戳
                }
                // 生成返回结果
                EventValue eventValue = new EventValue();
                eventValue.setSignedData(signedData);
                eventValue.setTimestamp(timestamp);
                return JsonHelper.generateResponse(0, "sign data successfully", eventValue);
            }
        } catch (CaHelperException e) {
            return JsonHelper
                .generateResponse(2, "failed to sign data, error: " + e.getMessage(),
                    null);
        }
        // server字段不为空，通过认证服务进行验签
        try {
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("authority", helper.GetAuthority());
            jsonObject.addProperty("sn", sn);
            jsonObject.addProperty("signCert", signCert);
            jsonObject.addProperty("sourceData", data);
            jsonObject.addProperty("signedData", signedData);
            jsonObject.addProperty("detach", detach ? 1 : 0);
            HttpClientUtil.HttpPostWithJson(
                String.format("http://%s:%d/v1.0/verify/data", server, remotePort),
                jsonObject.toString());
            logger.info("SZWJ_SignData(): verify signed data from remote successfully.");
        } catch (IOException e) {
            logger.error("SZWJ_SignData() catch IOException: " + e.getMessage());
            return JsonHelper.generateResponse(3,
                String.format("failed to sign data, catch IOException: %s.", e.getMessage()),
                null);
        } catch (CaHelperException e) {
            logger.error("SZWJ_SignData() catch CaHelperException: " + e.getMessage());
            return JsonHelper.generateResponse(4,
                String.format("failed to sign data, catch CaHelperException: %s.", e.getMessage()),
                null);
        }

        if (!withTsa) {
            // 生成返回结果
            EventValue eventValue = new EventValue();
            eventValue.setSignedData(signedData);
            return JsonHelper.generateResponse(0, "sign data successfully", eventValue);
        }

        // 通过认证服务进行时间戳签名
        try {
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("authority", helper.GetAuthority());
            jsonObject.addProperty("sourceData", signedData); // 签名后的数据
            String respJson = HttpClientUtil.HttpPostWithJson(
                String.format("http://%s:%d/v1.0/sign/timestamp", server, remotePort),
                jsonObject.toString());
            logger.info("SZWJ_SignData(): sign data with TSA from remote successfully.");

            ResponseBody responseBody = JsonHelper.parseResponse(respJson);
            if (null != responseBody.getEventValue()) {
                timestamp = responseBody.getEventValue().getTimestamp();
            }
        } catch (IOException e) {
            logger.error("SZWJ_SignData() catch IOException: " + e.getMessage());
        } catch (CaHelperException e) {
            logger.error("SZWJ_SignData() catch CaHelperException: " + e.getMessage());
        }

        // 生成返回结果
        EventValue eventValue = new EventValue();
        eventValue.setSignedData(signedData);
        eventValue.setTimestamp(timestamp);
        return JsonHelper.generateResponse(0, "sign data successfully", eventValue);
    }

    public static String SZWJ_VerSignData(String server, String sn, String data, String signValue,
        Boolean detach) {
        logger.info("SZWJ_VerSignData(): begin to verify signed data.");
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            logger.error(
                "SZWJ_VerSignData(): failed to verify signed data, error: incorrect serial number.");
            return JsonHelper.generateResponse(-1,
                "failed to verify signed data, error: incorrect serial number.", null);
        }

        String signCert = "";
        try {
            // step1：本地验签
            helper.VerSignData(data, signValue);
            signCert = helper.GetUserSignCert(sn);
            logger.info(
                "SZWJ_VerSignData(): local verify signed data successfully.");
        } catch (CaHelperException e) {
            return JsonHelper
                .generateResponse(2, "failed to verify signed data, error: " + e.getMessage(),
                    null);
        }

        // step2：服务端验签
        if (!Tools.isStringEmpty(server)) {
            // 通过认证服务进行验签
            try {
                JsonObject jsonObject = new JsonObject();
                jsonObject.addProperty("authority", helper.GetAuthority());
                jsonObject.addProperty("sn", sn);
                jsonObject.addProperty("signCert", signCert);
                jsonObject.addProperty("sourceData", data);
                jsonObject.addProperty("signedData", signValue);
                jsonObject.addProperty("detach", detach ? 1 : 0);
                String responseJson = HttpClientUtil.HttpPostWithJson(
                    String.format("http://%s:%d/v1.0/verify/data", server, remotePort),
                    jsonObject.toString());
                logger.info("SZWJ_VerSignData(): verify signed data from remote successfully.");
                return responseJson;
            } catch (IOException e) {
                logger.error("SZWJ_VerSignData() catch IOException: " + e.getMessage());
                return JsonHelper.generateResponse(3, String
                        .format("failed to verify signed data, catch IOException: %s.", e.getMessage()),
                    null);
            } catch (CaHelperException e) {
                System.out
                    .println("SZWJ_VerSignData() catch CaHelperException: " + e.getMessage());
                return e.getMessage();
            }
        }
        return JsonHelper.generateResponse(0, "verify signed data successfully", null);
    }

    /**
     * 获取所有证书的签章图片
     *
     * @return 所有证书签章图片二进制流格式json字符串
     */
    public static String SZWJ_GetPicS() {
        List<Dictionary> totalDictionaryList = new ArrayList<Dictionary>();

        List<Dictionary> netcaDictionaryList = netca.GetPicS();
        totalDictionaryList.addAll(netcaDictionaryList);

        List<Dictionary> bjcaDictionaryList = bjca.GetPicS();
        totalDictionaryList.addAll(bjcaDictionaryList);

        EventValue eventValue = new EventValue();
        eventValue.setDictionary(totalDictionaryList);
        return JsonHelper.generateResponse(0, "get pics successfully", eventValue);
    }

    public static String SZWJ_GetUserCert(String sn) {
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            return JsonHelper
                .generateResponse(-1, "failed to get user cert, error: incorrect serial number.",
                    null);
        }

        String base64Cert = "";
        try {
            base64Cert = helper.GetUserSignCert(sn);
        } catch (CaHelperException e) {
            return JsonHelper.generateResponse(1,
                String.format("failed to get user cert, error: %s.", e.getMessage()), null);
        }

        EventValue eventValue = new EventValue();
        eventValue.setBase64Cert(base64Cert.replace("\r\n", ""));
        return JsonHelper.generateResponse(0, "get user cert successfully", eventValue);
    }

    public static String SZWJ_SignWithTSA(String server, String sn, String data) {
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            return JsonHelper
                .generateResponse(-1,
                    "failed to sign with TSA, error: incorrect serial number.",
                    null);
        }

        // 通过认证服务进行时间戳签名
        try {
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("authority", helper.GetAuthority());
            jsonObject.addProperty("sourceData", data); // 签名后的数据
            String responseJson = HttpClientUtil.HttpPostWithJson(
                String.format("http://%s:%d/v1.0/sign/timestamp", server, remotePort),
                jsonObject.toString());
            logger.info("SZWJ_SignDataWithTSA(): sign data with tsa from remote successfully.");
            return responseJson;
        } catch (IOException e) {
            logger.error("SZWJ_SignDataWithTSA() catch IOException: " + e.getMessage());
            return JsonHelper.generateResponse(5,
                String.format("failed to sign data, catch IOException: %s.", e.getMessage()),
                null);
        } catch (CaHelperException e) {
            logger.error("SZWJ_SignDataWithTSA() catch CaHelperException: " + e.getMessage());
            return JsonHelper.generateResponse(6,
                String.format("failed to sign data, catch CaHelperException: %s.",
                    e.getMessage()),
                null);
        }
    }

    public static String SZWJ_GetPicBySN(String sn) {
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            return JsonHelper
                .generateResponse(-1, "failed to get user cert, error: incorrect serial number.",
                    null);
        }

        Dictionary dictionary = helper.GetPicBySN(sn);

        List<Dictionary> totalDictionaryList = new ArrayList<Dictionary>();
        totalDictionaryList.add(dictionary);

        EventValue eventValue = new EventValue();
        eventValue.setDictionary(totalDictionaryList);
        return JsonHelper.generateResponse(0, "get pic by sn successfully", eventValue);
    }

    public static String SZWJ_LoginByToken(String server, String businessSystemCode,
        String encryptedToken) {
        // 通过证书私钥解密动态口令
        String token = "";
        try {
            token = new String(Base64Util.decode(encryptedToken));
        } catch (IOException e) {
            return JsonHelper.generateResponse(-1,
                String.format("failed to login by encrypted token, error: %s.", e.getMessage()),
                null);
        }

        String[] tokenArray = token.split("\\|\\|\\|");
        String sn = tokenArray[0];
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            logger.error(
                "SZWJ_LoginByToken(): failed to login by encrypted token, error: incorrect serial number.");
            return JsonHelper.generateResponse(-1,
                "failed to login by encrypted token, error: incorrect serial number.", null);
        }

        try {
            // 通过认证服务器验证动态口令的时效性
            String authority = helper.GetAuthority();
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("businessSystemCode", businessSystemCode);
            jsonObject.addProperty("businessTypeCode", BusinessTypeCode_Login);
            jsonObject.addProperty("authority", authority);
            jsonObject.addProperty("encryptedToken", encryptedToken);

            HttpClientUtil.HttpPostWithJson(
                String.format("http://%s:%d/v1.0/login/verifytoken", server, remotePort),
                jsonObject.toString());
            logger.info("SZWJ_LoginByToken(): verify token from remote successfully.");
        } catch (IOException e) {
            logger.error("SZWJ_LoginByToken() catch IOException: " + e.getMessage());
            return JsonHelper.generateResponse(2,
                String.format("login by token failed, catch IOException: %s.", e.getMessage()),
                null);
        } catch (CaHelperException e) {
            logger.error("SZWJ_LoginByToken() catch CaHelperException: " + e.getMessage());
            return e.getMessage();
        }

        try {
            String pwd = tokenArray[1];
            helper.Login(sn, pwd);
            System.out
                .println("SZWJ_LoginByToken(): parse encryptedToken and login successfully.");

            Loginer loginer = new Loginer();
            loginer.setPwd(pwd);
            loginer.setEmployeeNum(tokenArray[2]);
            loginer.setSn(sn);
            EventValue eventValue = new EventValue();
            eventValue.setLoginer(loginer);
            return JsonHelper
                .generateResponse(0, "login by encrypted token successfully", eventValue);
        } catch (CaHelperException e) {
            return JsonHelper.generateResponse(2,
                String.format("login by encrypted token failed, error: %s.", e.getMessage()),
                null);
        }
    }

    public static String SZWJ_GenSignPDF(String server, String businessSystemCode,
        String businessTypeCode, String sn, String signedDigest) {
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            logger.error(
                "SZWJ_GenSignPDF(): failed to gen sign PDF, error: incorrect serial number.");
            return JsonHelper
                .generateResponse(-1, "failed to gen sign PDF, error: incorrect serial number.",
                    null);
        }

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("businessSystemCode", businessSystemCode);
        jsonObject.addProperty("businessTypeCode", businessTypeCode);
        jsonObject.addProperty("authority", helper.GetAuthority());
        jsonObject.addProperty("signedDigest", signedDigest);
        try {
            String responseJson = HttpClientUtil.HttpPostWithJson(
                String.format("http://%s:%d/v1.0/sign/pdf/seal", server, remotePort),
                jsonObject.toString());
            return responseJson;
        } catch (IOException e) {
            logger.error("SZWJ_GenSignPDF() catch IOException: " + e.getMessage());
            return JsonHelper.generateResponse(2,
                String.format("failed to gen PDF digest, catch IOException: %s.", e.getMessage()),
                null);
        } catch (CaHelperException e) {
            logger.error("SZWJ_GenSignPDF() catch CaHelperException: " + e.getMessage());
            return JsonHelper.generateResponse(3, String
                    .format("failed to gen PDF digest, catch CaHelperException: %s.", e.getMessage()),
                null);
        }
    }

    public static String SZWJ_SignPDF(String server, String businessSystemCode,
        String businessTypeCode, String encryptedToken, String pdfByte, String position,
        Boolean withTsa) {
        String errMsg = "";
        // 通过解密动态token得sn
        String token = "";
        try {
            token = new String(Base64Util.decode(encryptedToken));
        } catch (IOException e) {
            errMsg = String.format("failed to sign PDF, error: %s.", e.getMessage());
            logger.error("SZWJ_SignPDF(): {}", errMsg);
            return JsonHelper.generateResponse(-1, errMsg, null);
        }

        String[] tokenArray = token.split("\\|\\|\\|");
        String sn = tokenArray[0];
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            errMsg = "failed to sign PDF, error: incorrect serial number.";
            logger.error("SZWJ_SignPDF(): {}", errMsg);
            return JsonHelper.generateResponse(-1, errMsg, null);
        }

        ResponseBody responseBody = null;
        PDFInfo pdfInfo = null;
        try {
            String signCert = helper.GetUserSignCert(sn);
            Dictionary dictionary = helper.GetPicBySN(sn);
            String sealImg = dictionary.getSignFlow();

            JsonObject jsonObject = new JsonObject();
            if (NETCA_AUTHORITY.equals(helper.GetAuthority())) {
                byte[] pdfByteStream = Base64Util.decode(pdfByte);
                pdfInfo = helper
                    .GenPDFDigest(UUID.randomUUID().toString(), pdfByteStream, signCert, sealImg,
                        position);
                jsonObject.addProperty("pdfByte", Base64Util.encode(pdfInfo.getPdfByte()));
            } else if (BJCA_AUTHORITY.equals(helper.GetAuthority())) {
                jsonObject.addProperty("pdfByte", pdfByte);
            }

            jsonObject.addProperty("businessSystemCode", businessSystemCode);
            jsonObject.addProperty("businessTypeCode", businessTypeCode);
            jsonObject.addProperty("authority", helper.GetAuthority());
            jsonObject.addProperty("sn", sn);
            jsonObject.addProperty("signCert", signCert);
            jsonObject.addProperty("sealImg", sealImg);
            jsonObject.addProperty("position", position);
            String responseJson = HttpClientUtil.HttpPostWithJson(String
                    .format("http://%s:%d/v1.0/sign/pdf/digest", server, remotePort),
                jsonObject.toString());
            responseBody = JsonHelper.parseResponse(responseJson);
        } catch (CaHelperException e) {
            errMsg = String
                .format("failed to gen PDF digest, catch CaHelperException: %s.", e.getMessage());
            logger.error("SZWJ_GenPDFDigest(): {}", errMsg);
            return JsonHelper.generateResponse(3, errMsg, null);
        } catch (IOException e) {
            errMsg = String
                .format("failed to gen PDF digest, catch IOException: %s.", e.getMessage());
            logger.error("SZWJ_GenPDFDigest(): {}", errMsg);
            return JsonHelper.generateResponse(4, errMsg, null);
        }

        // 生成pdf时间戳签名
        if (NETCA_AUTHORITY.equals(helper.GetAuthority())) {
            if (!withTsa) {
                EventValue eventValue = new EventValue();
                eventValue.setSignPdfByte(Base64Util.encode(pdfInfo.getPdfByte()));
                return JsonHelper.generateResponse(0, "sign PDF successfully", eventValue);
            }
        } else if (BJCA_AUTHORITY.equals(helper.GetAuthority())) {
            // 对摘要进行hash签名
            return JsonHelper.generateResponse(0, "sign PDF successfully", null);
        }
        return JsonHelper.generateResponse(0, "sign PDF successfully", null);
    }

    /*
    public static String SZWJ_VerSignPDF(String server, String businessSystemCode,
        String businessTypeCode, String pdfTypeCode, String sn, String signedPath) {
        ICaHelper helper = mSnStore.get(sn);
        if (null == helper) {
            return JsonHelper
                .generateResponse(-1,
                    "failed to verify signed PDF, error: incorrect serial number.",
                    null);
        }

        String signCert = "";
        try {
            // step1：本地验签
            helper.VerSignPDF(signedPath);
            signCert = helper.GetUserSignCert(sn);
        } catch (CaHelperException e) {
            return JsonHelper
                .generateResponse(2, "failed to verify signed PDF, error: " + e.getMessage(),
                    null);
        }

        // step2：服务端验签
        if (!Tools.isStringEmpty(server)) {
            // 通过认证服务进行验签
            try {
                String signedPdfStream = netca.ConvertPDFToBase64Stream(signedPath)
                    .replace("\r\n", "");

                JsonObject jsonObject = new JsonObject();
                jsonObject.addProperty("businessSystemCode", businessSystemCode);
                jsonObject.addProperty("businessTypeCode", businessTypeCode);
                jsonObject.addProperty("authority", helper.GetAuthority());
                jsonObject.addProperty("pdfTypeCode", pdfTypeCode);
                jsonObject.addProperty("signCert", signCert);
                jsonObject.addProperty("signedPdfStream", signedPdfStream);
                String responseJson = HttpClientUtil.HttpPostWithJson(
                    String.format("http://%s:%d/v1.0/verify/pdf/%s", server, remotePort, sn),
                    jsonObject.toString());
                logger.info("SZWJ_VerSignPDF(): verify signed PDF from remote successfully.");
                return responseJson;
            } catch (IOException e) {
                logger.error("SZWJ_VerSignPDF() catch IOException: " + e.getMessage());
                return JsonHelper.generateResponse(3, String
                        .format("failed to verify signed PDF, catch IOException: %s.", e.getMessage()),
                    null);
            } catch (CaHelperException e) {
                System.out
                    .println("SZWJ_VerSignPDF() catch CaHelperException: " + e.getMessage());
                return e.getMessage();
            }
        }
        return JsonHelper.generateResponse(0, "verify signed PDF successfully", null);
    }
    */
}
