package org.szwj.ca.helper.bjca;

import cn.org.bjca.client.exceptions.ApplicationNotFoundException;
import cn.org.bjca.client.exceptions.CommonClientException;
import cn.org.bjca.client.exceptions.InitException;
import cn.org.bjca.client.exceptions.ParameterInvalidException;
import cn.org.bjca.client.exceptions.ParameterOutRangeException;
import cn.org.bjca.client.exceptions.ParameterTooLongException;
import cn.org.bjca.client.exceptions.SVSConnectException;
import cn.org.bjca.client.exceptions.UnkownException;
import cn.org.bjca.client.security.SecurityEngineDeal;
import cn.org.bjca.seal.esspdf.client.message.ChannelMessage;
import cn.org.bjca.seal.esspdf.client.message.ClientSignBean;
import cn.org.bjca.seal.esspdf.client.message.ClientSignMessage;
import cn.org.bjca.seal.esspdf.client.message.RectangleBean;
import cn.org.bjca.seal.esspdf.client.tools.ESSPDFClientTool;
import org.szwj.ca.helper.ICaHelper;
import org.szwj.ca.helper.models.CaHelperException;
import org.szwj.ca.helper.models.Dictionary;
import org.szwj.ca.helper.models.PDFInfo;
import org.szwj.ca.helper.models.UserCert;
import org.szwj.ca.helper.utils.Base64Util;
import org.szwj.ca.helper.utils.PropertiesUtil;
import org.szwj.ca.helper.utils.Tools;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bjca.xtxapp.GetKeyPic;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by maxm on 2017/6/7.
 */
public class Bjca implements ICaHelper {

    private XTXAppCOM com = new XTXAppCOM();

    private Map<String, String> mSnStone = new HashMap<String, String>();

    private static String mTsaProfile;

    private static String mRemoteIP;

    private static int mPort;

    private final Logger logger = LoggerFactory.getLogger(Bjca.class);

    /**
     * Bjca Struct Function
     */
    public Bjca() {
        String configPath = System.getProperty("user.dir") + "/config/CaHelper.properties";
        try {
            Map<String, String> propertiesMap = PropertiesUtil.getPropertiesUtil()
                .GetPropertiesContent(configPath);
            mRemoteIP = propertiesMap.get("bjca.pdf.remoteip");
            mPort = Integer.parseInt(propertiesMap.get("bjca.pdf.remoteport"));
            mTsaProfile = propertiesMap.get("bjca.tsa.profile");
            logger.info("Bjca(): init successfully, bjca.pdf.remoteip:{}, bjca.pdf.remoteport:{}",
                mRemoteIP, mPort);
        } catch (IOException e) {
            logger.error("Bjca(): failed to read properties file, error: {}", e.getMessage());
        } catch (NumberFormatException e) {
            logger.warn("Bjca(): failed to parse remote port");
            mPort = 8888;
        }
    }

    @Override
    public String GetAuthority() {
        return "BJCA";
    }

    private void checkComExecResult() throws CaHelperException {
        if (0 != com.SOF_GetLastError()) {
            // com exec failed, throw error message
            throw new CaHelperException(com.SOF_GetLastErrMsg());
        }
    }

    @Override
    public List<UserCert> GetUserList() throws CaHelperException {
        logger.info("Enter GetUserList()");
        List<UserCert> userCertList = new ArrayList<UserCert>();

        String userListSplice = com.SOF_GetUserList();
        checkComExecResult();
        String[] users = userListSplice.split("&&&");
        if (null == users) {
            return userCertList;
        }
        for (int i = 0; i < users.length; i++) {
            String[] user = users[i].split("\\|\\|");
            if (2 == user.length) {
                UserCert userCert = new UserCert();
                userCert.setUserName(user[0]);
                userCert.setSn(user[1]);
                userCertList.add(userCert);
                mSnStone.put(user[1], user[0]);
            }
        }
        logger.info("Leave GetUserList()");
        return userCertList;
    }

    @Override
    public Boolean Login(String sn, String pwd) throws CaHelperException {
        // 参数校验
        if (Tools.isStringEmpty(sn)) {
            logger.error("Login() error: sn is empty.");
            throw new CaHelperException("sn is empty");
        }
        if (Tools.isStringEmpty(pwd)) {
            logger.error("Login() error: pwd is empty.");
            throw new CaHelperException("pwd is empty");
        }

        if (!com.SOF_Login(sn, pwd)) {
            logger.error("Login() error: incorrect password.");
            throw new CaHelperException("incorrect password");
        }
        return true;
    }

    @Override
    public String Login(String sn, String pwd, String randomNum) throws CaHelperException {
        logger.info("Enter Login()");
        // 参数校验
        if (Tools.isStringEmpty(sn)) {
            logger.error("Login() error: sn is empty.");
            throw new CaHelperException("sn is empty");
        }
        if (Tools.isStringEmpty(pwd)) {
            logger.error("Login() error: pwd is empty.");
            throw new CaHelperException("pwd is empty");
        }
        if (Tools.isStringEmpty(randomNum)) {
            logger.error("Login() error: randomNum is empty.");
            throw new CaHelperException("randomNum is empty");
        }

        if (!com.SOF_Login(sn, pwd)) {
            logger.error("Login() error: incorrect password.");
            throw new CaHelperException("incorrect password");
        }

        short dwFlag = 0;
        String signedRandomNum = null;
        try {
            signedRandomNum = com.SOF_SignMessage(dwFlag, sn, randomNum);
        } catch (ClassCastException e) {
            logger
                .error(String.format("Login() error: failed to sign message, %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }

        checkComExecResult();
        logger.info("Leave Login()");
        return signedRandomNum;
    }

    @Override
    public String GetCheckKey(String base64Cert) throws CaHelperException {
        logger.info("Enter GetCheckKey()");
        String str = com.SOF_GetCertInfoByOid(base64Cert, "1.2.86.11.7.1");
        if (Tools.isStringEmpty(str)) {
            str = com.SOF_GetCertInfoByOid(base64Cert, "1.2.86.11.7.8");
        }
        if (Tools.isStringEmpty(str)) {
            str = com.SOF_GetCertInfoByOid(base64Cert, "2.16.840.1.113732.2");
        }
        if (Tools.isStringEmpty(str)) {
            str = com.SOF_GetCertInfoByOid(base64Cert, "1.2.156.112562.2.1.1.4");
        }
        checkComExecResult();
        logger.info("Leave GetCheckKey()");
        return str;
    }

    @Override
    public String SignData(String sn, String data, Boolean detach) throws CaHelperException {
        logger.info("Enter SignData(), detach:{}", detach);
        int dwFlag = detach ? 0 : 1;
        String signedData = com.SOF_SignMessage(dwFlag, sn, data);
        checkComExecResult();
        logger.info("Leave SignData()");
        return signedData;
    }

    public String SignWithTSA(String base64Cert, String data) throws CaHelperException {
        logger.debug("Enter SignDataWithTSA()");
        SecurityEngineDeal.setProfilePath(mTsaProfile);
        SecurityEngineDeal sed = null;
        try {
            sed = SecurityEngineDeal.getInstance("TSSDefault");
            String tsReq = sed.createTSRequest(data.getBytes(), true);
            String tsRep = sed.createTS(tsReq);
            int verifyRes = sed.verifyTS(tsRep, data.getBytes());
            switch (verifyRes) {
                case 1:
                    break;
                case -1:
                    logger.error("SignDataWithTSA(): 时间戳验证不通过.");
                    throw new CaHelperException("时间戳验证不通过");
                case -2:
                    logger.error("SignDataWithTSA(): 原文验证不通过.");
                    throw new CaHelperException("原文验证不通过");
                case -3:
                    logger.error("SignDataWithTSA(): 不是所信任的根.");
                    throw new CaHelperException("不是所信任的根");
                case -4:
                    logger.error("SignDataWithTSA(): 证书未生效.");
                    throw new CaHelperException("证书未生效");
                case -5:
                    logger.error("SignDataWithTSA(): 查询不到此证书.");
                    throw new CaHelperException("查询不到此证书");
                case -6:
                    logger.error("SignDataWithTSA(): 签发时间戳时服务器证书过期.");
                    throw new CaHelperException("签发时间戳时服务器证书过期");
                default:
                    logger.error("SignDataWithTSA(): 未知错误.");
                    throw new CaHelperException("未知错误");
            }
            logger.debug("Leave SignDataWithTSA()");
            return tsRep;
        } catch (SVSConnectException e) {
            logger.error("SignDataWithTSA(): 连接服务端异常.");
            throw new CaHelperException("连接服务端异常:" + e.getMessage());
        } catch (ApplicationNotFoundException e) {
            logger.error("SignDataWithTSA(): 此应用名不存在.");
            throw new CaHelperException("此应用名不存在:" + e.getMessage());
        } catch (InitException e) {
            logger.error("SignDataWithTSA(): 初始化异常.");
            throw new CaHelperException("初始化异常:" + e.getMessage());
        } catch (ParameterInvalidException e) {
            logger.error("SignDataWithTSA(): 参数无效.");
            throw new CaHelperException("参数无效:" + e.getMessage());
        } catch (ParameterTooLongException e) {
            logger.error("SignDataWithTSA(): 参数过长.");
            throw new CaHelperException("参数过长:" + e.getMessage());
        }
    }

    @Override
    public void VerSignData(String data, String signValue)
        throws CaHelperException {
        logger.info("Enter VerSignData()");
        Boolean verifiedResult = com.SOF_VerifySignedMessage(signValue, data);
        if (!verifiedResult) {
            throw new CaHelperException(com.SOF_GetLastErrMsg());
        }
        logger.info("Leave VerSignData()");
    }

    @Override
    public String GetSignText(String signValue) {
        return "";
    }

    @Override
    public List<Dictionary> GetPicS() {
        logger.info("Enter GetPicS()");
        List<Dictionary> dictionaryList = new ArrayList<Dictionary>();

        GetKeyPic toolPic = null;
        try {
            toolPic = new GetKeyPic();
        } catch (Exception e) {
            logger.error("GetPicS() error: {}.", e.getMessage());
            return dictionaryList;
        }

        for (Map.Entry<String, String> entry : mSnStone.entrySet()) {
            Dictionary dictionary = new Dictionary();
            String sn = entry.getKey();
            dictionary.setSn(sn);
            dictionary.setUserName(entry.getValue());
            dictionary.setSignFlow(toolPic.GetPic(sn));
            dictionaryList.add(dictionary);
        }

        logger.info("Leave GetPicS()");
        return dictionaryList;
    }

    @Override
    public String GetUserSignCert(String sn) throws CaHelperException {
        logger.info("Enter GetUserSignCert()");
        String base64Cert = com.SOF_ExportUserCert(sn);
        checkComExecResult();
        logger.info("Leave GetUserSignCert()");
        return base64Cert;
    }

    @Override
    public String GetUserCryptionCert(String sn) throws CaHelperException {
        logger.info("Enter GetUserCryptionCert()");
        String base64Cert = com.SOF_ExportUserCert(sn);
        checkComExecResult();
        logger.info("Leave GetUserCryptionCert()");
        return base64Cert;
    }

    @Override
    public String GetRandomNum() {
        logger.info("Enter GetRandomNum()");
        String randomNum = com.SOF_GenRandom(8);
        logger.info("Leave GetRandomNum()");
        return randomNum;
    }

    @Override
    public Dictionary GetPicBySN(String sn) {
        logger.info("Enter GetPicBySN()");
        GetKeyPic toolPic = null;
        try {
            toolPic = new GetKeyPic();
        } catch (Exception e) {
            logger.error("GetPicS() error: {}.", e.getMessage());
            return null;
        }
        Dictionary dictionary = new Dictionary();
        dictionary.setSn(sn);
        dictionary.setUserName(mSnStone.get(sn));
        dictionary.setSignFlow(toolPic.GetPic(sn));
        logger.info("Leave GetPicBySN()");
        return dictionary;
    }

    @Override
    public String PublicEncrypt(String base64Cert, String sourceData) throws CaHelperException {
        return null;
    }

    @Override
    public String PriKeyDecrypt(String sn, String encryptedData) throws CaHelperException {
        return null;
    }

    @Override
    public void VerSignPDF(String signedPath) throws CaHelperException {

    }

    @Override
    public String SignFileWithTSA(String sn, String filePath)
        throws CaHelperException {
        logger.info("Enter SignFileWithTSA()");
        SecurityEngineDeal.setProfilePath(mTsaProfile);
        SecurityEngineDeal sed = null;
        try {
            sed = SecurityEngineDeal.getInstance("TSSDefault");
            String tsReq = sed.createTSRequestByFile(filePath, true);
            String tsResp = sed.createTS(tsReq);
            int verifyRes = sed.verifyTSByFile(tsResp, filePath);
            switch (verifyRes) {
                case 1:
                    break;
                case -1:
                    logger.info("SignDataWithTSA(): 时间戳验证不通过.");
                    throw new CaHelperException("时间戳验证不通过");
                case -2:
                    logger.info("SignDataWithTSA(): 原文验证不通过.");
                    throw new CaHelperException("原文验证不通过");
                case -3:
                    logger.info("SignDataWithTSA(): 不是所信任的根.");
                    throw new CaHelperException("不是所信任的根");
                case -4:
                    logger.info("SignDataWithTSA(): 证书未生效.");
                    throw new CaHelperException("证书未生效");
                case -5:
                    logger.info("SignDataWithTSA(): 查询不到此证书.");
                    throw new CaHelperException("查询不到此证书");
                case -6:
                    logger.info("SignDataWithTSA(): 签发时间戳时服务器证书过期.");
                    throw new CaHelperException("签发时间戳时服务器证书过期");
                default:
                    logger.info("SignDataWithTSA(): 未知错误.");
                    throw new CaHelperException("未知错误");
            }
            logger.info("Leave SignDataWithTSA()");
            return tsReq;
        } catch (ParameterOutRangeException e) {
            logger.info("SignDataWithTSA(): 参数越界.");
            throw new CaHelperException("参数越界:" + e.getMessage());
        } catch (SVSConnectException e) {
            logger.info("SignDataWithTSA(): 连接服务端异常.");
            throw new CaHelperException("连接服务端异常:" + e.getMessage());
        } catch (InitException e) {
            logger.info("SignDataWithTSA(): 初始化异常.");
            throw new CaHelperException("初始化异常:" + e.getMessage());
        } catch (UnsupportedEncodingException e) {
            logger.info("SignDataWithTSA(): 不支持的编码格式.");
            throw new CaHelperException("不支持的编码格式:" + e.getMessage());
        } catch (ParameterTooLongException e) {
            logger.info("SignDataWithTSA(): 参数过长.");
            throw new CaHelperException("参数过长:" + e.getMessage());
        } catch (UnkownException e) {
            logger.info("SignDataWithTSA(): 未知异常.");
            throw new CaHelperException("未知异常:" + e.getMessage());
        } catch (ApplicationNotFoundException e) {
            logger.info("SignDataWithTSA(): 此应用名不存在.");
            throw new CaHelperException("此应用名不存在:" + e.getMessage());
        } catch (ParameterInvalidException e) {
            logger.info("SignDataWithTSA(): 参数无效.");
            throw new CaHelperException("参数无效:" + e.getMessage());
        } catch (CommonClientException e) {
            logger.info("SignDataWithTSA(): 客户端通用异常.");
            throw new CaHelperException("客户端通用异常:" + e.getMessage());
        } finally {
            if (null != sed) {
                sed.finalizeEngine();
            }
        }
    }

    @Override
    public PDFInfo GenPDFDigest(String target, byte[] pdfByte, String signCert, String sealImg,
        String position) throws CaHelperException {
        logger.info("Enter GenPDFDigest()");
        String[] positionArray = position.split("\\|\\|");
        if (positionArray.length != 5) {
            logger.error("GenPDFDigest() error: incorrect position.");
            throw new CaHelperException("incorrect position");
        }
        int pageNum;
        float xPos, yPos, width, height;
        try {
            pageNum = Integer.parseInt(positionArray[0]);
            xPos = Float.parseFloat(positionArray[1]);
            yPos = Float.parseFloat(positionArray[2]);
            width = Float.parseFloat(positionArray[3]);
            height = Float.parseFloat(positionArray[4]);
        } catch (NumberFormatException e) {
            logger.error(String.format("GenPDFDigest() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }

        ESSPDFClientTool essPDFClientTool = null;
        try {
            essPDFClientTool = new ESSPDFClientTool(mRemoteIP, mPort);
        } catch (Exception e) {
            logger.error(String.format("GenPDFDigest() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        essPDFClientTool.setTimeout(50 * 1000);
        essPDFClientTool.setRespTimeout(50 * 1000);

        List<ClientSignMessage> clientSignMessages = new ArrayList<ClientSignMessage>();
        ClientSignMessage clientSignMessage = new ClientSignMessage();
        float sealWidth = 0;
        float sealHeight = 0;
        String moveType = "3";
        String searchOrder = "2";
        clientSignMessage.setMoveType(moveType);
        clientSignMessage.setSearchOrder(searchOrder);
        clientSignMessage.setPdfBty(pdfByte);
        clientSignMessage.setFileUniqueId(target);

        RectangleBean bean = new RectangleBean();
        bean.setPageNo(pageNum);
        bean.setLeft(xPos);
        bean.setTop(yPos);
        bean.setRight(width);
        bean.setBottom(height);
        clientSignMessage.setRectangleBean(bean);
        clientSignMessage.setRuleType("2");
        clientSignMessages.add(clientSignMessage);

        ChannelMessage message = null;
        try {
            message = essPDFClientTool
                .genClientSignDigest(clientSignMessages, signCert, sealImg, sealWidth, sealHeight);
        } catch (Exception e) {
            logger.error(String.format("GenPDFDigest() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        if (null != message && "200".equals(message.getStatusCode())) {
            logger.info("GenPDFDigest(): gen PDF digest successfully");
            logger.info("Leave GenPDFDigest()");
            PDFInfo pdfInfo = new PDFInfo();
            pdfInfo.setPdfDigest(new String(message.getBody()));
            pdfInfo.setPdfByte(pdfByte);
            return pdfInfo;
        } else {
            logger.error(String
                .format("GenPDFDigest(): failed to gen PDF digest, statusCode:%s, statusInfo:%s.",
                    message.getStatusCode(), message.getStatusInfo()));
            throw new CaHelperException("failed to gen PDF digest from remote service.");
        }
    }

    @Override
    public String GenSignPDF(String signedDigest) throws CaHelperException {
        logger.info("Enter GenSignPDF()");
        ESSPDFClientTool essPDFClientTool = null;
        try {
            essPDFClientTool = new ESSPDFClientTool(mRemoteIP, mPort);
        } catch (Exception e) {
            logger.error(String.format("GenSignPDF() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        essPDFClientTool.setTimeout(50 * 1000);
        essPDFClientTool.setRespTimeout(50 * 1000);

        ChannelMessage signMessage = null;
        try {
            signMessage = essPDFClientTool.genClientSign(signedDigest);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if ("200".equals(signMessage.getStatusCode())) {
            //获取客户端签章bean
            List signBeanList = signMessage.getClientSignList();

            for (int i = 0; i < signBeanList.size(); i++) {
                ClientSignBean clientSignBean = (ClientSignBean) signBeanList.get(i);
                logger.info("Leave GenSignPDF()");
                return Base64Util.encode(clientSignBean.getPdfBty());
            }
        } else {
            logger.error(String
                .format("GenPDFDigest(): failed to gen sign PDF, statusCode:%s, statusInfo:%s.",
                    signMessage.getStatusCode(), signMessage.getStatusInfo()));
            throw new CaHelperException("failed to gen sign PDF from remote service.");
        }
        throw new CaHelperException(
            "failed to gen sign PDF from remote service, missing client sign bean.");
    }

    @Override
    public String GetCertInfo(String base64Cert, int type) throws CaHelperException {
        logger.info("Enter GetCertInfo()");
        String certInfo = com.SOF_GetCertInfo(base64Cert, type);
        logger.info("Leave GetCertInfo()");
        return certInfo;
    }
}
