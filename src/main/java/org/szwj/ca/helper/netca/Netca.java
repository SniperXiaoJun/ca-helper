package org.szwj.ca.helper.netca;

import org.szwj.ca.helper.ICaHelper;
import org.szwj.ca.helper.models.CaHelperException;
import org.szwj.ca.helper.models.Dictionary;
import org.szwj.ca.helper.models.PDFInfo;
import org.szwj.ca.helper.models.UserCert;
import org.szwj.ca.helper.utils.FileUtil;
import org.szwj.ca.helper.utils.PropertiesUtil;
import org.szwj.ca.helper.utils.Tools;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import net.netca.pki.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by maxm on 2017/6/7.
 */
public class Netca implements ICaHelper {

    private NetcaPic netcaPic = new NetcaPic();

    private Map<String, String> mCheckKeyStone = new HashMap<String, String>();

    private Map<String, Certificate> mSignCertStone = new HashMap<String, Certificate>();

    private Map<String, Certificate> mCertCryptionStone = new HashMap<String, Certificate>();

    private static String pdfTmpPath;

    private static String tsaUrl;

    private final Logger logger = LoggerFactory.getLogger(Netca.class);

    /**
     * Netca 构造函数
     */
    public Netca() {
        String configPath = System.getProperty("user.dir") + "/config/CaHelper.properties";
        try {
            Map<String, String> propertiesMap = PropertiesUtil.getPropertiesUtil()
                .GetPropertiesContent(configPath);
            pdfTmpPath = propertiesMap.get("netca.pdf.tmppath");
            tsaUrl = propertiesMap.get("netca.tsa.remoteurl");
            logger.info("Netca(): init successfully, netca.pdf.tmppath:{}, netca.tsa.remoteurl:{}",
                pdfTmpPath, tsaUrl);
        } catch (IOException e) {
            logger.error("Netca(): failed to read properties file, error: {}", e.getMessage());
        }
    }

    @Override
    public String GetAuthority() {
        return "NETCA";
    }

    /**
     * 重新从驱动中获取证书信息
     */
    private Boolean refresh() {
        // 清空历史证书
        mCheckKeyStone.clear();
        mSignCertStone.clear();
        mCertCryptionStone.clear();

        // 从驱动中获取证书信息
        CertStore oCertStore = null;
        try {
            oCertStore = new CertStore(CertStore.CURRENT_USER, CertStore.MY);
            if (null == oCertStore) {
                logger.error("refresh(): failed to open cert store.");
                return false;
            }
            int Count = oCertStore.getCertificateCount();
            for (int i = 0; i < Count; i++) {
                Certificate oCert = oCertStore.getCertificate(i);
                if (null == oCert) {
                    logger.warn("refresh(): failed to get certificate, index: {}.", i);
                    continue;
                }
                if (!oCert.getIssuer().contains("O=NETCA")) {
                    logger.warn("refresh(): cert's issuer doesn't contain NETCA, ignore.");
                    continue;
                }
                int kUsage = oCert.getKeyUsage();
                // 过滤证书：密钥用法(getKeyUsage)
                if (3 == kUsage) {
                    mCheckKeyStone
                        .put(oCert.getSerialNumber(), NetcaPKI.getX509CertificateInfo(oCert, 9));
                    mSignCertStone.put(oCert.getSerialNumber(), oCert);
                } else if (12 == kUsage) {
                    mCertCryptionStone.put(NetcaPKI.getX509CertificateInfo(oCert, 9), oCert);
                }
            }
            logger.info("get certificate list by cert store success.");
        } catch (PkiException e) {
            logger.error("refresh() catch PkiException", e);
            return false;
        } finally {
            if (null != oCertStore) {
                oCertStore.close();
            }
        }
        return true;
    }

    @Override
    public List<UserCert> GetUserList() throws CaHelperException {
        logger.info("Enter GetUserList()");
        List<UserCert> userCertList = new ArrayList<UserCert>();

        // 刷新证书
        if (!this.refresh()) {
            return userCertList;
        }

        try {
            for (Map.Entry<String, Certificate> entry : mSignCertStone.entrySet()) {
                Certificate oCert = entry.getValue();
                if (null == oCert || null == oCert.getIssuer()) {
                    logger.error("GetUserList() error: oCert or oCert.getIssuer is null.");
                    throw new CaHelperException("oCert or oCert.getIssuer is null");
                }
                UserCert userCert = new UserCert();
                userCert.setUserName(NetcaPKI.getX509CertificateInfo(oCert, 12));
                userCert.setSn(oCert.getSerialNumber());
                userCertList.add(userCert);
            }
        } catch (PkiException e) {
            logger.error(String.format("GetUserList() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
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
        Certificate oCert = mSignCertStone.get(sn);
        if (null == oCert) {
            logger.error("Login() error: oCert is null.");
            throw new CaHelperException("oCert is null");
        }

        if (!oCert.verifyUserPwd(pwd)) {
            logger.error("Login() error: incorrect password.");
            throw new CaHelperException("incorrect password");
        }
        return true;
    }

    @Override
    public String Login(String sn, String pwd, String randomNum) throws CaHelperException {
        logger.info("Enter Login()");
        // 参数校验
        if (Tools.isStringEmpty(randomNum)) {
            logger.error("Login() error: randomNum is empty.");
            throw new CaHelperException("randomNum is empty");
        }

        Login(sn, pwd);
        Certificate oCert = mSignCertStone.get(sn);

        String signedRandomNum = "";
        try {
            Boolean detach = true;
            signedRandomNum = NetcaPKI.signedDataByCertificate(oCert, randomNum, !detach, null);
        } catch (PkiException e) {
            logger.error(String.format("Login() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave Login()");
        return signedRandomNum;
    }

    @Override
    public String GetCheckKey(String base64Cert) throws CaHelperException {
        logger.info("Enter GetCheckKey()");
        String checkKey = "";
        try {
            byte[] bCert = NetcaPKI.base64Decode(base64Cert);
            Certificate oCert = new Certificate(bCert);
            checkKey = NetcaPKI.getX509CertificateInfo(oCert, 9);
        } catch (PkiException e) {
            logger.error(String.format("GetCheckKey() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave GetCheckKey()");
        return checkKey;
    }

    @Override
    public String SignData(String sn, String data, Boolean detach) throws CaHelperException {
        logger.info("Enter SignData(), detach:{}", detach);
        // 参数校验
        if (Tools.isStringEmpty(sn)) {
            logger.error("SignData() error: sn is empty.");
            throw new CaHelperException("sn is empty");
        }
        if (Tools.isStringEmpty(data)) {
            logger.error("SignData() error: data is empty.");
            throw new CaHelperException("data is empty");
        }

        Certificate oCert = mSignCertStone.get(sn);
        if (null == oCert) {
            logger.error("SignData() error: oCert is null.");
            throw new CaHelperException("oCert is null");
        }

        String signedData = "";
        try {
            signedData = NetcaPKI.signedDataByCertificate(oCert, data, !detach, null);
        } catch (PkiException e) {
            logger.error(String.format("SignData() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave SignData()");
        return signedData;
    }

    @Override
    public String SignWithTSA(String base64Cert, String date) throws CaHelperException {
        String timestamp = null;
        SignedData signedData = null;

        try {
            byte[] bCert = NetcaPKI.base64Decode(base64Cert);
            Certificate oCert = new Certificate(bCert);
            timestamp = NetcaPKI.signedDataWithTSA(oCert, date, tsaUrl, true);
        } catch (Exception e) {
            logger.error(String.format("SignWithTSA() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        } finally {
            if (null != signedData) {
                signedData.free();
            }
            signedData = null;
        }

        return timestamp.replace("\r\n", "");
    }

    @Override
    public void VerSignData(String data, String signValue)
        throws CaHelperException {
        logger.info("Enter VerSignData()");
        SignedData signedData = null;
        try {
            NetcaPKI.verifySignedData(data, signValue);
        } catch (PkiException e) {
            logger.error(String.format("VerSignData() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            logger.error(String.format("VerSignData() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave VerSignData()");
    }

    @Override
    public String GetSignText(String signValue) throws CaHelperException {
        logger.info("Enter GetSignText()");
        // 参数校验
        if (Tools.isStringEmpty(signValue)) {
            logger.error("GetSignText() error: signValue is empty.");
            return "";
        }

        byte[] originalBytes = null;
        try {
            SignedData signedData = new SignedData(false);
            byte[] bSignature = NetcaPKI.base64Decode(signValue);
            signedData.verifyInit();
            originalBytes = signedData.verifyUpdate(bSignature);
            signedData.verifyFinal();
            signedData.free();
        } catch (PkiException e) {
            logger.error(String.format("GetSignText() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave GetSignText()");
        return new String(originalBytes);
    }

    @Override
    public List<Dictionary> GetPicS() {
        logger.info("Enter GetPicS()");
        List<Dictionary> dictionaryList = new ArrayList<Dictionary>();

        for (Map.Entry<String, Certificate> entry : mSignCertStone.entrySet()) {
            Dictionary dictionary = new Dictionary();
            try {
                dictionary.setSn(entry.getKey());
                Certificate oCert = entry.getValue();
                dictionary.setUserName(NetcaPKI.getX509CertificateInfo(oCert, 12));
                String base64Cert = NetcaPKI.getX509CertificateInfo(oCert, 0).replace("\r\n", "");
                String base64SignFlow = netcaPic.GetBase64ImgFromDevByCert(base64Cert);
                dictionary.setSignFlow(base64SignFlow);
            } catch (PkiException e) {
                logger.error("GetPicS() error: {}.", e.getMessage());
                continue;
            }
            dictionaryList.add(dictionary);
        }

        logger.info("Leave GetPicS()");
        return dictionaryList;
    }

    @Override
    public String GetUserSignCert(String sn) throws CaHelperException {
        logger.info("Enter GetUserSignCert()");
        Certificate oCert = mSignCertStone.get(sn);
        if (null == oCert) {
            logger.error("GetUserSignCert() error: oCert is null.");
            throw new CaHelperException("oCert is null");
        }
        String base64Cert = "";
        try {
            base64Cert = NetcaPKI.getX509CertificateInfo(oCert, 0);
        } catch (PkiException e) {
            logger.error(String.format("GetUserSignCert() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave GetUserSignCert()");
        return base64Cert;
    }

    @Override
    public String GetUserCryptionCert(String sn) throws CaHelperException {
        logger.info("Enter GetUserCryptionCert()");
        String checkKey = mCheckKeyStone.get(sn);
        if (Tools.isStringEmpty(checkKey)) {
            logger.error("GetUserCryptionCert() error: checkKey is null.");
            throw new CaHelperException("checkKey is null");
        }
        Certificate oCert = mCertCryptionStone.get(checkKey);
        if (null == oCert) {
            logger.error("GetUserCryptionCert() error: oCert is null.");
            throw new CaHelperException("oCert is null");
        }
        String base64Cert = "";
        try {
            base64Cert = NetcaPKI.getX509CertificateInfo(oCert, 0);
        } catch (PkiException e) {
            logger.error(String.format("GetUserCryptionCert() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave GetUserCryptionCert()");
        return base64Cert;
    }

    @Override
    public String GetRandomNum() {
        logger.info("Enter GetRandomNum()");
        try {
            byte[] bRandomNum = NetcaPKI.getRandom(8);
            logger.info("Leave GetRandomNum()");
            return NetcaPKI.base64Encode(bRandomNum);
        } catch (PkiException e) {
            logger.error(String.format("GetRandomNum() error: %s.", e.getMessage()));
            return "";
        }
    }

    @Override
    public Dictionary GetPicBySN(String sn) {
        Certificate oCert = mSignCertStone.get(sn);
        if (null == oCert) {
            logger.error("GetPicBySN() error: oCert is null.");
            return null;
        }

        try {
            Dictionary dictionary = new Dictionary();
            dictionary.setSn(sn);
            dictionary.setUserName(NetcaPKI.getX509CertificateInfo(oCert, 12));
            String base64Cert = NetcaPKI.getX509CertificateInfo(oCert, 0).replace("\r\n", "");
            String base64SignFlow = netcaPic.GetBase64ImgFromDevByCert(base64Cert);
            dictionary.setSignFlow(base64SignFlow);
            return dictionary;
        } catch (PkiException e) {
            logger.error(String.format("GetPicBySN() error: %s.", e.getMessage()));
            return null;
        }
    }

    @Override
    public String PublicEncrypt(String base64Cert, String sourceData) throws CaHelperException {
        logger.info("Enter PublicEncrypt()");
        String encryptedData = "";
        try {
            byte[] bCert = NetcaPKI.base64Decode(base64Cert);
            Certificate oCert = new Certificate(bCert);
            encryptedData = NetcaPKI.envelopedData(oCert, sourceData.getBytes());
        } catch (PkiException e) {
            logger.error(String.format("PublicEncrypt() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave PublicEncrypt()");
        return encryptedData;
    }

    @Override
    public String PriKeyDecrypt(String sn, String encryptedData) throws CaHelperException {
        logger.info("Enter PriKeyDecrypt()");
        byte[] sourceData = null;
        try {
            sourceData = NetcaPKI.developedData(encryptedData);
        } catch (PkiException e) {
            logger.error(String.format("PriKeyDecrypt() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            logger.error(String.format("PriKeyDecrypt() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave PriKeyDecrypt()");
        return new String(sourceData);
    }

    @Override
    public void VerSignPDF(String signedPath) throws CaHelperException {
        logger.info("Enter VerSignPDF()");
        // 设置待验证文档
        netcaPic.SetVerifyPDF(signedPath, null);
        int signCnt = netcaPic.GetSignaturesCount();
        for (int i = 1; i <= signCnt; i++) {
            // 获取签名域的名称
            String fieldName = netcaPic.GetSignFieldName(i);
            int ret = netcaPic.VerifySignatureByNum(i, 2);
            if (netcaPic.NETCA_PKI_VERIFY_SIGNEDDATA_CERT_FAIL == ret) {
                logger.error("VerSignPDF(): 签名证书验证失败！");
                throw new CaHelperException("签名证书验证失败");
            } else if (netcaPic.NETCA_PKI_SUCCESS != ret) {
                logger.error("VerSignPDF(): 签名所在的原文内容验证失败！文档可能已被篡改！");
                throw new CaHelperException("签名所在的原文内容验证失败！文档可能已被篡改");
            }
        }
        logger.info("VerSignPDF(): 签名所在的原文内容验证成功！");
        logger.info("Leave VerSignPDF()");
    }

    /**
     * PDF 转换 Base64字符串
     *
     * @param srcFile 文件路径
     * @return Base64字符串
     */
    public String ConvertPDFToBase64Stream(String srcFile) throws CaHelperException {
        logger.info("Enter ConvertPDFToBase64Stream().");
        byte[] fileContent = new byte[0];
        try {
            fileContent = NetcaPKI.readFile(srcFile);
        } catch (IOException e) {
            logger.error(String.format("ConvertPDFToBase64Stream() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        if (null == fileContent) {
            logger.error("ConvertPDFToBase64Stream() error: failed to read src file.");
            throw new CaHelperException("failed to read src file");
        }
        String base64Stream = "";
        try {
            base64Stream = NetcaPKI.base64Encode(fileContent);
        } catch (PkiException e) {
            logger.error(String.format("ConvertPDFToBase64Stream() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave ConvertPDFToBase64Stream().");
        return base64Stream;
    }

    /**
     * PDF 转换 Base64字符串
     *
     * @param saveFile 文件路径
     * @param base64FileContent Base64编码文件内容
     */
    public void ConvertBase64StreamToPDF(String saveFile, String base64FileContent)
        throws CaHelperException {
        logger.info("Enter ConvertBase64StreamToPDF().");
        byte[] fileContent = null;
        try {
            fileContent = NetcaPKI.base64Decode(base64FileContent);
        } catch (PkiException e) {
            logger.error(String.format("ConvertBase64StreamToPDF() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        try {
            NetcaPKI.writeFile(saveFile, fileContent);
        } catch (IOException e) {
            logger.error(String.format("ConvertBase64StreamToPDF() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave ConvertBase64StreamToPDF().");
    }

    @Override
    public String SignFileWithTSA(String sn, String filePath)
        throws CaHelperException {
        return null;
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
        int pageNum, xPos, yPos, width, height;
        try {
            pageNum = Integer.parseInt(positionArray[0]);
            xPos = Integer.parseInt(positionArray[1]);
            yPos = Integer.parseInt(positionArray[2]);
            width = Integer.parseInt(positionArray[3]);
            height = Integer.parseInt(positionArray[4]);
        } catch (NumberFormatException e) {
            logger.error("GenPDFDigest() error: {}.", e.getMessage());
            throw new CaHelperException(e.getMessage());
        }
        String returnCode = null;
        String pdfPath = String.format("%s/%s.pdf", pdfTmpPath, UUID.randomUUID().toString());
        try {
            File pdfFile = new File(pdfPath);
            FileUtil.WriteByteArrayToFile(pdfFile, pdfByte);
        } catch (IOException e) {
            logger.error("GenPDFDigest() error: {}.", e.getMessage());
            throw new CaHelperException(e.getMessage());
        }
        try {
            netcaPic.SetSignCert(signCert, null, null);
            netcaPic.SetSignPDF(pdfPath, "");
            netcaPic.SetVisible(true);
            returnCode = netcaPic
                .SealPosition(pdfPath, pageNum, xPos, yPos, width, height, target, sealImg);
        } catch (Exception e) {
            logger.error("GenPDFDigest() error: {}.", e.getMessage());
            throw new CaHelperException(e.getMessage());
        }
        switch (Integer.parseInt(returnCode)) {
            case 0:
                break;
            case -1:
                logger.info("GenPDFDigest(): 失败.");
                throw new CaHelperException("失败");
            case -2:
                logger.info("GenPDFDigest(): 找不到指定的文档.");
                throw new CaHelperException("找不到指定的文档");
            case -3:
                logger.info("GenPDFDigest(): 参数无效.");
                throw new CaHelperException("参数无效");
            default:
                logger.info("GenPDFDigest(): 未知错误.");
                throw new CaHelperException("未知错误");
        }

        // gen PDF Digest
        PDFInfo pdfInfo = new PDFInfo();
        pdfInfo.setPdfDigest(null);
        File pdf = null;
        try {
            pdf = new File(pdfPath);
            byte[] signedPdfByte = FileUtil.ReadFileToByteArray(pdf);
            pdfInfo.setPdfByte(signedPdfByte);
        } catch (IOException e) {
            logger.error("GenPDFDigest() error: {}.", e.getMessage());
            throw new CaHelperException(e.getMessage());
        } finally {
            logger.info("Leave GenPDFDigest()");
            if (null != pdf) {
                pdf.delete();
            }
        }
        return pdfInfo;
    }

    @Override
    public String GenSignPDF(String signedDigest) throws CaHelperException {
        return null;
    }

    @Override
    public String GetCertInfo(String base64Cert, int type) throws CaHelperException {
        logger.info("Enter GetCertInfo()");
        String certInfo = "";
        try {
            byte[] bCert = NetcaPKI.base64Decode(base64Cert);
            Certificate oCert = new Certificate(bCert);
            certInfo = NetcaPKI.getX509CertificateInfo(oCert, type);
        } catch (PkiException e) {
            logger.error(String.format("GetCertInfo() error: %s.", e.getMessage()));
            throw new CaHelperException(e.getMessage());
        }
        logger.info("Leave GetCertInfo()");
        return certInfo;
    }
}
