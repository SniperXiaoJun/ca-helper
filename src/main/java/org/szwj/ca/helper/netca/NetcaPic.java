package org.szwj.ca.helper.netca;

import com.jacob.activeX.ActiveXComponent;
import com.jacob.com.Dispatch;
import com.jacob.com.Variant;

public class NetcaPic {

    public static final int NETCA_PKI_SUCCESS = 1;

    public static final int NETCA_PKI_VERIFY_SIGNEDDATA_CERT_FAIL = -36;

    /**
     * 定义ActiveX对象
     */
    private ActiveXComponent utilToolCom = null;

    private ActiveXComponent creatorCom = null;

    private ActiveXComponent verifierCom = null;

    public NetcaPic() {
        try {
            // Netca.UtilTool
            utilToolCom = new ActiveXComponent("Netca.UtilTool");
            Variant[] varNet = {new Variant()};
            utilToolCom.logCallbackEvent("", varNet);

            // Netca.SignatureCreator
            creatorCom = new ActiveXComponent("Netca.SignatureCreator");
            Variant[] var = {new Variant()};
            creatorCom.logCallbackEvent("", var);

            // Netca.SignatureVerifier
            verifierCom = new ActiveXComponent("Netca.SignatureVerifier");
            Variant[] varSgnV = {new Variant()};
            verifierCom.logCallbackEvent("", varSgnV);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 通过证书获取签章图片的base64编码值
    public String GetBase64ImgFromDevByCert(String base64CertEncode) {
        if (utilToolCom != null) {
            Variant var = Dispatch.call(utilToolCom, "GetBase64ImgFromDevByCert", base64CertEncode);
            return var.toString();
        }
        return "";
    }

    // 设置签名源文件
    public void SetSignPDF(String srcFile, String pwd) {
        if (creatorCom != null) {
            Variant var = Dispatch.call(creatorCom, "SetSignPDF", srcFile, pwd);
        }
    }

    // 选择证书
    public String SelectCert(String issuerName, int flags) {
        if (creatorCom != null) {
            Variant var = Dispatch.call(creatorCom, "SelectCert", issuerName, flags);
            return var.toString();
        }
        return "";
    }

    // （从证书库）选择签名证书
    public String SelectCertEx(String issuerName, int flags) {
        if (creatorCom != null) {
            Variant var = Dispatch.call(creatorCom, "SelectCertEx", issuerName, flags);
            return var.toString();
        }
        return "";
    }


    // 设置签名的PDF文档字节流
    public void SetSignPDFBytes(String pdfIn, String pwd) {
        if (creatorCom != null) {
            Variant var = Dispatch.call(creatorCom, "SetSignPDFBytes", pdfIn, pwd);
        }
    }

    // 设置签名证书
    public boolean SetSignCert(String encodedCert, String hashAlgo, String pwd) {
        if (creatorCom != null) {
            Variant var = Dispatch.call(creatorCom, "SetSignCert", encodedCert, hashAlgo, pwd);
            var.toBoolean();
            return true;
        }
        return false;
    }

    // 设置签名是否显示
    public void SetVisible(boolean isVisible) {
        if (creatorCom != null) {
            Variant var = Dispatch.call(creatorCom, "SetVisible", isVisible);
        }
    }

    // 设置签名是否包含证书吊销信息
    public void SetRevInfoIncludeFlag(boolean isInclude) {
        if (creatorCom != null) {
            Dispatch.call(creatorCom, "SetRevInfoIncludeFlag", isInclude);
        }
    }

    // 设置签名理由
    public void SetReason(String reason) {
        if (creatorCom != null) {
            Dispatch.call(creatorCom, "SetReason", reason);
        }
    }

    // 设置签名地点
    public void SetLocation(String location) {
        if (creatorCom != null) {
            Dispatch.call(creatorCom, "SetLocation", location);
        }
    }

    // 设置OCSP（在线证书状态协议）的访问地址
    public void SetOCSPUrl(String signCertOcspUrl, String caCertOcspUrl) {
        if (creatorCom != null) {
            Dispatch.call(creatorCom, "SetOCSPUrl", signCertOcspUrl, caCertOcspUrl);
        }
    }

    // 设置签名时自动获取吊销信息
    public void SetRevInfoIncludeFlag(Boolean isInclude) {
        if (creatorCom != null) {
            Dispatch.call(creatorCom, "SetRevInfoIncludeFlag", isInclude);
        }
    }

    // 获取待签名PDF文档包含页面的总数
    public int GetPagesCount() {
        if (creatorCom != null) {
            Variant var = Dispatch.call(creatorCom, "GetPagesCount");
            return var.toInt();
        }
        return 0;
    }

    // 对指定的位置进行签名
    public int SignPosition(String savePath, int pageNum, int xPos, int yPos, int width, int height,
        String fieldName, String text) {
        if (creatorCom != null) {
            Variant var = Dispatch
                .call(creatorCom, "Position", savePath, pageNum, xPos, yPos, width, height,
                    fieldName, text);
            return var.toInt();
        }
        return -1;
    }

    // 设置签名时是否包含时间戳
    public void SetTSAUrl(String url, String user, String pwd, String hashAlgo) {
        if (creatorCom != null) {
            Variant var = Dispatch.call(creatorCom, "SetTSAUrl", url, user, pwd, hashAlgo);
        }
    }

    // 对指定的位置进行签章（带图片）
    public String SealPosition(String savePath, int pageNum, int xPos, int yPos, int width,
        int height, String fieldName, String imgBase64Encoded) {
        if (creatorCom != null) {
            Variant var = Dispatch
                .call(creatorCom, "SealPosition", savePath, pageNum, xPos, yPos, width, height,
                    fieldName, imgBase64Encoded);
            return var.toString();
        }
        return "";
    }

    // 对指定域名的签名域进行签章（带图片），与 对指定域名的签名域进行签名 参数冲突， 在签名域名显示文字也可以使用这个方法
    public String SealField(String savePath, String fieldName, String imgBase64Encoded) {
        if (creatorCom != null) {
            Variant var = Dispatch
                .call(creatorCom, "SealField", savePath, fieldName, imgBase64Encoded);
            return var.toString();
        }
        return "";
    }

    // 设置待验证的PDF文档
    public void SetVerifyPDF(String path, String pwd) {
        if (verifierCom != null) {
            Dispatch.call(verifierCom, "SetVerifyPDF", path, pwd);
        }
    }

    // 设置验证的PDF文档字节流
    public void SetVerifyPDFBytes(String pdfIn, String pwd) {
        if (verifierCom != null) {
            Dispatch.call(verifierCom, "SetVerifyPDFBytes", pdfIn, pwd);
        }
    }

    // 获取签名个数
    public int GetSignaturesCount() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetSignaturesCount");
            return var.toInt();
        }
        return 0;
    }

    // 获取签名域的名称
    public String GetSignFieldName(int fieldNum) {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetSignFieldName", fieldNum);
            return var.toString();
        }
        return "";
    }

    // 验证指定编号的签名有效性
    public int VerifySignatureByNum(int fieldNum, int level) {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "VerifySignatureByNum", fieldNum, level);
            return var.toInt();
        }
        return -1;
    }

    // 验证指定位置的签名有效性
    public int VerifySignatureByPos(int pageNum, int xPos, int yPos, String fieldName, int level) {
        if (verifierCom != null) {
            Variant var = Dispatch
                .call(verifierCom, "VerifySignatureByPos", pageNum, xPos, yPos, fieldName, level);
            return var.toInt();
        }
        return -1;
    }

    // 获取签名者名字
    public String GetSignName() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetSignName");
            return var.toString();
        }
        return "";
    }

    // 获取签名日期
    public String GetSignDate(String format) {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetSignDate", format);
            return var.toString();
        }
        return "";
    }

    // 获取签名时间戳Token
    public String GetTimestampToken() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetTimestampToken");
            return var.toString();
        }
        return "";
    }


    // 获取签名理由
    public String GetReason() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetReason");
            return var.toString();
        }
        return "";
    }

    // 获取签名地点
    public String GetLocation() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetLocation");
            return var.toString();
        }
        return "";
    }

    // 获取签名哈希算法
    public String GetHashAlgorithm() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetHashAlgorithm");
            return var.toString();
        }
        return "";
    }

    // 获取签名证书
    public String GetSignCert() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetSignCert");
            return var.toString();
        }
        return "";
    }

    // 签名是否包含时间戳签名
    public boolean hasTimestamp() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "hasTimestamp");
            return var.toBoolean();
        }
        return false;
    }

    // 判断签名时间戳是否有效
    public boolean IsTimestampValid() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "IsTimestampValid");
            return var.toBoolean();
        }
        return false;
    }

    // 获取签名时间戳日期
    public String GetTimestampDate(String format) {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetTimestampDate", format);
            return var.toString();
        }
        return "";
    }

    // 签名是否包含有效的证书吊销信息
    public boolean hasRevokeInfo() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "hasRevokeInfo");
            return var.toBoolean();
        }
        return false;
    }

    // 获取签名证书的吊销状态
    public int GetRevokeStatus() {
        if (verifierCom != null) {
            Variant var = Dispatch.call(verifierCom, "GetRevokeStatus");
            return var.toInt();
        }
        return -1;
    }

    // 设置CRL（证书吊销列表）的访问地址
    public void SetCRLUrl(String signCertCrlUrl, String caCertCrlUrl) {
        if (creatorCom != null) {
            Dispatch.call(creatorCom, "SetCRLUrl", signCertCrlUrl, caCertCrlUrl);
        }
    }
}