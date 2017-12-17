package org.szwj.ca.helper.netca.secuauth;

import java.io.ByteArrayInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/**
 * 功能:网关V1型开发接口
 *
 * @author lhm
 */
public class ClientInterface {

    private URL m_url;
    private Signature m_rsaSign;
    private int m_iseq;

    public ClientInterface(String url, byte[] bCertSev) throws Exception {
        m_iseq = 1;
        m_url = new URL(url);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf
            .generateCertificate(new ByteArrayInputStream(bCertSev));
        RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();
        // "SHA1withRSA"
        // SunJCE not
        // support this
        // aglithm
        m_rsaSign = Signature.getInstance("SHA1withRSA");
        m_rsaSign.initVerify(pubKey);
    }

    private synchronized int getSeq() {
        m_iseq++;
        return m_iseq;
    }

    private boolean VerifyData(byte[] content, byte[] signature)
        throws Exception {
        m_rsaSign.update(content);
        return m_rsaSign.verify(signature);
    }

    /**
     * 验证证书
     */
    public int[] checkCert(String certBeChk) throws Exception {

        byte[] bCertChk = Base64Encoder.decode(certBeChk);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf
            .generateCertificate(new ByteArrayInputStream(bCertChk));
        MessageDigest md = MessageDigest.getInstance("SHA");
        byte[] bDigest = md.digest(cert.getEncoded());
        String hexdigest = HexEncoder.encode(bDigest);

        int seq = getSeq();
        String strReq = Integer.toString(seq) + "|" + certBeChk;

        HttpURLConnection connection = (HttpURLConnection) m_url
            .openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-type", "text/plain");
        connection.setDoOutput(true);
        connection.connect();
        connection.getOutputStream().write(strReq.getBytes());

        int statuscode = connection.getResponseCode();
        if (statuscode != HttpURLConnection.HTTP_OK) {
            connection.disconnect();
            throw new Exception("http通信错误,statuscode=" + statuscode);
        }
        // response content
        int nLen = connection.getContentLength();
        byte[] bResponse = new byte[nLen];
        int rdlen = connection.getInputStream().read(bResponse);
        while (rdlen < nLen) {
            int len = connection.getInputStream().read(bResponse, rdlen,
                nLen - rdlen);
            if (len < 0) {
                break;
            }
            rdlen += len;
        }
        connection.disconnect();
        String strResp = new String(bResponse);

        // verify the signature
        // 请求流水号 | 响应码 | 验证证书姆印Hex编码 | 证书状态码 | 对前面内容的签名 Base64编码
        int pos = strResp.lastIndexOf('|');
        if (pos < 0) {
            throw new Exception("服务端返回数据包有误");
        }
        String content = strResp.substring(0, pos);
        String signature = strResp.substring(pos + 1);
        byte[] bSign = Base64Encoder.decode(signature);
        boolean isPass = VerifyData(content.getBytes(), bSign);
        if (!isPass) {
            throw new Exception("服务端签名无效");
        }
        // parse response
        int[] ret = new int[2];
        String[] strs = content.split("\\|");
        if (strs.length < 2) {
            throw new Exception("服务端返回数据包有误");
        }
        String strseq = strs[0];
        if (Integer.parseInt(strseq) != seq) {
            throw new Exception("交易流水号不匹配,可能遭到恶意攻击");
        }
        ret[0] = Integer.parseInt(strs[1]);
        if (ret[0] == 0) {
            if (strs.length != 4) {
                throw new Exception("服务端返回数据包有误");
            }
            String digest = strs[2];
            if (!digest.equalsIgnoreCase(hexdigest)) {
                throw new Exception("被验证的证书摘要不匹配,可能遭到恶意攻击");
            }
            ret[1] = Integer.parseInt(strs[3]);
        }
        //
        return ret;
    }

    public static String parseEchoCode(int echoCode) {
        String msg = "响应码: " + echoCode;
        switch (echoCode) {
            case 0:
                msg += " (响应成功)";
                break;
            case 1:
                msg += " (请求数据包有误)";
                break;
            case 2:
                msg += " (证书验证服务器内部出错)";
                break;
            case 3:
                msg += " (证书验证服务器压力过重，请以后再试)";
                break;
            case 4:
                msg += " (客户端签名有误)";
                break;
            case 5:
                msg += " (请求数据需要签名)";
                break;
            case 6:
                msg += " (请求未被授权)";
                break;
        }
        return msg;
    }

    public static String parseCertCode(int certCode) {
        String msg = "证书状态码: " + certCode;
        switch (certCode) {
            case 0:
                msg += " (证书有效)";
                break;
            case 1:
                msg += " (证书被注销)";
                break;
            case 2:
                msg += " (状态未知)";
                break;
            case 3:
                msg += " (证书格式有误)";
                break;
            case 4:
                msg += " (证书已过有效期)";
                break;
            case 5:
                msg += " (不是NETCA颁发的证书)";
                break;
            case 6:
                msg += " (该用户未注册)";
                break;
            case 7:
                msg += " (该用户被冻结)";
                break;
            case 8:
                msg += " (其他错误)";
                break;
        }
        return msg;
    }

}
