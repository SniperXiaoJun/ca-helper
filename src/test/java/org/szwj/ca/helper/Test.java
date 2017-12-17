package org.szwj.ca.helper;

import cn.org.bjca.seal.esspdf.client.message.ChannelMessage;
import cn.org.bjca.seal.esspdf.client.message.ClientSignBean;
import cn.org.bjca.seal.esspdf.client.message.ClientSignMessage;
import cn.org.bjca.seal.esspdf.client.message.RectangleBean;
import cn.org.bjca.seal.esspdf.client.tools.ESSPDFClientTool;
import cn.org.bjca.seal.esspdf.client.utils.ClientUtil;
import com.google.gson.JsonObject;
import org.szwj.ca.helper.models.ResponseBody;
import org.szwj.ca.helper.models.UserCert;
import org.szwj.ca.helper.utils.Base64Util;
import org.szwj.ca.helper.utils.FileUtil;
import org.szwj.ca.helper.utils.HttpClientUtil;
import org.szwj.ca.helper.utils.JsonHelper;
import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Created by maxm on 2017/6/7.
 */
public class Test {

    private static final String remoteServer = "172.16.241.158";
    private static final String localServer = "127.0.0.1";
    private static final String testServer = "testca.top";
    private static final String server = localServer;
    private static final String businessSystemCode = "0002";
    private static final String businessTypeCode = "999";

//        private static final String netcaSn = "75EC557E2434BC2636FBA456E9ADEFD5";
    private static final String netcaSn = "12846CD4A8AF6A381200137A59579DAE";
//    private static final String netcaSn = "2BE6AE80CB052A76CF9EF01B0DB1E543";
        private static final String bjcaSn = "102000005283067/051012018332";
//    private static final String bjcaSn = "806000112575478/051412018427";

    // 产生客户端PDF签名摘要数据
    public static void testGenClientSignDigest() throws Exception {
        String remoteIp = "60.247.77.123";
        int port = 8888;
        ESSPDFClientTool essPDFClientTool = new ESSPDFClientTool(remoteIp, port);
        essPDFClientTool.setTimeout(50 * 1000);
        essPDFClientTool.setRespTimeout(50 * 1000);

        byte[] pdfBty = ClientUtil.readFileToByteArray(new File("D:\\tmp\\pdfFilled.pdf"));
        String signCert = GetUserCert(bjcaSn);
        System.out.println("signCert: " + signCert);
        String sealImg = GetPicBySN(bjcaSn);
        System.out.println("sealImg: " + sealImg);

        List<ClientSignMessage> clientSignMessages = new ArrayList<ClientSignMessage>();
        ClientSignMessage clientSignMessage = new ClientSignMessage();
        float sealWidth = 0;
        float sealHeight = 0;

        //设置移动类型1:重叠、2: 居下、3:居右,默认居右
        String moveType = "3";

        //设置关键字查找顺序，1:正序、2:倒序
        String searchOrder = "2";

        clientSignMessage.setMoveType(moveType);
        clientSignMessage.setSearchOrder(searchOrder);
        clientSignMessage.setPdfBty(pdfBty);

        String uuid = UUID.randomUUID().toString();
        clientSignMessage.setFileUniqueId(uuid);

        //设置签章查找的页码及坐标
        String pageNo = "1";
        String posL = "200";
        String posT = "300";
        String posR = "300";
        String posB = "200";
        RectangleBean bean = new RectangleBean();
        bean.setPageNo(Integer.parseInt(pageNo));
        bean.setLeft(Float.parseFloat(posL));
        bean.setTop(Float.parseFloat(posT));
        bean.setRight(Float.parseFloat(posR));
        bean.setBottom(Float.parseFloat(posB));
        clientSignMessage.setRectangleBean(bean);
        clientSignMessage.setRuleType("2");
        clientSignMessages.add(clientSignMessage);

        ChannelMessage message = essPDFClientTool
            .genClientSignDigest(clientSignMessages, signCert, sealImg, sealWidth, sealHeight);
        System.out.println("状态码：" + message.getStatusCode());
        System.out.println("状态信息：" + message.getStatusInfo());
        System.out.println("摘要数据：" + new String(message.getBody()));
    }

    private static void testGenSignPDF() throws Exception {
        String remoteIp = "60.247.77.123";
        int port = 8888;
        ESSPDFClientTool essPDFClientTool = new ESSPDFClientTool(remoteIp, port);
        essPDFClientTool.setTimeout(50 * 1000);
        essPDFClientTool.setRespTimeout(50 * 1000);

        String clientHash = "{\"digestMessage\":[{\"signUniqueId\":\"f6c3d16383be4992980c051aab00af91_2130706433\",\"fileUniqueId\":\"d851a2ea-8d06-458a-ba5a-92d99205295d\",\"clientSignData\":\"WVV9FYz0siqgCahiZWdmQ0I4x2TtN6N942mJ32MTxcQtu+avGnVQiE4FjmpWCtbX2li0qxuJZ6XXt9DiRFM1TyVrmt8qu4yrIVRTJAxtKFassKkjH2EnTnkH6n4Y3fz7N5q4EA6m+hUseXTLnzNykMZAjkjXZAMF6Vov6mbv/28=\"}]}";
        ChannelMessage signMessage = essPDFClientTool.genClientSign(clientHash);
        System.out.println("状态码：" + signMessage.getStatusCode());
        System.out.println("状态信息：" + signMessage.getStatusInfo());
        if ("200".equals(signMessage.getStatusCode())) {
            //获取客户端签章bean
            List signBeanList = signMessage.getClientSignList();

            for (int i = 0; i < signBeanList.size(); i++) {
                ClientSignBean clientSignBean = (ClientSignBean) signBeanList.get(i);
                String signUniqueId = clientSignBean.getSignUniqueId();
                ClientUtil.writeByteArrayToFile(new File("D:\\tmp\\" + signUniqueId + "_sign.pdf"),
                    clientSignBean.getPdfBty());
            }
        }
    }

    private static void httpclient() throws Exception {
        String position = "1||200||300||300||200";
        byte[] pdfByte = ClientUtil.readFileToByteArray(new File("D:\\tmp\\HelloWorld.pdf"));
        String pdfByteStream = Base64Util.encode(pdfByte);
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("businessSystemCode", businessSystemCode);
        jsonObject.addProperty("businessTypeCode", businessTypeCode);
        jsonObject.addProperty("sn", bjcaSn);
        jsonObject.addProperty("pdfByte", pdfByteStream);
        jsonObject.addProperty("position", position);
        jsonObject.addProperty("withTsa", false);
        String url = String.format("http://%s:%d/CaApi/SZWJ_SignPDF", "localhost", 55668);
        System.out.println(url);
        String respJson = HttpClientUtil.HttpPostWithJson(url, jsonObject.toString());
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        byte[] signPdfByte = Base64Util.decode(responseBody.getEventValue().getSignPdfByte());
        ClientUtil.writeByteArrayToFile(new File("D:\\tmp\\HelloWorld.pdf"), signPdfByte);
    }

    public static void main(String args[]) throws Exception {
        System.out.println("dll需要放到以下目录下:");
        System.out.println("java.library.path=" + System.getProperty("java.library.path"));

        GetUserList();
        httpclient();
        if (1 == 1) {
            return;
        }

//        String srcPath = "D:\\tmp\\pdfFilled.pdf";
//        String savePath = "D:\\tmp\\pdfFilled_signed.pdf";
//        byte[] pdfBty = ClientUtil.readFileToByteArray(new File(srcPath));
//        String sealImg = GetPicBySN(bjcaSn);
//        Bjca bjca = new Bjca();
//        String position = "1||200||300||300||200";
//        PDFInfo pdfInfo = bjca.GenPDFDigest(pdfBty, GetUserCert(bjcaSn), sealImg, position);
//        System.out.println(pdfInfo.getPdfDigest());

//        String clientHash = "{\"digestMessage\":[{\"signUniqueId\":\"f74c9f9fc55f478e972d2a891428ffe2_2130706433\",\"fileUniqueId\":\"pdfFilled\",\"clientSignData\":\"htTLpv5ZLXNt+CLLAgospTxlTtH4hxG5WBwFXw/zUgbRiYOB93y9CnlmKb1tBGewJh1SJUNi4IIXhvQGhLq9UoQx8GhTDhMt/LLqyDE74p7XlQXYynSKXgCKRfTM/T+78JUX0qXsVCvBCENaWRlmnlQSz03+C77Eqjg474r3n/c=\"}]}";
//        Bjca bjca = new Bjca();
//        String base64PdfByte = bjca.GenSignPDF(clientHash);
//        byte[] pdfByte = Base64Util.decode(base64PdfByte);
//        ClientUtil.writeByteArrayToFile(new File("D:\\tmp\\" + "wangrentao_sign.pdf"), pdfByte);


//        testGenClientSignDigest();
//        testGenSignPDF();

//        String encryptedToken = Login(bjcaSn, "111111");
        String encryptedToken = Login(netcaSn, "12345678");
//        String src = "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";
//        String signedData = SignData(bjcaSn, src, true, true);

//        System.out.println(
//            "signWithTsa: " + SZWJ_CaHelper.getCaHelperImplByAuthority(SZWJ_CaHelper.BJCA_AUTHORITY)
//                .SignWithTSA(bjcaSn, "f74c9f9fc55f478e972d2a891428ffe2_2130706433"));


        String srcPath = "D:\\tmp\\pdfFilled.pdf";
        byte[] pdfByte = FileUtil.ReadFileToByteArray(new File(srcPath));
        String base64PdfByte = Base64Util.encode(pdfByte);
        String position = "1||0||0||100||100";
//        String position = "1||200||300||300||200";
        SignPDF(encryptedToken, base64PdfByte, position, false);
//        String clientHash = "{\"digestMessage\":[{\"signUniqueId\":\"15800df5c0504199ba46ae80c28dfdee_2130706433\",\"fileUniqueId\":\"pdfFilled\",\"clientSignData\":\"krqlqjhwwRlexgkx1mKxVlDXLh8LqPJtEM+sepjuG8owKkWgRorga+KBYxFPyqyvy6FXWBA4vSqrRJEDGCxD2DQgcHZPxsa78pSntfWQPTJl0PHMEGABCynQDOCUBbPdcmjgtQ6+XZeIym9Gfxbi5TRkNmzjZgCmbUH6RK9s+co=\"}]}";
//        SZWJ_CaHelper.SZWJ_GenSignPDF(server, businessSystemCode, businessTypeCode, bjcaSn, clientHash);
        if (1 == 1) {
            return;
        }

        String base64Cert = "MIIEcjCCA1qgAwIBAgIQaIc+SqZQFxacNTL3ZHA5tjANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJDTjEkMCIGA1UEChMbTkVUQ0EgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MR8wHQYDVQQLExZPcmdhbml6YXRpb24gQ2xhc3NBIENBMSUwIwYDVQQDExxORVRDQSBPcmdhbml6YXRpb24gQ2xhc3NBIENBMB4XDTE3MTIxMTAzMTg1OFoXDTE4MTIxMTAzMTg1OFowgaYxCzAJBgNVBAYTAkNOMRIwEAYDVQQIEwlHdWFuZ2RvbmcxJzAlBgNVBAceHm3xVzNeAn9XblZTOk66bBFTF43vADIAMgAxADBT9zEbMBkGA1UECh4SbfFXM14CUztbZk/hYG9OLV/DMRswGQYDVQQDHhJP4WBvTi1fw21Li9UAawBlAHkxIDAeBgkqhkiG9w0BCQEWETg4ODg4ODg4QGNuY2EubmV0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCEZ1u/ajWvgjtgO/LYyH2sodlzkOf7jERKvQeZF5vFydfEXuH1f1xaU4CKOBrnwSF8w6ecyx19jN8fraUnw8Q1bCcCkroFfJbHJbQwonZFbhKK9kZENpvls/ybnNwjDUSnSgm5IcclYmBDE50zw9eMf+sxGBc0ITm5GlIFJS4PcQIDAQABo4IBSDCCAUQwHwYDVR0jBBgwFoAULQlDgvlKV2qEJrB197Or1PncwW8wHQYDVR0OBBYEFLgr+vswpggrjlIfL2OtFYp8qytSMFcGA1UdIARQME4wTAYKKwYBBAGBkkgBCjA+MDwGCCsGAQUFBwIBFjBodHRwOi8vd3d3LmNuY2EubmV0L2NzL2tub3dsZWRnZS93aGl0ZXBhcGVyL2Nwcy8wHAYDVR0RBBUwE4ERODg4ODg4ODhAY25jYS5uZXQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBsAwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NsYXNzYWNhMS5jbmNhLm5ldC9jcmwvT3JnYW5pemF0aW9uQ0EuY3JsMCoGCysGAQQBgZJIAQwLBBsMGTEwMDAxQDAwMDZQTzFPRGc0T0RnNE9EZz0wDQYJKoZIhvcNAQEFBQADggEBAH0uDjZ2dDszuCgWMmtWoNIJHvUKxQLd9aUxRzz2KbM1L7Gp5AewYDUgY1mWUZoyZhnQMXubfae6jn3EO+fsfLqCyHBa6HxNyBqwwuFLa5WFpVkJ1+ykYJO7QLjdHqtbgIcZX/prgYkpeW3jifAeq7jbV/zOroRHpWKQdToA4TLYcvVjuF1nJUEHZRrfbSkx66mVGYw1uFTJ9Ncz7c7ULJvkN34OzaAW/MWDg6DM9W4H65DGBMeGPIikteVkBOAQ2JK9cbgvZmmsMnT6cdJ5d0p4pC5Sg144viW93HQr0p10oBF8UPt41XaEeQWrpESQ7CKqZN5BcPL72SP0V+hbHC0=";
        ICaHelper helper = SZWJ_CaHelper
            .getCaHelperImplByAuthority(SZWJ_CaHelper.NETCA_AUTHORITY);
        //1：服务器证书;2：个人证书;3: 机构证书;4：机构员工证书;5：机构业务证书(注：该类型国密标准待定);0：其他证书
        String certType = helper.GetCertInfo(base64Cert, 22);
        int certTypeNum = Integer.parseInt(certType);
        switch (certTypeNum) {
            case 1:
                certType = "服务器证书";
                break;
            case 2:
                certType = "个人证书";
                break;
            case 3:
                certType = "机构证书";
                break;
            case 4:
                certType = "机构员工证书";
                break;
            case 5:
                certType = "机构业务证书(注：该类型国密标准待定)";
                break;
            default:
                certType = "其他证书";
        }

        String serialNumber = helper.GetCertInfo(base64Cert, 2);
        String validFromDate = helper.GetCertInfo(base64Cert, 5);
        String validToDate = helper.GetCertInfo(base64Cert, 6);
        String signCert = base64Cert;
        String cryptionCert = "MIIEcjCCA1qgAwIBAgIQfNWx2Y1er5k0sDnbzzp+VTANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJDTjEkMCIGA1UEChMbTkVUQ0EgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MR8wHQYDVQQLExZPcmdhbml6YXRpb24gQ2xhc3NBIENBMSUwIwYDVQQDExxORVRDQSBPcmdhbml6YXRpb24gQ2xhc3NBIENBMB4XDTE3MTIxMTAzMTg1OFoXDTE4MTIxMTAzMTg1OFowgaYxCzAJBgNVBAYTAkNOMRIwEAYDVQQIEwlHdWFuZ2RvbmcxJzAlBgNVBAceHm3xVzNeAn9XblZTOk66bBFTF43vADIAMgAxADBT9zEbMBkGA1UECh4SbfFXM14CUztbZk/hYG9OLV/DMRswGQYDVQQDHhJP4WBvTi1fw21Li9UAawBlAHkxIDAeBgkqhkiG9w0BCQEWETg4ODg4ODg4QGNuY2EubmV0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5QrCA087uUTxsyjoLMf3shbUnXVHMiTd4riYJha6aedWQtxZbhCAV7EYY+nnphWAAuWjWlp1shRKsZsyXk6tcdm0/EsLmT2hz1WujMSx4g4ismN3R/6XL5BxFtD9wNBqRwVbn2N/pRWveQ4V3/vTbO5JBc7z76jyq5LfUsAumEQIDAQABo4IBSDCCAUQwHwYDVR0jBBgwFoAULQlDgvlKV2qEJrB197Or1PncwW8wHQYDVR0OBBYEFMwZ72sJopwCsQnIZUz0u+EEwl9qMFcGA1UdIARQME4wTAYKKwYBBAGBkkgBCjA+MDwGCCsGAQUFBwIBFjBodHRwOi8vd3d3LmNuY2EubmV0L2NzL2tub3dsZWRnZS93aGl0ZXBhcGVyL2Nwcy8wHAYDVR0RBBUwE4ERODg4ODg4ODhAY25jYS5uZXQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBDAwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NsYXNzYWNhMS5jbmNhLm5ldC9jcmwvT3JnYW5pemF0aW9uQ0EuY3JsMCoGCysGAQQBgZJIAQwLBBsMGTEwMDAxQDAwMDZQTzFPRGc0T0RnNE9EZz0wDQYJKoZIhvcNAQEFBQADggEBAGZBXlnv8ZbpkGw+M/2XgiN6If6p2ManeNMKhbtJCRxeIX8ex9x02i51JL8ZCLACMnsLe8WhKvfZy4MPNbUvLWFS3x4Fqyc+TU91dUHUnnjWX32Cdk1CczUpDjCTmpKcSex9gyQ8TkVjUWOl6su14N5pV2/Gfcmg0M0EKFB0CzoWOlBJmVBpvUElcVoe9uRQ6BAMcmn3rrt0zR4rzJoXOXYB501+CgWrp+nb56ZdKoxLAKk4q9En0SV/Nk0J+O9YvhzJKw4+CdPulc3rRhVDzc42ixL5MkMPTiF9gQMCAfIy62+EoLgCXu4TmWKOPQ3bKwNDftdVc2UDVx8cj1YNixs=";
        String authority = SZWJ_CaHelper.NETCA_AUTHORITY;
        String userName = helper.GetCertInfo(base64Cert, 12);
        String userDepartment = helper.GetCertInfo(base64Cert, 16);
        String sql = String.format(
            "INSERT INTO T_CERT_INFO(ID, Type, SerialNumber, ValidFromDate, ValidToDate, SignCert, CryptionCert, Authority, "
                + "SignFlow, UserName, UserDepartment) VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');",
            UUID.randomUUID().toString(), certType, serialNumber, formatDateTimeFromCST(validFromDate),
            formatDateTimeFromCST(validToDate), signCert, cryptionCert, authority, "", userName,
            userDepartment);
        System.out.println(sql);
        if (1 == 1) {
            return;
        }

        System.out.println("GetCheckKey: " + GetCheckKey(netcaSn));

//        String encryptedToken = "MkJFNkFFODBDQjA1MkE3NkNGOUVGMDFCMERCMUU1NDN8fHwxMjM0NTY3OHx8fDAwMDAzfHx8eGMyS25pNW4xYkU9";
//        String loginer = SZWJ_CaHelper
//            .SZWJ_LoginByToken(server, businessSystemCode, encryptedToken);
//        System.out.println("loginer: " + loginer);

//        VerSignPDF(netcaSn, savePath);
//        SignPDFWithTSA(netcaSn, srcPath, savePath, position);

        // PDF <-> Base64字符串
//        Netca netca = new Netca();
//        String signedPdfStream = netca.ConvertPDFToBase64Stream(savePath).replace("\r\n", "");
//        netca.ConvertBase64StreamToPDF("D:\\pdf文档测试b.pdf", signedPdfStream);

        String src = "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";
        String signedData = SignData(bjcaSn, src, true, true);
        VerSignData(netcaSn, src, signedData, true);
//        VerSignData(bjcaSn, src + "aaa", signedData, true);
//        VerSignData(bjcaSn, src, signedData + "aaa", true);
//        String signedData = "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";
//        System.out.println("signText: " + GetSignText(signedData));

        /*
        for (int i = 0; i < 5000; i++) {
            String tsaSignedData = SignData(netcaSn, "66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd66495942fdafadsfsdfwergfgsdfgafgfsdgsdfgsfgaafgsd", true, true);
            System.out.println("tsaSignData: " + tsaSignedData);
//            VerSignData(netcaSn, "66495942", tsaSignedData, true);
            Thread.sleep(1000);
        }
        */

//        GetPicS();
//        String sealImg = GetPicBySN(bjcaSn);
//        System.out.println("sealImg: " + sealImg);
//        System.out.println(GetUserCert(netcaSn));
    }

    private static String formatDateTimeFromCST(String CSTtime) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.US);
        Date date = (Date) sdf.parse(CSTtime);
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(date);
    }

    private static final char[] a = {48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101,
        102};

    public static final String testDigest(String paramString) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(paramString.getBytes());
            return byteToHex(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String byteToHex(byte[] paramArrayOfByte) {
        StringBuilder localStringBuilder = new StringBuilder(paramArrayOfByte.length * 2);
        int i = 0;
        while (i < paramArrayOfByte.length) {
            localStringBuilder.append(a[((paramArrayOfByte[i] & 0xF0) >>> 4)]);
            localStringBuilder.append(a[(paramArrayOfByte[i] & 0xF)]);
            i += 1;
        }
        return localStringBuilder.toString();
    }

    private static String get1thUserSN(ResponseBody responseBody) {
        return responseBody.getEventValue().getUserCerts().get(0).getSn();
    }

    private static List<UserCert> GetUserList() {
        String respJson = SZWJ_CaHelper.SZWJ_GetUserList();
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
            return null;
        }
        for (UserCert userCert : responseBody.getEventValue().getUserCerts()) {
            System.out.println("cert name: " + userCert.getUserName());
            System.out.println("cert sn: " + userCert.getSn());
        }
        return responseBody.getEventValue().getUserCerts();
    }

    private static String Login(String sn, String pwd) {
        String respJson = SZWJ_CaHelper.SZWJ_Login(server, businessSystemCode, sn, pwd);
        ResponseBody responseBody = JsonHelper.parseJsonToClass(respJson, ResponseBody.class);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
            return "";
        } else {
            System.out.println("Login success. response: " + respJson);
            if (null != responseBody.getEventValue()) {
                return responseBody.getEventValue().getEncryptedToken();
            } else {
                return "success";
            }
        }
    }

    private static String GetCheckKey(String sn) {
        String respJson = SZWJ_CaHelper.SZWJ_GetCheckKey(sn);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
            return "";
        } else {
            System.out.println("Login success.");
            return responseBody.getEventValue().getCheckKey();
        }
    }

    private static String SignData(String sn, String data, Boolean detach, Boolean withTsa) {
        String respJson = SZWJ_CaHelper.SZWJ_SignData(server, sn, data, detach, withTsa);
        System.out.println(respJson);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
            return "";
        } else {
            System.out.println("Sign data success.");
            return responseBody.getEventValue().getSignedData();
        }
    }

    private static Boolean VerSignData(String sn, String data, String signValue, Boolean detach) {
        String respJson = SZWJ_CaHelper.SZWJ_VerSignData(server, sn, data, signValue, detach);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
            return false;
        } else {
            System.out.println("Verify signed value success.");
            return true;
        }
    }

    private static String SignWithTsa(String sn, String data) {
        String respJson = SZWJ_CaHelper
            .SZWJ_SignWithTSA(server, sn, data);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
            return "";
        } else {
            System.out.println("Sign data success.");
            return responseBody.getEventValue().getTimestamp();
        }
    }

    private static String GetPicBySN(String sn) {
        String respJson = SZWJ_CaHelper.SZWJ_GetPicBySN(sn);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
            return "";
        } else {
            System.out.println("Get pic by sn success.");
            return responseBody.getEventValue().getDictionary().get(0).getSignFlow();
        }
    }

    public static void GetPicS() {
        String respJson = SZWJ_CaHelper.SZWJ_GetPicS();
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
        } else {
            System.out.println("Get pics success.");
            System.out.println(respJson);
        }
    }

    public static String GetUserCert(String sn) {
        String respJson = SZWJ_CaHelper.SZWJ_GetUserCert
            (sn);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
            return "";
        } else {
            System.out.println("Get user cert success.");
            return responseBody.getEventValue().getBase64Cert();
        }
    }

    private static void SignPDF(String encryptedToken, String pdfByte, String position, Boolean withTsa) {
        String respJson = SZWJ_CaHelper
            .SZWJ_SignPDF(server, businessSystemCode, businessTypeCode, encryptedToken, pdfByte,
                position, withTsa);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
        } else {
            System.out.println("Sign PDF success. response: " + respJson);
        }
    }

    /*
    private static Boolean VerSignPDF(String sn, String signedPath) {
        String respJson = SZWJ_CaHelper
            .SZWJ_VerSignPDF(server, businessSystemCode, businessTypeCode, pdfTypeCode, sn,
                signedPath);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
            return false;
        } else {
            System.out.println("Verify signed value success.");
            return true;
        }
    }

    private static void SignPDFWithTSA(String sn, String srcPath, String savePath, String position) {
        String respJson = SZWJ_CaHelper
            .SZWJ_SignPDFwithTSA(server, businessSystemCode, businessTypeCode, pdfTypeCode, sn,
                srcPath, savePath, position);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println(responseBody.getEventMsg());
        } else {
            System.out.println("Sign PDF success. response: " + respJson);
        }
    }
    */

    private static void testcase_netcaSignData() {
        String userList = SZWJ_CaHelper.SZWJ_GetUserList();
        System.out.println(userList);
        String data = "abcdefghijklmnopqrstuvwxyz;abcdefghijklmnopqrstuvwxyz'abcdefghijklmnopqrstuvwxyz|abcdefghijklmnopqrstuvwxyz";
        String signedData = SZWJ_CaHelper
            .SZWJ_Login(server, businessSystemCode, netcaSn, "12345678");
        System.out.println(signedData);
        ResponseBody responseBody = JsonHelper.parseResponse(signedData);
        if (0 != responseBody.getStatusCode()) {
            System.out.println("Login failed!");
            return;
        }
        signedData = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, false, false);
        System.out.println(signedData);
        signedData = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, true, false);
        System.out.println(signedData);
    }

    private static void testcase_multiNetCaSignData() {
        String userList = SZWJ_CaHelper.SZWJ_GetUserList();
        System.out.println(userList);
        String data = "abcdefghijklmnopqrstuvwxyz;abcdefghijklmnopqrstuvwxyz'abcdefghijklmnopqrstuvwxyz|abcdefghijklmnopqrstuvwxyz";
        String respJson = SZWJ_CaHelper.SZWJ_Login(server, businessSystemCode, netcaSn, "12345678");
        System.out.println(respJson);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println("Login failed!");
            return;
        }
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, false, false);
        System.out.println(respJson);
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, true, false);
        System.out.println(respJson);

        String netcaSn = "75EC557E2434BC2636FBA456E9ADEFD5";
        respJson = SZWJ_CaHelper.SZWJ_Login(server, businessSystemCode, netcaSn, "12345678");
        System.out.println(respJson);
        responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println("Login failed!");
            return;
        }
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, false, false);
        System.out.println(respJson);
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, true, false);
        System.out.println(respJson);

        data = "12345678";
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, false, false);
        System.out.println(respJson);
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, true, false);
        System.out.println(respJson);
    }

    private static void testcase_multiNetCaVerSignData() {
        String userList = SZWJ_CaHelper.SZWJ_GetUserList();
        System.out.println(userList);
        String data = "abcdefghijklmnopqrstuvwxyz;abcdefghijklmnopqrstuvwxyz'abcdefghijklmnopqrstuvwxyz|abcdefghijklmnopqrstuvwxyz";
        String respJson = SZWJ_CaHelper.SZWJ_Login(server, businessSystemCode, netcaSn, "12345678");
        System.out.println(respJson);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println("Login failed!");
            return;
        }
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, false, false);
        System.out.println(respJson);
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, true, false);
        System.out.println(respJson);

        String netcaSn = "75EC557E2434BC2636FBA456E9ADEFD5";
        respJson = SZWJ_CaHelper.SZWJ_Login(server, businessSystemCode, netcaSn, "12345678");
        System.out.println(respJson);
        responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println("Login failed!");
            return;
        }
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, false, false);
        System.out.println(respJson);
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, true, false);
        System.out.println(respJson);

        data = "12345678";
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, false, false);
        System.out.println(respJson);
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, true, false);
        System.out.println(respJson);
    }

    private static void testcase_bjcaSignData() {
        String userList = SZWJ_CaHelper.SZWJ_GetUserList();
        System.out.println(userList);
        String bjcaSN = "102000005283067/051012018332";
        String data = "abcdefghijklmnopqrstuvwxyz;abcdefghijklmnopqrstuvwxyz'abcdefghijklmnopqrstuvwxyz|abcdefghijklmnopqrstuvwxyz";
        String respJson = SZWJ_CaHelper.SZWJ_Login(server, businessSystemCode, bjcaSN, "111111");
        System.out.println(respJson);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println("Login failed!");
            return;
        }
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, bjcaSN, data, false, false);
        System.out.println(respJson);
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, bjcaSN, data, true, false);
        System.out.println(respJson);
    }

    private static void testcase_netcaVerSignData() {
        String userList = SZWJ_CaHelper.SZWJ_GetUserList();
        System.out.println(userList);
        String data = "abcdefghijklmnopqrstuvwxyz;abcdefghijklmnopqrstuvwxyz'abcdefghijklmnopqrstuvwxyz|abcdefghijklmnopqrstuvwxyz";
        String respJson = SZWJ_CaHelper.SZWJ_Login(server, businessSystemCode, netcaSn, "12345678");
        System.out.println(respJson);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println("Login failed!");
            return;
        }
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, false, false);
        System.out.println(respJson);
        responseBody = JsonHelper.parseResponse(respJson);
        respJson = SZWJ_CaHelper
            .SZWJ_VerSignData(server, netcaSn, data, responseBody.getEventValue().getSignedData(),
                false);
        System.out.println(respJson);

        respJson = SZWJ_CaHelper.SZWJ_SignData(server, netcaSn, data, true, false);
        System.out.println(respJson);
        responseBody = JsonHelper.parseResponse(respJson);
        respJson = SZWJ_CaHelper
            .SZWJ_VerSignData(server, netcaSn, data, responseBody.getEventValue().getSignedData(),
                true);
        System.out.println(respJson);
    }

    private static void testcase_bjcaVerSignData() {
        String userList = SZWJ_CaHelper.SZWJ_GetUserList();
        System.out.println(userList);
        String bjcaSN = "102000005283067/051012018332";
        String data = "abcdefghijklmnopqrstuvwxyz;abcdefghijklmnopqrstuvwxyz'abcdefghijklmnopqrstuvwxyz|abcdefghijklmnopqrstuvwxyz";
        String respJson = SZWJ_CaHelper.SZWJ_Login(server, businessSystemCode, bjcaSN, "111111");
        System.out.println(respJson);
        ResponseBody responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println("Login failed!");
            return;
        }
        respJson = SZWJ_CaHelper
            .SZWJ_SignData(server, bjcaSN, data, false, false);
        System.out.println(respJson);
        responseBody = JsonHelper.parseResponse(respJson);
        if (0 == responseBody.getStatusCode()) {
            respJson = SZWJ_CaHelper.SZWJ_VerSignData(server, bjcaSN, data,
                responseBody.getEventValue().getSignedData(), false);
            System.out.println(respJson);
        } else {
            System.out.println("Sign data failed!");
        }

        respJson = SZWJ_CaHelper.SZWJ_Login(server, businessSystemCode, bjcaSN, "111111");
        System.out.println(respJson);
        responseBody = JsonHelper.parseResponse(respJson);
        if (0 != responseBody.getStatusCode()) {
            System.out.println("Login failed!");
            return;
        }
        respJson = SZWJ_CaHelper.SZWJ_SignData(server, bjcaSN, data, true, false);
        System.out.println(respJson);
        responseBody = JsonHelper.parseResponse(respJson);
        if (0 == responseBody.getStatusCode()) {
            respJson = SZWJ_CaHelper.SZWJ_VerSignData(server, bjcaSN, data,
                responseBody.getEventValue().getSignedData(), false);
            System.out.println(respJson);
        } else {
            System.out.println("Sign data failed!");
        }
    }

    // TODO 测试场景：登录成功，登出，登录失败，进行签名；预期：签名失败
}
