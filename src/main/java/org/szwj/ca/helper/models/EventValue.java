package org.szwj.ca.helper.models;

import java.util.List;

public class EventValue {

    // 获取用户列表
    private List<UserCert> userCerts;

    // 用户登录
    private String encryptedToken;

    // 获取证书唯一标识
    private String checkKey;

    // 数据签名
    private String signedData;

    // 在签名后的数据中获取原文
    private String signText;

    // 获取所有证书的签章图片
    private List<Dictionary> dictionary;

    // base64编码格式证书
    private String base64Cert;

    // 随机数
    private String randomNum;

    // 用户登录信息
    private Loginer loginer;

    // 时间戳签名结果
    private String timestamp;

    // 签章后的pdf base64格式字节流
    private String signPdfByte;

    public List<UserCert> getUserCerts() {
        return userCerts;
    }

    public void setUserCerts(List<UserCert> userCerts) {
        this.userCerts = userCerts;
    }

    public String getEncryptedToken() {
        return encryptedToken;
    }

    public void setEncryptedToken(String encryptedToken) {
        this.encryptedToken = encryptedToken;
    }

    public String getCheckKey() {
        return checkKey;
    }

    public void setCheckKey(String checkKey) {
        this.checkKey = checkKey;
    }

    public String getSignedData() {
        return signedData;
    }

    public void setSignedData(String signedData) {
        this.signedData = signedData;
    }

    public String getSignText() {
        return signText;
    }

    public void setSignText(String signText) {
        this.signText = signText;
    }

    public List<Dictionary> getDictionary() {
        return dictionary;
    }

    public void setDictionary(List<Dictionary> dictionary) {
        this.dictionary = dictionary;
    }

    public String getBase64Cert() {
        return base64Cert;
    }

    public void setBase64Cert(String base64Cert) {
        this.base64Cert = base64Cert;
    }

    public String getRandomNum() {
        return randomNum;
    }

    public void setRandomNum(String randomNum) {
        this.randomNum = randomNum;
    }

    public Loginer getLoginer() {
        return loginer;
    }

    public void setLoginer(Loginer loginer) {
        this.loginer = loginer;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getSignPdfByte() {
        return signPdfByte;
    }

    public void setSignPdfByte(String signPdfByte) {
        this.signPdfByte = signPdfByte;
    }
}
