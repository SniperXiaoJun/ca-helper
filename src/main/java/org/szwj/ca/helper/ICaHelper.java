package org.szwj.ca.helper;

import org.szwj.ca.helper.models.CaHelperException;
import org.szwj.ca.helper.models.Dictionary;
import org.szwj.ca.helper.models.PDFInfo;
import org.szwj.ca.helper.models.UserCert;
import java.util.List;

/**
 * Created by maxm on 2017/6/7.
 */
public interface ICaHelper {

    /**
     * 获取证书颁发机构
     *
     * @return 证书颁发机构简称
     */
    String GetAuthority();

    /**
     * 获取用户列表
     *
     * @return 返回证书用户的列表信息
     */
    List<UserCert> GetUserList() throws CaHelperException;

    /**
     * 用户登录
     *
     * @param sn 证书SN码
     * @param pwd 证书的密码
     * @return 返回登陆结果
     */
    Boolean Login(String sn, String pwd) throws CaHelperException;

    /**
     * 用户登录
     *
     * @param sn 证书SN码，用于判断是哪个证书
     * @param pwd 证书的密码
     * @param randomNum 登陆签名所需的随机数
     * @return 返回登陆结果
     */
    String Login(String sn, String pwd, String randomNum) throws CaHelperException;

    /**
     * 获取证书唯一标识
     *
     * @param base64Cert Base64编码的公钥或证书
     * @return 返回证书唯一值
     */
    String GetCheckKey(String base64Cert) throws CaHelperException;

    /**
     * 数据签名
     *
     * @param sn 证书SN码
     * @param data 需要签名的文本数据
     * @param detach 是否包含原文，True包含、False不包含
     * @return 返回证书签名结果
     */
    String SignData(String sn, String data, Boolean detach) throws CaHelperException;

    /**
     * 时间戳服务器签名
     *
     * @return json格式字符串
     */
    String SignWithTSA(String base64Cert, String date) throws CaHelperException;

    /**
     * 验证签名
     *
     * @param data 被签名原文
     * @param signValue 签名后值
     */
    void VerSignData(String data, String signValue) throws CaHelperException;

    /**
     * 在签名后的数据中获取原文
     *
     * @param signValue 签名后数据
     * @return 返回签名前的数据
     */
    String GetSignText(String signValue) throws CaHelperException;

    /**
     * 获取所有的签章图片
     *
     * @return 签章图片信息列表
     */
    List<Dictionary> GetPicS();

    /**
     * 根据证书操作唯一标识获取Base64编码格式的签名证书
     *
     * @param sn 证书操作唯一标识
     * @return 成功返回 Base64 编码的签名证书
     * @throws CaHelperException 异常
     */
    String GetUserSignCert(String sn) throws CaHelperException;

    /**
     * 根据证书操作唯一标识获取Base64编码格式的加密证书
     *
     * @param sn 证书sn码
     * @return 成功返回 Base64 编码的签名证书
     */
    String GetUserCryptionCert(String sn) throws CaHelperException;

    /**
     * 获取随机数
     *
     * @return 返回 Base64 编码的随机数
     */
    String GetRandomNum();

    /**
     * 根据SN码获取签章图片
     *
     * @param sn 证书SN码
     * @return 签章图片信息类
     */
    Dictionary GetPicBySN(String sn);

    /**
     * 公钥加密数据
     *
     * @param base64Cert Base64 编码的公钥或证书
     * @param sourceData 原文数据
     * @return 返回 Base64 编码的密文数据
     */
    String PublicEncrypt(String base64Cert, String sourceData) throws CaHelperException;

    /**
     * 私钥解密数据
     *
     * @param sn 证书SN码
     * @param encryptedData Base64 编码的密文数据
     * @return 返回明文数据
     */
    String PriKeyDecrypt(String sn, String encryptedData) throws CaHelperException;

    /**
     * 验签PDF签章
     */
    void VerSignPDF(String signedPath) throws CaHelperException;

    /**
     * 文件时间戳签名
     *
     * @param sn 证书SN码
     * @param filePath 文件路径
     * @return 返回时间戳信息字符串
     */
    String SignFileWithTSA(String sn, String filePath) throws CaHelperException;

    /**
     * 计算PDF文件摘要
     */
    PDFInfo GenPDFDigest(String target, byte[] pdfByte, String signCert, String sealImg,
        String position) throws CaHelperException;

    /**
     * 执行PDF文件签章
     */
    String GenSignPDF(String signedDigest) throws CaHelperException;

    /**
     * @param base64Cert Base64编码的公钥或证书
     * @param type 信息类型
     * @return 返回证书的基本信息
     */
    String GetCertInfo(String base64Cert, int type) throws CaHelperException;
}
