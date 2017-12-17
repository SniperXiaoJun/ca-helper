package org.szwj.ca.helper.bjca;

import com.jacob.activeX.ActiveXComponent;
import com.jacob.com.Dispatch;
import com.jacob.com.Variant;

/**
 * Created by maxm on 2017/6/8.
 */
public class XTXAppCOM {

    /**
     * 定义ActiveX对象
     */
    private ActiveXComponent dotnetCom = null;

    public XTXAppCOM() {
        try {
            // XTXAppCOM.XTXApp
            dotnetCom = new ActiveXComponent("XTXAppCOM.XTXApp.1");
            Variant[] var = {new Variant()};
            dotnetCom.logCallbackEvent("", var);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String SOF_GetVersion() {
        if (dotnetCom != null) {
            Variant var = Dispatch.call(dotnetCom, "SOF_GetVersion");
            return var.toString();
        }
        return "";
    }

    public int SOF_SetSignMethod(int SignMethod) {
        if (dotnetCom != null) {
            Variant var = Dispatch.call(dotnetCom, "SOF_SetSignMethod", SignMethod);
            return var.toInt();
        }
        return 0;
    }

    public int SOF_GetSignMethod() {
        if (dotnetCom != null) {
            Variant var = Dispatch.call(dotnetCom, "SOF_GetSignMethod");
            return var.toInt();
        }
        return 0;
    }

    public int SOF_SetEncryptMethod(int EncryptMethod) {
        if (dotnetCom != null) {
            Variant var = Dispatch.call(dotnetCom, "SOF_SetEncryptMethod", EncryptMethod);
            return var.toInt();
        }
        return 0;
    }

    public int SOF_GetEncryptMethod() {
        if (dotnetCom != null) {
            Variant var = Dispatch.call(dotnetCom, "SOF_GetEncryptMethod");
            return var.toInt();
        }
        return 0;
    }

    public String SOF_GetUserList() {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_GetUserList");
        return var.toString();
    }

    public String SOF_ExportUserCert(String CertID) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_ExportUserCert", CertID);
        return var.toString();
    }

    public String SOF_ExportExChangeUserCert(String CertID) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_ExportExChangeUserCert", CertID);
        return var.toString();
    }

    public boolean SOF_Login(String CertID, String PassWd) {
        if (dotnetCom == null) {
            return false;
        }

        Variant var = Dispatch.call(dotnetCom, "SOF_Login", CertID, PassWd);
        return var.toBoolean();
    }

    public boolean SOF_Logout(String CertID) {
        if (dotnetCom == null) {
            return false;
        }

        Variant var = Dispatch.call(dotnetCom, "SOF_Logout", CertID);
        return var.toBoolean();
    }

    public long SOF_GetPinRetryCount(String CertID) {
        if (dotnetCom == null) {
            return 0;
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_GetPinRetryCount", CertID);
        return var.toInt();
    }

    public boolean SOF_ChangePassWd(String CertID, String OldPassWd, String NewPassWd) {
        if (dotnetCom == null) {
            return false;
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_ChangePassWd", CertID, OldPassWd, NewPassWd);
        return var.toBoolean();
    }

    public String SOF_SignData(String CertID, String InData) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_SignData", CertID, InData);
        return var.toString();
    }

    public boolean SOF_VerifySignedData(String Cert, String InData, String SignValue) {
        if (dotnetCom == null) {
            return false;
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_VerifySignedData", Cert, InData, SignValue);
        return var.toBoolean();
    }

    public String SOF_SignFile(String CertID, String InFile) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_SignFile", CertID, InFile);
        return var.toString();
    }

    public boolean SOF_VerifySignedFile(String Cert, String InFile, String SignValue) {
        if (dotnetCom == null) {
            return false;
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_VerifySignedFile", Cert, InFile, SignValue);
        return var.toBoolean();
    }

    public String SOF_EncryptData(String Cert, String Indata) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_EncryptData", Cert, Indata);
        return var.toString();
    }

    public String SOF_DecryptData(String CertID, String Indata) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_DecryptData", CertID, Indata);
        return var.toString();
    }

    public String SOF_SignMessage(int dwFlag, String CertID, String InData) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_SignMessage", dwFlag, CertID, InData);
        return var.toString();
    }

    public boolean SOF_VerifySignedMessage(String MessageData, String InData) {
        if (dotnetCom == null) {
            return false;
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_VerifySignedMessage", MessageData, InData);
        return var.toBoolean();
    }

    public String SOF_GenRandom(int RandomLen) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_GenRandom", RandomLen);
        return var.toString();
    }

    public String SOF_PubKeyEncrypt(String sCert, String sInData) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_PubKeyEncrypt", sCert, sInData);
        return var.toString();
    }

    public String SOF_PriKeyDecrypt(String CertID, String sInData) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_PriKeyDecrypt", CertID, sInData);
        return var.toString();
    }

    public String SOF_SymEncryptData(String sKey, String indata) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_SymEncryptData", sKey, indata);
        return var.toString();
    }

    public String SOF_SymDecryptData(String sKey, String indata) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_SymDecryptData", sKey, indata);
        return var.toString();
    }

    public boolean SOF_SymEncryptFile(String sKey, String inFile, String outFile) {
        if (dotnetCom == null) {
            return false;
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_SymEncryptFile", sKey, inFile, outFile);
        return var.toBoolean();
    }

    public boolean SOF_SymDecryptFile(String sKey, String inFile, String outFile) {
        if (dotnetCom == null) {
            return false;
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_SymDecryptFile", sKey, inFile, outFile);
        return var.toBoolean();
    }

    public String SOF_Base64Encode(byte[] sIndata) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_Base64Encode", new String(sIndata));
        return var.toString();
    }

    public byte[] SOF_Base64Decode(String sIndata) {
        if (dotnetCom == null) {
            return null;
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_SOF_Base64Decode", sIndata);
        return var.toString().getBytes();
    }

    public String SOF_HashData(int hashAlg, String sInData) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_HashData", hashAlg, sInData);
        return var.toString();
    }

    public String SOF_HashFile(int hashAlg, String inFile) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_HashFile", hashAlg, inFile);
        return var.toString();
    }

    public String Base64EncodeFile(String inFile) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "Base64EncodeFile", inFile);
        return var.toString();
    }

    public String GetCert(String bSignCert) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "GetCert", bSignCert);
        return var.toString();
    }

    public String GetCertInfo(int iType) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "GetCertInfo", iType);
        return var.toString();
    }

    public String GetCertName() {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "GetCertName");
        return var.toString();
    }

    public String GetCertInfoByOID(String sOID) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "GetCertInfoByOID", sOID);
        return var.toString();
    }

    public String GetCertOID() {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "GetCertOID");
        return var.toString();
    }

    public int SOF_GetLastError() {
        if (dotnetCom == null) {
            return 0;
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_GetLastError");
        return var.toInt();
    }

    public String SOF_GetLastErrMsg() {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_GetLastError");
        return var.toString();
    }

    public String SOF_GetCertInfoByOid(String Cert, String Oid) {
        if (dotnetCom == null) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_GetCertInfoByOid", Cert, Oid);
        return var.toString();
    }

    public String SOF_GetCertInfo(String base64Cert, int type) {
        if (null == dotnetCom) {
            return "";
        }
        Variant var = Dispatch.call(dotnetCom, "SOF_GetCertInfo", base64Cert, type);
        return var.toString();
    }
}
