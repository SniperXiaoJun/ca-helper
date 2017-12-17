package org.szwj.ca.helper.models;

import java.util.List;

public class SignInfo {

    String businessSystemCode;

    String businessTypeCode;

    String pdfTypeCode;

    List<Position> positionList;

    public String getBusinessSystemCode() {
        return businessSystemCode;
    }

    public void setBusinessSystemCode(String businessSystemCode) {
        this.businessSystemCode = businessSystemCode;
    }

    public String getBusinessTypeCode() {
        return businessTypeCode;
    }

    public void setBusinessTypeCode(String businessTypeCode) {
        this.businessTypeCode = businessTypeCode;
    }

    public String getPdfTypeCode() {
        return pdfTypeCode;
    }

    public void setPdfTypeCode(String pdfTypeCode) {
        this.pdfTypeCode = pdfTypeCode;
    }

    public List<Position> getPositionList() {
        return positionList;
    }

    public void setPositionList(List<Position> positionList) {
        this.positionList = positionList;
    }
}
