package org.szwj.ca.helper.models;

public class ResponseBody {

    private int statusCode;

    private String eventMsg;

    private EventValue eventValue;

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getEventMsg() {
        return eventMsg;
    }

    public void setEventMsg(String eventMsg) {
        this.eventMsg = eventMsg;
    }

    public EventValue getEventValue() {
        return eventValue;
    }

    public void setEventValue(EventValue eventValue) {
        this.eventValue = eventValue;
    }
}
