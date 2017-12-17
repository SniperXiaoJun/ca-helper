package org.szwj.ca.helper.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.szwj.ca.helper.models.EventValue;
import org.szwj.ca.helper.models.ResponseBody;
import java.util.ArrayList;
import java.util.List;

public class JsonHelper {

    public static String generateResponse(int statusCode, String eventMsg, EventValue eventValue) {
        ResponseBody resp = new ResponseBody();
        resp.setStatusCode(statusCode);
        resp.setEventMsg(eventMsg);
        resp.setEventValue(eventValue);

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        return gson.toJson(resp);
    }

    public static ResponseBody parseResponse(String responseJson) {
        Gson gson = new Gson();
        ResponseBody responseBody = gson.fromJson(responseJson, ResponseBody.class);
        return responseBody;
    }

    public static String getValueFromEventValue(String responseJson, String eventValueKey) {
        final JsonObject jsonObject = new JsonParser().parse(responseJson).getAsJsonObject();
        final JsonObject eventValueJsonObject = jsonObject.getAsJsonObject("eventValue");
        final JsonElement jsonElement = eventValueJsonObject.get(eventValueKey);
        return jsonElement.getAsString();
    }

    public static String generateJsonString(Object object) {
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        return gson.toJson(object);
    }

    public static <T> T parseJsonToClass(String jsonData, Class<T> classOfT) {
        Gson gson = new Gson();
        T target = gson.fromJson(jsonData, classOfT);
        return target;
    }

    public static <T> List<T> parseJsonToList(String jsonData, Class<T> type) {
        List<T> list = new ArrayList<T>();
        Gson gson = new Gson();
        JsonParser parser = new JsonParser();
        JsonArray jsonarray = parser.parse(jsonData).getAsJsonArray();
        for (JsonElement element : jsonarray) {
            list.add(gson.fromJson(element, type));
        }
        return list;
    }
}