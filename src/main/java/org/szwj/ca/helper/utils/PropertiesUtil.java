package org.szwj.ca.helper.utils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class PropertiesUtil {

    private static PropertiesUtil propertiesUtil = new PropertiesUtil();

    private static Map<String, Map<String, String>> mPropertiesMap;

    public static PropertiesUtil getPropertiesUtil() {
        return propertiesUtil;
    }

    private PropertiesUtil() {
        mPropertiesMap = new HashMap<String, Map<String, String>>();
    }

    public Map<String, String> GetPropertiesContent(String filePath) throws IOException {
        Map<String, String> propertiesContent = mPropertiesMap.get(filePath);
        if (null == propertiesContent) {
            propertiesContent = ConfigUtil.readProperties(filePath);
            mPropertiesMap.put(filePath, propertiesContent);
        }
        return propertiesContent;
    }
}
