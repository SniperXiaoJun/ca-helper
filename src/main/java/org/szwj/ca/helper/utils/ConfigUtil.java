package org.szwj.ca.helper.utils;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

public class ConfigUtil {

    public static Map<String, String> readProperties(String fileName)
        throws FileNotFoundException, IOException {

        Map<String, String> propertiesMap = new HashMap<String, String>();
        Properties prop = new Properties();

        InputStream in = new BufferedInputStream(new FileInputStream(fileName));
        prop.load(in);     ///加载属性列表
        Iterator<String> it = prop.stringPropertyNames().iterator();
        while (it.hasNext()) {
            String key = it.next();
            propertiesMap.put(key, prop.getProperty(key));
        }
        in.close();
        return propertiesMap;
    }

}
