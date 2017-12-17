package org.szwj.ca.helper.utils;

import org.szwj.ca.helper.models.CaHelperException;
import java.io.IOException;
import java.nio.charset.Charset;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

public class HttpClientUtil {

    public static String HttpPostWithJson(String url, String requestBody)
        throws IOException, CaHelperException {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        try {
            HttpPost httpPost = new HttpPost(url);

            // 构造消息头
            httpPost.setHeader("Content-type", "application/json; charset=utf-8");
            httpPost.setHeader("Connection", "Close");

            StringEntity entity = null;
            if (!Tools.isStringEmpty(requestBody)) {
                // 构建消息实体
                entity = new StringEntity(requestBody, Charset.forName("UTF-8"));
                entity.setContentEncoding("UTF-8");
                // 发送Json格式的数据请求
                entity.setContentType("application/json");
                httpPost.setEntity(entity);
            }

            CloseableHttpResponse httpResponse = null;
            try {
                httpResponse = httpclient.execute(httpPost);
                String responseEntity = EntityUtils.toString(httpResponse.getEntity());

                // 检查返回码
                int httpStatusCode = httpResponse.getStatusLine().getStatusCode();
                if (HttpStatus.SC_OK != httpStatusCode) {
                    throw new CaHelperException(responseEntity);
                }
                return responseEntity;
            } finally {
                if (null != httpResponse) {
                    try {
                        httpResponse.close();
                    } catch (IOException e) {
                        System.out.println("close httpResponse failed, error: " + e.getMessage());
                    }
                }
            }
        } finally {
            if (null != httpclient) {
                try {
                    httpclient.close();
                } catch (IOException e) {
                    System.out.println("close httpclient failed, error: " + e.getMessage());
                }
            }
        }
    }
}
