package com.against.oascan.utils;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

public class HttpUtil {
    private static Response response;

    //直接全局忽略SSL
    static {
        response = new Response();  //定义response
        try {
            trustAllHttpsCertificates();
            HttpsURLConnection.setDefaultHostnameVerifier((urlHostName, session) -> true);
        } catch (Exception e) {
        }
    }

    /**
     * 发送http的Get请求
     *
     * @param url
     * @param proxy
     * @return
     */
    public static Response doGet(String url, Proxy proxy) {
        StringBuilder result = new StringBuilder();
        HttpURLConnection conn = null;
        BufferedReader br = null;
        String content;
        try {
            URL u = new URL(url);
            if (proxy == null) {
                conn = (HttpURLConnection) u.openConnection();
            } else {
                conn = (HttpURLConnection) u.openConnection(proxy);
            }
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(60000);
            conn.setReadTimeout(60000);
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
            conn.setRequestProperty("Connection", "close");
            conn.connect();

            try {
                //获取返回的数据信息并设置response的text
                br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"));
                while ((content = br.readLine()) != null) {
                    result.append(content + "\n");
                }
                response.setText(result.toString());
                response.setCode(conn.getResponseCode());
                response.setHead(conn.getHeaderFields().toString());
            } catch (Exception e) {
                //当返回代码为500，404，403时获取报错信息并设置response的text为报错信息，避免丢失数据,解决空指针异常
                if (conn.getErrorStream() == null) {
                    response.setText("");
                    response.setCode(0);
                    response.setHead("");
                } else {
                    br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "utf-8"));
                    while ((content = br.readLine()) != null) {
                        result.append(content + "\n");
                    }
                    response.setText(result.toString());
                    response.setCode(conn.getResponseCode());
                    response.setHead(conn.getHeaderFields().toString());
                }
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
        return response;
    }

    /**
     * 发送自定义的GET请求
     *
     * @param url
     * @param heads
     * @param proxy
     * @return
     */
    public static Response doComplexGet(String url, List<String> heads, Proxy proxy) {
        StringBuilder result = new StringBuilder();
        HttpURLConnection conn = null;
        BufferedReader br = null;
        String content;
        try {
            URL u = new URL(url);
            if (proxy == null) {
                conn = (HttpURLConnection) u.openConnection();
            } else {
                conn = (HttpURLConnection) u.openConnection(proxy);
            }
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(60000);
            conn.setReadTimeout(60000);
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
            conn.setRequestProperty("Connection", "close");

            //循环加上请求头
            for (String head : heads) {
                String data[] = head.split(":");
                conn.setRequestProperty(data[0].trim(), data[1].trim());
            }
            conn.connect();

            try {
                //获取返回的数据信息并设置response的text
                br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"));
                while ((content = br.readLine()) != null) {
                    result.append(content + "\n");
                }
                response.setText(result.toString());
                response.setCode(conn.getResponseCode());
                response.setHead(conn.getHeaderFields().toString());
            } catch (Exception e) {
                //当返回代码为500，404，403时获取报错信息并设置response的text为报错信息，避免丢失数据,解决空指针异常
                if (conn.getErrorStream() == null) {
                    response.setText("");
                    response.setCode(0);
                    response.setHead("");
                } else {
                    br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "utf-8"));
                    while ((content = br.readLine()) != null) {
                        result.append(content + "\n");
                    }
                    response.setText(result.toString());
                    response.setCode(conn.getResponseCode());
                    response.setHead(conn.getHeaderFields().toString());
                }
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
        return response;
    }

    /**
     * 发送http的Post请求
     *
     * @param url
     * @param postData
     * @param proxy
     * @return
     */
    public static Response doPost(String url, String postData, Proxy proxy) {
        StringBuilder result = new StringBuilder();
        HttpURLConnection conn = null;
        BufferedReader br = null;
        String content;

        try {
            URL u = new URL(url);
            if (proxy == null) {
                conn = (HttpURLConnection) u.openConnection();
            } else {
                conn = (HttpURLConnection) u.openConnection(proxy);
            }
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(60000);
            conn.setReadTimeout(60000);
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
            conn.setRequestProperty("Connection", "close");
            OutputStream os = conn.getOutputStream();
            os.write(postData.getBytes());
            os.flush();
            os.close();
            conn.connect();

            try {
                //获取返回的数据信息并设置response的text
                br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"));
                while ((content = br.readLine()) != null) {
                    result.append(content + "\n");
                }
                response.setText(result.toString());
                response.setCode(conn.getResponseCode());
                response.setHead(conn.getHeaderFields().toString());
            } catch (Exception e) {
                //当返回代码为500，404，403时获取报错信息并设置response的text为报错信息，避免丢失数据,解决空指针异常
                if (conn.getErrorStream() == null) {
                    response.setText("");
                    response.setCode(0);
                    response.setHead("");
                } else {
                    br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "utf-8"));
                    while ((content = br.readLine()) != null) {
                        result.append(content + "\n");
                    }
                    response.setText(result.toString());
                    response.setCode(conn.getResponseCode());
                    response.setHead(conn.getHeaderFields().toString());
                }
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
        return response;
    }


    /**
     * 发送自定义请求头的POST请求
     *
     * @param url
     * @param postData
     * @param heads
     * @param proxy
     * @return
     */
    public static Response doComplexPost(String url, String postData, List<String> heads, Proxy proxy) {
        StringBuilder result = new StringBuilder();
        HttpURLConnection conn = null;
        BufferedReader br = null;
        String content;

        try {
            URL u = new URL(url);
            if (proxy == null) {
                conn = (HttpURLConnection) u.openConnection();
            } else {
                conn = (HttpURLConnection) u.openConnection(proxy);
            }
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(60000);
            conn.setReadTimeout(60000);
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
            conn.setRequestProperty("Connection", "close");

            //循环加上请求头
            for (String head : heads) {
                String data[] = head.split(":");
                conn.setRequestProperty(data[0].trim(), data[1].trim());
            }

            OutputStream os = conn.getOutputStream();
            os.write(postData.getBytes());
            os.flush();
            os.close();
            conn.connect();

            try {
                //获取返回的数据信息并设置response的text
                br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"));
                while ((content = br.readLine()) != null) {
                    result.append(content + "\n");
                }
                response.setText(result.toString());
                response.setCode(conn.getResponseCode());
                response.setHead(conn.getHeaderFields().toString());
            } catch (Exception e) {
                //当返回代码为500，404，403时获取报错信息并设置response的text为报错信息，避免丢失数据,解决空指针异常
                if (conn.getErrorStream() == null) {
                    response.setText("");
                    response.setCode(0);
                    response.setHead("");
                } else {
                    br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "utf-8"));
                    while ((content = br.readLine()) != null) {
                        result.append(content + "\n");
                    }
                    response.setText(result.toString());
                    response.setCode(conn.getResponseCode());
                    response.setHead(conn.getHeaderFields().toString());
                }
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
        return response;
    }

    public static Response uploadFile(String url, StringBuilder tempParams, List<String> heads, Proxy proxy) {
        StringBuilder result = new StringBuilder();
        HttpURLConnection conn = null;
        BufferedReader br = null;
        String content;

        try {
            URL u = new URL(url);
            if (proxy == null) {
                conn = (HttpURLConnection) u.openConnection();
            } else {
                conn = (HttpURLConnection) u.openConnection(proxy);
            }
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(60000);
            conn.setReadTimeout(60000);
            conn.setRequestProperty("Accept-Charset", "GBK");
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36");
            conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryBE2AUcdQ1Hp3HWDu");
            conn.setRequestProperty("Connection", "close");

            //循环加上请求头
            for (String head : heads) {
                String data[] = head.split(":");
                conn.setRequestProperty(data[0].trim(), data[1].trim());
            }

            DataOutputStream requestStream = new DataOutputStream(conn.getOutputStream());
            requestStream.writeBytes("------WebKitFormBoundaryBE2AUcdQ1Hp3HWDu" + "\r\n");
            tempParams.append("\r\n");
            requestStream.writeBytes(tempParams.toString());
            requestStream.flush();
            requestStream.close();
            conn.connect();

            try {
                //获取返回的数据信息并设置response的text
                br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                while ((content = br.readLine()) != null) {
                    result.append(content + "\n");
                }
                response.setText(result.toString());
            } catch (Exception e) {
                //当返回代码为500，404，403时获取报错信息并设置response的text为报错信息，避免丢失数据,解决空指针异常
                br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
                while ((content = br.readLine()) != null) {
                    result.append(content + "\n");
                }
                response.setText(result.toString());
            }

            response.setCode(conn.getResponseCode());
            response.setHead(conn.getHeaderFields().toString());

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
        return response;
    }

    /**
     * 跳过ssl证书
     *
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     */
    private static void trustAllHttpsCertificates() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllCerts = new TrustManager[1];
        trustAllCerts[0] = (TrustManager) new TrustAllManager();
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    private static class TrustAllManager implements X509TrustManager {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }
    }
}
