import com.against.oascan.utils.Response;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Test {
    public static void main(String[] args) throws Exception {
        String data = "<Input type=\"text\" name=\"WEBROOT\" class=\"SmallInput\" value=\"E:\\MYOA\\webroot\" size=\"40\">";
        String info = Response.dataCleaning2(data, Pattern.compile("name=\"WEBROOT\".+?value=\"(.+?)\""));
        System.out.println(info);
    }
    public static String getUUID() {
        UUID uuid = UUID.randomUUID();
        String str = uuid.toString();
        String uuidStr = str.replace("-", "");
        return uuidStr;
    }
    public static String dataCleaning(String str, Pattern pattern) {
        Matcher matcher = pattern.matcher(str);
        if (matcher.find()) {
            str = matcher.group(1);
        }
        return str;
    }
}
