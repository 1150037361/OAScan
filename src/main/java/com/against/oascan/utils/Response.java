package com.against.oascan.utils;

import lombok.Data;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Data
public class Response {
    private String text;
    private Integer code;
    private String head;

    public Response() {
    }

    public Response(String text, Integer code, String head) {
        this.text = text;
        this.code = code;
        this.head = head;
    }

    public static String dataCleaning(String str, Pattern pattern) {
        Matcher matcher = pattern.matcher(str);
        if (matcher.find()) {
            str = matcher.group(0);
        }
        return str;
    }

    public static String dataCleaning2(String str, Pattern pattern) {
        Matcher matcher = pattern.matcher(str);
        if (matcher.find()) {
            str = matcher.group(1);
        }
        return str;
    }

    public static String base64Encode(String str) {
        return Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8));
    }

    public static String base64Decode(String str) {
        return new String(Base64.getDecoder().decode(str), StandardCharsets.UTF_8);
    }

}
