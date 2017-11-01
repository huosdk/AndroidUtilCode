/*
 * Copyright (c) 2017.
 * AuthCodeUtil.java   UTF-8
 * Create by liuhongliang <752284118@qq.com> on 17-1-20 下午3:48
 *
 * Last modified 17-1-20 下午3:45
 */

package com.blankj.utilcode.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
/**
 * PHP authcode 对称加密算法
 * 特点：使用相同的key加密，加密内容相同但每次加密结果不一样
 * add 2017-11-01 by liang530
 */
public class AuthCodeUtil {
    /**
     * 加密字符集使用的长度
     */
    private static int charLength = 128;
    /**
     * ios只能使用128,使用此长度可兼容ios和android
     */
    public static final int LENGTH_128 = 128;
    public static final int LENGTH_256 = 256;

    /**
     * BASE64解密
     * @param key
     * @return
     * @throws Exception
     */private static byte[] decryptBASE64(String key) throws Exception {
        return  EncodeUtils.base64Decode(key);
    }

    /**
     * BASE64加密
     * @param key
     * @return
     * @throws Exception
     */private static String encryptBASE64(byte[] key)throws Exception {
        return EncodeUtils.base64Encode2String(key);
    }


    /**
     * 获取加密字符集使用的长度
     *
     * @return 加密字符传的长度
     */
    public static int getCharLength() {
        return charLength;
    }

    /**
     * 设置加密字符集使用的长度
     * @param charLength 加密字符串的长度
     */
    public static void setCharLength(int charLength) {
        AuthCodeUtil.charLength = charLength;
    }
    public enum DiscuzAuthcodeMode {
        Encode, Decode
    }
    /// <summary>
    /// 从字符串的指定位置截取指定长度的子字符串
    /// </summary>
    /// <param name="str">原字符串</param>
    /// <param name="startIndex">子字符串的起始位置</param>
    /// <param name="charLength">子字符串的长度</param>
    /// <returns>子字符串</returns>
    public static String CutString(String str, int startIndex, int length) {
        if (startIndex >= 0) {
            if (length < 0) {
                length = length * -1;
                if (startIndex - length < 0) {
                    length = startIndex;
                    startIndex = 0;
                } else {
                    startIndex = startIndex - length;
                }
            }

            if (startIndex > str.length()) {
                return "";
            }
        } else {
            if (length < 0) {
                return "";
            } else {
                if (length + startIndex > 0) {
                    length = length + startIndex;
                    startIndex = 0;
                } else {
                    return "";
                }
            }
        }

        if (str.length() - startIndex < length) {

            length = str.length() - startIndex;
        }
        return str.substring(startIndex, startIndex + length);
    }

    /// <summary>
    /// 从字符串的指定位置开始截取到字符串结尾的了符串
    /// </summary>
    /// <param name="str">原字符串</param>
    /// <param name="startIndex">子字符串的起始位置</param>
    /// <returns>子字符串</returns>
    private static String CutString(String str, int startIndex) {
        return CutString(str, startIndex, str.length());
    }

    /// <summary>
    /// 用于 RC4 处理密码
    /// </summary>
    /// <param name="pass">密码字串</param>
    /// <param name="kLen">密钥长度，一般为 charLength</param>
    /// <returns></returns>
    static private byte[] GetKey(byte[] pass, int kLen) {
        byte[] mBox = new byte[kLen];

        for (int i = 0; i < kLen; i++) {
            mBox[i] = (byte) i;
        }

        int j = 0;
        for (int i = 0; i < kLen; i++) {

            j = (j +  ((mBox[i] + charLength) % charLength) + pass[i % pass.length])
                    % kLen;

            byte temp = mBox[i];
            mBox[i] = mBox[j];
            mBox[j] = temp;
        }

        return mBox;
    }

    /// <summary>
    /// 生成随机字符
    /// </summary>
    /// <param name="lens">随机字符长度</param>
    /// <returns>随机字符</returns>
    private static String RandomString(int lens) {
        char[] CharArray = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k',
                'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
                'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
        int clens = CharArray.length;
        String sCode = "";
        Random random = new Random();
        for (int i = 0; i < lens; i++) {
            sCode += CharArray[Math.abs(random.nextInt(clens))];
        }
        return sCode;
    }

    /// <summary>
    /// 使用 Discuz authcode 方法对字符串加密
    /// </summary>
    /// <param name="source">原始字符串</param>
    /// <param name="key">密钥</param>
    /// <param name="expiry">加密字串有效时间，单位是秒</param>
    /// <returns>加密结果</returns>
    public static String authcodeEncode(String source, String key, int expiry) {
        return authcode(source, key, DiscuzAuthcodeMode.Encode, expiry);

    }

    /// <summary>
    /// 使用 Discuz authcode 方法对字符串加密
    /// </summary>
    /// <param name="source">原始字符串</param>
    /// <param name="key">密钥</param>
    /// <returns>加密结果</returns>
    public static String authcodeEncode(String source, String key) {
        String authcode = authcode(source, key, DiscuzAuthcodeMode.Encode, 0);
        return authcode;

    }

    /// <summary>
    /// 使用 Discuz authcode 方法对字符串解密
    /// </summary>
    /// <param name="source">原始字符串</param>
    /// <param name="key">密钥</param>
    /// <returns>解密结果</returns>
    public static String authcodeDecode(String source, String key) {
        return authcode(source, key, DiscuzAuthcodeMode.Decode, 0);

    }

    /// <summary>
    /// 使用 变形的 rc4 编码方法对字符串进行加密或者解密
    /// </summary>
    /// <param name="source">原始字符串</param>
    /// <param name="key">密钥</param>
    /// <param name="operation">操作 加密还是解密</param>
    /// <param name="expiry">加密字串过期时间</param>
    /// <returns>加密或者解密后的字符串</returns>
    private static String authcode(String source, String key,
                                   DiscuzAuthcodeMode operation, int expiry) {
        try {
            if (source == null || key == null) {
                return "";
            }
            int ckey_length = 4;
            String keya, keyb, keyc, cryptkey, result;

            key = MD52(key);
            keya = MD52(CutString(key, 0, 16));
            keyb = MD52(CutString(key, 16, 16));
            keyc = ckey_length > 0 ? (operation == DiscuzAuthcodeMode.Decode ? CutString(
                    source, 0, ckey_length)
                    : RandomString(ckey_length))
                    : "";
            cryptkey = keya + MD52(keya + keyc);
            if (operation == DiscuzAuthcodeMode.Decode) {
                byte[] temp;

                temp = decryptBASE64(CutString(source, ckey_length));
                result = new String(RC4(temp, cryptkey));
                if (CutString(result, 10, 16).equals(CutString(MD52(CutString(result, 26) + keyb), 0, 16))) {
                    return CutString(result, 26);
                } else {
                    temp = decryptBASE64(CutString(source + "=", ckey_length));
                    result = new String(RC4(temp, cryptkey));
                    if (CutString(result, 10, 16).equals(CutString(MD52(CutString(result, 26) + keyb), 0, 16))) {
                        return CutString(result, 26);
                    } else {
                        temp = decryptBASE64(CutString(source + "==", ckey_length));
                        //temp = Base64.decode(CutString(source+"", ckey_length), 0);
                        result = new String(RC4(temp, cryptkey));
                        if (CutString(result, 10, 16).equals(CutString(MD52(CutString(result, 26) + keyb), 0, 16))) {
                            return CutString(result, 26);
                        } else {
                            return "2";
                        }
                    }
                }
            } else {
                source = "0000000000" + CutString(MD52(source + keyb), 0, 16)
                        + source;

                byte[] temp = RC4(source.getBytes("UTF-8"), cryptkey);
                return keyc + encryptBASE64(temp);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }

    }

    // / <summary>
    // / RC4 原始算法
    // / </summary>
    // / <param name="input">原始字串数组</param>
    // / <param name="pass">密钥</param>
    // / <returns>处理后的字串数组</returns>
    private static byte[] RC4(byte[] input, String pass) {
        if (input == null || pass == null)
            return null;


        byte[] output = new byte[input.length];
        byte[] mBox = GetKey(pass.getBytes(), charLength);

        // 加密
        int i = 0;
        int j = 0;

        for (int offset = 0; offset < input.length; offset++) {
            i = (i + 1) % mBox.length;
            j = (j +  ((mBox[i] + charLength) % charLength)) % mBox.length;

            byte temp = mBox[i];
            mBox[i] = mBox[j];
            mBox[j] = temp;
            byte a = input[offset];

            //byte b = mBox[(mBox[i] + mBox[j] % mBox.Length) % mBox.Length];
            // mBox[j] 一定比 mBox.Length 小，不需要在取模
            byte b = mBox[(toInt(mBox[i]) + toInt(mBox[j])) % mBox.length];

            output[offset] = (byte) ((int) a ^ toInt(b));
        }

        return output;
    }

    private static String MD52(String MD5) {
        StringBuilder sb = new StringBuilder();
        String part;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] md5 = md.digest(MD5.getBytes());

            for (byte aMd5 : md5) {
                part = Integer.toHexString(aMd5 & 0xFF);
                if (part.length() == 1) {
                    part = "0" + part;
                }
                sb.append(part);
            }

        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return sb.toString();

    }

    private static int toInt(byte b) {
        return (b + charLength) % charLength;
    }


    public static void main(String[] args) {
        String test = "13148984025";
        String key = "62b7aa0af4b700031b1342700cf5fe75";
        String afStr = AuthCodeUtil.authcodeEncode(test, key);
        System.out.println("--------encode:" + afStr);
        String deStr = AuthCodeUtil.authcodeDecode("d3en4BGq7+BiFkLQFvbuNioIXxJbruTbUx0RRea0sNrhK/JYoq0WQw==", key);
        System.out.println("--------decode:" + deStr);
    }
}
