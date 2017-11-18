package com.yuan.passwordcore;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 密码生成器
 */
public class PasswordCreator {

    /**
     * 密码中的特殊字符
     */
    private static char[] specialChar = new char[]{'~', '@', '#', '$', '^', '&', '*', '[', ']'};

    public static MessageDigest md5Digest;

    static {
        try {
            md5Digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成n位数字密码
     *
     * @param numberLen 密码位数
     * @return
     */
    public static String createNumberPassword(String mainKey, String domain, String username, String versionCode, int numberLen) {
        String password = "";

        byte[] secret = createSecretByte(mainKey, domain, username, versionCode);
        if (secret != null) {
            password = new BigInteger(1, secret).toString(10);
        }
        if (password.length() > numberLen) {
            password = password.substring(0, numberLen);
        }
        return password;
    }

    /**
     * 生成混合密码，包含数字，大小写字母，特殊字符
     *
     * @param numberLen 密码位数
     * @return
     */
    public static String createMixPassword(String mainKey, String domain, String username, String versionCode, int numberLen) {
        String password = "";

        byte[] secret = createSecretByte(mainKey, domain, username, versionCode);
        BigInteger bigInteger = null;
        if (secret != null) {
            if (secret != null) {
                bigInteger = new BigInteger(1, secret);
                password = bigInteger.toString(16);
            }
            if (password.length() > numberLen) {
                StringBuilder stringBuilder = new StringBuilder(password);

                //替换特殊字符到某个位置
                int bigNumber = bigInteger.bitCount();
                int specialOffset = bigNumber % numberLen;
                specialOffset = specialOffset % specialChar.length;
                char special = specialChar[specialOffset];
                stringBuilder.replace(specialOffset, specialOffset + 1, special + "");

                //寻找第一个字母字符替换成大写, 如果没有字母，则将除特殊字符的第一个字符替换成字母
                int letterIndex = -1;
                for (int i = 0; i < numberLen; i++) {
                    char currentChar = stringBuilder.charAt(i);
                    if (Character.isLetter(currentChar)) {
                        currentChar = Character.toUpperCase(currentChar);
                        stringBuilder.replace(i, i + 1, currentChar + "");
                        letterIndex = i;
                        break;
                    }
                }
                if (letterIndex == -1) {
                    int i = 0;
                    while (i < numberLen) {
                        if (i == specialOffset) {
                            i++;
                            continue;
                        }
                        int letter = bigNumber % 25 + 65;  //获取 A-Z 对应的其中一个
                        stringBuilder.replace(i, i + 1, (char) letter + "");
                        letterIndex = i;
                        break;
                    }
                }

                //如果没有数字，则在相应位置设置一个数字
                int numIndex = -1;
                for (int i = 0; i < numberLen; i++) {
                    char currentChar = stringBuilder.charAt(i);
                    if (Character.isDigit(currentChar)) {
                        numIndex = i;
                        break;
                    }
                }
                if (numIndex == -1) {
                    int i = 0;
                    while (i < numberLen) {
                        if (i == specialOffset || i == letterIndex) {
                            i++;
                            continue;
                        }
                        int numberCount = bigNumber % 10;
                        stringBuilder.replace(i, i + 1, numberCount + "");
                        break;
                    }
                }

                password = stringBuilder.substring(0, numberLen);
            }
        }

        return password;
    }

    /**
     * 生成密码二进制数据
     *
     * @param mainKey     秘钥，自己保管
     * @param domain      应用、网址、银行等名称
     * @param username    用户名，可以是手机号，email地址等
     * @param versionCode 对应版本，1，2, 3 ...
     * @return
     */
    private static byte[] createSecretByte(String mainKey, String domain, String username, String versionCode) {
        StringBuilder keyBuilder = new StringBuilder();
        keyBuilder.append(mainKey).append(domain).append(username).append(versionCode);
        String key = keyBuilder.toString();
        if (md5Digest != null) {
            md5Digest.update(key.getBytes(Charset.forName("UTF-8")));
            return md5Digest.digest();
        }
        return null;
    }
}
