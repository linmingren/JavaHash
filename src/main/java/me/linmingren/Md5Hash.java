package me.linmingren;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Md5Hash {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        String message = "password";

        md.update(message.getBytes());
        byte[] bytes = md.digest();

        StringBuilder sb = new StringBuilder();
        //bytes的长度是16个字节， 每个字节最多为2位数的16进制数字，所以最后的字符串长度是16 x 2 = 32
        for(int i=0; i< bytes.length ;i++)
        {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        System.out.println("md5 hash of '" + message + "' is '" + sb.toString() + "'");
    }
}
