package me.linmingren;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Md5HashWithSalt {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        String message = "password";

        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        md.update(salt);
        md.update(message.getBytes());
        byte[] bytes = md.digest();

        System.out.println("md5 hash of '" + message + "' with salt '" +toHexString(salt)+ "' is '" + toHexString(bytes) + "'");
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        //bytes的长度是16个字节， 每个字节最多为2位数的16进制数字，所以最后的字符串长度是16 x 2 = 32
        for(int i=0; i< bytes.length ;i++)
        {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }
}
