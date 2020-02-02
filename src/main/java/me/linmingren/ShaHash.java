package me.linmingren;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ShaHash {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        MessageDigest[] mdList = new MessageDigest[]{MessageDigest.getInstance("MD5"), MessageDigest.getInstance("SHA-1"),
                MessageDigest.getInstance("SHA-256"),
                MessageDigest.getInstance("SHA-384"),
                MessageDigest.getInstance("SHA-512")};
        String message = "password";

        for (MessageDigest md : mdList) {
            md.update(message.getBytes());
            byte[] bytes = md.digest();
            System.out.println(md.getAlgorithm() + " hash of '" + message + "' is '" + toHexString(bytes) + "'");
        }
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        //bytes的长度是16个字节， 每个字节最多为2位数的16进制数字，所以最后的字符串长度是16 x 2 = 32
        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }
}

