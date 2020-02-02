package me.linmingren;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class PBKDF2Hash {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String message = "password";

        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        int iterations = 1000; //通过增加或者减小这个迭代次数来达到控制速度的目的
        PBEKeySpec spec = new PBEKeySpec(message.toCharArray(), salt, iterations, 64 * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] bytes = skf.generateSecret(spec).getEncoded();


        System.out.println("PBKDF2 hash of '" + message + "' with salt '" + toHexString(salt) + "' is '" + toHexString(bytes) + "'");
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
