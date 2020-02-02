package me.linmingren;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptHash {
    public static void main(String[] args)  {
        //换成SCryptPasswordEncoder 就是SCrypt算法的哈希
        //强度默认是10， 最大31
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(16);
        String message = "password";

        String encryptedMessage = encoder.encode(message);
        System.out.println("BCrypt hash of '" + message + "' is '" + encryptedMessage + "'");
    }
}
