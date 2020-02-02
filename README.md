# Java语言中的哈希算法
### MD5

MD5消息摘要算法是最常见的哈希算法，它的思路是把输入的内容，分成512位的块，最后一个块如果不足512位，则在最后填充内容。
输出的哈希值一般是个32字母的字符串。

```java
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
        System.out.println("MD5 hash of '" + message + "' is '" + sb.toString() + "'");
    }
}

```
MD5哈希的问题是它非常容易被暴力破解，而且不同的输入产生的结果可能会输出一样的结果。我们一般不会直接使用MD5对原始消息进行哈希，而是在
哈希时加入一些盐（salt）。需要指出的是，盐这个概念不是MD5算法的东西，你可以在任何的哈希算法里加入盐。根据维基百科的解释，盐是一串随机数据，
可以用来作为哈希函数的附加输入，我们把盐理解成一串随机的字符串就可以了。最初提出盐的概念是为了防止彩虹表攻击，现在则主要是用来减慢哈希的速度。
现在我们知道盐最重要的是特征是随机性，那么在Java语言中，对应的东西就是SecureRandom, 只需要通过SecureRandom生成对应长度的字符串即可。

让我们在上面的例子里加上盐，这一次我们把从byte数组转换成16进制字符串的功能抽取到toHexString函数中，以便代码更清晰一点。
```java
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

```

###SHA哈希
由于MD5实在太不安全，人们又提出了SHA算法的哈希函数组，这些哈希算法比MD5安全很多，但是仍然可能会产生同样的输出。Java语言内置了
以下4种SHA算法。

* SHA-1 输出160位的哈希值
* SHA-256 输出256位的哈希值
* SHA-384 
* SHA-512 
在Java里使用这些算法和使用MD5一样简单，让我们继续改进第一个例子。

```java
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
```

### CPU密集型哈希算法
我们前面说到增加盐可以减少彩虹表攻击， 但是前面提到的几种算法速度其实都太快了， 人们就想到是否认为让这些算法变慢，但是又不至于影响到用户的体验。
像PBKDF2， Bcrypt，Scrypt这几个算法就是按这种思路提出来的，这几种算法在生成哈希时，可以人为调整它的参数，来让它更快或者
更慢。Java语言内置了PBKDF2算法，不过实际的名字叫做PBKDF2WithHmacSHA1。当迭代次数是1000时，可以明显感觉到输出不是马上出来的。

```java
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

```

Java语言并没有内置BCrypt和Scrypt，不过Spring Security内置了这2种算法的实现，使用起来非常简单。首先增加了Spring Security Core的依赖。

```xml
 <dependency>
      <groupId>org.springframework.security</groupId>
      <artifactId>spring-security-core</artifactId>
      <version>5.2.1.RELEASE</version>
    </dependency>
```
然后使用BCryptPasswordEncoder或者SCryptPasswordEncoder来encode一个字符串，这样的使用场景和实际应用更加贴切，一般我们保存到数据中的都是字符串，而不是
byte数组，我们定位问题时想看到的也是字符串，而不是一堆byte。需要注意的是BCrypt和SCrypt都不需要从外部传入盐， 它内部已经处理这个问题。唯一可以控制的就是哈希的嵌强度。

```java
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
```

