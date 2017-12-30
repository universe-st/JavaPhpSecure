package secure;

/*
* Java、PHP安全通讯解决方案。
* */

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

public class EncryptUtil {

    public static final String SMALL_ALPHABET = "abcdefghijklmnopqrstuvwxyz";
    public static final String NUMBERS = "0123456789";
    public static final String BIG_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String BIG_OR_SMALL_ALPHABET = SMALL_ALPHABET + BIG_ALPHABET;
    public static final String URL_SUPPORT = BIG_OR_SMALL_ALPHABET + NUMBERS + "-";

    private static final String AES = "AES";
    private static final String AES_MODE = "AES/CBC/NoPadding";
    private static final int NORMAL_KEY_SIZE = 16;
    private static final String SHA256 = "SHA-256";
    private static final String RSA = "RSA";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";

    public static String AesEncrypt(String key, String iv, String plaintext){
        if(plaintext.length()==0)return "";
        key = normalKey(key);
        iv = normalKey(iv);
        IvParameterSpec ips = new IvParameterSpec(iv.getBytes());
        SecretKeySpec sks = new SecretKeySpec(key.getBytes(),AES);
        try {
            Cipher cipher = Cipher.getInstance(AES_MODE);
            cipher.init(Cipher.ENCRYPT_MODE,sks,ips);
            byte[] encrypted = cipher.doFinal(padString(plaintext).getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        }catch (Exception e){
            throw new EncryptException(e);
        }
    }

    public static String AesDecrypt(String key, String iv, String ciphertext){
        if(ciphertext.length()==0)return "";
        key = normalKey(key);
        iv = normalKey(iv);
        IvParameterSpec ips = new IvParameterSpec(iv.getBytes());
        SecretKeySpec sks = new SecretKeySpec(key.getBytes(),AES);
        try {
            Cipher cipher = Cipher.getInstance(AES_MODE);
            cipher.init(Cipher.DECRYPT_MODE,sks,ips);
            byte[] origin = Base64.getDecoder().decode(ciphertext);
            byte[] decrypt = cipher.doFinal(origin);
            return new String(decrypt).trim();
        }catch (Exception e){
            throw new EncryptException(e);
        }
    }

    public static String Sha256Encrypt(String ciphertext){
        try {
            byte[] digest = MessageDigest.getInstance(SHA256).digest(ciphertext.getBytes(Charset.forName("UTF-8")));
            return bytesToHex(digest);
        }catch (Exception e){
            throw new EncryptException(e);
        }
    }

    public static String RsaEncrypt(String publicKey,String plaintext){
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKey.trim());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory factory = KeyFactory.getInstance(RSA);
            RSAPublicKey key = (RSAPublicKey)factory.generatePublic(spec);
            Cipher cipher = Cipher.getInstance(RSA_MODE);
            cipher.init(Cipher.ENCRYPT_MODE,key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
        }catch (Exception e){
            throw new EncryptException(e);
        }
    }

    public static String RsaDecrypt(String privateKey,String ciphertext){
        try {
            byte[] keyBytes = Base64.getDecoder().decode(privateKey.trim());
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory factory = KeyFactory.getInstance(RSA);
            RSAPrivateKey key = (RSAPrivateKey)factory.generatePrivate(spec);
            Cipher cipher = Cipher.getInstance(RSA_MODE);
            cipher.init(Cipher.DECRYPT_MODE,key);
            return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
        }catch (Exception e){
            throw new EncryptException(e);
        }
    }

    public static String RsaSignature(String privateKey,String plaintext){
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getBytes()));
            KeyFactory factory = KeyFactory.getInstance(RSA);
            RSAPrivateKey key = (RSAPrivateKey)factory.generatePrivate(spec);
            Cipher cipher = Cipher.getInstance(RSA_MODE);
            cipher.init(Cipher.ENCRYPT_MODE,key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
        }catch (Exception e){
            throw new EncryptException(e);
        }
    }

    public static boolean RsaSignatureVerify(String message, String publicKey, String signature){
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
            KeyFactory factory = KeyFactory.getInstance(RSA);
            RSAPublicKey key = (RSAPublicKey)factory.generatePublic(spec);
            Cipher cipher = Cipher.getInstance(RSA_MODE);
            cipher.init(Cipher.DECRYPT_MODE,key);
            String ret = new String(cipher.doFinal(Base64.getDecoder().decode(signature)));
            return ret.equals(message);
        }catch (Exception e){
            e.printStackTrace(System.err);
            return false;
        }
    }

    public static String hashRsaSignature(String privateKey, String plaintext){
        return RsaSignature(privateKey,Sha256Encrypt(plaintext));
    }

    public static boolean hashRsaSignatureVerify(String origin,String publicKey, String signature){
        return RsaSignatureVerify(origin,publicKey,Sha256Encrypt(signature));
    }

    public static String randomString(int length){
        return randomString(length,SMALL_ALPHABET);
    }

    public static String randomString(int length,String pool){
        char[] str = new char[length];
        Random random = new Random();
        for(int i=0;i<length;i++){
            str[i] = pool.charAt(random.nextInt(pool.length()));
        }
        return new String(str);
    }

    private static String normalKey(String key){
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.getBytes(Charset.forName("UTF-8")));
            return Base64.getEncoder().encodeToString(digest).substring( 0, NORMAL_KEY_SIZE );
        }catch (Exception e){
            throw new EncryptException(e);
        }
    }

    private static String padString(String origin){
        StringBuilder sb = new StringBuilder(origin);
        final char paddingChar = ' ';
        final int size = 16;
        final int padLength =size - origin.getBytes(Charset.forName("UTF-8")).length % size;
        for (int i=0;i<padLength;i++){
            sb.append(paddingChar);
        }
        return sb.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes){
            String tmp = (Integer.toHexString(b & 0xFF));
            if(tmp.length() == 1){
                sb.append("0");
            }
            sb.append(tmp);
        }
        return sb.toString();
    }

    public static String readKeyFromFile(File file){
        try {
            FileInputStream input = new FileInputStream(file);
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));
            String line;
            StringBuilder sb = new StringBuilder();
            while((line = reader.readLine())!=null){
                sb.append(line);
            }
            reader.close();
            return sb.toString();
        }catch (Exception e){
            throw new EncryptException(e);
        }
    }
}
