package com.mertalptekin.cryptosamples.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.io.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Service
public class RSAService {

    // PublicKey dosyasını okuyup döndürme
    public PublicKey loadPublicKey(String path) throws Exception {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path)) {
            if (inputStream == null) {
                throw new Exception("Public key dosyası bulunamadı.");
            }
            InputStreamReader reader = new InputStreamReader(inputStream);
            StringBuilder keyBuilder = new StringBuilder();
            int ch;
            while ((ch = reader.read()) != -1) {
                keyBuilder.append((char) ch);
            }
            String publicKeyPEM = keyBuilder.toString()
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(encoded));
        }
    }

    // PrivateKey dosyasını okuyup döndürme
    public PrivateKey loadPrivateKey(String path) throws Exception {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path)) {
            if (inputStream == null) {
                throw new Exception("Private key dosyası bulunamadı.");
            }
            InputStreamReader reader = new InputStreamReader(inputStream);
            StringBuilder keyBuilder = new StringBuilder();
            int ch;
            while ((ch = reader.read()) != -1) {
                keyBuilder.append((char) ch);
            }
            String privateKeyPEM = keyBuilder.toString()
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            // KeyFactory, şifreleme algoritmalarında kullanılan anahtarları dönüştürmek ve yeni anahtarlar oluşturmak için kullanılan bir sınıftır. Bu sınıf, şifreleme işlemlerinde kullanılan asymmetric key (asimetrik anahtarlar) veya symmetric key (simetrik anahtarlar) yapılarını yönetmek için kullanılır.
            // Anahtarın şifreli veya belirli bir formatta (örneğin PEM ) olması durumunda, bu anahtarları byte dizilerine dönüştürmek için kullanılır.

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(encoded));
        }
    }

    // Şifreleme (Encryption)
    public byte[] encrypt(PublicKey publicKey, String data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    // Deşifreleme (Decryption)
    public String decrypt(PrivateKey privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        return new String(decryptedBytes);
    }

    // Test etme
    public void test(String originalMessage) throws Exception {
        PublicKey publicKey = loadPublicKey("keys/public.pem");
        PrivateKey privateKey = loadPrivateKey("keys/private.pem");

        System.out.println("Orijinal Mesaj: " + originalMessage);

        // Şifreleme
        byte[] encryptedMessage = encrypt(publicKey, originalMessage);
        System.out.println("Şifreli Mesaj: " + new String(encryptedMessage));

        // Deşifreleme
        String decryptedMessage = decrypt(privateKey, encryptedMessage);
        System.out.println("Deşifreli Mesaj: " + decryptedMessage);
    }
}
