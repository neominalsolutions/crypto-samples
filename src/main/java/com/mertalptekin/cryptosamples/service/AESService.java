package com.mertalptekin.cryptosamples.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

// Anahtar Uzunluğu: AES, genellikle 128, 192 veya 256 bit anahtar uzunluklarıyla kullanılır. Anahtar uzunluğu arttıkça güvenlik seviyesi de artar.
// Blok Şifreleme: AES, veriyi bloklar halinde şifreler. AES her seferinde 128 bit (16 byte) uzunluğunda veri bloklarını işler.
//
//Yüksek Performans: AES, güvenliği sağlarken hızlı çalışabilen ve verimli bir algoritmadır.

// VPN (Virtual Private Network)
// SSL/TLS hem simetrik hemde asimetrik
// Wi-Fi güvenliği WPA2  128bit
// Dosya ve Veri Şifreleme Uygulamaları
// Endüstriyel Sistemler ve IoT

@Service
public class AESService {

    // AES Anahtar Üretme (128 bit)
    public String generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);  // 128-bit anahtar
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public String encrypt(String data, String secretKey) throws Exception {
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public String decrypt(String encryptedData, String secretKey) throws Exception {
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = cipher.doFinal(decodedData);
        return new String(decryptedData);
    }
}
