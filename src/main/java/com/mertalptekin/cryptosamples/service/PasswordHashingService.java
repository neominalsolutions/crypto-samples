package com.mertalptekin.cryptosamples.service;

import org.springframework.stereotype.Service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

// PBKDF2 (Password-Based Key Derivation Function 2), şifreleri hash'lemek için kullanılan bir algoritmadır. Bu algoritma, şifreyi hash'lemek için salt (bir rastgele veri) ve çok sayıda iterasyon kullanır. İterasyon sayısının artırılması, brute-force saldırılarına karşı daha dayanıklı hale gelir.

@Service
public class PasswordHashingService {

    public byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];  // 16 baytlık bir salt
        secureRandom.nextBytes(salt);
        return salt;
    }

    public String hashPassword(String password, byte[] salt) throws Exception {
        // PBKDF2 algoritmasını kullanacağız
        int iterations = 10000; // Iterasyon sayısı
        int keyLength = 512;    // Hash uzunluğu (bit cinsinden)


        // KeySpec,  Anahtar oluşturulurken, genellikle KeySpec sınıflarını kullanarak çeşitli parametreler (salt, şifre, algoritma vs.) belirlenir.
        // KeySpec, genellikle SecretKeyFactory veya KeyFactory gibi sınıflar tarafından kullanılır ve bunlar üzerinden anahtar türetmek için kullanılır.
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);

        // SecretKeyFactory, simetrik anahtarlar (symmetric keys) oluşturmak ve dönüştürmek için kullanılır.
        // Hashing algoritmaları kullanarak, şifreleri güçlü bir şekilde hash'lemek veya şifreleme anahtarları türetmek için kullanılır.
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hashedPassword); // Hash'i Base64 formatında döndürüyoruz
    }

    public boolean verifyPassword(String inputPassword, String storedHash, byte[] storedSalt) throws Exception {
        String inputPasswordHash = hashPassword(inputPassword, storedSalt);
        return inputPasswordHash.equals(storedHash);
    }

}
