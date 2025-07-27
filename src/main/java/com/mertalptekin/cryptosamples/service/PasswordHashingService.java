package com.mertalptekin.cryptosamples.service;

import org.springframework.stereotype.Service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

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

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hashedPassword); // Hash'i Base64 formatında döndürüyoruz
    }

    public boolean verifyPassword(String inputPassword, String storedHash, byte[] storedSalt) throws Exception {
        String inputPasswordHash = hashPassword(inputPassword, storedSalt);
        return inputPasswordHash.equals(storedHash);
    }

}
