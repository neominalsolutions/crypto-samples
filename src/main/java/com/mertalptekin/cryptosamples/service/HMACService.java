package com.mertalptekin.cryptosamples.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

// HMAC (Hash-based Message Authentication Code) algoritması, mesaj bütünlüğü sağlamak ve mesajın kaynağını doğrulamak için kullanılan bir yöntemdir. HMAC, bir kriptografik hash fonksiyonunun (örneğin, SHA256) anahtar ile birlikte kullanılmasıyla oluşturulan bir tür imza işlemidir.
//
//Spring Boot ile HMAC algoritması kullanarak bir dijital imza servisi yazabiliriz.


@Service
public class HMACService {
    private static final String HMAC_SHA256 = "HmacSHA256";

    public String generateHMACSignature(String message, String secret) throws Exception {
        // Anahtar (SecretKey) oluşturuluyor
        SecretKey key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256);

        // Mac (Message Authentication Code) nesnesi oluşturuluyor
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(key);

        // Mesajın HMAC değeri oluşturuluyor
        byte[] rawHmac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // HMAC değeri Base64 ile şifreleniyor
        return Base64.getEncoder().encodeToString(rawHmac);
    }

    public boolean validateHMACSignature(String message, String secret, String signature) throws Exception {
        // İmzayı yeniden oluşturuyoruz
        String generatedSignature = generateHMACSignature(message, secret);

        // Oluşturulan imza ile gelen imzayı karşılaştırıyoruz
        return generatedSignature.equals(signature);
    }
}
