package com.mertalptekin.cryptosamples.controller;

import com.mertalptekin.cryptosamples.service.PasswordHashingService;
import com.mertalptekin.cryptosamples.service.RSAService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/cryptography")
public class CryptoController {

    @Autowired
    private RSAService rsaService;

    @Autowired
    private PasswordHashingService passwordHashingService;

    @PostMapping("rsa")
    public ResponseEntity testRsa() throws Exception {
        rsaService.test("Deneme1");
        return  ResponseEntity.ok().build();
    }

    @PostMapping("hashPassword")
    public ResponseEntity testHashPassword() throws Exception {
        byte[] salt = passwordHashingService.generateSalt();

        // Şifre hash'leniyor
        String storedHash = passwordHashingService.hashPassword("P@ssword1",salt);
        System.out.println("PasswordHash : " + storedHash);

        // Şifre doğrulaması
        boolean isPasswordValid = passwordHashingService.verifyPassword("P@ssword1", storedHash, salt);
        System.out.println("Password is valid: " + isPasswordValid);

        return  ResponseEntity.ok().build();
    }

}
