package com.example.aesdemo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

@Configuration
public class BlockChipHerConfig {

    @Value("${spring.aes.secret.key}")
    private String secretKey;

    @Value("${spring.aes.secret.salt}")
    private String secretSalt;

    @Value("${spring.aes.vector.key}")
    private String vectorKey;

//    @Bean()
//    public SecretKey generateByRandom() throws NoSuchAlgorithmException {
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(256);
//        return keyGenerator.generateKey();
//    }

    @Bean()
    public SecretKey generateByPassword() throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), secretSalt.getBytes(), 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    @Bean
    public IvParameterSpec generateIV() {
        return new IvParameterSpec(vectorKey.getBytes());
    }

    @Bean
    public BlockChipHerUtil blockChipHerUtil(SecretKey secretKey, IvParameterSpec vectorKey) {
        return new BlockChipHerUtil(secretKey, vectorKey);
    }
}
