package com.example.aesdemo;

import org.springframework.lang.NonNull;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class BlockChipHerUtil {

    private final SecretKey secretKeySpec;
    private final IvParameterSpec ivSpec;

    public BlockChipHerUtil(SecretKey secretKeySpec, IvParameterSpec ivSpec) {
        this.secretKeySpec = secretKeySpec;
        this.ivSpec = ivSpec;
    }

    public String encryptingString(
            @NonNull String rawMessage
    ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        byte[] secretMessagesBytes = rawMessage.getBytes();
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessagesBytes);

        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);

        return encodedMessage;
    }

    public String decryptingString(
            @NonNull String decodedMessage
    ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        byte[] rawEncryptedMessage = Base64.getDecoder().decode(decodedMessage);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(rawEncryptedMessage);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

        return decryptedMessage;
    }
}
