package com.example.aesdemo;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(path = "/aes")
public class BlockChipHerController {

    private final BlockChipHerUtil blockChipHerUtil;

    public BlockChipHerController(BlockChipHerUtil blockChipHerUtil) {
        this.blockChipHerUtil = blockChipHerUtil;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<Map<String, Object>> requestEncrypt(
            @RequestBody BlockChipHerDto dto
    ) {
        try {
            var result = blockChipHerUtil.encryptingString(dto.getMessage());
            return response(HttpStatus.OK, result);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            return response(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            return response(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<Map<String, Object>> requestDecrypt(
            @RequestBody BlockChipHerDto dto
    ) {
        try {
            var result = blockChipHerUtil.decryptingString(dto.getMessage());
            return response(HttpStatus.OK, result);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            return response(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            return response(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    @NonNull
    private <T> ResponseEntity<Map<String, T>> response(HttpStatus httpStatus, T result) {
        var map = new HashMap<String, T>();
        map.put("data", result);
        return new ResponseEntity<>(map, httpStatus);
    }
}
