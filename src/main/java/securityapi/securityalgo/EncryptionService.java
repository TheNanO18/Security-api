package securityapi.securityalgo;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptionService {
    private final SecretKeySpec secretKey;
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    public EncryptionService(byte[] key) {
        this.secretKey = new SecretKeySpec(key, "AES");
    }

    public String generateIv() {
        byte[] iv = new byte[16]; // AES-128/192/256 CBC 모드의 IV는 16바이트
        new SecureRandom().nextBytes(iv);
        
        return Base64.getEncoder().encodeToString(iv);
    }

    public String encrypt(String plainText, String base64Iv) throws Exception {
        Cipher cipher                   = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(base64Iv));
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedText, String base64Iv) throws Exception {
        Cipher cipher                   = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(base64Iv));
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}