package securityapi.securityalgo;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

// HIGHT 알고리즘 전용 암호화 서비스
public class EncryptionService {
    private final byte[] secretKey;
    
    private final hight_cbc hightCbcProcessor;
    private final hight_ctr hightCtrProcessor;

    public EncryptionService(byte[] key) {
        if (key.length != 16) {
            throw new IllegalArgumentException("HIGHT key must be 16 bytes.");
        }
        this.secretKey = key;
        
        // 인스턴스를 생성자에서 한 번만 생성하여 재사용
        this.hightCbcProcessor = new hight_cbc();
        this.hightCtrProcessor = new hight_ctr();
    }

    public String generateIv() {
        byte[] iv = new byte[8];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    public String encrypt(String plainText, String base64Iv, String algo) {
        byte[] ivBytes = Base64.getDecoder().decode(base64Iv);
        byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes;

        if ("hight_cbc".equalsIgnoreCase(algo)) {
            encryptedBytes = this.hightCbcProcessor.process(plainTextBytes, this.secretKey, ivBytes, true);
        } 
         else if ("hight_ctr".equalsIgnoreCase(algo)) {
             encryptedBytes = this.hightCtrProcessor.process(plainTextBytes, this.secretKey, ivBytes, true);
         } 
        else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algo);
        }

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedText, String base64Iv, String algo) {
        byte[] ivBytes = Base64.getDecoder().decode(base64Iv);
        byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes;

        if ("hight_cbc".equalsIgnoreCase(algo)) {
            decryptedBytes = this.hightCbcProcessor.process(encryptedTextBytes, this.secretKey, ivBytes, false);
        } else if ("hight_ctr".equalsIgnoreCase(algo)) {
            decryptedBytes = this.hightCtrProcessor.process(encryptedTextBytes, this.secretKey, ivBytes, false);
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algo);
        }
        
        if (decryptedBytes != null && decryptedBytes.length > 0) {
            int paddingLength = decryptedBytes[decryptedBytes.length - 1] & 0xff; // 부호 없는 바이트로 읽기
            if (paddingLength > 0 && paddingLength <= 8) {
                int originalLength = decryptedBytes.length - paddingLength;
                
                boolean isPaddingValid = true;
                for (int i = 0; i < paddingLength; i++) {
                    if ((decryptedBytes[originalLength + i] & 0xff) != paddingLength) {
                        isPaddingValid = false;
                        break;
                    }
                }

                if(isPaddingValid) {
                    byte[] unpaddedBytes = new byte[originalLength];
                    System.arraycopy(decryptedBytes, 0, unpaddedBytes, 0, originalLength);
                    return new String(unpaddedBytes, StandardCharsets.UTF_8);
                }
            }
        }
        
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}