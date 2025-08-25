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
        } else if ("hight_ctr".equalsIgnoreCase(algo)) {
            encryptedBytes = this.hightCtrProcessor.process(plainTextBytes, this.secretKey, ivBytes, true);
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algo);
        }

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * 데이터를 복호화합니다.
     * CBC 모드는 PKCS7 패딩을 제거하고, CTR 모드는 후행 널(0x00) 바이트를 제거합니다.
     */
    public String decrypt(String encryptedText, String base64Iv, String algo) {
        byte[] ivBytes = Base64.getDecoder().decode(base64Iv);
        byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes;

        // 1. 알고리즘에 따라 복호화 수행
        if ("hight_cbc".equalsIgnoreCase(algo)) {
            decryptedBytes = this.hightCbcProcessor.process(encryptedTextBytes, this.secretKey, ivBytes, false);

            // 2-1. CBC 모드: PKCS7 패딩 제거 로직
            if (decryptedBytes != null && decryptedBytes.length > 0) {
                int paddingLength = decryptedBytes[decryptedBytes.length - 1] & 0xff;
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
            // 유효한 패딩이 없거나 배열이 비어있으면 그대로 반환
            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } else if ("hight_ctr".equalsIgnoreCase(algo)) {
            decryptedBytes = this.hightCtrProcessor.process(encryptedTextBytes, this.secretKey, ivBytes, false);

            // 2-2. CTR 모드: 후행 널(0x00) 바이트 패딩 제거 로직
            if (decryptedBytes == null || decryptedBytes.length == 0) {
                return "";
            }
            
            int effectiveLength = decryptedBytes.length;
            // 배열의 끝에서부터 0x00 값을 만나면 길이를 1씩 줄여나감
            while (effectiveLength > 0 && decryptedBytes[effectiveLength - 1] == 0) {
                effectiveLength--;
            }
            
            // 널 바이트가 제거된 실제 길이만큼 새로운 배열을 생성하여 복사
            byte[] unpaddedBytes = new byte[effectiveLength];
            System.arraycopy(decryptedBytes, 0, unpaddedBytes, 0, effectiveLength);
            
            return new String(unpaddedBytes, StandardCharsets.UTF_8);

        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algo);
        }
    }
}