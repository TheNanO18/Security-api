package securityapi.authtoken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;

import java.util.Date;
import javax.crypto.SecretKey;

public class JwsGenerator {
    public String generateToken(SecretKey key, String userId, String username) {
        long nowMillis = System.currentTimeMillis();
        Date now       = new Date(nowMillis);
        long expMillis = nowMillis + 3600000; // 1시간 후 만료
        Date exp       = new Date(expMillis);

        return Jwts.builder()
                .setHeaderParam("typ", "JWS")
                .setSubject(userId)
                .claim("name", username)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact(); // JWS 문자열 생성
    }

    public Jws<Claims> validateToken(SecretKey key, String jwsToken) {
        try {
            JwtParser parser = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build();

            Jws<Claims> claimsJws = parser.parseClaimsJws(jwsToken);
            
            System.out.println("토큰 검증 성공!");
            
            return claimsJws;
        } catch (SignatureException e) {
            System.err.println("오류: 서명이 유효하지 않습니다.");
        } catch (Exception e) {
            System.err.println("오류: 토큰 검증에 실패했습니다. " + e.getMessage());
        }
        
        return null;
    }
}
