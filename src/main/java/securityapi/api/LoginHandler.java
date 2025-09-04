package securityapi.api;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import securityapi.authtoken.JwsGenerator;
import securityapi.dbmanage.UserDAO;
import securityapi.dto.LoginRequest; // DTO 임포트

public class LoginHandler implements HttpHandler {

    private static final Gson GSON = new Gson();
    private final JwsGenerator jwsGenerator;
    private final SecretKey secretKey;
    private final UserDAO userDAO;

    public LoginHandler(JwsGenerator jwsGenerator, SecretKey secretKey, UserDAO userDAO) {
        this.jwsGenerator = jwsGenerator;
        this.secretKey    = secretKey;
        this.userDAO      = userDAO;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            handleOptionsRequest(exchange);
            return;
        }
        
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJsonResponse(exchange, 405, Map.of("error", "Method Not Allowed"));
            return;
        }

        try {
            String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            // DTO를 사용하여 더 안전하게 JSON 파싱
            LoginRequest loginData = GSON.fromJson(requestBody, LoginRequest.class);

            if (userDAO.validateUser(loginData.getId(), loginData.getPassword())) {
                // --- 인증 성공 ---
                String userId = loginData.getId();
                String accessToken = jwsGenerator.generateAccessToken(secretKey, userId, "user"); // 'issuer' 대신 'name'
                String refreshToken = jwsGenerator.generateRefreshToken(secretKey, userId);
                
                userDAO.saveRefreshToken(userId, refreshToken);

                exchange.getResponseHeaders().set("Authorization", "Bearer " + accessToken);
                
                Map<String, String> responseBody = new HashMap<>();
                responseBody.put("status", "success");
                responseBody.put("refreshToken", refreshToken);
                
                sendJsonResponse(exchange, 200, responseBody);

            } else {
                // --- 인증 실패 (ID 또는 비밀번호 불일치) ---
                sendJsonResponse(exchange, 401, Map.of("error", "Invalid ID or password"));
            }
        } catch (SQLException e) {
            // ✅ 데이터베이스 연결 또는 쿼리 중 발생한 에러 처리
            e.printStackTrace();
            sendJsonResponse(exchange, 500, Map.of("error", "Database error during authentication."));
        } catch (Exception e) {
            // ✅ 그 외 예상치 못한 모든 에러 처리
            e.printStackTrace();
            sendJsonResponse(exchange, 500, Map.of("error", "An unexpected server error occurred."));
        }
    }
    
    private void handleOptionsRequest(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().set("Access-Control-Expose-Headers", "Authorization");
        exchange.sendResponseHeaders(204, -1);
    }

    private void sendJsonResponse(HttpExchange exchange, int statusCode, Map<String, ?> responseMap) throws IOException {
        String jsonResponse = GSON.toJson(responseMap);
        byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Expose-Headers", "Authorization");
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
