package securityapi.api;

import java.io.IOException;
import java.io.InputStream;
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

public class LoginHandler implements HttpHandler {

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
        
        // 1. CORS Pre-flight(OPTIONS) 요청 처리
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            handleOptionsRequest(exchange);
            return;
        }
        
        // 2. 로그인 요청은 POST 방식만 허용
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        InputStream is = exchange.getRequestBody();
        String requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);

        String id       = parseJsonField(requestBody, "id");
        String password = parseJsonField(requestBody, "password");

        if (userDAO.validateUser(id, password)) {
            // --- Authentication Success ---
            String issuer = "wedatalab";
            String accessToken = jwsGenerator.generateAccessToken(secretKey, id, issuer);
            String refreshToken = jwsGenerator.generateRefreshToken(secretKey, id);
            
            try {
                userDAO.saveRefreshToken(id, refreshToken);
            } catch (SQLException e) {
                e.printStackTrace();
                // Send an error response if saving the token fails
                sendResponse(exchange, 500, "{\"error\":\"Could not save user session\"}");
                return;
            }

            // ✅ 1. Set the Authorization header with ONLY the accessToken.
            exchange.getResponseHeaders().set("Authorization", "Bearer " + accessToken);
            
            // ✅ 2. Create a Map for the JSON response body.
            Map<String, String> responseBodyMap = new HashMap<>();
            responseBodyMap.put("status", "success");
            responseBodyMap.put("refreshToken", refreshToken);
            
            // ✅ 3. Convert the Map to a JSON string and send it as the response.
            String jsonResponse = new Gson().toJson(responseBodyMap);
            sendResponse(exchange, 200, jsonResponse);

        } else {
            // --- Authentication Failure ---
            String jsonResponse = "{\"error\":\"Invalid ID or password\"}";
            sendResponse(exchange, 401, jsonResponse);
        }
    }
    
    /**
     * OPTIONS 요청을 처리하고 CORS 헤더를 설정하는 메소드
     */
    private void handleOptionsRequest(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
        
        exchange.getResponseHeaders().set("Access-Control-Expose-Headers", "Authorization");
        exchange.sendResponseHeaders(204, -1);
    }

    /**
     * 응답을 전송하는 메소드 (CORS 헤더 포함)
     */
    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Expose-Headers", "Authorization");
        
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    /**
     * JSON 문자열에서 특정 필드의 값을 파싱하는 간단한 메소드
     */
    private String parseJsonField(String json, String fieldName) {
        try {
            String search = "\"" + fieldName + "\":\"";
            int start = json.indexOf(search) + search.length();
            int end = json.indexOf("\"", start);
            return json.substring(start, end);
        } catch (Exception e) {
            return null;
        }
    }
}