package securityapi.api;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

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
        
        // ◀️ 1. CORS Pre-flight(OPTIONS) 요청을 먼저 처리하고 즉시 종료합니다.
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            handleOptionsRequest(exchange);
            return;
        }
        
        // ◀️ 2. 로그인 요청은 POST 방식만 허용
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        // --- (이하 기존 POST 처리 로직은 동일) ---
        InputStream is = exchange.getRequestBody();
        String requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);

        String id = parseJsonField(requestBody, "id");
        String password = parseJsonField(requestBody, "password");

        if (userDAO.validateUser(id, password)) {
            // 인증 성공: 토큰 생성
            String issuer = "wedatalab";
            String token = jwsGenerator.generateToken(secretKey, id, issuer);

            String jsonResponse = "{\"token\":\"" + token + "\"}";
            sendResponse(exchange, 200, jsonResponse);
        } else {
            // 인증 실패
            String jsonResponse = "{\"error\":\"Invalid ID or password\"}";
            sendResponse(exchange, 401, jsonResponse);
        }
    }
    
    // ◀️ 3. OPTIONS 요청을 처리하고 CORS 헤더를 설정하는 메소드 (신규 추가)
    private void handleOptionsRequest(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*"); // 모든 도메인에서의 요청을 허용 (개발용)
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, GET, OPTIONS"); // 허용할 HTTP 메소드
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization"); // 허용할 헤더
        exchange.sendResponseHeaders(204, -1); // 204 No Content 응답
    }

    // ◀️ 4. sendResponse 메소드에 CORS 헤더 추가
    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        // 실제 POST 응답에도 이 헤더를 추가해야 브라우저가 응답을 정상적으로 읽을 수 있습니다.
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, response.getBytes(StandardCharsets.UTF_8).length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes(StandardCharsets.UTF_8));
        os.close();
    }
    
    // --- (parseJsonField 메소드는 동일) ---
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