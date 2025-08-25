package securityapi.api;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import securityapi.authtoken.JwsGenerator;
import securityapi.dbmanage.DatabaseManager;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP 요청/응답 처리 및 인증을 담당하는 컨트롤러 클래스
 */
public class ProcessHandler implements HttpHandler {
    private static final Gson GSON = new Gson();
    private final JwsGenerator jwsHandler;
    private final SecretKey serverSecretKey;
    private final ProcessService processService;
    private final DatabaseManager dbManager;

    public ProcessHandler(JwsGenerator jwsHandler, SecretKey secretKey) {
        this.jwsHandler = jwsHandler;
        this.serverSecretKey = secretKey;
        this.processService = new ProcessService();
        this.dbManager = new DatabaseManager(
            securityapi.config.ConfigLoader.getProperty("db.url"),
            securityapi.config.ConfigLoader.getProperty("db.user"),
            securityapi.config.ConfigLoader.getProperty("db.pass")
        );
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // ◀️ 1. CORS Pre-flight(OPTIONS) 요청을 먼저 처리하고 즉시 종료합니다.
        // 이렇게 하면 불필요한 로직을 타지 않아 더 효율적입니다.
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
            exchange.sendResponseHeaders(204, -1); // 204 No Content로 응답
            return;
        }

        // ◀️ 2. POST 요청이 아닐 경우의 에러 처리
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonResponse(exchange, 405, Map.of("status", "error", "message", "POST 요청만 허용됩니다."));
            return;
        }

        // ◀️ 3. 토큰 인증 로직
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        String token = (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : null;

        if (token == null) {
            sendJsonResponse(exchange, 401, Map.of("status", "error", "message", "Unauthorized: 토큰이 없습니다."));
            return;
        }

        Jws<Claims> validatedClaims = jwsHandler.validateToken(serverSecretKey, token);
        if (validatedClaims == null) {
            sendJsonResponse(exchange, 401, Map.of("status", "error", "message", "Unauthorized: 유효하지 않은 토큰입니다."));
            return;
        }

        System.out.println("인증 성공! 사용자: " + validatedClaims.getBody().getSubject());

        // ◀️ 4. 인증 성공 후 비즈니스 로직 처리
        List<Map<String, Object>> batchResults = new ArrayList<>();
        try (Connection conn = dbManager.getConnection()) {
            String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            List<Map<String, Object>> requestList = GSON.fromJson(requestBody, new TypeToken<List<Map<String, Object>>>() {}.getType());

            for (Map<String, Object> requestData : requestList) {
                Map<String, Object> result = processService.processSingleRequest(conn, requestData);
                batchResults.add(result);
            }

            Map<String, Object> finalResponse = new HashMap<>();
            finalResponse.put("batch_status", "completed");
            finalResponse.put("results", batchResults);
            sendJsonResponse(exchange, 200, finalResponse);

        } catch (Exception e) {
            e.printStackTrace();
            sendJsonResponse(exchange, 500, Map.of("status", "error", "message", "서버 내부 오류: " + e.getMessage()));
        }
    }

    /**
     * 응답을 JSON 형식으로 변환하여 클라이언트에게 전송하는 헬퍼 메소드
     */
    private void sendJsonResponse(HttpExchange exchange, int statusCode, Map<String, Object> responseMap) throws IOException {
        // ◀️ 중요: 실제 데이터 응답(POST, 에러 등)에 CORS 헤더를 반드시 포함해야 합니다.
        // 이 헤더가 없으면 브라우저가 Pre-flight(OPTIONS)는 성공시키고 실제 요청의 응답은 보안 정책 위반으로 차단합니다.
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");

        String jsonResponse = GSON.toJson(responseMap);
        byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}