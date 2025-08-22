package securityapi.api;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import securityapi.authtoken.JwsGenerator;
import securityapi.dbmanage.DatabaseManager;

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
        this.jwsHandler      = jwsHandler;
        this.serverSecretKey = secretKey;
        this.processService  = new ProcessService();
        this.dbManager       = new DatabaseManager(
            securityapi.config.ConfigLoader.getProperty("db.url"),
            securityapi.config.ConfigLoader.getProperty("db.user"),
            securityapi.config.ConfigLoader.getProperty("db.pass")
        );
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // =======================================================
        // ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼ CORS 처리 코드 추가 ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
        // =======================================================
    	
    	//서버끼리의 통신이 아니면 삭제, proxy에서만 적용 ?

        // 1. 모든 응답에 CORS 헤더를 추가합니다.
        // 보안을 위해 "*" 대신 실제 프론트엔드 주소("http://127.0.0.1:8000" 등)를 사용하는 것이 좋습니다.
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type,Authorization");

        // 2. 브라우저의 사전 요청(Pre-flight)인 OPTIONS 메서드에 응답합니다.
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1); // No Content 응답 후 처리 종료
            return;
        }

        // =======================================================
        // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ CORS 처리 코드 종료 ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
        // =======================================================


        // ----- 기존 로직 시작 (수정 없음) -----
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonResponse(exchange, 405, Map.of("status", "error", "message", "POST 요청만 허용됩니다."));
            return;
        }

        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        String token      = (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : null;

        if (token == null) {
            sendJsonResponse(exchange, 401, Map.of("status", "error", "message", "Unauthorized: No token provided"));
            return;
        }

        Jws<Claims> validatedClaims = jwsHandler.validateToken(serverSecretKey, token);
        if (validatedClaims == null) {
            sendJsonResponse(exchange, 401, Map.of("status", "error", "message", "Unauthorized: Invalid token"));
            return;
        }
        
        System.out.println("인증 성공! 사용자: " + validatedClaims.getBody().getSubject());

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

    private void sendJsonResponse(HttpExchange exchange, int statusCode, Map<String, Object> responseMap) throws IOException {
        String jsonResponse = GSON.toJson(responseMap);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}