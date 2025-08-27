package securityapi.api;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import securityapi.authtoken.JwsGenerator;
import securityapi.dbmanage.DatabaseManager;
import securityapi.dto.TableRequest; // 이전 답변에서 만든 DTO

public class TableDataHandler implements HttpHandler {
    private static final Gson GSON = new Gson();
    private final JwsGenerator jwsHandler;
    private final SecretKey serverSecretKey;
    
    public TableDataHandler(JwsGenerator jwsHandler, SecretKey secretKey) {
        this.jwsHandler = jwsHandler;
        this.serverSecretKey = secretKey;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
    	if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
            exchange.sendResponseHeaders(204, -1); // 204 No Content로 응답
            return;
        }
    	
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
        	sendJsonResponse(exchange, 405, Map.of("error", "Method Not Allowed"));
            return;
        }
        
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

        try {
            // 1. 요청 Body(JSON) 읽기 및 DTO로 변환
            InputStreamReader reader = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
            TableRequest request = GSON.fromJson(reader, TableRequest.class);

            // 2. 요청 데이터 유효성 검사
            if (request.getTableName() == null || request.getDbConfig() == null) {
            	sendJsonResponse(exchange, 400, Map.of("error", "tableName 또는 db_config가 누락되었습니다."));
                return;
            }

            // 3. DatabaseManager 생성 및 DB 작업 수행
            var dbConfig = request.getDbConfig();
            DatabaseManager dbManager = new DatabaseManager(dbConfig.getUrl(), dbConfig.getUser(), dbConfig.getPass());

            List<Map<String, Object>> data;
            try (Connection conn = dbManager.getConnection()) {
                // 이 부분에서 tableName 유효성 검사를 수행하는 것이 안전합니다.
                data = dbManager.getAllData(conn, request.getTableName());
            }

            sendJsonResponse(exchange, 200, Map.of("data", data));

        } catch (Exception e) {
            e.printStackTrace();
            sendJsonResponse(exchange, 500, Map.of("error", "서버 내부 오류: " + e.getMessage()));
        }
    }
    
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