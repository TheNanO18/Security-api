package securityapi.api;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import securityapi.authtoken.JwsGenerator;
import securityapi.config.ConfigLoader;
import securityapi.dbmanage.DatabaseManager;
import securityapi.dbmanage.UserDAO;
import securityapi.dto.MainRequest;
import securityapi.dto.ProcessRequest;
import securityapi.dto.User;

/**
 * HTTP 요청/응답 처리 및 인증을 담당하는 컨트롤러 클래스
 */
public class ProcessHandler implements HttpHandler {
    private static final Gson GSON = new Gson();
    private final JwsGenerator jwsHandler;
    private final SecretKey serverSecretKey;
    private final ProcessService processService;
    private final DatabaseManager defaultDbManager;
    private final UserDAO userDAO;

    public ProcessHandler(JwsGenerator jwsHandler, SecretKey secretKey) {
        this.jwsHandler = jwsHandler;
        this.serverSecretKey = secretKey;
        this.processService = new ProcessService();
        
        String dbUrl  = ConfigLoader.getProperty("db.url");
        String dbUser = ConfigLoader.getProperty("db.user");
        String dbPass = ConfigLoader.getProperty("db.pass");
        
        this.defaultDbManager = new DatabaseManager(dbUrl, dbUser, dbPass);
        this.userDAO          = new UserDAO(dbUrl, dbUser, dbPass);
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
        
        String userId = validatedClaims.getBody().getSubject();

        // ◀️ 4. 인증 성공 후 비즈니스 로직 처리
        try {
            // 1. 요청 본문을 읽고 새로운 MainRequest DTO로 파싱합니다.
            String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            MainRequest mainRequest = GSON.fromJson(requestBody, MainRequest.class);
            
         // --- AUTHORIZATION LOGIC ---
            User permissions;
            
            try (Connection conn = defaultDbManager.getConnection()) {
                permissions = userDAO.getUserPermissions(conn, userId);
            }

            if (permissions == null) {
                sendJsonResponse(exchange, 403, Map.of("status", "error", "message", "Forbidden: User permissions not found."));
                return;
            }

            // 1. IP 주소 검사
         // ✅ Add these logs to see the actual values being compared

            
            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
            
            System.out.println(clientIp);
            System.out.println(permissions.getIp());
            
            if ("0:0:0:0:0:0:0:1".equals(clientIp)) {
                // clientIp 변수의 값을 "127.0.0.1"로 변경합니다.
            	 clientIp = "127.0.0.1";
            }
            
            if (!clientIp.equals(permissions.getIp())) {
                sendJsonResponse(exchange, 403, Map.of("status", "error", "message", "Forbidden: Access from your IP is not allowed."));
                return;
            }
            
         // ✅ 2. 포트(PORT) 확인 로직 추가
            int clientPort = exchange.getRemoteAddress().getPort();
            // permissions.getPort()가 문자열이므로 정수(int)로 변환하여 비교합니다.
            int allowedPort = Integer.parseInt(permissions.getPort()); 
            if (clientPort != allowedPort) {
                sendJsonResponse(exchange, 403, Map.of("status", "error", "message", "Forbidden: Access from your port (" + clientPort + ") is not allowed."));
                return;
            }
            
            List<String> allowedTables = Arrays.asList(permissions.getDatabase().split("\\s*,\\s*"));
            for (ProcessRequest req : mainRequest.getRequests()) {
                if (!allowedTables.contains(req.getTable())) {
                    sendJsonResponse(exchange, 403, Map.of("status", "error", "message", "Forbidden: You do not have permission to access table '" + req.getTable() + "'."));
                    return;
                }
            }
         // --- END OF AUTHORIZATION ---
            
            List<Map<String, Object>> results = processService.processBatchRequest(mainRequest);

            // 3. 서비스로부터 받은 최종 결과를 클라이언트에 응답합니다.
            Map<String, Object> finalResponse = new HashMap<>();
            finalResponse.put("batch_status", "completed");
            finalResponse.put("results", results);
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