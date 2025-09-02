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
        this.jwsHandler      = jwsHandler;
        this.serverSecretKey = secretKey;
        this.processService  = new ProcessService();
        
        String dbUrl  = ConfigLoader.getProperty("db.url");
        String dbUser = ConfigLoader.getProperty("db.user");
        String dbPass = ConfigLoader.getProperty("db.pass");
        
        this.defaultDbManager = new DatabaseManager(dbUrl, dbUser, dbPass);
        this.userDAO          = new UserDAO(dbUrl, dbUser, dbPass);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonResponse(exchange, 405, Map.of("status", "error", "message", "POST 요청만 허용됩니다."));
            return;
        }

        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        String token      = (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : null;

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

        try {
            String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            MainRequest mainRequest = GSON.fromJson(requestBody, MainRequest.class);
            
            User permissions;
            
            try (Connection conn = defaultDbManager.getConnection()) {
                permissions = userDAO.getUserPermissions(conn, userId);
            }

            if (permissions == null) {
                sendJsonResponse(exchange, 403, Map.of("status", "error", "message", "Forbidden: User permissions not found."));
                return;
            }
            
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
            
         // ✅ 2. 포트(PORT) 확인 로직 추가 -> 삭제 예정
            /*
            int clientPort = exchange.getRemoteAddress().getPort();
            // permissions.getPort()가 문자열이므로 정수(int)로 변환하여 비교합니다.
            int allowedPort = Integer.parseInt(permissions.getPort()); 
            if (clientPort != allowedPort) {
                sendJsonResponse(exchange, 403, Map.of("status", "error", "message", "Forbidden: Access from your port (" + clientPort + ") is not allowed."));
                return;
            }
            */
            
            List<String> allowedTables = Arrays.asList(permissions.getDatabase().split("\\s*,\\s*"));
            for (ProcessRequest req : mainRequest.getRequests()) {
                if (!allowedTables.contains(req.getTable())) {
                    sendJsonResponse(exchange, 403, Map.of("status", "error", "message", "Forbidden: You do not have permission to access table '" + req.getTable() + "'."));
                    return;
                }
            }
         // --- END OF AUTHORIZATION ---
            
            List<Map<String, Object>> results = processService.processBatchRequest(mainRequest);

            Map<String, Object> finalResponse = new HashMap<>();
            finalResponse.put("batch_status", "completed");
            finalResponse.put("results", results);
            sendJsonResponse(exchange, 200, finalResponse);

        } catch (Exception e) {
            e.printStackTrace();
            sendJsonResponse(exchange, 500, Map.of("status", "error", "message", "서버 내부 오류: " + e.getMessage()));
        }
    }

    private void sendJsonResponse(HttpExchange exchange, int statusCode, Map<String, Object> responseMap) throws IOException {

        String jsonResponse  = GSON.toJson(responseMap);
        byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}