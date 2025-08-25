package securityapi.api;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import securityapi.dbmanage.UserDAO;

public class RegisterHandler implements HttpHandler {
    private final UserDAO userDAO;

    public RegisterHandler(UserDAO userDAO) {
        this.userDAO = userDAO;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // CORS Pre-flight(OPTIONS) 요청 처리
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            handleOptionsRequest(exchange);
            return;
        }

        // 회원가입은 POST 방식만 허용
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        try {
            InputStream is     = exchange.getRequestBody();
            String requestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);

            String id       = parseJsonField(requestBody, "id");
            String password = parseJsonField(requestBody, "password");

            // 간단한 유효성 검사
            if (id == null || id.isBlank() || password == null || password.isBlank()) {
                sendResponse(exchange, 400, "{\"error\":\"ID and password are required\"}");
                return;
            }

            boolean isCreated = userDAO.createUser(id, password);

            if (isCreated) {
                // 성공: 201 Created (리소스가 성공적으로 생성됨)
                sendResponse(exchange, 201, "{\"message\":\"User created successfully\"}");
            } else {
                // 실패 (아이디 중복): 409 Conflict (요청이 현재 서버 상태와 충돌됨)
                sendResponse(exchange, 409, "{\"error\":\"User ID already exists\"}");
            }

        } catch (SQLException e) {
            e.printStackTrace();
            sendResponse(exchange, 500, "{\"error\":\"Database error occurred\"}");
        } catch (Exception e) {
            e.printStackTrace();
            sendResponse(exchange, 500, "{\"error\":\"Internal server error\"}");
        }
    }

    private void handleOptionsRequest(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
        exchange.sendResponseHeaders(204, -1);
    }
    
    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, response.getBytes(StandardCharsets.UTF_8).length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes(StandardCharsets.UTF_8));
        os.close();
    }
    
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