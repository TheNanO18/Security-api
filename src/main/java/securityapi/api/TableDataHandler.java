package securityapi.api;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import securityapi.dbmanage.DatabaseManager;
import securityapi.dto.TableRequest; // 이전 답변에서 만든 DTO

public class TableDataHandler implements HttpHandler {
    private final Gson gson = new Gson();

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // POST 요청만 허용
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed");
            return;
        }

        try {
            // 1. 요청 Body(JSON) 읽기 및 DTO로 변환
            InputStreamReader reader = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
            TableRequest request = gson.fromJson(reader, TableRequest.class);

            // 2. 요청 데이터 유효성 검사
            if (request.getTableName() == null || request.getDbConfig() == null) {
                sendError(exchange, 400, "tableName 또는 db_config가 누락되었습니다.");
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

            // 4. 조회된 데이터를 JSON 문자열로 변환
            String responseBody = gson.toJson(data);

            // 5. 성공 응답 전송 (200 OK)
            sendResponse(exchange, 200, responseBody);

        } catch (Exception e) {
            e.printStackTrace();
            sendError(exchange, 500, "서버 내부 오류: " + e.getMessage());
        }
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String responseBody) throws IOException {
        byte[] responseBytes = responseBody.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }

    private void sendError(HttpExchange exchange, int statusCode, String message) throws IOException {
        String responseBody = gson.toJson(Map.of("error", message));
        sendResponse(exchange, statusCode, responseBody);
    }
}