package securityapi.api;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
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
import securityapi.dbmanage.UserDAO;
import securityapi.pwdhash.Bcrypt;

public class RefreshTokenHandler implements HttpHandler {
    private static final Gson GSON = new Gson();
    private final JwsGenerator jwsGenerator;
    private final SecretKey secretKey;
    private final UserDAO userDAO;
    private final DatabaseManager dbManager;

    public RefreshTokenHandler(JwsGenerator jwsGenerator, SecretKey secretKey, UserDAO userDAO, DatabaseManager dbManager) {
        this.jwsGenerator = jwsGenerator;
        this.secretKey = secretKey;
        this.userDAO = userDAO;
        this.dbManager = dbManager;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonResponse(exchange, 405, Map.of("error", "Method Not Allowed"));
            return;
        }

        try {
            Reader reader = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
            Type mapType = new TypeToken<Map<String, String>>() {}.getType();
            Map<String, String> body = GSON.fromJson(reader, mapType);
            String refreshToken = body.get("refreshToken");

            if (refreshToken == null || refreshToken.isBlank()) {
                sendJsonResponse(exchange, 400, Map.of("error", "Refresh token is missing."));
                return;
            }

            Jws<Claims> claims = jwsGenerator.validateToken(secretKey, refreshToken);
            if (claims == null) {
                sendJsonResponse(exchange, 401, Map.of("error", "Invalid or expired refresh token."));
                return;
            }

            String userId = claims.getBody().getSubject();
            try (Connection conn = dbManager.getConnection()) {
                String storedTokenHash = userDAO.getRefreshToken(conn, userId);
                if (storedTokenHash == null || !Bcrypt.checkPassword(refreshToken, storedTokenHash)) {
                    sendJsonResponse(exchange, 401, Map.of("error", "Refresh token not found or revoked. Please log in again."));
                    return;
                }
            }
            
            // Assuming 'name' claim is not essential for refresh, using a placeholder
            String newAccessToken = jwsGenerator.generateAccessToken(secretKey, userId, "Refreshed Session");
            
            exchange.getResponseHeaders().set("Authorization", "Bearer " + newAccessToken);
            sendJsonResponse(exchange, 200, Map.of("accessToken", newAccessToken));

        } catch (Exception e) {
            e.printStackTrace();
            sendJsonResponse(exchange, 500, Map.of("error", "Server error during token refresh."));
        }
    }
    
    private void sendJsonResponse(HttpExchange exchange, int statusCode, Map<String, ?> responseMap) throws IOException {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Expose-Headers", "Authorization");
        String jsonResponse = GSON.toJson(responseMap);
        byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}