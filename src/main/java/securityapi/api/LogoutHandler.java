package securityapi.api;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import securityapi.authtoken.JwsGenerator;
import securityapi.dbmanage.UserDAO;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class LogoutHandler implements HttpHandler {
    private static final Gson GSON = new Gson();
    private final JwsGenerator jwsGenerator;
    private final SecretKey secretKey;
    private final UserDAO userDAO;

    public LogoutHandler(JwsGenerator jwsGenerator, SecretKey secretKey, UserDAO userDAO) {
        this.jwsGenerator = jwsGenerator;
        this.secretKey = secretKey;
        this.userDAO = userDAO;
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
            sendJsonResponse(exchange, 405, Map.of("error", "Method Not Allowed"));
            return;
        }

        try {
            // Logout requires a valid access token to identify the user.
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            String accessToken = (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : null;

            if (accessToken == null) {
                sendJsonResponse(exchange, 401, Map.of("error", "Unauthorized: Access token is missing."));
                return;
            }

            Jws<Claims> claims = jwsGenerator.validateToken(secretKey, accessToken);
            if (claims == null) {
                // Even if the access token is expired, we can still proceed with logout
                // by parsing it without validation to get the user ID.
                // For simplicity here, we require a valid token.
                sendJsonResponse(exchange, 401, Map.of("error", "Unauthorized: Invalid access token."));
                return;
            }

            String userId = claims.getBody().getSubject();

            // Call the DAO to clear the refresh token from the database.
            userDAO.clearRefreshToken(userId);

            sendJsonResponse(exchange, 200, Map.of("message", "Logout successful."));

        } catch (Exception e) {
            e.printStackTrace();
            sendJsonResponse(exchange, 500, Map.of("error", "Server error during logout."));
        }
    }

    private void sendJsonResponse(HttpExchange exchange, int statusCode, Map<String, ?> responseMap) throws IOException {
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