package securityapi.dbmanage;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import securityapi.config.ConfigLoader;
import securityapi.dto.User;
import securityapi.pwdhash.Bcrypt;

public class UserDAO {
    private static final Logger logger = LoggerFactory.getLogger(UserDAO.class);
    private final long slowQueryThreshold;
    
    private final String dbUrl;
    private final String dbUser;
    private final String dbPass;

    public UserDAO(String dbUrl, String dbUser, String dbPass) {
        this.dbUrl  = dbUrl;
        this.dbUser = dbUser;
        this.dbPass = dbPass;
        this.slowQueryThreshold = Long.parseLong(ConfigLoader.getProperty("slow.query.threshold.ms", "1"));
    }
    
    /**
     * A centralized wrapper for all database operations that handles connection,
     * timing, and logging.
     */
    private <T> T executeDbOperation(String sql, SQLOperation<T> operation) throws SQLException {
        long startTime = System.currentTimeMillis();
        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {
            T result = operation.execute(conn);
            long duration = System.currentTimeMillis() - startTime;
            if (duration > slowQueryThreshold) {
                logger.warn("Slow query detected: [{}] took {}ms", sql, duration);
            }
            return result;
        } catch (SQLException e) {
            logger.error("Database error on query: [{}]", sql, e);
            throw e; // Re-throw the exception so the handler can catch it
        }
    }
    
    /**
     * A functional interface to allow passing SQL logic as a lambda.
     */
    @FunctionalInterface
    private interface SQLOperation<T> {
        T execute(Connection conn) throws SQLException;
    }

    public boolean createUser(String id, String rawPassword) throws SQLException {
        String sql = "INSERT INTO en_user (id, password) VALUES (?, ?)";
        return executeDbOperation(sql, conn -> {
            // First, check if user already exists
            try (PreparedStatement checkStmt = conn.prepareStatement("SELECT id FROM en_user WHERE id = ?")) {
                checkStmt.setString(1, id);
                if (checkStmt.executeQuery().next()) {
                    logger.warn("Attempted to create a user that already exists: {}", id);
                    return false; // User already exists
                }
            }

            // If not, hash password and insert the new user
            String hashedPassword = Bcrypt.hashPassword(rawPassword);
            try (PreparedStatement insertStmt = conn.prepareStatement(sql)) {
                insertStmt.setString(1, id);
                insertStmt.setString(2, hashedPassword);
                return insertStmt.executeUpdate() > 0;
            }
        });
    }
    
    public boolean validateUser(String id, String rawPassword) throws SQLException {
        String sql = "SELECT password FROM en_user WHERE id = ?";
        return executeDbOperation(sql, conn -> {
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, id);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        String storedHashedPassword = rs.getString("password");
                        return Bcrypt.checkPassword(rawPassword, storedHashedPassword);
                    }
                }
            }
            return false;
        });
    }
    
    public User getUserPermissions(String userId) throws SQLException {
        String sql = "SELECT id, password, ip, port, database FROM en_user WHERE id = ?";
        return executeDbOperation(sql, conn -> {
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        User user = new User();
                        user.setId(rs.getString("id"));
                        // user.setPasswordHash(rs.getString("password")); // Avoid sending hash unless needed
                        user.setIp(rs.getString("ip"));
                        user.setPort(rs.getString("port"));
                        user.setDatabase(rs.getString("database"));
                        return user;
                    }
                }
            }
            return null; // User not found
        });
    }
    
    public void saveRefreshToken(String userId, String refreshToken) throws SQLException {
        String sql = "UPDATE en_user SET refresh_token = ? WHERE id = ?";
        executeDbOperation(sql, conn -> {
            String hashedToken = Bcrypt.hashPassword(refreshToken);
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, hashedToken);
                pstmt.setString(2, userId);
                int affectedRows = pstmt.executeUpdate();
                if (affectedRows == 0) {
                    logger.warn("Failed to save refresh token, user not found: {}", userId);
                }
                return affectedRows > 0; // Return value is required, but we can ignore it
            }
        });
    }

    public String getRefreshToken(String userId) throws SQLException {
        String sql = "SELECT refresh_token FROM en_user WHERE id = ?";
        
        return executeDbOperation(sql, conn -> {
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, userId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("refresh_token");
                    }
                }
            }
            return null;
        });
    }
    
    public void clearRefreshToken(String userId) throws SQLException {
        String sql = "UPDATE en_user SET refresh_token = NULL WHERE id = ?";
        executeDbOperation(sql, conn -> {
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, userId);
                pstmt.executeUpdate();
                logger.info("Refresh token cleared for user: {}", userId);
                return true; // Return value is required
            }
        });
    }
}