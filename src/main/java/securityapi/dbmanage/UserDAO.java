package securityapi.dbmanage;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import securityapi.dto.User;
import securityapi.pwdhash.Bcrypt; // Bcrypt 클래스 임포트

public class UserDAO {
    private final String dbUrl;
    private final String dbUser;
    private final String dbPass;

    public UserDAO(String dbUrl, String dbUser, String dbPass) {
        this.dbUrl = dbUrl;
        this.dbUser = dbUser;
        this.dbPass = dbPass;
    }

    /**
     * 신규 사용자를 생성하고 데이터베이스에 저장합니다.
     * @param id 생성할 사용자의 아이디
     * @param rawPassword 해싱되지 않은 원본 비밀번호
     * @return 생성 성공 시 true, 아이디 중복 시 false
     * @throws SQLException 데이터베이스 처리 중 오류 발생 시
     */
    public boolean createUser(String id, String rawPassword) throws SQLException {
        String checkUserSql  = "SELECT id FROM en_user WHERE id = ?";
        String insertUserSql = "INSERT INTO en_user (id, password) VALUES (?, ?)";

        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {
            // 1. 아이디 중복 확인
            try (PreparedStatement checkStmt = conn.prepareStatement(checkUserSql)) {
                checkStmt.setString(1, id);
                try (ResultSet rs = checkStmt.executeQuery()) {
                    if (rs.next()) {
                        return false; // 이미 존재하는 아이디인 경우 false 반환
                    }
                }
            }

            // 2. 비밀번호 해싱
            String hashedPassword = Bcrypt.hashPassword(rawPassword);

            // 3. 사용자 정보 저장
            try (PreparedStatement insertStmt = conn.prepareStatement(insertUserSql)) {
                insertStmt.setString(1, id);
                insertStmt.setString(2, hashedPassword);
                int affectedRows = insertStmt.executeUpdate();
                return affectedRows > 0;
            }
        }
    }
    
    public boolean validateUser(String id, String rawPassword) {
        String sql = "SELECT password FROM en_user WHERE id = ?";
        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    String storedHashedPassword = rs.getString("password");
                    // ◀️ 중요: Bcrypt.checkPassword로 비교
                    return Bcrypt.checkPassword(rawPassword, storedHashedPassword);
                }
            }
        } catch (SQLException e) {
            System.err.println("Database validation error: " + e.getMessage());
        }
        return false;
    }
    
    public User getUserPermissions(Connection conn, String userId) throws SQLException {
        String sql = "SELECT id, password, ip, port, database FROM en_user WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, userId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                User user = new User();
                user.setId(rs.getString("id"));
                user.setIp(rs.getString("ip"));
                user.setPort(rs.getString("port"));
                user.setDatabase(rs.getString("database"));
                return user;
            }
        }
        return null; // 사용자를 찾지 못한 경우
    }
    
    public void saveRefreshToken(String userId, String refreshToken) throws SQLException {
        // ❗ 보안: 원본 토큰 대신 해시된 값을 저장하는 것이 더 안전합니다.
        String hashedToken = Bcrypt.hashPassword(refreshToken);
        String sql = "UPDATE en_user SET refresh_token = ? WHERE id = ?";

        // UserDAO가 생성자에서 dbUrl 등을 받으므로, 여기서 직접 Connection을 생성합니다.
        try (Connection conn = DriverManager.getConnection(this.dbUrl, this.dbUser, this.dbPass);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, hashedToken);
            pstmt.setString(2, userId);
            
            int affectedRows = pstmt.executeUpdate();
            
            // 저장 성공 여부 확인 (디버깅용)
            if (affectedRows > 0) {
                System.out.println("SUCCESS: Refresh token saved for user '" + userId + "'");
            } else {
                System.err.println("ERROR: Failed to save refresh token. User '" + userId + "' not found.");
            }
        }
    }

    // Get the stored (hashed) refresh token for a user
    public String getRefreshToken(Connection conn, String userId) throws SQLException {
        String sql = "SELECT refresh_token FROM en_user WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("refresh_token");
                }
            }
        }
        return null;
    }
    
    public void clearRefreshToken(String userId) throws SQLException {
        String sql = "UPDATE en_user SET refresh_token = NULL WHERE id = ?";

        try (Connection conn = DriverManager.getConnection(this.dbUrl, this.dbUser, this.dbPass);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, userId);
            pstmt.executeUpdate();
            System.out.println("Refresh token cleared for user: " + userId);
        }
    }
}