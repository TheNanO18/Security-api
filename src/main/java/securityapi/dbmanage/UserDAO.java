package securityapi.dbmanage; // DAO 클래스를 위한 새 패키지 생성 권장

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDAO {
    private final String dbUrl;
    private final String dbUser;
    private final String dbPass;

    public UserDAO(String dbUrl, String dbUser, String dbPass) {
        this.dbUrl = dbUrl;
        this.dbUser = dbUser;
        this.dbPass = dbPass;
    }
    
    public boolean validateUser(String id, String password) {
        // SQL Injection 공격 방지를 위해 PreparedStatement 사용
        String sql = "SELECT password FROM en_user WHERE id = ?";
        
        // try-with-resources 구문으로 자원 자동 해제
        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, id); // 첫 번째 ?에 사용자 id 바인딩

            try (ResultSet rs = pstmt.executeQuery()) {
                // 해당 ID의 사용자가 존재하고, 비밀번호가 일치하는지 확인
                if (rs.next()) {
                    String storedPassword = rs.getString("password");
                    // 🚨 중요: 실제 서비스에서는 반드시 해시된 비밀번호를 비교해야 합니다! (아래 보안 섹션 참고)
                    return storedPassword.equals(password);
                }
            }
        } catch (SQLException e) {
            System.err.println("Database validation error: " + e.getMessage());
            // 예외 처리 (로깅 등)
        }
        return false; // 사용자가 없거나 비밀번호가 틀리면 false 반환
    }
}