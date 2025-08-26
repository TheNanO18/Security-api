package securityapi.dbmanage;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class DatabaseManager {

    private final String dbUrl;
    private final String user;
    private final String pass;

    public DatabaseManager(String dbUrl, String user, String pass) {
        this.dbUrl = dbUrl;
        this.user  = user;
        this.pass  = pass;
    }

    public Connection getConnection() throws SQLException {
        System.out.println("데이터베이스 연결 시도 중...");
        Connection conn = DriverManager.getConnection(dbUrl, user, pass);
        System.out.println("PostgreSQL 데이터베이스에 성공적으로 연결되었습니다.");
        
        return conn;
    }
    
    public List<Map<String, Object>> getAllData(Connection conn, String tableName) throws SQLException {
        // 1. 반환 타입을 List<Map<String, Object>>로 변경
        List<Map<String, Object>> allRows = new ArrayList<>();
        
        // SQL 구문의 마지막에 빠져있던 큰따옴표(")를 추가합니다.
        // 경고: 이 방식은 SQL 인젝션에 취약할 수 있습니다. 아래 '보안' 섹션을 참고하세요.
        String sql = "SELECT * FROM \"" + tableName + "\"";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            ResultSet rs = pstmt.executeQuery();
            ResultSetMetaData md = rs.getMetaData();
            int columnCount = md.getColumnCount();

            // 2. if -> while 반복문으로 변경하여 모든 행을 순회
            while (rs.next()) {
                // 각 행의 데이터를 저장할 새로운 Map 생성
                Map<String, Object> row = new HashMap<>();
                for (int i = 1; i <= columnCount; i++) {
                    // 컬럼 타입을 유지하기 위해 getString 대신 getObject 사용
                    row.put(md.getColumnName(i), rs.getObject(i));
                }
                // 완성된 행을 리스트에 추가
                allRows.add(row);
            }
        }
        
        return allRows;
    }

    public Map<String, String> getDataById(Connection conn, String tableName, UUID uuid) throws SQLException {
        Map<String, String> data = new HashMap<>();
        String sql = "SELECT * FROM \"" + tableName + "\" WHERE uuid = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setObject(1, uuid);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                ResultSetMetaData md = rs.getMetaData();
                int columns          = md.getColumnCount();
                for (int i = 1; i <= columns; i++) {
                    data.put(md.getColumnName(i).toLowerCase(), rs.getString(i));
                }
            }
        }
        
        return data;
    }
    
    public List<String> getColumnNames(Connection conn, String tableName) throws SQLException {
        List<String> columnNames = new ArrayList<>();
        String sql = "SELECT * FROM \"" + tableName + "\" LIMIT 0";
        try (Statement stmt = conn.createStatement();
             ResultSet rs   = stmt.executeQuery(sql)) {
            ResultSetMetaData metaData = rs.getMetaData();
            int columnCount            = metaData.getColumnCount();
            for (int i = 1; i <= columnCount; i++) {
                columnNames.add(metaData.getColumnName(i));
            }
        }
        
        return columnNames;
    }
    
    public void executeUpdate(Connection conn, UUID primaryKeyValue, Map<String, String> columnsToUpdate, List<String> allTableColumnNames, boolean encryptMode, String ivBase64ToSave, String algoToSave, List<String> originalEncryptedColumns, List<String> columnsToProcess, String tableName) throws SQLException {
        List<String> setClauses = new ArrayList<>();
        List<Object> params     = new ArrayList<>();

        // 1. 해시된 패스워드나 암/복호화된 컬럼 값들을 SET 절에 추가
        for (Map.Entry<String, String> entry : columnsToUpdate.entrySet()) {
            setClauses.add("\"" + entry.getKey() + "\" = ?");
            params.add(entry.getValue());
        }

        // ⭐️ [핵심 수정] 암/복호화할 컬럼이 있을 때만 아래 로직을 실행합니다.
        if (columnsToProcess != null && !columnsToProcess.isEmpty()) {
            if (encryptMode) {
                // 암호화 모드일 때 en_col, iv_data, algo 업데이트
                Set<String> newEncryptedSet = new HashSet<>(originalEncryptedColumns);
                newEncryptedSet.addAll(columnsToProcess);
                String newEncryptedColumns = String.join(",", newEncryptedSet);

                setClauses.add("iv_data = ?");
                setClauses.add("encryption_algo = ?");
                setClauses.add("en_col = ?");
                params.add(ivBase64ToSave);
                params.add(algoToSave);
                params.add(newEncryptedColumns);
            } else {
                // 복호화 모드일 때 en_col 업데이트 (필요시 iv_data, algo는 NULL로)
                List<String> remainingEncryptedColumns = new ArrayList<>(originalEncryptedColumns);
                remainingEncryptedColumns.removeAll(columnsToProcess);
                
                if (remainingEncryptedColumns.isEmpty()) {
                    setClauses.add("iv_data = NULL");
                    setClauses.add("encryption_algo = NULL");
                    setClauses.add("en_col = NULL");
                } else {
                    setClauses.add("en_col = ?");
                    params.add(String.join(",", remainingEncryptedColumns));
                }
            }
        }
        
        // 2. 최종 SQL 쿼리 생성 및 실행
        String sql = "UPDATE \"" + tableName + "\" SET " + String.join(", ", setClauses) + " WHERE uuid = ?";
        params.add(primaryKeyValue);

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            int rowsAffected = pstmt.executeUpdate();
            System.out.println("최종 DB 업데이트 완료: " + rowsAffected + " 개의 행이 업데이트되었습니다.");
        }
    }
    
    public void insertOldData(Connection conn, String tableName, UUID uuid,
        Map<String, String> dataToInsert,
        List<String> encryptedColumnNames,// DB에 저장될 최종 데이터 (암호화된 값+원본 값)
        String iv, String algo) throws SQLException {
        
        // 💡 INSERT할 컬럼 목록 동적 생성 (메타데이터 포함)
        String en_tableName = "en_" + tableName;
        List<String> columns = new ArrayList<>(dataToInsert.keySet());
        columns.add("uuid");
        columns.add("iv_data");
        columns.add("encryption_algo");
        columns.add("en_col");
        
        String colsPart   = columns.stream().map(c -> "\"" + c + "\"").collect(Collectors.joining(", "));
        String valuesPart = String.join(", ", Collections.nCopies(columns.size(), "?"));
        String sql        = "INSERT INTO \"" + en_tableName + "\" (" + colsPart + ") VALUES (" + valuesPart + ")";
        
        System.out.println("\n--- DB에 새로운 데이터 삽입 (PreparedStatement 사용) ---");
        System.out.println("SQL Template: " + sql);
        
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            int paramIndex = 1;
            
            for (String colName : columns) {
                if (dataToInsert.containsKey(colName)) {
                  pstmt.setString(paramIndex++, dataToInsert.get(colName));
                }
            }
            
            pstmt.setObject(paramIndex++, uuid);
            pstmt.setString(paramIndex++, iv);
            pstmt.setString(paramIndex++, algo);
            pstmt.setString(paramIndex++, String.join(",", encryptedColumnNames));
            
            int rowsAffected = pstmt.executeUpdate();
            System.out.println("DB에 " + rowsAffected + "개의 행이 성공적으로 삽입되었습니다.");
        }
    }
    

    public void insertNewData(Connection conn, String tableName,
        Map<String, String> dataToInsert,  // DB에 저장될 최종 데이터 (암호화된 값+원본 값)
        List<String> encryptedColumnNames, // 암호화된 컬럼들의 이름 목록
        String iv, String algo) throws SQLException {
        
        // 💡 INSERT할 컬럼 목록 동적 생성 (메타데이터 포함)
    	String en_tableName = "en_" + tableName;
        List<String> columns = new ArrayList<>(dataToInsert.keySet());
        columns.add("uuid");
        columns.add("iv_data");
        columns.add("encryption_algo");
        columns.add("en_col");
        
        String colsPart   = columns.stream().map(c -> "\"" + c + "\"").collect(Collectors.joining(", "));
        String valuesPart = String.join(", ", Collections.nCopies(columns.size(), "?"));
        String sql        = "INSERT INTO \"" + en_tableName + "\" (" + colsPart + ") VALUES (" + valuesPart + ")";
        
        System.out.println("\n--- DB에 새로운 데이터 삽입 (PreparedStatement 사용) ---");
        System.out.println("SQL Template: " + sql);
        
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            int paramIndex = 1;
            
            for (String colName : columns) {
                if (dataToInsert.containsKey(colName)) {
                  pstmt.setString(paramIndex++, dataToInsert.get(colName));
                }
            }
            
            pstmt.setObject(paramIndex++, UUID.randomUUID());
            pstmt.setString(paramIndex++, iv);
            pstmt.setString(paramIndex++, algo);
            pstmt.setString(paramIndex++, String.join(",", encryptedColumnNames));
            
            int rowsAffected = pstmt.executeUpdate();
            System.out.println("DB에 " + rowsAffected + "개의 행이 성공적으로 삽입되었습니다.");
        }
    }
}