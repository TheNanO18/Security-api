package securityapi.api;

import securityapi.dbmanage.DatabaseManager;
import securityapi.pwdhash.Bcrypt;
import securityapi.securityalgo.EncryptionService;
import java.sql.Connection;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 실제 비즈니스 로직(데이터 처리)을 담당하는 서비스 클래스
 */
public class ProcessService {
    private final DatabaseManager dbManager;
    private final EncryptionService encryptionService;

    public ProcessService() {
        this.dbManager = new DatabaseManager(
                securityapi.config.ConfigLoader.getProperty("db.url"),
                securityapi.config.ConfigLoader.getProperty("db.user"),
                securityapi.config.ConfigLoader.getProperty("db.pass")
        );
        byte[] testKey = { (byte) 0x88, (byte) 0xE3, (byte) 0x4F, (byte) 0x8F, (byte) 0x08, (byte) 0x17, (byte) 0x79, (byte) 0xF1, (byte) 0xE9, (byte) 0x9F, (byte) 0x94, (byte) 0x37, (byte) 0x0A, (byte) 0xD4, (byte) 0x05, (byte) 0x89 };
        this.encryptionService = new EncryptionService(testKey);
    }

    public Map<String, Object> processSingleRequest(Connection conn, Map<String, Object> requestData) {
        Map<String, Object> response = new LinkedHashMap<>();
        String hashedPassword = null;
        String passwordColumn = null;
        Object passwordObject = requestData.get("password");
        
        if (passwordObject instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, String> passwordData = (Map<String, String>) passwordObject;
            String rawPassword = passwordData.get("value");
            passwordColumn = passwordData.get("column");
            if (rawPassword != null && !rawPassword.isEmpty() && passwordColumn != null) {
                hashedPassword = Bcrypt.hashPassword(rawPassword);
            }
        }

        try {
        	String routeType        = (String) requestData.get("route_type");
            String infoType         = (String) requestData.get("info_type");
            String table            = (String) requestData.get("table");
    		String algo             = (String) requestData.get("algo");
            String colsToProcessStr = (String) requestData.get("col");
    		
            if("api".equals(routeType)) {
            	if("new".equals(infoType)) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> originalDataMap = (Map<String, String>) requestData.get("data");
                    if (originalDataMap == null || originalDataMap.isEmpty()) {
                        throw new IllegalArgumentException("'new' 타입 요청에는 'data' 객체가 반드시 필요합니다.");
                    }

                    Map<String, String> dataToInsert = new HashMap<>();
                    String iv = encryptionService.generateIv();
                    List<String> columnsToEncrypt = (colsToProcessStr == null || colsToProcessStr.isBlank()) ?
                                                    Collections.emptyList() :
                                                    Arrays.asList(colsToProcessStr.split("\\s*,\\s*"));

                    for (Map.Entry<String, String> entry : originalDataMap.entrySet()) {
                        String currentColumn = entry.getKey();
                        String currentValue  = entry.getValue();
                        if (currentColumn.equals(passwordColumn)) {
                            dataToInsert.put(currentColumn, hashedPassword);
                        } else if (columnsToEncrypt.contains(currentColumn)) {
                            dataToInsert.put(currentColumn, encryptionService.encrypt(currentValue, iv, algo));
                        } else {
                            dataToInsert.put(currentColumn, currentValue);
                        }
                    }
                    
                    response.put("status", "success");
                    response.put("iv", iv);
                    response.put("result", dataToInsert);
                    
            	} else if("old".equals(infoType)) {
            		String uuidStr    = (String) requestData.get("uuid");
                    String mode       = (String) requestData.get("mode");
                    UUID uuid         = UUID.fromString(uuidStr);

                    Map<String, String> targetData = dbManager.getDataById(conn, table, uuid);
                    Map<String, String> encrypData = dbManager.getDataById(conn, table, uuid);
                    if (targetData.isEmpty()) {
                        throw new NoSuchElementException("해당 UUID의 데이터를 찾을 수 없습니다: " + uuid);
                    }
                    
                    Map<String, String> processedData = new HashMap<>();
                    if (hashedPassword != null && passwordColumn != null) {
                        processedData.put(passwordColumn, hashedPassword);
                    }

                    List<String> requestedColumns = (colsToProcessStr != null && !colsToProcessStr.isBlank()) ?
                            Arrays.stream(colsToProcessStr.split("\\s*,\\s*"))
                                .map(String::trim)
                                .filter(colName -> !"uuid".equalsIgnoreCase(colName))
                                .collect(Collectors.toList()) : new ArrayList<>();
                    
                    List<String> columnsToProcess;
                    boolean isEncryptMode = "en".equalsIgnoreCase(mode);
                    String originalEncryptedColsStr = encrypData.getOrDefault("en_col", "");
                    List<String> alreadyEncryptedColumns = (originalEncryptedColsStr == null || originalEncryptedColsStr.isBlank()) ?
                            new ArrayList<>() : new ArrayList<>(Arrays.asList(originalEncryptedColsStr.split(",")));

                    // ⭐️ [핵심 수정] IV를 한번만 생성하고 재사용하기 위해 변수를 상단으로 이동
                    String ivToUse = null; 

                    if (!requestedColumns.isEmpty()) {
                        columnsToProcess = isEncryptMode ? requestedColumns : requestedColumns.stream()
                                .filter(alreadyEncryptedColumns::contains)
                                .collect(Collectors.toList());
                        
                        // ⭐️ [핵심 수정] isEncryptMode일 때 ivToUse에 새 IV 할당, 아니면 기존 IV 사용
                        ivToUse = isEncryptMode ? encryptionService.generateIv() : encrypData.get("iv_data");
                        if (!isEncryptMode && ivToUse == null && !columnsToProcess.isEmpty()) {
                            throw new IllegalStateException("복호화를 위한 IV 값이 없습니다.");
                        }

                        for (String col : columnsToProcess) {
                            String value = targetData.get(col.toLowerCase());
                            String result = "";
                            if (value != null) {
                                // ⭐️ [핵심 수정] ivToUse 변수를 사용하여 암/복호화 수행
                            	if(isEncryptMode) {
                            		result = encryptionService.encrypt(value, ivToUse, algo);
                            		processedData.put(col, result);
                            	} else {
                            		algo = encrypData.get("encryption_algo");
                            		result = encryptionService.decrypt(value, ivToUse, algo);
                                    processedData.put(col, result);
                            	}
                            }
                        }
                    }

                    response.put("status", "success");
                    response.put("iv", ivToUse);
                    response.put("result", processedData);
            	}
            	
            } else if("proxy".equals(routeType)) {
            	if("new".equals(infoType)) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> originalDataMap = (Map<String, String>) requestData.get("data");
                    if (originalDataMap == null || originalDataMap.isEmpty()) {
                        throw new IllegalArgumentException("'new' 타입 요청에는 'data' 객체가 반드시 필요합니다.");
                    }

                    Map<String, String> dataToInsert = new HashMap<>();
                    String iv = encryptionService.generateIv();
                    List<String> columnsToEncrypt = (colsToProcessStr == null || colsToProcessStr.isBlank()) ?
                                                    Collections.emptyList() :
                                                    Arrays.asList(colsToProcessStr.split("\\s*,\\s*"));

                    for (Map.Entry<String, String> entry : originalDataMap.entrySet()) {
                        String currentColumn = entry.getKey();
                        String currentValue  = entry.getValue();
                        if (currentColumn.equals(passwordColumn)) {
                            dataToInsert.put(currentColumn, hashedPassword);
                        } else if (columnsToEncrypt.contains(currentColumn)) {
                            dataToInsert.put(currentColumn, encryptionService.encrypt(currentValue, iv, algo));
                        } else {
                            dataToInsert.put(currentColumn, currentValue);
                        }
                    }
                    
                    response.put("status", "success");
                    response.put("iv", iv);
                    response.put("result", dataToInsert);
                    
            	} else if("old".equals(infoType)) {
            		String uuidStr    = (String) requestData.get("uuid");
                    String mode       = (String) requestData.get("mode");
                    String updateFlag = (String) requestData.get("update");
                    UUID uuid         = UUID.fromString(uuidStr);

                    Map<String, String> targetData = dbManager.getDataById(conn, table, uuid);
                    if (targetData.isEmpty()) {
                        throw new NoSuchElementException("해당 UUID의 데이터를 찾을 수 없습니다: " + uuid);
                    }
                    
                    Map<String, String> processedData = new HashMap<>();
                    if (hashedPassword != null && passwordColumn != null) {
                        processedData.put(passwordColumn, hashedPassword);
                    }

                    List<String> requestedColumns = (colsToProcessStr != null && !colsToProcessStr.isBlank()) ?
                            Arrays.stream(colsToProcessStr.split("\\s*,\\s*"))
                                .map(String::trim)
                                .filter(colName -> !"uuid".equalsIgnoreCase(colName))
                                .collect(Collectors.toList()) : new ArrayList<>();
                    
                    List<String> columnsToProcess;
                    boolean isEncryptMode = "en".equalsIgnoreCase(mode);
                    String originalEncryptedColsStr = targetData.getOrDefault("en_col", "");
                    List<String> alreadyEncryptedColumns = (originalEncryptedColsStr == null || originalEncryptedColsStr.isBlank()) ?
                            new ArrayList<>() : new ArrayList<>(Arrays.asList(originalEncryptedColsStr.split(",")));

                    // ⭐️ [핵심 수정] IV를 한번만 생성하고 재사용하기 위해 변수를 상단으로 이동
                    String ivToUse = null; 

                    if (!requestedColumns.isEmpty()) {
                        columnsToProcess = isEncryptMode ? requestedColumns : requestedColumns.stream()
                                .filter(alreadyEncryptedColumns::contains)
                                .collect(Collectors.toList());
                        
                        // ⭐️ [핵심 수정] isEncryptMode일 때 ivToUse에 새 IV 할당, 아니면 기존 IV 사용
                        ivToUse = isEncryptMode ? encryptionService.generateIv() : targetData.get("iv_data");
                        if (!isEncryptMode && ivToUse == null && !columnsToProcess.isEmpty()) {
                            throw new IllegalStateException("복호화를 위한 IV 값이 없습니다.");
                        }

                        for (String col : columnsToProcess) {
                            String value = targetData.get(col.toLowerCase());
                            if (value != null) {
                                // ⭐️ [핵심 수정] ivToUse 변수를 사용하여 암/복호화 수행
                                String result = isEncryptMode ? encryptionService.encrypt(value, ivToUse, algo) : encryptionService.decrypt(value, ivToUse, algo);
                                processedData.put(col, result);
                            }
                        }
                    }
                    
                    if ("T".equals(updateFlag)) {
                        if (!processedData.isEmpty()) {
                            List<String> allTableColumnNames = dbManager.getColumnNames(conn, table);
                            
                            // ⭐️ [핵심 수정] 불필요한 ivToSave 변수 선언을 제거하고 ivToUse를 그대로 사용합니다.
                            List<String> columnsToUpdateInDB = new ArrayList<>(processedData.keySet());
                            
                            List<String> orderedProcessdColumns = allTableColumnNames.stream()
                            		                              .filter(colName -> processedData.keySet().contains(colName) && !"password".equals(colName))
                            		                              .collect(Collectors.toList());
                            
                            if(isEncryptMode) {
                                // ⭐️ [핵심 수정] 암호화 시 사용했던 ivToUse를 DB에 전달
                                dbManager.insertOldData(conn, table, uuid, processedData, orderedProcessdColumns, ivToUse, algo);
                            } else {
                                // ⭐️ [핵심 수정] 복호화 시 iv는 null로 전달하여 DB 업데이트
                                dbManager.executeUpdate(conn, uuid, processedData, allTableColumnNames, isEncryptMode, null, algo, alreadyEncryptedColumns, columnsToUpdateInDB, table);
                            }
                            
                            response.put("message", "작업 완료 (DB 업데이트됨).");
                        } else {
                            response.put("message", "업데이트할 데이터가 없습니다.");
                        }
                    } else if("F".equals(updateFlag)) {
                        response.put("message", "작업이 시뮬레이션 되었습니다 (DB 업데이트 없음).");
                        response.put("iv", ivToUse);
                    }

                    response.put("status", "success");
                    response.put("result", processedData);
            	}
            	
            }
            
            return response;
        } catch (Exception e) {
            e.printStackTrace();
            response.put("status", "error");
            response.put("message", "처리 중 오류 발생: " + e.getMessage());
            
            return response;
        }
    }
}