package securityapi.api;

import securityapi.dbmanage.DatabaseManager;
import securityapi.dto.DbConfig;
import securityapi.dto.MainRequest;
import securityapi.dto.PasswordInfo;
import securityapi.dto.ProcessRequest;
import securityapi.pwdhash.Bcrypt;
import securityapi.securityalgo.EncryptionService;

import java.sql.Connection;
import java.util.*;
import java.util.stream.Collectors;

public class ProcessService {

    private final EncryptionService encryptionService;

    public ProcessService() {
        byte[] testKey = { (byte) 0x88, (byte) 0xE3, (byte) 0x4F, (byte) 0x8F, (byte) 0x08, (byte) 0x17, (byte) 0x79, (byte) 0xF1, (byte) 0xE9, (byte) 0x9F, (byte) 0x94, (byte) 0x37, (byte) 0x0A, (byte) 0xD4, (byte) 0x05, (byte) 0x89 };
        this.encryptionService = new EncryptionService(testKey);
    }

    public List<Map<String, Object>> processBatchRequest(MainRequest mainRequest) throws Exception {
        DbConfig dbConfig = mainRequest.getDbConfig();
        if (dbConfig == null || dbConfig.getUrl() == null || dbConfig.getUser() == null || dbConfig.getPass() == null) {
            throw new IllegalArgumentException("요청에 유효한 'db_config' 객체가 필요합니다.");
        }

        DatabaseManager dbManager              = new DatabaseManager(dbConfig.getUrl(), dbConfig.getUser(), dbConfig.getPass());
        List<Map<String, Object>> batchResults = new ArrayList<>();

        try (Connection conn = dbManager.getConnection()) {
            for (ProcessRequest request : mainRequest.getRequests()) {
                Map<String, Object> result = processSingleRequest(conn, dbManager, request);
                batchResults.add(result);
            }
        }
        return batchResults;
    }

    public Map<String, Object> processSingleRequest(Connection conn, DatabaseManager dbManager, ProcessRequest requestData) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("uuid", requestData.getUuid());

        try {
            String hashedPassword = null;
            String passwordColumn = null;
            PasswordInfo passwordInfo = requestData.getPassword();

            if (passwordInfo != null && passwordInfo.getValue() != null && !passwordInfo.getValue().isEmpty()) {
                passwordColumn = passwordInfo.getColumn();
                hashedPassword = Bcrypt.hashPassword(passwordInfo.getValue());
            }

            String routeType        = requestData.getRoute_type();
            String infoType         = requestData.getInfo_type();
            String table            = requestData.getTable();
            String algo             = requestData.getAlgo();
            String colsToProcessStr = requestData.getCol();
            
            if ("api".equals(routeType)) {
                if ("new".equals(infoType)) {
                    Map<String, String> originalDataMap = requestData.getData();
                    if (originalDataMap == null || originalDataMap.isEmpty()) {
                        throw new IllegalArgumentException("'new' 타입 요청에는 'data' 객체가 반드시 필요합니다.");
                    }
                    Map<String, String> dataToInsert = new HashMap<>();
                    String iv                        = encryptionService.generateIv();
                    List<String> columnsToEncrypt    = (colsToProcessStr == null || colsToProcessStr.isBlank()) ? Collections.emptyList() : Arrays.asList(colsToProcessStr.split("\\s*,\\s*"));
                    
                    for (Map.Entry<String, String> entry : originalDataMap.entrySet()) {
                        String currentColumn = entry.getKey();
                        String currentValue = entry.getValue();
                        if (currentColumn.equals(passwordColumn)) {
                            dataToInsert.put(currentColumn, hashedPassword);
                        } else if (columnsToEncrypt.contains(currentColumn)) {
                            dataToInsert.put(currentColumn, encryptionService.encrypt(currentValue, iv, algo));
                        } else {
                            dataToInsert.put(currentColumn, currentValue);
                        }
                    }
                    
                    response.put("status", "success");
                    response.put("en_col", colsToProcessStr);
                    response.put("iv", iv);
                    response.put("result", dataToInsert);

                } else if ("old".equals(infoType)) {
                    // ✅ 'api'/'old' 로직 전체를 DTO 기반으로 구현
                    String uuidStr = requestData.getUuid();
                    String mode    = requestData.getMode();
                    UUID uuid      = UUID.fromString(uuidStr);

                    if (mode == null || (!"en".equalsIgnoreCase(mode) && !"de".equalsIgnoreCase(mode))) {
                        throw new IllegalArgumentException("mode 파라미터는 'en' 또는 'de' 값만 허용됩니다.");
                    }

                    Map<String, String> targetData = dbManager.getDataById(conn, table, uuid);
                    if (targetData.isEmpty()) {
                        throw new NoSuchElementException("해당 UUID의 데이터를 찾을 수 없습니다: " + uuid);
                    }

                    Map<String, String> processedData = new HashMap<>();
                    if (hashedPassword != null && passwordColumn != null) {
                        processedData.put(passwordColumn, hashedPassword);
                    }

                    List<String> requestedColumns = (colsToProcessStr != null && !colsToProcessStr.isBlank()) ?
                            Arrays.stream(colsToProcessStr.split("\\s*,\\s*")).map(String::trim)
                                    .filter(colName -> !"uuid".equalsIgnoreCase(colName)).collect(Collectors.toList())
                            : new ArrayList<>();

                    String ivToUse = null;

                    if (!requestedColumns.isEmpty()) {
                        if ("en".equalsIgnoreCase(mode)) {
                            ivToUse = encryptionService.generateIv();
                            String algoToUse = requestData.getAlgo();
                            if (algoToUse == null || algoToUse.isBlank()) {
                                throw new IllegalArgumentException("암호화(en) 시에는 'algo' 파라미터가 반드시 필요합니다.");
                            }
                            for (String col : requestedColumns) {
                                String value = targetData.get(col.toLowerCase());
                                if (value != null) {
                                    String result = encryptionService.encrypt(value, ivToUse, algoToUse);
                                    processedData.put(col, result);
                                }
                            }
                            response.put("en_col", colsToProcessStr);
                        } else { // "de" mode
                            String originalEncryptedColsStr      = targetData.getOrDefault("en_col", "");
                            List<String> alreadyEncryptedColumns = (originalEncryptedColsStr.isBlank()) ? new ArrayList<>() : new ArrayList<>(Arrays.asList(originalEncryptedColsStr.split(",")));
                            List<String> columnsToProcess        = requestedColumns.stream().filter(alreadyEncryptedColumns::contains).collect(Collectors.toList());

                            if (!columnsToProcess.isEmpty()) {
                                ivToUse = targetData.get("iv_data");
                                String algoToUse = targetData.get("encryption_algo");
                                if (ivToUse == null || algoToUse == null) {
                                    throw new IllegalStateException("복호화를 위한 IV 또는 알고리즘 값이 DB에 없습니다.");
                                }
                                for (String col : columnsToProcess) {
                                    String value = targetData.get(col.toLowerCase());
                                    if (value != null) {
                                        String result = encryptionService.decrypt(value, ivToUse, algoToUse);
                                        processedData.put(col, result);
                                    }
                                }
                            }
                        }
                    }
                    
                    response.put("status", "success");
                    response.put("iv", ivToUse);
                    response.put("result", processedData);
                    
                }
            } else if ("proxy".equals(routeType)) {
                String uuidStr    = requestData.getUuid();
                String mode       = requestData.getMode();
                String updateFlag = requestData.getUpdate();
                UUID uuid         = UUID.fromString(uuidStr);
                
                if ("new".equals(infoType)) {
                    if (mode == null || (!"en".equalsIgnoreCase(mode))) {
                        throw new IllegalArgumentException("proxy mode 파라미터는 'en' 값만 허용됩니다.");
                    }
                    
                    Map<String, String> originalDataMap = requestData.getData();
                    if (originalDataMap == null || originalDataMap.isEmpty()) {
                        throw new IllegalArgumentException("'new' 타입 요청에는 'data' 객체가 반드시 필요합니다.");
                    }
                    Map<String, String> dataToInsert = new HashMap<>();
                    String iv                        = encryptionService.generateIv();
                    List<String> columnsToEncrypt    = (colsToProcessStr == null || colsToProcessStr.isBlank()) ? Collections.emptyList() : Arrays.asList(colsToProcessStr.split("\\s*,\\s*"));
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
                    
                    if ("T".equals(updateFlag)) {
                        if (!dataToInsert.isEmpty()) {
                            boolean isEncryptMode = "en".equalsIgnoreCase(mode);
                            if (isEncryptMode) {
                                dbManager.insertOldData(conn, table, uuid, dataToInsert, columnsToEncrypt, iv, algo);
                            }
                            response.put("message", "작업 완료 (DB 업데이트됨).");
                        } else {
                            response.put("message", "업데이트할 데이터가 없습니다.");
                        }
                    } else if ("F".equals(updateFlag)) {
                        response.put("message", "작업이 시뮬레이션 되었습니다 (DB 업데이트 없음).");
                    }
                    
                    response.put("status", "success");
                    response.put("iv", iv);
                    response.put("result", dataToInsert);

                } else if ("old".equals(infoType)) {
                    if (mode == null || (!"en".equalsIgnoreCase(mode) && !"de".equalsIgnoreCase(mode))) {
                        throw new IllegalArgumentException("mode 파라미터는 'en' 또는 'de' 값만 허용됩니다.");
                    }

                    Map<String, String> targetData = dbManager.getDataById(conn, table, uuid);
                    if (targetData.isEmpty()) {
                        throw new NoSuchElementException("해당 UUID의 데이터를 찾을 수 없습니다: " + uuid);
                    }

                    Map<String, String> processedData = new HashMap<>();
                    if (hashedPassword != null && passwordColumn != null) {
                        processedData.put(passwordColumn, hashedPassword);
                    }

                    String ivToUse = null;

                    // ✅ 1. 'en' 모드와 'de' 모드의 로직을 명확히 분리합니다.
                    if ("en".equalsIgnoreCase(mode)) {
                        // --- 'en' (암호화) 모드 로직 ---
                        List<String> requestedColumns = (colsToProcessStr != null && !colsToProcessStr.isBlank()) ?
                                Arrays.stream(colsToProcessStr.split("\\s*,\\s*")).map(String::trim)
                                        .filter(colName -> !"uuid".equalsIgnoreCase(colName)).collect(Collectors.toList())
                                : new ArrayList<>();

                        if (requestedColumns.isEmpty()) {
                            throw new IllegalArgumentException("'en' 모드에서는 'col' 파라미터가 반드시 필요합니다.");
                        }

                        ivToUse = encryptionService.generateIv();
                        String algoToUse = requestData.getAlgo();
                        if (algoToUse == null || algoToUse.isBlank()) {
                            throw new IllegalArgumentException("암호화(en) 시에는 'algo' 파라미터가 반드시 필요합니다.");
                        }
                        for (String col : requestedColumns) {
                            String value = targetData.get(col.toLowerCase());
                            if (value != null) {
                                String result = encryptionService.encrypt(value, ivToUse, algoToUse);
                                processedData.put(col, result);
                            }
                        }

                        if ("T".equals(updateFlag)) {
                            if (!processedData.isEmpty()) {
                                dbManager.insertOldData(conn, table, uuid, processedData, requestedColumns, ivToUse, algo);
                                response.put("message", "작업 완료 (DB 업데이트됨).");
                            } else {
                                response.put("message", "업데이트할 데이터가 없습니다.");
                            }
                        }

                    } else if("de".equalsIgnoreCase(mode)) { // 'de' (복호화) 모드 로직
                        // --- ✅ 'de' (복호화) 모드 로직 ---
                        String originalEncryptedColsStr = targetData.getOrDefault("en_col", "");

                        if (originalEncryptedColsStr.isBlank()) {
                            response.put("message", "복호화할 컬럼이 없습니다 (en_col이 비어있음).");
                        } else {
                            // 1. DB에 저장된, 복호화 가능한 모든 컬럼의 목록을 준비합니다.
                            List<String> allEncryptableColumns = new ArrayList<>(Arrays.asList(originalEncryptedColsStr.split(",")));
                            
                            // 2. 이번 요청에서 '실제로' 복호화를 수행할 컬럼 목록을 담을 변수입니다.
                            List<String> columnsToDecrypt;

                            // 3. 시나리오에 따라 'columnsToDecrypt' 리스트를 결정합니다.
                            boolean isSimulationModeWithSpecificCols = "F".equals(updateFlag) && (colsToProcessStr != null && !colsToProcessStr.isBlank());

                            if (isSimulationModeWithSpecificCols) {
                                // 시나리오: update:"F" 이고, 특정 컬럼("col")이 지정된 경우
                                List<String> requestedCols = Arrays.asList(colsToProcessStr.split("\\s*,\\s*"));
                                // 요청된 컬럼 중, 실제로 암호화된 컬럼만 추려냅니다.
                                columnsToDecrypt = allEncryptableColumns.stream()
                                                                        .filter(requestedCols::contains)
                                                                        .collect(Collectors.toList());
                            } else {
                                // 시나리오 1: update:"T" (전체 복호화 후 저장)
                                // 시나리오 2: update:"F" 이고, 특정 컬럼 지정이 없는 경우 (전체 복호화 시뮬레이션)
                                columnsToDecrypt = allEncryptableColumns;
                            }

                            // 4. 결정된 'columnsToDecrypt' 목록을 기반으로 복호화를 수행합니다.
                            if (!columnsToDecrypt.isEmpty()) {
                                ivToUse = targetData.get("iv_data");
                                String algoToUse = targetData.get("encryption_algo");
                                if (ivToUse == null || algoToUse == null) {
                                    throw new IllegalStateException("복호화를 위한 IV 또는 알고리즘 값이 DB에 없습니다.");
                                }
                                for (String col : columnsToDecrypt) {
                                    String value = targetData.get(col.toLowerCase());
                                    if (value != null) {
                                        String result = encryptionService.decrypt(value, ivToUse, algoToUse);
                                        processedData.put(col, result);
                                    }
                                }
                            }

                            // 5. DB 업데이트는 "T" 플래그일 때만 수행합니다.
                            if ("T".equals(updateFlag)) {
                                if (!processedData.isEmpty()) {
                                    // 'update:T'일 때는 항상 전체 복호화를 의미하므로, allEncryptableColumns를 파라미터로 사용합니다.
                                    dbManager.updateDecryptedData(conn, uuid, processedData, allEncryptableColumns, allEncryptableColumns, table);
                                    response.put("message", "작업 완료 (DB 업데이트됨).");
                                } else {
                                    response.put("message", "복호화 처리 후 업데이트할 데이터가 없습니다.");
                                }
                            }
                        }
                    }

                    if ("F".equals(updateFlag)) {
                        response.put("message", "작업이 시뮬레이션 되었습니다 (DB 업데이트 없음).");
                    }

                    response.put("status", "success");
                    response.put("iv", ivToUse);
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