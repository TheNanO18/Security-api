package securityapi.api;

import securityapi.dbmanage.DatabaseManager;
import securityapi.pwdhash.Bcrypt;
import securityapi.securityalgo.EncryptionService;

import java.sql.Connection;
import java.util.*;
import java.util.stream.Collectors;

public class ProcessService {
    private DatabaseManager dbManager;
    private final EncryptionService encryptionService;

    public ProcessService() {
        byte[] testKey = { (byte) 0x88, (byte) 0xE3, (byte) 0x4F, (byte) 0x8F, (byte) 0x08, (byte) 0x17, (byte) 0x79, (byte) 0xF1, (byte) 0xE9, (byte) 0x9F, (byte) 0x94, (byte) 0x37, (byte) 0x0A, (byte) 0xD4, (byte) 0x05, (byte) 0x89 };
        this.encryptionService = new EncryptionService(testKey);
    }

    private void ensureDbManagerInitialized(Map<String, Object> requestData) {
        if (this.dbManager == null) {
            @SuppressWarnings("unchecked")
            Map<String, String> dbConfig = (Map<String, String>) requestData.get("db_config");

            if (dbConfig == null || !dbConfig.containsKey("url") || !dbConfig.containsKey("user") || !dbConfig.containsKey("pass")) {
                throw new IllegalArgumentException("요청에 유효한 'db_config' 객체(url, user, pass 포함)가 필요합니다.");
            }

            this.dbManager = new DatabaseManager(
                    dbConfig.get("url"),
                    dbConfig.get("user"),
                    dbConfig.get("pass")
            );
        }
    }

    public Map<String, Object> processSingleRequest(Connection conn, Map<String, Object> requestData) {
        Map<String, Object> response = new LinkedHashMap<>();

        try {
            ensureDbManagerInitialized(requestData);

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

            String routeType = (String) requestData.get("route_type");
            String infoType = (String) requestData.get("info_type");
            String table = (String) requestData.get("table");
            String algo = (String) requestData.get("algo");
            String colsToProcessStr = (String) requestData.get("col");

            if ("api".equals(routeType)) {
                if ("new".equals(infoType)) {
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
                    String uuidStr = (String) requestData.get("uuid");
                    String mode = (String) requestData.get("mode");
                    UUID uuid = UUID.fromString(uuidStr);

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
                            Arrays.stream(colsToProcessStr.split("\\s*,\\s*"))
                                    .map(String::trim)
                                    .filter(colName -> !"uuid".equalsIgnoreCase(colName))
                                    .collect(Collectors.toList()) : new ArrayList<>();

                    String ivToUse = null;

                    if (!requestedColumns.isEmpty()) {
                        if ("en".equalsIgnoreCase(mode)) {
                            List<String> columnsToProcess = requestedColumns;
                            ivToUse = encryptionService.generateIv();
                            String algoToUse = (String) requestData.get("algo");
                            if (algoToUse == null || algoToUse.isBlank()) {
                                throw new IllegalArgumentException("암호화(en) 시에는 'algo' 파라미터가 반드시 필요합니다.");
                            }

                            for (String col : columnsToProcess) {
                                String value = targetData.get(col.toLowerCase());
                                if (value != null) {
                                    String result = encryptionService.encrypt(value, ivToUse, algoToUse);
                                    processedData.put(col, result);
                                }
                            }
                            response.put("en_col", colsToProcessStr);
                        } else { // mode가 "de"인 경우
                            String originalEncryptedColsStr = targetData.getOrDefault("en_col", "");
                            List<String> alreadyEncryptedColumns = (originalEncryptedColsStr == null || originalEncryptedColsStr.isBlank()) ?
                                    new ArrayList<>() : new ArrayList<>(Arrays.asList(originalEncryptedColsStr.split(",")));

                            List<String> columnsToProcess = requestedColumns.stream()
                                    .filter(alreadyEncryptedColumns::contains)
                                    .collect(Collectors.toList());

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
                if ("new".equals(infoType)) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> originalDataMap = (Map<String, String>) requestData.get("data");
                    if (originalDataMap == null || originalDataMap.isEmpty()) {
                        throw new IllegalArgumentException("'new' 타입 요청에는 'data' 객체가 반드시 필요합니다.");
                    }
                    Map<String, String> dataToInsert = new HashMap<>();
                    String iv = encryptionService.generateIv();
                    List<String> columnsToEncrypt = (colsToProcessStr == null || colsToProcessStr.isBlank()) ? Collections.emptyList() : Arrays.asList(colsToProcessStr.split("\\s*,\\s*"));
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
                    response.put("iv", iv);
                    response.put("result", dataToInsert);

                } else if ("old".equals(infoType)) {
                    String uuidStr = (String) requestData.get("uuid");
                    String mode = (String) requestData.get("mode");
                    String updateFlag = (String) requestData.get("update");
                    UUID uuid = UUID.fromString(uuidStr);

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
                            Arrays.stream(colsToProcessStr.split("\\s*,\\s*"))
                                    .map(String::trim)
                                    .filter(colName -> !"uuid".equalsIgnoreCase(colName))
                                    .collect(Collectors.toList()) : new ArrayList<>();

                    String ivToUse = null;

                    if (!requestedColumns.isEmpty()) {
                        if ("en".equalsIgnoreCase(mode)) {
                            List<String> columnsToProcess = requestedColumns;
                            ivToUse = encryptionService.generateIv();
                            String algoToUse = (String) requestData.get("algo");
                            if (algoToUse == null || algoToUse.isBlank()) {
                                throw new IllegalArgumentException("암호화(en) 시에는 'algo' 파라미터가 반드시 필요합니다.");
                            }
                            for (String col : columnsToProcess) {
                                String value = targetData.get(col.toLowerCase());
                                if (value != null) {
                                    String result = encryptionService.encrypt(value, ivToUse, algoToUse);
                                    processedData.put(col, result);
                                }
                            }
                        } else { // mode is "de"
                            String originalEncryptedColsStr = targetData.getOrDefault("en_col", "");
                            List<String> alreadyEncryptedColumns = (originalEncryptedColsStr == null || originalEncryptedColsStr.isBlank()) ? new ArrayList<>() : new ArrayList<>(Arrays.asList(originalEncryptedColsStr.split(",")));
                            List<String> columnsToProcess = requestedColumns.stream().filter(alreadyEncryptedColumns::contains).collect(Collectors.toList());

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

                    if ("T".equals(updateFlag)) {
                        if (!processedData.isEmpty()) {
                            boolean isEncryptMode = "en".equalsIgnoreCase(mode);
                            String originalEncryptedColsStr = targetData.getOrDefault("en_col", "");
                            List<String> alreadyEncryptedColumns = (originalEncryptedColsStr == null || originalEncryptedColsStr.isBlank()) ? new ArrayList<>() : new ArrayList<>(Arrays.asList(originalEncryptedColsStr.split(",")));
                            List<String> allTableColumnNames = dbManager.getColumnNames(conn, table);
                            List<String> columnsToUpdateInDB = new ArrayList<>(processedData.keySet());

                            if (isEncryptMode) {
                                dbManager.insertOldData(conn, table, uuid, processedData, requestedColumns, ivToUse, algo);
                            } else {
                                dbManager.executeUpdate(conn, uuid, processedData, allTableColumnNames, isEncryptMode, null, algo, alreadyEncryptedColumns, columnsToUpdateInDB, table);
                            }
                            response.put("message", "작업 완료 (DB 업데이트됨).");
                        } else {
                            response.put("message", "업데이트할 데이터가 없습니다.");
                        }
                    } else if ("F".equals(updateFlag)) {
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