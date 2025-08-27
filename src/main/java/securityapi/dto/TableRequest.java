package securityapi.dto;

// Gson 라이브러리는 이미 pom.xml에 있으므로 바로 사용 가능
import com.google.gson.annotations.SerializedName;

public class TableRequest {
    private String tableName;

    // @JsonProperty 대신 @SerializedName 사용
    @SerializedName("db_config")
    private DbConfig dbConfig;

    // Getter와 Setter
    public String getTableName() { return tableName; }
    public void setTableName(String tableName) { this.tableName = tableName; }
    public DbConfig getDbConfig() { return dbConfig; }
    public void setDbConfig(DbConfig dbConfig) { this.dbConfig = dbConfig; }
}