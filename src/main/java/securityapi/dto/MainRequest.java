package securityapi.dto;

import java.util.List;

import com.google.gson.annotations.SerializedName;

public class MainRequest {
    
    @SerializedName("db_config")
    // ✅ Use your existing class here instead of creating a new DbConfig.java
    private DbConfig dbConfig; 
    
    private List<ProcessRequest> requests;

    // Getters and setters
    public DbConfig getDbConfig() { return dbConfig; }
    public void setDbConfig(DbConfig dbConfig) { this.dbConfig = dbConfig; }
    public List<ProcessRequest> getRequests() { return requests; }
    public void setRequests(List<ProcessRequest> requests) { this.requests = requests; }
}