package securityapi.dto;

public class User {
    private String id;
    private String password;
    private String ip;
    private String port;
    private String database;
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    
    public String getPort() { return port; }
    public void setPort(String port) { this.port = port; }
    
    public String getDatabase() { return database; }
    public void setDatabase(String database) { this.database = database; }
}