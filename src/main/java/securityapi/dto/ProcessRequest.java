package securityapi.dto;

import java.util.Map;

//requests 배열 안의 각 객체를 위한 클래스
public class ProcessRequest {
    private String route_type;
    private String table;
    private String mode;
    private String info_type;
    private String uuid;
    private String col;
    private String algo;
    private PasswordInfo password;
    
    private String update;
    private Map<String, String> data;
    
    public String getRoute_type() {
    	return route_type;
    }
    public void setRoute_type(String route_type) {
    	this.route_type = route_type;
    }
    
    public String getTable() {
    	return table;
    }
    public void setTable(String table) {
    	this.table = table;
    }
    
    public String getMode() {
    	return mode;
    }
    public void setMode(String mode) {
    	this.mode = mode;
    }
    
    public String getInfo_type() {
    	return info_type;
    }
    public void setInfo_type(String info_type) {
    	this.info_type = info_type;
    }
    
    public String getUuid() {
    	return uuid;
    }
    public void setUuid(String uuid) {
    	this.uuid = uuid;
    }
    
    public String getCol() {
    	return col;
    }
    public void setCol(String col) {
    	this.col = col;
    }
    
    public String getAlgo() {
    	return algo;
    }
    public void setAlgo(String algo) {
    	this.algo = algo;
    }
    
    public PasswordInfo getPassword() {
    	return password;
    }
    public void setPassword(PasswordInfo password) {
    	this.password = password;
    }
    
	public String getUpdate() {
		return update;
	}
	public void setUpdate(String update) {
		this.update = update;
	}
	
	public Map<String, String> getData() {
		return data;
	}
	public void setData(Map<String, String> data) {
		this.data = data;
	}
}