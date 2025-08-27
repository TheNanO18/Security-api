package securityapi.dto;

public class PasswordInfo {
    private String pass_algo;
    private String value;
    private String column;
    
	public String getPass_algo() {
		return pass_algo;
	}
	public void setPass_algo(String pass_algo) {
		this.pass_algo = pass_algo;
	}
	
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}
	
	public String getColumn() {
		return column;
	}
	public void setColumn(String column) {
		this.column = column;
	}
}
