package securityapi.pwdhash;

import org.mindrot.jbcrypt.BCrypt;

public class Bcrypt {
    public static String hashPassword(String rawPassword) {
    	
        return BCrypt.hashpw(rawPassword, BCrypt.gensalt());
    }

    public static boolean checkPassword(String rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
        
        	return false;
        }
        
        return BCrypt.checkpw(rawPassword, encodedPassword);
    }
}