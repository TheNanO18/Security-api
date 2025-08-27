package securityapi.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

// 현재 사용 x, 나중에 유저 로그인 관리를 다른 특정 DB에서 하고 암호화 설정 DB 접속을 따로할 경우에만 사용

public class ConfigLoader {
    private static final Properties properties = new Properties();

    static {
        try (InputStream input = ConfigLoader.class.getClassLoader().getResourceAsStream("config.properties")) {
            if (input == null) {
                throw new IOException("config.properties 파일을 찾을 수 없습니다.");
            }
            properties.load(input);
        } catch (IOException e) {
            throw new RuntimeException("설정 파일 로딩 중 에러 발생", e);
        }
    }

    public static String getProperty(String key) {
    	
        return properties.getProperty(key);
    }

    public static int getIntProperty(String key) {
    	
        return Integer.parseInt(properties.getProperty(key));
    }
}