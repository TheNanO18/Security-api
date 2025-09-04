package securityapi.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class ConfigLoader {
    private static final Properties properties = new Properties();

    static {
        // This logic correctly loads an external file first, then falls back to internal.
        File externalConfig = new File("config.properties");
        InputStream input = null;
        try {
            if (externalConfig.exists()) {
                input = new FileInputStream(externalConfig);
            } else {
                input = ConfigLoader.class.getClassLoader().getResourceAsStream("config.properties");
            }
            if (input == null) {
                throw new IOException("config.properties file not found.");
            }
            properties.load(input);
        } catch (IOException e) {
            throw new RuntimeException("Error loading configuration file", e);
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Gets a property value for the given key.
     * @param key The property key.
     * @return The property value, or null if not found.
     */
    public static String getProperty(String key) {
        return properties.getProperty(key);
    }

    /**
     * ✅ ADDED THIS NEW METHOD
     * Gets a property value. If the key is not found, returns the provided default value.
     * @param key The property key.
     * @param defaultValue The value to return if the key is not found.
     * @return The property value or the default value.
     */
    public static String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    public static int getIntProperty(String key) {
        return Integer.parseInt(properties.getProperty(key));
    }
}