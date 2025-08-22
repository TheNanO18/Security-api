package securityapi;

import com.sun.net.httpserver.HttpServer;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import securityapi.api.ProcessHandler;
import securityapi.authtoken.JwsGenerator;
import securityapi.config.ConfigLoader;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.InetSocketAddress;

import java.util.Base64;

public class Main {
    private static final JwsGenerator jwsHandler = new JwsGenerator();
    private static final SecretKey serverSecretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public static void main(String[] args) throws IOException {
        int port       = ConfigLoader.getIntProperty("server.port");
        String apiPath = ConfigLoader.getProperty("server.api.path");

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext(apiPath, new ProcessHandler(jwsHandler, serverSecretKey));
        server.setExecutor(null);
        server.start();

        System.out.println("✅ 서버가 시작되었습니다. http://localhost:" + port + apiPath);

        String authToken = jwsHandler.generateToken(serverSecretKey, "ezis", "wedatalab");
        System.out.println("---");
        System.out.println("사용할 테스트 토큰:");
        System.out.println("Bearer " + authToken);
        String base64UrlKey = Base64.getUrlEncoder().withoutPadding().encodeToString(serverSecretKey.getEncoded());
        System.out.println("secret key (Base64URL): " + base64UrlKey);
        System.out.println("---");
    }
}