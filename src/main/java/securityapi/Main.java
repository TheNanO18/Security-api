package securityapi;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Base64;

import javax.crypto.SecretKey;

import com.sun.net.httpserver.HttpServer;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import securityapi.api.LoginHandler;
import securityapi.api.ProcessHandler;
import securityapi.api.RegisterHandler;
import securityapi.api.TableDataHandler;
import securityapi.authtoken.JwsGenerator;
import securityapi.config.ConfigLoader;
import securityapi.dbmanage.UserDAO;

public class Main {
    private static final JwsGenerator jwsHandler = new JwsGenerator();
    private static final SecretKey serverSecretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public static void main(String[] args) throws IOException {
        // 1. config.properties에서 모든 경로 정보 읽어오기
        int port             = ConfigLoader.getIntProperty("server.port");
        String apiPath       = ConfigLoader.getProperty("server.api.path");
        String loginPath     = ConfigLoader.getProperty("server.login.path");
        String registerPath  = ConfigLoader.getProperty("server.register.path");
        String tableDataPath = ConfigLoader.getProperty("server.tableData.path");

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        
        String dbUrl  = ConfigLoader.getProperty("db.url");
        String dbUser = ConfigLoader.getProperty("db.user");
        String dbPass = ConfigLoader.getProperty("db.pass");
        
        UserDAO userDAO = new UserDAO(dbUrl, dbUser, dbPass);

        // 2. 읽어온 변수를 사용하여 컨텍스트 생성
        server.createContext(loginPath,     new LoginHandler(jwsHandler, serverSecretKey, userDAO));
        server.createContext(apiPath,       new ProcessHandler(jwsHandler, serverSecretKey));
        server.createContext(registerPath,  new RegisterHandler(userDAO));
        server.createContext(tableDataPath, new TableDataHandler(jwsHandler, serverSecretKey));
        
        server.setExecutor(null);
        server.start();

        // 3. 서버 시작 메시지에서도 변수 사용
        System.out.println("✅ 서버가 시작되었습니다. http://localhost:" + port);
        System.out.println("로그인 엔드포인트: http://localhost:" + port + loginPath);
        System.out.println("API 엔드포인트: http://localhost:" + port + apiPath);

        String base64UrlKey = Base64.getUrlEncoder().withoutPadding().encodeToString(serverSecretKey.getEncoded());
        System.out.println("---");
        System.out.println("🔑 서버 비밀키 (Base64URL): " + base64UrlKey);
        System.out.println("---");
    }
}