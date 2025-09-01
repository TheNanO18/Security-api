package securityapi;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Base64;

import javax.crypto.SecretKey;

import com.sun.net.httpserver.HttpServer;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import securityapi.api.LoginHandler;
import securityapi.api.LogoutHandler;
import securityapi.api.ProcessHandler;
import securityapi.api.RefreshTokenHandler;
import securityapi.api.RegisterHandler;
import securityapi.api.TableDataHandler;
import securityapi.authtoken.JwsGenerator;
import securityapi.config.ConfigLoader;
import securityapi.dbmanage.DatabaseManager;
import securityapi.dbmanage.UserDAO;

public class Main {
    private static final JwsGenerator jwsHandler = new JwsGenerator();
    private static final SecretKey serverSecretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public static void main(String[] args) throws IOException {
        // 1. config.properties에서 모든 경로 정보 읽어오기
        int port                = ConfigLoader.getIntProperty("server.port");
        String apiPath          = ConfigLoader.getProperty("server.api.path");
        String loginPath        = ConfigLoader.getProperty("server.login.path");
        String registerPath     = ConfigLoader.getProperty("server.register.path");
        String tableDataPath    = ConfigLoader.getProperty("server.tableData.path");
        String refreshTokenPath = ConfigLoader.getProperty("server.refreshToken.path");
        String logoutPath       = ConfigLoader.getProperty("server.logout.path");

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        
        DatabaseManager dbManager = new DatabaseManager(
                ConfigLoader.getProperty("db.url"),
                ConfigLoader.getProperty("db.user"),
                ConfigLoader.getProperty("db.pass")
        );
        
        String dbUrl  = ConfigLoader.getProperty("db.url");
        String dbUser = ConfigLoader.getProperty("db.user");
        String dbPass = ConfigLoader.getProperty("db.pass");
        
        UserDAO userDAO = new UserDAO(dbUrl, dbUser, dbPass);
        
        LoginHandler loginHandler               = new LoginHandler(jwsHandler, serverSecretKey, userDAO);
        RegisterHandler registerHandler         = new RegisterHandler(userDAO);
        ProcessHandler processHandler           = new ProcessHandler(jwsHandler, serverSecretKey);
        TableDataHandler tableDataHandler       = new TableDataHandler(jwsHandler, serverSecretKey);
        RefreshTokenHandler refreshTokenHandler = new RefreshTokenHandler(jwsHandler, serverSecretKey, userDAO, dbManager);
        LogoutHandler logoutHandler             = new LogoutHandler(jwsHandler, serverSecretKey, userDAO);

        server.createContext(loginPath,     loginHandler);
        server.createContext(apiPath,       processHandler);
        server.createContext(registerPath,  registerHandler);
        server.createContext(tableDataPath, tableDataHandler);
        server.createContext(refreshTokenPath, refreshTokenHandler);
        server.createContext(logoutPath, logoutHandler);
        
        server.setExecutor(null);
        server.start();

        System.out.println("✅ 서버가 시작되었습니다. http://localhost:" + port);
        System.out.println("로그인 엔드포인트: http://localhost:" + port + loginPath);
        System.out.println("API 엔드포인트: http://localhost:" + port + apiPath);

        String base64UrlKey = Base64.getUrlEncoder().withoutPadding().encodeToString(serverSecretKey.getEncoded());
        System.out.println("---");
        System.out.println("🔑 서버 비밀키 (Base64URL): " + base64UrlKey);
        System.out.println("---");
    }
}