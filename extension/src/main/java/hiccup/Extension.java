package hiccup;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

/**
 * Entry point. Starts a token-protected REST API on 127.0.0.1 and writes the
 * runtime file (~/.hiccup/burp.json) that the hiccup CLI uses to find it.
 */
public class Extension implements BurpExtension {
    static final int DEFAULT_PORT = 8099;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("hiccup");

        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String token = HexFormat.of().formatHex(raw);
        int port = port(api);

        Throttle throttle = new Throttle(api);
        Browser browser = new Browser(api, throttle);
        api.http().registerHttpHandler(throttle);

        Api server = new Api(api, token, browser, throttle);
        try {
            server.start(port);
        } catch (IOException e) {
            api.logging().logToError("hiccup: cannot listen on 127.0.0.1:" + port + ": " + e.getMessage());
            return;
        }

        String url = "http://127.0.0.1:" + port;
        Path runtime = runtimeFile();
        writeRuntime(api, runtime, Map.of("url", url, "token", token, "pid", ProcessHandle.current().pid()));
        api.logging().logToOutput("hiccup API listening on " + url + " (token in " + runtime + ")");

        api.extension().registerUnloadingHandler(() -> {
            server.stop();
            browser.stop();
            try {
                Files.deleteIfExists(runtime);
            } catch (IOException ignored) {
            }
        });
    }

    private static int port(MontoyaApi api) {
        String env = System.getenv("HICCUP_BURP_PORT");
        if (env != null && !env.isBlank()) {
            return Integer.parseInt(env.trim());
        }
        Integer pref = api.persistence().preferences().getInteger("port");
        return pref != null ? pref : DEFAULT_PORT;
    }

    static Path hiccupHome() {
        String env = System.getenv("HICCUP_HOME");
        return env != null && !env.isBlank() ? Path.of(env) : Path.of(System.getProperty("user.home"), ".hiccup");
    }

    static Path runtimeFile() {
        return hiccupHome().resolve("burp.json");
    }

    private static void writeRuntime(MontoyaApi api, Path file, Map<String, Object> data) {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling("burp.json.tmp");
            Files.writeString(tmp, new Gson().toJson(data));
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // Windows: the file lives under the user's profile, which is already private.
            }
            Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            api.logging().logToError("hiccup: cannot write " + file + ": " + e.getMessage());
        }
    }
}
