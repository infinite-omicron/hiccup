package hiccup;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Launches Burp's bundled Chromium with a DevTools (CDP) port, proxied through
 * Burp's first running listener. Burp's own "Open browser" button can't expose
 * CDP, so we start the same binary ourselves.
 */
public class Browser {
    private final MontoyaApi api;
    private final Throttle throttle;
    private static final java.util.regex.Pattern DEVTOOLS =
            java.util.regex.Pattern.compile("DevTools listening on (ws://\\S+)(?: with token (\\S+))?");

    private Process process;
    private int cdpPort;
    // Burp's Chromium build prints its CDP websocket URL and an auth token at
    // start-up; its HTTP endpoints (/json/*) need the token in x-burp-authorization.
    private volatile String wsUrl;
    private volatile String token;

    public Browser(MontoyaApi api, Throttle throttle) {
        this.api = api;
        this.throttle = throttle;
    }

    public synchronized Map<String, Object> launch(String url, int port, String ua, boolean headless, String binary)
            throws IOException {
        if (process != null && process.isAlive()) {
            return status();
        }
        Path chromium = binary != null && !binary.isBlank() ? Path.of(binary) : findChromium()
                .orElseThrow(() -> new IOException("Burp's bundled Chromium not found; pass \"binary\""));
        String proxy = proxyListener();
        Path profile = Extension.hiccupHome().resolve("browser-profile");
        Files.createDirectories(profile);

        if (ua == null || ua.isBlank()) ua = throttle.userAgent();
        List<String> cmd = new ArrayList<>(List.of(
                chromium.toString(),
                "--remote-debugging-port=" + port,
                "--remote-debugging-address=127.0.0.1",
                "--remote-allow-origins=*",
                "--user-data-dir=" + profile,
                "--proxy-server=http://" + proxy,
                "--proxy-bypass-list=<-loopback>",
                "--ignore-certificate-errors",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-sync"));
        if (ua != null) cmd.add("--user-agent=" + ua);
        if (headless) cmd.add("--headless=new");
        cmd.add(url == null || url.isBlank() ? "about:blank" : url);

        wsUrl = null;
        token = null;
        process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        cdpPort = port;
        watchOutput(process, Extension.hiccupHome().resolve("browser.log"));
        api.logging().logToOutput("hiccup: launched " + chromium + " (CDP 127.0.0.1:" + port + ", proxy " + proxy + ")");
        awaitDevTools(30_000);
        return status();
    }

    /** Copies browser output to a log file and picks out the DevTools line. */
    private void watchOutput(Process p, Path log) {
        Thread t = new Thread(() -> {
            try (var in = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
                 var out = Files.newBufferedWriter(log)) {
                for (String line; (line = in.readLine()) != null; ) {
                    var m = DEVTOOLS.matcher(line);
                    if (m.find()) {
                        wsUrl = m.group(1);
                        token = m.group(2);
                    }
                    out.write(line);
                    out.newLine();
                    out.flush();
                }
            } catch (IOException ignored) {
            }
        }, "hiccup-browser-output");
        t.setDaemon(true);
        t.start();
    }

    public synchronized Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<>();
        boolean running = process != null && process.isAlive();
        m.put("running", running);
        if (running) {
            m.put("pid", process.pid());
            m.put("cdp", "http://127.0.0.1:" + cdpPort);
            m.put("ws", wsUrl);
            m.put("token", token);
        }
        return m;
    }

    /** Waits briefly for the DevTools line so launch can return the websocket URL. */
    void awaitDevTools(long millis) {
        long end = System.currentTimeMillis() + millis;
        while (wsUrl == null && process != null && process.isAlive() && System.currentTimeMillis() < end) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    public synchronized void stop() {
        if (process == null) return;
        process.descendants().forEach(ProcessHandle::destroy);
        process.destroy();
        process = null;
    }

    /** "host:port" of the first running proxy listener, defaulting to 127.0.0.1:8080. */
    String proxyListener() {
        for (String json : List.of(
                safe(() -> api.burpSuite().exportProjectOptionsAsJson("proxy.request_listeners")),
                safe(() -> api.burpSuite().exportUserOptionsAsJson("proxy.request_listeners")))) {
            if (json == null) continue;
            try {
                JsonObject proxy = JsonParser.parseString(json).getAsJsonObject().getAsJsonObject("proxy");
                JsonArray listeners = proxy == null ? null : proxy.getAsJsonArray("request_listeners");
                if (listeners == null) continue;
                for (JsonElement e : listeners) {
                    JsonObject l = e.getAsJsonObject();
                    if (l.has("running") && !l.get("running").getAsBoolean()) continue;
                    int port = l.get("listener_port").getAsInt();
                    String mode = l.has("listen_mode") ? l.get("listen_mode").getAsString() : "loopback_only";
                    String host = "specific_address".equals(mode) && l.has("listen_specific_address")
                            ? l.get("listen_specific_address").getAsString() : "127.0.0.1";
                    return host + ":" + port;
                }
            } catch (RuntimeException ignored) {
                // Unexpected shape; try the next source.
            }
        }
        return "127.0.0.1:8080";
    }

    private static String safe(java.util.function.Supplier<String> s) {
        try {
            return s.get();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Walks up from Burp's JRE looking for burpbrowser/<version>/, then tries well-known install roots. */
    static Optional<Path> findChromium() {
        List<Path> roots = new ArrayList<>();
        ProcessHandle.current().info().command().map(Path::of).ifPresent(p -> {
            for (Path d = p.getParent(); d != null; d = d.getParent()) roots.add(d);
        });
        Path home = Path.of(System.getProperty("user.home"));
        roots.add(home.resolve("BurpSuiteCommunity"));
        roots.add(home.resolve("BurpSuitePro"));
        for (String app : List.of("Burp Suite.app", "Burp Suite Community Edition.app", "Burp Suite Professional.app")) {
            roots.add(Path.of("/Applications", app, "Contents", "Resources", "app"));
            roots.add(home.resolve("Applications").resolve(app).resolve("Contents/Resources/app"));
        }
        String pf = System.getenv("ProgramFiles");
        if (pf != null) {
            roots.add(Path.of(pf, "BurpSuiteCommunity"));
            roots.add(Path.of(pf, "BurpSuitePro"));
        }
        String local = System.getenv("LOCALAPPDATA");
        if (local != null) {
            roots.add(Path.of(local, "Programs", "BurpSuiteCommunity"));
            roots.add(Path.of(local, "Programs", "BurpSuitePro"));
        }
        for (Path root : roots) {
            Path bb = root.resolve("burpbrowser");
            if (!Files.isDirectory(bb)) bb = root.resolve("app").resolve("burpbrowser");
            if (!Files.isDirectory(bb)) continue;
            try (Stream<Path> versions = Files.list(bb)) {
                Optional<Path> bin = versions.filter(Files::isDirectory)
                        .sorted(Comparator.comparing(Browser::versionKey).reversed())
                        .map(Browser::binaryIn)
                        .filter(Optional::isPresent).map(Optional::get)
                        .findFirst();
                if (bin.isPresent()) return bin;
            } catch (IOException ignored) {
            }
        }
        return Optional.empty();
    }

    private static Optional<Path> binaryIn(Path dir) {
        for (String rel : List.of("chrome", "chrome.exe")) {
            Path p = dir.resolve(rel);
            if (Files.isRegularFile(p)) return Optional.of(p);
        }
        // macOS: "Burp Browser.app/Contents/MacOS/Burp Browser" (older builds: Chromium.app/.../Chromium).
        try (Stream<Path> apps = Files.list(dir)) {
            return apps.filter(a -> a.getFileName().toString().endsWith(".app"))
                    .map(a -> a.resolve("Contents/MacOS").resolve(a.getFileName().toString().replaceFirst("\\.app$", "")))
                    .filter(Files::isRegularFile)
                    .findFirst();
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /** Zero-pads numeric parts so "142.0.7444.59" sorts above "99.0.1.2". */
    private static String versionKey(Path p) {
        StringBuilder sb = new StringBuilder();
        for (String part : p.getFileName().toString().split("\\.")) {
            sb.append(part.matches("\\d+") ? String.format("%010d", Long.parseLong(part)) : part).append('.');
        }
        return sb.toString();
    }
}
