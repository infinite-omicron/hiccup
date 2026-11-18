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
    /** The browser started without a name (one per Burp, as before). */
    public static final String DEFAULT = "default";

    private final MontoyaApi api;
    private final Throttle throttle;
    private static final java.util.regex.Pattern DEVTOOLS =
            java.util.regex.Pattern.compile("DevTools listening on (ws://\\S+)(?: with token (\\S+))?");
    private static final java.util.regex.Pattern NAME = java.util.regex.Pattern.compile("[A-Za-z0-9._-]{1,64}");

    /** One launched Chromium: its own CDP port, proxy and profile. */
    private static final class Instance {
        Process process;
        int cdpPort;
        String proxy;
        // Burp's Chromium build prints its CDP websocket URL and an auth token at
        // start-up; its HTTP endpoints (/json/*) need the token in x-burp-authorization.
        volatile String wsUrl;
        volatile String token;

        boolean alive() {
            return process != null && process.isAlive();
        }
    }

    private final Map<String, Instance> instances = new LinkedHashMap<>();

    public Browser(MontoyaApi api, Throttle throttle) {
        this.api = api;
        this.throttle = throttle;
    }

    static String name(String name) {
        if (name == null || name.isBlank()) return DEFAULT;
        if (!NAME.matcher(name).matches()) throw new IllegalArgumentException("bad browser name: " + name);
        return name;
    }

    /**
     * Launches the named browser (or returns its status if it's running). With
     * proxyPort > 0 it uses that Burp listener, otherwise Burp's first one.
     */
    public synchronized Map<String, Object> launch(String name, String url, int port, int proxyPort, String ua,
                                                   boolean headless, String binary) throws IOException {
        name = name(name);
        Instance running = instances.get(name);
        if (running != null && running.alive()) {
            return status(name);
        }
        for (var e : instances.entrySet()) {
            if (e.getValue().alive() && e.getValue().cdpPort == port) {
                throw new IOException("CDP port " + port + " is used by browser \"" + e.getKey() + "\"");
            }
        }
        Path chromium = binary != null && !binary.isBlank() ? Path.of(binary) : findChromium()
                .orElseThrow(() -> new IOException("Burp's bundled Chromium not found; pass \"binary\""));
        String proxy = proxyPort > 0 ? "127.0.0.1:" + proxyPort : proxyListener();
        String suffix = DEFAULT.equals(name) ? "" : "-" + name;
        Path profile = Extension.hiccupHome().resolve("browser-profile" + suffix);
        Files.createDirectories(profile);
        disablePasswordManager(profile);

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
                "--disable-sync",
                "--password-store=basic"));
        if (ua != null) cmd.add("--user-agent=" + ua);
        if (headless) cmd.add("--headless=new");
        cmd.add(url == null || url.isBlank() ? "about:blank" : url);

        Instance in = new Instance();
        in.process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        in.cdpPort = port;
        in.proxy = proxy;
        instances.put(name, in);
        watchOutput(in, Extension.hiccupHome().resolve("browser" + suffix + ".log"));
        api.logging().logToOutput("hiccup: launched browser \"" + name + "\" (CDP 127.0.0.1:" + port + ", proxy " + proxy + ")");
        awaitDevTools(in, 30_000);
        return status(name);
    }

    /**
     * Turns the profile's password manager off, which also stops Chrome's
     * password-leak lookups to Google: those would send a hash of the test
     * credentials and clutter history. Flags can't do this in current builds.
     */
    static void disablePasswordManager(Path profile) throws IOException {
        Path prefs = profile.resolve("Default").resolve("Preferences");
        Files.createDirectories(prefs.getParent());
        com.google.gson.JsonObject root = new com.google.gson.JsonObject();
        if (Files.exists(prefs)) {
            try {
                root = com.google.gson.JsonParser.parseString(Files.readString(prefs)).getAsJsonObject();
            } catch (RuntimeException ignored) {
                // Unreadable preferences: start over with just ours.
            }
        }
        root.addProperty("credentials_enable_service", false);
        com.google.gson.JsonObject prof = root.has("profile") && root.get("profile").isJsonObject()
                ? root.getAsJsonObject("profile") : new com.google.gson.JsonObject();
        prof.addProperty("password_manager_enabled", false);
        prof.addProperty("password_manager_leak_detection", false);
        root.add("profile", prof);
        Files.writeString(prefs, root.toString());
    }

    /** Copies browser output to a log file and picks out the DevTools line. */
    private void watchOutput(Instance in, Path log) {
        Thread t = new Thread(() -> {
            try (var reader = new java.io.BufferedReader(new java.io.InputStreamReader(in.process.getInputStream()));
                 var out = Files.newBufferedWriter(log)) {
                for (String line; (line = reader.readLine()) != null; ) {
                    var m = DEVTOOLS.matcher(line);
                    if (m.find()) {
                        in.wsUrl = m.group(1);
                        in.token = m.group(2);
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

    public synchronized Map<String, Object> status(String name) {
        name = name(name);
        Instance in = instances.get(name);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        boolean running = in != null && in.alive();
        m.put("running", running);
        if (running) {
            m.put("pid", in.process.pid());
            m.put("cdp", "http://127.0.0.1:" + in.cdpPort);
            m.put("ws", in.wsUrl);
            m.put("token", in.token);
            m.put("proxy", in.proxy);
        }
        return m;
    }

    /** Status of every browser that is running. */
    public synchronized List<Map<String, Object>> statusAll() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String name : instances.keySet()) {
            if (instances.get(name).alive()) out.add(status(name));
        }
        return out;
    }

    /** Waits briefly for the DevTools line so launch can return the websocket URL. */
    private static void awaitDevTools(Instance in, long millis) {
        long end = System.currentTimeMillis() + millis;
        while (in.wsUrl == null && in.alive() && System.currentTimeMillis() < end) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    public synchronized void stop(String name) {
        Instance in = instances.remove(name(name));
        if (in == null || in.process == null) return;
        in.process.descendants().forEach(ProcessHandle::destroy);
        in.process.destroy();
    }

    public synchronized void stopAll() {
        for (String name : new ArrayList<>(instances.keySet())) stop(name);
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
