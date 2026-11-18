package hiccup;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMapFilter;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** The REST API. Every handler is a thin wrapper over one Montoya call; logic lives in the hiccup CLI. */
public class Api {
    private static final Gson GSON = new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final MontoyaApi api;
    private final byte[] auth;
    private final Browser browser;
    private final Throttle throttle;
    private HttpServer server;
    private ExecutorService pool;
    private int port;

    /** Thrown by handlers to produce a non-200 JSON error. */
    static final class HttpError extends RuntimeException {
        final int status;

        HttpError(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    public Api(MontoyaApi api, String token, Browser browser, Throttle throttle) {
        this.api = api;
        this.auth = ("Bearer " + token).getBytes(StandardCharsets.UTF_8);
        this.browser = browser;
        this.throttle = throttle;
    }

    public void start(int port) throws IOException {
        this.port = port;
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "hiccup-api");
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(pool);
        server.createContext("/", this::handle);
        server.start();
    }

    public void stop() {
        if (server != null) server.stop(0);
        if (pool != null) pool.shutdownNow();
    }

    private void handle(HttpExchange ex) throws IOException {
        int status = 200;
        Object out;
        try {
            guard(ex);
            out = route(ex.getRequestMethod(), ex.getRequestURI().getPath(), query(ex.getRequestURI()), body(ex));
        } catch (HttpError e) {
            status = e.status;
            out = Map.of("error", e.getMessage());
        } catch (com.google.gson.JsonParseException | IllegalArgumentException | IllegalStateException
                 | ClassCastException | NullPointerException e) {
            // Malformed JSON, bad numbers, unknown enum names (severity), wrong field types or missing fields.
            status = 400;
            out = Map.of("error", "bad request: " + e.getMessage());
        } catch (Exception e) {
            status = 500;
            out = Map.of("error", String.valueOf(e));
            api.logging().logToError("hiccup: " + ex.getRequestMethod() + " " + ex.getRequestURI() + ": " + e);
        }
        byte[] bytes = GSON.toJson(out).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Bearer token, no browser-originated requests (CSRF), and a loopback Host header (DNS rebinding). */
    private void guard(HttpExchange ex) {
        if (ex.getRequestHeaders().containsKey("Origin")) throw new HttpError(403, "browser requests are not allowed");
        String host = ex.getRequestHeaders().getFirst("Host");
        if (host == null || !(host.equals("127.0.0.1:" + port) || host.equals("localhost:" + port))) {
            throw new HttpError(403, "bad Host header");
        }
        String got = ex.getRequestHeaders().getFirst("Authorization");
        if (got == null || !MessageDigest.isEqual(auth, got.getBytes(StandardCharsets.UTF_8))) {
            throw new HttpError(401, "missing or bad bearer token");
        }
    }

    private Object route(String method, String path, Map<String, String> q, JsonElement body) throws Exception {
        String key = method + " " + path;
        if (path.startsWith("/proxy/history/") && method.equals("GET")) {
            return historyItem(Integer.parseInt(path.substring("/proxy/history/".length())));
        }
        return switch (key) {
            case "GET /health" -> health();
            case "GET /browser" -> browser.status();
            case "POST /browser/launch" -> launch(obj(body));
            case "POST /browser/stop" -> {
                browser.stop();
                yield browser.status();
            }
            case "GET /proxy/history" -> history(q);
            case "GET /proxy/intercept" -> Map.of("enabled", api.proxy().isInterceptEnabled());
            case "POST /proxy/intercept" -> {
                if (obj(body).get("enabled").getAsBoolean()) api.proxy().enableIntercept();
                else api.proxy().disableIntercept();
                yield Map.of("enabled", api.proxy().isInterceptEnabled());
            }
            case "GET /sitemap" -> sitemap(q);
            case "POST /http/send" -> send(body);
            case "POST /repeater" -> {
                JsonObject o = obj(body);
                api.repeater().sendToRepeater(request(o), str(o, "tab"));
                yield Map.of("ok", true);
            }
            case "POST /intruder" -> {
                JsonObject o = obj(body);
                api.intruder().sendToIntruder(request(o), str(o, "tab"));
                yield Map.of("ok", true);
            }
            case "POST /scan" -> scan(obj(body));
            case "GET /issues" -> issues(q);
            case "POST /issues" -> addIssues(body);
            case "GET /scope" -> Map.of("url", req(q, "url"), "in_scope", api.scope().isInScope(req(q, "url")));
            case "POST /scope" -> scope(obj(body));
            case "GET /throttle" -> throttle.rules();
            case "POST /throttle" -> setThrottle(body);
            case "DELETE /throttle" -> {
                throttle.clear();
                yield List.of();
            }
            case "GET /useragent" -> throttle.userAgentInfo();
            case "POST /useragent" -> {
                JsonObject o = obj(body);
                Map<String, String> hints = new LinkedHashMap<>();
                if (o.has("client_hints") && o.get("client_hints").isJsonObject()) {
                    for (var e : o.getAsJsonObject("client_hints").entrySet()) hints.put(e.getKey(), e.getValue().getAsString());
                }
                throttle.setUserAgent(str(o, "ua"), str(o, "scope"), hints);
                yield throttle.userAgentInfo();
            }
            case "POST /extensions/install" -> installExtension(obj(body));
            case "GET /options/user" -> JsonParser.parseString(api.burpSuite().exportUserOptionsAsJson(paths(q)));
            case "GET /options/project" -> JsonParser.parseString(api.burpSuite().exportProjectOptionsAsJson(paths(q)));
            default -> throw new HttpError(404, "no route for " + key);
        };
    }

    // ---- handlers ----

    private Object health() {
        var v = api.burpSuite().version();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", v.name());
        m.put("version", v.toString());
        m.put("edition", v.edition().name());
        m.put("extension", "hiccup");
        m.put("proxy", browser.proxyListener());
        m.put("intercept", api.proxy().isInterceptEnabled());
        return m;
    }

    private Object launch(JsonObject o) throws IOException {
        // Intercept holds every request until someone clicks Forward, which hangs automation.
        if (!(o.has("keep_intercept") && o.get("keep_intercept").getAsBoolean())) api.proxy().disableIntercept();
        int cdp = o.has("port") ? o.get("port").getAsInt() : 9222;
        boolean headless = o.has("headless") && o.get("headless").getAsBoolean();
        return browser.launch(str(o, "url"), cdp, str(o, "ua"), headless, str(o, "binary"));
    }

    private Object history(Map<String, String> q) {
        String contains = q.get("contains");
        int since = Integer.parseInt(q.getOrDefault("since", "-1"));
        int limit = Integer.parseInt(q.getOrDefault("limit", "100"));
        boolean inScope = "true".equals(q.get("in_scope"));
        List<ProxyHttpRequestResponse> all = api.proxy().history(item ->
                item.id() > since
                        && (contains == null || item.finalRequest().url().contains(contains))
                        && (!inScope || item.finalRequest().isInScope()));
        List<ProxyHttpRequestResponse> page = all.subList(Math.max(0, all.size() - limit), all.size());
        List<Map<String, Object>> out = new ArrayList<>(page.size());
        for (ProxyHttpRequestResponse item : page) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", item.id());
            m.put("time", item.time().toString());
            m.put("method", item.finalRequest().method());
            m.put("url", item.finalRequest().url());
            HttpResponse resp = item.originalResponse();
            m.put("status", resp == null ? null : resp.statusCode());
            m.put("length", resp == null ? null : resp.toByteArray().length());
            m.put("mime", resp == null ? null : resp.statedMimeType().name());
            out.add(m);
        }
        return out;
    }

    private Object historyItem(int id) {
        List<ProxyHttpRequestResponse> found = api.proxy().history(item -> item.id() == id);
        if (found.isEmpty()) throw new HttpError(404, "no proxy history item " + id);
        ProxyHttpRequestResponse item = found.get(0);
        Map<String, Object> m = rr(item.finalRequest(), item.originalResponse());
        m.put("id", item.id());
        m.put("time", item.time().toString());
        return m;
    }

    private Object sitemap(Map<String, String> q) {
        String prefix = q.get("prefix");
        boolean full = "true".equals(q.get("full"));
        List<HttpRequestResponse> items = prefix == null
                ? api.siteMap().requestResponses()
                : api.siteMap().requestResponses(SiteMapFilter.prefixFilter(prefix));
        List<Map<String, Object>> out = new ArrayList<>(items.size());
        for (HttpRequestResponse rr : items) {
            if (full) {
                out.add(rr(rr.request(), rr.hasResponse() ? rr.response() : null));
            } else {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("method", rr.request().method());
                m.put("url", rr.request().url());
                m.put("status", rr.hasResponse() ? rr.response().statusCode() : null);
                out.add(m);
            }
        }
        return out;
    }

    /** Single request object, or {"requests":[...]} for a batch (sent in order, so throttling applies). */
    private Object send(JsonElement body) {
        JsonObject o = obj(body);
        if (o.has("requests")) {
            List<Object> out = new ArrayList<>();
            for (JsonElement e : o.getAsJsonArray("requests")) out.add(sendOne(e.getAsJsonObject()));
            return out;
        }
        return sendOne(o);
    }

    private Map<String, Object> sendOne(JsonObject o) {
        HttpRequest req = request(o);
        long start = System.nanoTime();
        HttpRequestResponse rr = api.http().sendRequest(req);
        Map<String, Object> m = rr(rr.request(), rr.hasResponse() ? rr.response() : null);
        m.put("elapsed_ms", (System.nanoTime() - start) / 1_000_000);
        return m;
    }

    private Object scan(JsonObject o) {
        if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) {
            throw new HttpError(501, "scanning requires Burp Suite Professional");
        }
        List<String> urls = strings(o.getAsJsonArray("urls"));
        String mode = str(o, "mode");
        if ("crawl".equals(mode)) {
            api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(urls.toArray(String[]::new)));
        } else {
            Audit audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(
                    "passive".equals(mode) ? BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                            : BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
            for (String u : urls) audit.addRequest(HttpRequest.httpRequestFromUrl(u));
        }
        return Map.of("ok", true, "mode", mode == null ? "audit" : mode, "urls", urls);
    }

    private Object issues(Map<String, String> q) {
        String prefix = q.get("prefix");
        List<AuditIssue> issues = prefix == null ? api.siteMap().issues()
                : api.siteMap().issues(SiteMapFilter.prefixFilter(prefix));
        List<Map<String, Object>> out = new ArrayList<>(issues.size());
        for (AuditIssue i : issues) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", i.name());
            m.put("url", i.baseUrl());
            m.put("severity", i.severity().name());
            m.put("confidence", i.confidence().name());
            m.put("detail", i.detail());
            m.put("remediation", i.remediation());
            out.add(m);
        }
        return out;
    }

    /** One issue object or an array of them. Evidence: [{url?, request_b64, response_b64}]. */
    private Object addIssues(JsonElement body) {
        JsonArray arr = body.isJsonArray() ? body.getAsJsonArray() : wrap(body);
        int before = api.siteMap().issues().size();
        int n = 0;
        for (JsonElement e : arr) {
            JsonObject o = e.getAsJsonObject();
            String url = req(o, "url");
            List<HttpRequestResponse> evidence = new ArrayList<>();
            if (o.has("evidence")) {
                for (JsonElement ev : o.getAsJsonArray("evidence")) {
                    JsonObject x = ev.getAsJsonObject();
                    HttpService svc = HttpService.httpService(x.has("url") ? x.get("url").getAsString() : url);
                    HttpRequest r = HttpRequest.httpRequest(svc, bytes(x, "request_b64"));
                    HttpResponse resp = x.has("response_b64") ? HttpResponse.httpResponse(bytes(x, "response_b64")) : null;
                    evidence.add(HttpRequestResponse.httpRequestResponse(r, resp));
                }
            }
            AuditIssueSeverity sev = AuditIssueSeverity.valueOf(upper(o, "severity", "INFORMATION"));
            api.siteMap().add(AuditIssue.auditIssue(
                    req(o, "name"),
                    str(o, "detail"),
                    str(o, "remediation"),
                    url,
                    sev,
                    AuditIssueConfidence.valueOf(upper(o, "confidence", "FIRM")),
                    str(o, "background"),
                    str(o, "remediation_background"),
                    sev,
                    evidence));
            n++;
        }
        // Community accepts siteMap().add(issue) but silently discards it.
        if (n > 0 && api.siteMap().issues().size() == before
                && api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) {
            throw new HttpError(501, "this Burp edition does not store issues (Burp Suite Professional is required)");
        }
        return Map.of("added", n);
    }

    private Object scope(JsonObject o) {
        boolean exclude = o.has("exclude") && o.get("exclude").getAsBoolean();
        List<String> urls = strings(o.getAsJsonArray("urls"));
        for (String u : urls) {
            if (exclude) api.scope().excludeFromScope(u);
            else api.scope().includeInScope(u);
        }
        return Map.of("ok", true, exclude ? "excluded" : "included", urls);
    }

    private Object setThrottle(JsonElement body) {
        JsonArray arr = body.isJsonArray() ? body.getAsJsonArray() : wrap(body);
        for (JsonElement e : arr) {
            Throttle.Rule r = GSON.fromJson(e, Throttle.Rule.class);
            if (r.host == null || r.host.isBlank()) throw new HttpError(400, "throttle rule needs \"host\"");
            throttle.set(r);
        }
        return throttle.rules();
    }

    /**
     * Adds jar/py/rb files to Burp's extension list via user options:
     * {"extensions":[{path, type?, name?}]} or a single {path, type?, name?}.
     * Importing the list makes Burp reload every extension, this one included,
     * so the import runs after the response is sent; the reloaded hiccup writes
     * a new runtime file (new token) that the CLI waits for.
     */
    private Object installExtension(JsonObject o) {
        JsonArray wanted = o.has("extensions") ? o.getAsJsonArray("extensions") : wrap(o);
        JsonObject root = JsonParser.parseString(api.burpSuite().exportUserOptionsAsJson("user_options.extender"))
                .getAsJsonObject();
        JsonObject extender = root.getAsJsonObject("user_options").getAsJsonObject("extender");
        JsonArray exts = extender.has("extensions") ? extender.getAsJsonArray("extensions") : new JsonArray();
        List<String> added = new ArrayList<>();
        List<String> already = new ArrayList<>();
        for (JsonElement w : wanted) {
            JsonObject x = w.getAsJsonObject();
            String file = req(x, "path");
            String type = x.has("type") ? str(x, "type")
                    : file.endsWith(".py") ? "python" : file.endsWith(".rb") ? "ruby" : "java";
            String name = x.has("name") ? str(x, "name") : java.nio.file.Path.of(file).getFileName().toString();
            boolean present = false;
            for (JsonElement e : exts) {
                JsonObject ex = e.getAsJsonObject();
                if (ex.has("extension_file") && file.equals(ex.get("extension_file").getAsString())) present = true;
            }
            if (present) {
                already.add(file);
                continue;
            }
            JsonObject ext = new JsonObject();
            ext.addProperty("auto_reload", false);
            ext.addProperty("errors", "ui");
            ext.addProperty("extension_file", file);
            ext.addProperty("extension_type", type);
            ext.addProperty("loaded", true);
            ext.addProperty("name", name);
            ext.addProperty("output", "ui");
            ext.addProperty("use_ai", false);
            exts.add(ext);
            added.add(file);
        }
        if (!added.isEmpty()) {
            extender.add("extensions", exts);
            String patch = GSON.toJson(root);
            Thread t = new Thread(() -> {
                try {
                    Thread.sleep(300);
                    api.burpSuite().importUserOptionsFromJson(patch);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, "hiccup-install");
            t.setDaemon(true);
            t.start();
        }
        return Map.of("added", added, "already", already, "reloading", !added.isEmpty());
    }

    // ---- request building / serialization ----

    /**
     * {url, method?, headers?: {k:v} | [[k,v]], body?, body_b64?} or
     * {raw | raw_b64, url} / {raw | raw_b64, host, port?, https?}.
     */
    private static HttpRequest request(JsonObject o) {
        if (o.has("raw") || o.has("raw_b64")) {
            HttpService svc;
            if (o.has("host")) {
                boolean https = !o.has("https") || o.get("https").getAsBoolean();
                int port = o.has("port") ? o.get("port").getAsInt() : https ? 443 : 80;
                svc = HttpService.httpService(o.get("host").getAsString(), port, https);
            } else {
                svc = HttpService.httpService(req(o, "url"));
            }
            byte[] raw = o.has("raw_b64") ? B64D.decode(o.get("raw_b64").getAsString())
                    : crlf(o.get("raw").getAsString()).getBytes(StandardCharsets.ISO_8859_1);
            return HttpRequest.httpRequest(svc, ByteArray.byteArray(raw));
        }
        HttpRequest r = HttpRequest.httpRequestFromUrl(req(o, "url"));
        if (o.has("method")) r = r.withMethod(o.get("method").getAsString());
        if (o.has("headers")) {
            JsonElement h = o.get("headers");
            if (h.isJsonObject()) {
                for (var e : h.getAsJsonObject().entrySet()) r = setHeader(r, e.getKey(), e.getValue().getAsString());
            } else {
                for (JsonElement e : h.getAsJsonArray()) {
                    JsonArray kv = e.getAsJsonArray();
                    r = setHeader(r, kv.get(0).getAsString(), kv.get(1).getAsString());
                }
            }
        }
        if (o.has("body_b64")) r = r.withBody(ByteArray.byteArray(B64D.decode(o.get("body_b64").getAsString())));
        else if (o.has("body")) r = r.withBody(o.get("body").getAsString());
        return r;
    }

    private static HttpRequest setHeader(HttpRequest r, String k, String v) {
        return r.hasHeader(k) ? r.withUpdatedHeader(k, v) : r.withAddedHeader(k, v);
    }

    /** Raw requests typed in a shell usually have bare \n line endings; HTTP needs CRLF in the head. */
    private static String crlf(String raw) {
        if (raw.contains("\r\n")) return raw;
        int split = raw.indexOf("\n\n");
        String head = split < 0 ? raw : raw.substring(0, split);
        String rest = split < 0 ? "" : raw.substring(split + 2);
        head = head.replace("\n", "\r\n");
        return head + "\r\n\r\n" + rest;
    }

    private static Map<String, Object> rr(HttpRequest req, HttpResponse resp) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("method", req.method());
        m.put("url", req.url());
        m.put("request_b64", B64.encodeToString(req.toByteArray().getBytes()));
        if (resp != null) {
            m.put("status", resp.statusCode());
            m.put("length", resp.toByteArray().length());
            List<List<String>> headers = new ArrayList<>();
            for (HttpHeader h : resp.headers()) headers.add(List.of(h.name(), h.value()));
            m.put("response_headers", headers);
            m.put("response_b64", B64.encodeToString(resp.toByteArray().getBytes()));
        } else {
            m.put("status", null);
        }
        return m;
    }

    // ---- small JSON / query helpers ----

    private static JsonElement body(HttpExchange ex) throws IOException {
        byte[] b = ex.getRequestBody().readAllBytes();
        return b.length == 0 ? new JsonObject() : JsonParser.parseString(new String(b, StandardCharsets.UTF_8));
    }

    private static Map<String, String> query(URI uri) {
        Map<String, String> m = new LinkedHashMap<>();
        String q = uri.getRawQuery();
        if (q == null) return m;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            String k = URLDecoder.decode(i < 0 ? kv : kv.substring(0, i), StandardCharsets.UTF_8);
            String v = i < 0 ? "" : URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8);
            m.put(k, v);
        }
        return m;
    }

    private static JsonObject obj(JsonElement e) {
        if (e == null || !e.isJsonObject()) throw new HttpError(400, "expected a JSON object");
        return e.getAsJsonObject();
    }

    private static JsonArray wrap(JsonElement e) {
        JsonArray a = new JsonArray();
        a.add(e);
        return a;
    }

    private static String str(JsonObject o, String k) {
        return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : null;
    }

    private static String upper(JsonObject o, String k, String def) {
        String s = str(o, k);
        return s == null ? def : s.toUpperCase();
    }

    private static String req(JsonObject o, String k) {
        String s = str(o, k);
        if (s == null || s.isBlank()) throw new HttpError(400, "missing \"" + k + "\"");
        return s;
    }

    private static String req(Map<String, String> q, String k) {
        String s = q.get(k);
        if (s == null || s.isBlank()) throw new HttpError(400, "missing query parameter \"" + k + "\"");
        return s;
    }

    private static ByteArray bytes(JsonObject o, String k) {
        return ByteArray.byteArray(B64D.decode(req(o, k)));
    }

    /** "?paths=a.b,c.d" for the options export endpoints. */
    private static String[] paths(Map<String, String> q) {
        String p = q.get("paths");
        return p == null || p.isBlank() ? new String[0] : p.split(",");
    }

    private static List<String> strings(JsonArray a) {
        if (a == null) throw new HttpError(400, "missing \"urls\"");
        List<String> out = new ArrayList<>();
        for (JsonElement e : a) out.add(e.getAsString());
        return out;
    }
}
