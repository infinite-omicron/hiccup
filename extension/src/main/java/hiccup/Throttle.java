package hiccup;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * One HttpHandler that sees traffic from every Burp tool (Proxy/browser, Repeater,
 * Intruder, Scanner, extensions). It paces requests per host and backs off on
 * 429/503, and optionally rewrites the User-Agent.
 */
public class Throttle implements HttpHandler {

    /** Wire format for GET/POST /throttle. */
    public static class Rule {
        public String host;
        public double rps;
        public int burst = 1;
        public int[] jitter_ms = {0, 0};
        public Backoff backoff = new Backoff();
    }

    public static class Backoff {
        public int[] on_status = {429, 503};
        public boolean honor_retry_after = true;
        public int max_s = 120;
    }

    /** GCRA-style limiter: requests are given slots; jitter widens the gap after each slot. */
    static final class Bucket {
        final Rule rule;
        long nextSlotNs;
        long pausedUntilNs;
        int strikes;

        Bucket(Rule rule) {
            this.rule = rule;
            this.nextSlotNs = System.nanoTime();
        }

        synchronized long reserve() {
            long now = System.nanoTime();
            long interval = (long) (1e9 / rule.rps);
            long earliest = now - (long) Math.max(0, rule.burst - 1) * interval;
            long slot = Math.max(Math.max(nextSlotNs, earliest), pausedUntilNs);
            nextSlotNs = slot + interval + jitterNs();
            return Math.max(0, slot - now);
        }

        private long jitterNs() {
            int lo = rule.jitter_ms[0];
            int hi = Math.max(lo, rule.jitter_ms[1]);
            return (lo == hi ? lo : ThreadLocalRandom.current().nextInt(lo, hi + 1)) * 1_000_000L;
        }

        synchronized void observe(int status, String retryAfter) {
            for (int s : rule.backoff.on_status) {
                if (s == status) {
                    strikes++;
                    long seconds = Math.min(rule.backoff.max_s, 1L << Math.min(strikes, 16));
                    if (rule.backoff.honor_retry_after && retryAfter != null) {
                        try {
                            seconds = Math.min(rule.backoff.max_s, Long.parseLong(retryAfter.trim()));
                        } catch (NumberFormatException ignored) {
                            // HTTP-date form: keep the exponential delay.
                        }
                    }
                    pausedUntilNs = Math.max(pausedUntilNs, System.nanoTime() + seconds * 1_000_000_000L);
                    return;
                }
            }
            strikes = 0;
        }
    }

    private final MontoyaApi api;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private volatile String userAgent;
    private volatile String userAgentScope = "browser";
    private volatile Map<String, String> clientHints = Map.of();

    public Throttle(MontoyaApi api) {
        this.api = api;
    }

    public void set(Rule rule) {
        String host = rule.host.toLowerCase();
        if (rule.rps <= 0) {
            buckets.remove(host);
        } else {
            if (rule.jitter_ms == null || rule.jitter_ms.length != 2) rule.jitter_ms = new int[]{0, 0};
            if (rule.backoff == null) rule.backoff = new Backoff();
            rule.burst = Math.max(1, rule.burst);
            buckets.put(host, new Bucket(rule));
        }
    }

    public void clear() {
        buckets.clear();
    }

    public List<Rule> rules() {
        return buckets.values().stream().map(b -> b.rule).toList();
    }

    public void setUserAgent(String ua, String scope, Map<String, String> hints) {
        this.userAgent = ua == null || ua.isBlank() ? null : ua;
        this.userAgentScope = scope == null ? "browser" : scope;
        this.clientHints = hints == null ? Map.of() : Map.copyOf(hints);
    }

    public String userAgent() {
        return userAgent;
    }

    public Map<String, Object> userAgentInfo() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ua", userAgent);
        m.put("scope", userAgentScope);
        m.put("client_hints", clientHints);
        return m;
    }

    private Bucket bucketFor(String host) {
        host = host.toLowerCase();
        Bucket b = buckets.get(host);
        if (b != null) return b;
        // "*.example.com" rules cover subdomains.
        for (int i = host.indexOf('.'); i >= 0; i = host.indexOf('.', i + 1)) {
            b = buckets.get("*" + host.substring(i));
            if (b != null) return b;
        }
        return null;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        Bucket b = bucketFor(request.httpService().host());
        if (b != null) {
            long waitNs = b.reserve();
            if (waitNs > 0) {
                try {
                    Thread.sleep(waitNs / 1_000_000, (int) (waitNs % 1_000_000));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        HttpRequest out = request;
        String ua = userAgent;
        // "browser": rewrite proxied traffic so Sec-CH-UA* matches the --user-agent string.
        // "all": also rewrite Repeater, Intruder, Scanner and extension traffic.
        if (ua != null && ("all".equals(userAgentScope) || request.toolSource().isFromTool(ToolType.PROXY))) {
            if (request.hasHeader("User-Agent")) out = out.withUpdatedHeader("User-Agent", ua);
            for (Map.Entry<String, String> h : clientHints.entrySet()) {
                if (!out.hasHeader(h.getKey())) continue;
                // An empty value strips the hint (non-Chromium UAs don't send them).
                out = h.getValue().isEmpty() ? out.withRemovedHeader(h.getKey()) : out.withUpdatedHeader(h.getKey(), h.getValue());
            }
        }
        return RequestToBeSentAction.continueWith(out);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        Bucket b = bucketFor(response.initiatingRequest().httpService().host());
        if (b != null) {
            b.observe(response.statusCode(), response.headerValue("Retry-After"));
        }
        return ResponseReceivedAction.continueWith(response);
    }
}
