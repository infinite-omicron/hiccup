package hiccup;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Burp proxy listeners, through project options. hiccup adds loopback
 * listeners so each account's browser has its own, and Proxy history records
 * which listener (so which account) every request came through. The ports
 * hiccup added are remembered in the extension's preferences, so removing
 * "hiccup's listeners" never touches the user's own, even after a reload.
 */
public class Listeners {
    private static final String PREF = "hiccup.listeners";
    private final MontoyaApi api;

    public Listeners(MontoyaApi api) {
        this.api = api;
    }

    private JsonArray current() {
        JsonObject root = JsonParser.parseString(api.burpSuite().exportProjectOptionsAsJson("proxy.request_listeners"))
                .getAsJsonObject();
        JsonObject proxy = root.getAsJsonObject("proxy");
        return proxy != null && proxy.has("request_listeners") ? proxy.getAsJsonArray("request_listeners") : new JsonArray();
    }

    private void save(JsonArray listeners) {
        JsonObject proxy = new JsonObject();
        proxy.add("request_listeners", listeners);
        JsonObject root = new JsonObject();
        root.add("proxy", proxy);
        api.burpSuite().importProjectOptionsFromJson(new Gson().toJson(root));
    }

    private TreeSet<Integer> owned() {
        TreeSet<Integer> ports = new TreeSet<>();
        String v = api.persistence().preferences().getString(PREF);
        if (v != null) {
            for (String p : v.split(",")) {
                if (!p.isBlank()) ports.add(Integer.parseInt(p.trim()));
            }
        }
        return ports;
    }

    private void setOwned(TreeSet<Integer> ports) {
        api.persistence().preferences().setString(PREF, String.join(",", ports.stream().map(String::valueOf).toList()));
    }

    private static int port(JsonElement e) {
        JsonObject o = e.getAsJsonObject();
        return o.has("listener_port") ? o.get("listener_port").getAsInt() : -1;
    }

    /** Every listener: port, interface, whether it's running, and whether hiccup added it. */
    public synchronized List<Map<String, Object>> list() {
        TreeSet<Integer> owned = owned();
        List<Map<String, Object>> out = new ArrayList<>();
        for (JsonElement e : current()) {
            JsonObject o = e.getAsJsonObject();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("port", port(e));
            m.put("listen_mode", o.has("listen_mode") ? o.get("listen_mode").getAsString() : null);
            m.put("running", o.has("running") && o.get("running").getAsBoolean());
            m.put("hiccup", owned.contains(port(e)));
            out.add(m);
        }
        return out;
    }

    /** Adds loopback listeners for ports that don't have one yet. */
    public synchronized List<Map<String, Object>> add(Collection<Integer> ports) {
        JsonArray listeners = current();
        TreeSet<Integer> existing = new TreeSet<>();
        for (JsonElement e : listeners) existing.add(port(e));
        TreeSet<Integer> owned = owned();
        boolean changed = false;
        for (int p : ports) {
            if (p < 1 || p > 65535) throw new IllegalArgumentException("bad port " + p);
            if (existing.contains(p)) continue;
            // The same defaults Burp gives a new listener, bound to loopback only.
            JsonObject l = new JsonObject();
            l.addProperty("certificate_mode", "per_host");
            l.add("custom_tls_protocols", new JsonArray());
            l.addProperty("enable_http2", true);
            l.addProperty("listen_mode", "loopback_only");
            l.addProperty("listener_port", p);
            l.addProperty("running", true);
            l.addProperty("use_custom_tls_protocols", false);
            listeners.add(l);
            owned.add(p);
            changed = true;
        }
        if (changed) {
            save(listeners);
            setOwned(owned);
        }
        return list();
    }

    /** Removes the given listeners, or every listener hiccup added when ports is empty. */
    public synchronized List<Map<String, Object>> remove(Collection<Integer> ports) {
        TreeSet<Integer> owned = owned();
        TreeSet<Integer> drop = new TreeSet<>(ports.isEmpty() ? owned : ports);
        JsonArray kept = new JsonArray();
        for (JsonElement e : current()) {
            if (!drop.contains(port(e))) kept.add(e);
        }
        save(kept);
        owned.removeAll(drop);
        setOwned(owned);
        return list();
    }
}
