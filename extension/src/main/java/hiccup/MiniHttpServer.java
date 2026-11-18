package hiccup;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A minimal HTTP/1.1 server on plain sockets. Burp's bundled JRE omits the
 * jdk.httpserver module, so com.sun.net.httpserver is not available to
 * extensions. One request per connection (responses carry Connection: close),
 * Content-Length bodies only, loopback only.
 */
final class MiniHttpServer {
    static final int MAX_HEAD = 64 * 1024;
    static final int MAX_BODY = 64 * 1024 * 1024;
    static final int READ_TIMEOUT_MS = 30_000;

    /** A parsed request. Header names are lower-cased; the last value wins. */
    record Request(String method, URI uri, Map<String, String> headers, byte[] body) {
        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }
    }

    record Response(int status, String contentType, byte[] body) {
    }

    interface Handler {
        Response handle(Request request);
    }

    /** A request that can't be parsed; answered with its status and closed. */
    static final class BadRequest extends IOException {
        final int status;

        BadRequest(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    private final Handler handler;
    private ServerSocket socket;
    private ExecutorService pool;
    private Thread acceptor;

    MiniHttpServer(Handler handler) {
        this.handler = handler;
    }

    void start(int port) throws IOException {
        socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 50);
        pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "hiccup-api");
            t.setDaemon(true);
            return t;
        });
        acceptor = new Thread(this::acceptLoop, "hiccup-api-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    void stop() {
        try {
            if (socket != null) socket.close();
        } catch (IOException ignored) {
        }
        if (pool != null) pool.shutdownNow();
    }

    private void acceptLoop() {
        while (!socket.isClosed()) {
            try {
                Socket conn = socket.accept();
                pool.execute(() -> serve(conn));
            } catch (SocketException closed) {
                return; // stop() closed the socket
            } catch (IOException e) {
                // accept failed for one connection; keep serving
            }
        }
    }

    private void serve(Socket conn) {
        try (conn) {
            conn.setSoTimeout(READ_TIMEOUT_MS);
            InputStream in = new BufferedInputStream(conn.getInputStream());
            Response resp;
            try {
                resp = handler.handle(read(in));
            } catch (BadRequest e) {
                resp = new Response(e.status, "text/plain; charset=utf-8", (e.getMessage() + "\n").getBytes(StandardCharsets.UTF_8));
            }
            write(conn.getOutputStream(), resp);
        } catch (IOException ignored) {
            // client went away or timed out
        }
    }

    static Request read(InputStream in) throws IOException {
        String head = readHead(in);
        String[] lines = head.split("\r\n");
        String[] start = lines[0].split(" ");
        if (start.length != 3 || !start[2].startsWith("HTTP/1.")) throw new BadRequest(400, "bad request line");
        URI uri;
        try {
            uri = new URI(start[1]);
        } catch (URISyntaxException e) {
            throw new BadRequest(400, "bad request target");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon <= 0) throw new BadRequest(400, "bad header line");
            headers.put(lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT), lines[i].substring(colon + 1).trim());
        }
        if (headers.containsKey("transfer-encoding")) throw new BadRequest(411, "send a Content-Length body");
        int length = 0;
        if (headers.containsKey("content-length")) {
            try {
                length = Integer.parseInt(headers.get("content-length"));
            } catch (NumberFormatException e) {
                throw new BadRequest(400, "bad Content-Length");
            }
            if (length < 0) throw new BadRequest(400, "bad Content-Length");
            if (length > MAX_BODY) throw new BadRequest(413, "body too large");
        }
        byte[] body = in.readNBytes(length);
        if (body.length != length) throw new BadRequest(400, "body shorter than Content-Length");
        return new Request(start[0], uri, headers, body);
    }

    /** Reads up to and including the blank line that ends the head. */
    private static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int last4 = 0; // the last four bytes read, oldest in the high byte
        while (last4 != 0x0d0a0d0a) { // "\r\n\r\n"
            int b = in.read();
            if (b < 0) throw new BadRequest(400, "connection closed mid-request");
            buf.write(b);
            if (buf.size() > MAX_HEAD) throw new BadRequest(431, "request head too large");
            last4 = (last4 << 8) | b;
        }
        String head = buf.toString(StandardCharsets.ISO_8859_1);
        return head.substring(0, head.length() - 4);
    }

    static void write(OutputStream out, Response r) throws IOException {
        String head = "HTTP/1.1 " + r.status() + " " + reason(r.status()) + "\r\n"
                + "Content-Type: " + r.contentType() + "\r\n"
                + "Content-Length: " + r.body().length + "\r\n"
                + "Connection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.ISO_8859_1));
        out.write(r.body());
        out.flush();
    }

    private static String reason(int status) {
        return switch (status) {
            case 200 -> "OK";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 411 -> "Length Required";
            case 413 -> "Content Too Large";
            case 431 -> "Request Header Fields Too Large";
            case 501 -> "Not Implemented";
            default -> status >= 500 ? "Internal Server Error" : "Error";
        };
    }
}
