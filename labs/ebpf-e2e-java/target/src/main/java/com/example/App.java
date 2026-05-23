package com.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.text.StringSubstitutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * VulnReach eBPF E2E target — Java variant.
 *
 * Vulnerable packages (intentional — do NOT upgrade):
 *   log4j-core 2.14.1  — CVE-2021-44228 (Log4Shell)
 *   commons-text 1.9   — CVE-2022-42889 (Text4Shell)
 *   snakeyaml 1.30     — CVE-2022-1471  (constructor injection via yaml.load)
 *
 * Routes:
 *   /health      — returns {"status":"ok"}          — never calls logger, sub, or yaml
 *   /log         — calls logger.info()              — exercises log4j
 *   /substitute  — calls StringSubstitutor.replace  — exercises commons-text
 *   /yaml        — calls new Yaml().load()          — exercises snakeyaml
 *   /nolog       — no library calls                 — negative control
 */
public class App {

    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "5002"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/health", exchange -> {
            if (!allowOnly(exchange, "GET")) return;
            respond(exchange, 200, "{\"status\":\"ok\"}");
        });

        server.createContext("/log", exchange -> {
            if (!allowOnly(exchange, "GET")) return;
            logger.info("eBPF E2E test — log4j exercised");
            respond(exchange, 200, "{\"logged\":true}");
        });

        server.createContext("/substitute", exchange -> {
            if (!allowOnly(exchange, "GET")) return;
            String input = queryParam(exchange.getRequestURI(), "input", "Hello ${name}");
            Map<String, String> values = new LinkedHashMap<>();
            values.put("name", "VulnReach");
            String result = StringSubstitutor.replace(input, values);
            respond(exchange, 200, "{\"result\":\"" + jsonEscape(result) + "\"}");
        });

        server.createContext("/yaml", exchange -> {
            if (!allowOnly(exchange, "GET")) return;
            String data = queryParam(exchange.getRequestURI(), "data", "key: value");
            try {
                Yaml yaml = new Yaml();
                Object parsed = yaml.load(data);
                respond(exchange, 200, "{\"parsed\":\"" + jsonEscape(String.valueOf(parsed)) + "\"}");
            } catch (Exception e) {
                // yaml.load() was called (eBPF probe fires); return 200 so schema-fuzzers
                // don't flag valid-string inputs as "rejected"
                respond(exchange, 200, "{\"parsed\":\"error: " + jsonEscape(e.getClass().getSimpleName()) + "\"}");
            }
        });

        server.createContext("/nolog", exchange -> {
            if (!allowOnly(exchange, "GET")) return;
            // All three packages imported but deliberately not called — negative control
            respond(exchange, 200, "{\"called\":false}");
        });

        server.start();
        System.out.println("VulnReach Java E2E target listening on port " + port);
    }

    /** Return false and send 405 if the request method is not in the allowed set. */
    private static boolean allowOnly(HttpExchange exchange, String... methods) throws IOException {
        String m = exchange.getRequestMethod().toUpperCase();
        for (String allowed : methods) {
            if (allowed.equals(m)) return true;
        }
        exchange.getResponseHeaders().set("Allow", String.join(", ", methods));
        exchange.sendResponseHeaders(405, -1);
        exchange.close();
        return false;
    }

    private static String queryParam(URI uri, String key, String defaultValue) {
        String query = uri.getRawQuery();  // avoid double-decoding: getQuery() pre-decodes %25→%, then URLDecoder chokes on bare %
        if (query == null) return defaultValue;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equals(key)) {
                return java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return defaultValue;
    }

    /** Escape a string for embedding in a JSON string value. */
    private static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if      (c == '"')  sb.append("\\\"");
            else if (c == '\\') sb.append("\\\\");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\r') sb.append("\\r");
            else if (c == '\t') sb.append("\\t");
            else if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
            else                sb.append(c);
        }
        return sb.toString();
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
