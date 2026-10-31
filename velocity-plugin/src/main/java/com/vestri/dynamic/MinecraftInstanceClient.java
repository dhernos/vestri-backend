package com.vestri.dynamic;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

final class MinecraftInstanceClient {
    private final URI endpoint;
    private final Map<String, String> templateKeys;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER).build();

    MinecraftInstanceClient(URI backend, Map<String, String> keys) {
        String host = backend.getHost();
        boolean local = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                || "[::1]".equals(host) || "::1".equals(host);
        if (host == null || backend.getUserInfo() != null || backend.getQuery() != null
                || backend.getFragment() != null || !("https".equals(backend.getScheme())
                || ("http".equals(backend.getScheme()) && local))) {
            throw new IllegalArgumentException("backendUrl must use HTTPS (HTTP is allowed only on loopback)");
        }
        endpoint = URI.create(backend.toString().replaceAll("/+$", "") + "/api/minecraft/v1/instances");
        templateKeys = new LinkedHashMap<>();
        keys.forEach((name, key) -> {
            String normalized = normalizeName(name);
            if (normalized.isEmpty() || !key.matches("vmc_[a-fA-F0-9]{64}")
                    || templateKeys.putIfAbsent(normalized, key) != null) {
                throw new IllegalArgumentException("Invalid or duplicate template configuration");
            }
        });
        if (templateKeys.isEmpty()) {
            throw new IllegalArgumentException("Configure at least one template API key");
        }
    }

    static MinecraftInstanceClient load(Path file) throws IOException {
        if (Files.size(file) > 64 * 1024) {
            throw new IOException("Plugin configuration exceeds 64 KiB");
        }
        try {
            JsonObject config = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8)).getAsJsonObject();
            Map<String, String> keys = new LinkedHashMap<>();
            config.getAsJsonObject("templates").entrySet().forEach(entry ->
                    keys.put(entry.getKey(), entry.getValue().getAsString()));
            return new MinecraftInstanceClient(URI.create(config.get("backendUrl").getAsString()), keys);
        } catch (RuntimeException failure) {
            throw new IOException("Invalid plugin configuration; check backendUrl and templates");
        }
    }

    List<String> templates() {
        return List.copyOf(templateKeys.keySet());
    }

    String spawn(String template, UUID requestId) throws IOException, InterruptedException {
        JsonObject body = new JsonObject();
        body.addProperty("requestId", requestId.toString());
        JsonObject result = request(template, "POST", "", body.toString());
        return UUID.fromString(result.get("serverId").getAsString()).toString();
    }

    List<String> instances(String template) throws IOException, InterruptedException {
        JsonArray result = request(template, "GET", "", null).getAsJsonArray("instances");
        List<String> ids = new ArrayList<>();
        for (var entry : result) {
            ids.add(UUID.fromString(entry.getAsJsonObject().get("serverId").getAsString()).toString());
        }
        return ids;
    }

    String delete(String template, UUID selected) throws IOException, InterruptedException {
        List<String> ids = instances(template);
        String id;
        if (selected != null) {
            id = selected.toString();
            if (!ids.contains(id)) {
                throw new IOException("Instance is not owned by this template API key");
            }
        } else {
            if (ids.size() != 1) {
                throw new IOException("Expected one instance, found " + ids.size() + "; use list and --instance <UUID>");
            }
            id = ids.get(0);
        }
        request(template, "DELETE", "/" + id, null);
        return id;
    }

    private JsonObject request(String template, String method, String suffix, String body)
            throws IOException, InterruptedException {
        String key = templateKeys.get(normalizeName(template));
        if (key == null) {
            throw new IOException("Unknown configured template; use vestridynamic templates");
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(endpoint + suffix))
                .timeout(Duration.ofMinutes(6)).header("Authorization", "Bearer " + key)
                .header("Accept", "application/json");
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        HttpResponse<String> response = http.send(builder.method(method, body == null
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Vestri API returned HTTP " + response.statusCode()
                    + "; check key expiry, template limits, and backend logs");
        }
        if ("DELETE".equals(method)) {
            return new JsonObject();
        }
        try {
            return JsonParser.parseString(response.body()).getAsJsonObject();
        } catch (RuntimeException failure) {
            throw new IOException("Invalid Vestri API response");
        }
    }

    private static String normalizeName(String name) {
        return name.trim().toLowerCase(Locale.ROOT);
    }
}