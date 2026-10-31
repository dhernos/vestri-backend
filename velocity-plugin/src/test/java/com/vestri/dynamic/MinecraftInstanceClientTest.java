package com.vestri.dynamic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MinecraftInstanceClientTest {
    private final String key = "vmc_" + "a".repeat(64);
    private final UUID instance = UUID.randomUUID();
    private final List<String> calls = new ArrayList<>();
    private HttpServer server;
    private MinecraftInstanceClient client;
    private String listed;
    private String spawnBody;
    private int responseStatus;

    @BeforeEach
    void startServer() throws Exception {
        responseStatus = 200;
        listed = "{\"instances\":[{\"serverId\":\"" + instance + "\"}]}";
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/minecraft/v1/instances", exchange -> {
            assertEquals("Bearer " + key, exchange.getRequestHeaders().getFirst("Authorization"));
            calls.add(exchange.getRequestMethod() + " " + exchange.getRequestURI());
            String body = listed;
            if ("POST".equals(exchange.getRequestMethod())) {
                spawnBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                body = "{\"serverId\":\"" + instance + "\",\"state\":\"starting\"}";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            if ("DELETE".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
            } else {
                exchange.sendResponseHeaders(responseStatus, bytes.length);
                exchange.getResponseBody().write(bytes);
            }
            exchange.close();
        });
        server.start();
        client = new MinecraftInstanceClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                Map.of("Bed Wars", key));
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void spawnsWithStableRequestIdAndScopedBearerKey() throws Exception {
        UUID request = UUID.randomUUID();
        assertEquals(instance.toString(), client.spawn("BED WARS", request));
        assertEquals(request.toString(), JsonParser.parseString(spawnBody).getAsJsonObject().get("requestId").getAsString());
        assertEquals(List.of("POST /api/minecraft/v1/instances"), calls);
    }

    @Test
    void deletesOnlySingleOwnedInstance() throws Exception {
        assertEquals(instance.toString(), client.delete("bed wars", null));
        assertEquals(List.of("GET /api/minecraft/v1/instances", "DELETE /api/minecraft/v1/instances/" + instance), calls);
    }

    @Test
    void refusesAmbiguousMissingAndUnownedInstances() {
        listed = "{\"instances\":[]}";
        assertThrows(IOException.class, () -> client.delete("bed wars", null));
        listed = "{\"instances\":[{\"serverId\":\"" + instance + "\"},{\"serverId\":\"" + UUID.randomUUID() + "\"}]}";
        assertThrows(IOException.class, () -> client.delete("bed wars", null));
        assertThrows(IOException.class, () -> client.delete("bed wars", UUID.randomUUID()));
        assertEquals(3, calls.size());
    }

    @Test
    void allowsExplicitOwnedInstanceSelection() throws Exception {
        listed = "{\"instances\":[{\"serverId\":\"" + instance + "\"},{\"serverId\":\"" + UUID.randomUUID() + "\"}]}";
        assertEquals(instance.toString(), client.delete("bed wars", instance));
    }

    @Test
    void rejectsUnknownNamesAndApiFailures() {
        assertThrows(IOException.class, () -> client.spawn("other", UUID.randomUUID()));
        assertEquals(0, calls.size());
        responseStatus = 401;
        assertThrows(IOException.class, () -> client.instances("bed wars"));
    }

    @Test
    void rejectsRemotePlaintextAndCredentialBearingUrls() {
        for (String url : List.of("http://backend.example", "https://user:password@backend.example", "https://backend.example?key=secret")) {
            assertThrows(IllegalArgumentException.class, () -> new MinecraftInstanceClient(URI.create(url), Map.of("test", key)));
        }
    }
}