package com.vestri.dynamic;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.inject.Inject;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.ConsoleCommandSource;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

@Plugin(id = "vestri-dynamic", name = "Vestri Dynamic Servers", version = "1.0.0")
public final class VestriDynamicServers {
    private static final Pattern SERVER_NAME = Pattern.compile("mcgame-[a-f0-9]{32}");
    private final ProxyServer proxy;
    private final Logger logger;

    @Inject
    public VestriDynamicServers(ProxyServer proxy, Logger logger) {
        this.proxy = proxy;
        this.logger = logger;
    }

    @Subscribe
    public void initialize(ProxyInitializeEvent event) {
        proxy.getCommandManager().register(proxy.getCommandManager().metaBuilder("vestridynamic").plugin(this).build(), new SimpleCommand() {
            @Override
            public boolean hasPermission(Invocation invocation) {
                return invocation.source() instanceof ConsoleCommandSource;
            }

            @Override
            public void execute(Invocation invocation) {
                if (!hasPermission(invocation) || invocation.arguments().length != 1 || !"sync".equals(invocation.arguments()[0])) {
                    return;
                }
                try {
                    synchronizeServers(Path.of("vestri-dynamic-servers.json"));
                    invocation.source().sendMessage(Component.text("VESTRI_DYNAMIC_SYNC_OK"));
                } catch (Exception failure) {
                    logger.error("Dynamic server synchronization failed", failure);
                    invocation.source().sendMessage(Component.text("VESTRI_DYNAMIC_SYNC_FAILED"));
                }
            }
        });
        if (Files.exists(Path.of("vestri-dynamic-servers.json"))) {
            try {
                synchronizeServers(Path.of("vestri-dynamic-servers.json"));
            } catch (Exception failure) {
                logger.error("Initial dynamic server synchronization failed", failure);
            }
        }
    }

    synchronized void synchronizeServers(Path manifest) throws IOException {
        if (Files.size(manifest) > 1024 * 1024) {
            throw new IOException("Dynamic server manifest exceeds 1 MiB");
        }
        JsonObject servers = JsonParser.parseString(Files.readString(manifest, StandardCharsets.UTF_8)).getAsJsonObject().getAsJsonObject("servers");
        if (servers == null || servers.size() > 100) {
            throw new IOException("Invalid dynamic server manifest");
        }
        Map<String, ServerInfo> desired = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> entry : servers.entrySet()) {
            String name = entry.getKey();
            JsonObject target = entry.getValue().getAsJsonObject();
            String host = target.get("host").getAsString();
            int port = target.get("port").getAsInt();
            if (!SERVER_NAME.matcher(name).matches() || !("vestri-" + name).equals(host) || port != 25565) {
                throw new IOException("Invalid dynamic server address");
            }
            desired.put(name, new ServerInfo(name, InetSocketAddress.createUnresolved(host, port)));
        }
        for (var registered : proxy.getAllServers()) {
            String name = registered.getServerInfo().getName();
            if (SERVER_NAME.matcher(name).matches() && !desired.containsKey(name)) {
                proxy.unregisterServer(registered.getServerInfo());
            }
        }
        for (ServerInfo target : desired.values()) {
            var registered = proxy.getServer(target.getName());
            if (registered.isPresent() && !registered.get().getServerInfo().equals(target)) {
                proxy.unregisterServer(registered.get().getServerInfo());
                registered = java.util.Optional.empty();
            }
            if (registered.isEmpty()) {
                proxy.registerServer(target);
            }
        }
    }
}