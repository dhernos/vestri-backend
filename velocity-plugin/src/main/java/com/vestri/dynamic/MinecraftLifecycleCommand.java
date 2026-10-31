package com.vestri.dynamic;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.ConsoleCommandSource;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;
import net.kyori.adventure.text.Component;

final class MinecraftLifecycleCommand implements SimpleCommand {
    private static final String USAGE = "vestridynamic templates | list <template name> | "
            + "spawn <template name> [--request-id UUID] | delete <template name> [--instance UUID] --confirm | sync";
    private final Consumer<Runnable> schedule;
    private final Path configuration;

    MinecraftLifecycleCommand(Consumer<Runnable> schedule, Path configuration) {
        this.schedule = schedule;
        this.configuration = configuration;
    }

    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source() instanceof ConsoleCommandSource;
    }

    @Override
    public void execute(Invocation invocation) {
        if (!hasPermission(invocation)) {
            return;
        }
        LifecycleRequest command;
        try {
            command = parse(invocation.arguments());
        } catch (IllegalArgumentException failure) {
            invocation.source().sendMessage(Component.text(USAGE));
            return;
        }
        if (command.action().equals("spawn")) {
            invocation.source().sendMessage(Component.text("Spawning " + command.template()
                    + "; requestId=" + command.requestId() + ". Retry with this ID if the request fails."));
        }
        schedule.accept(() -> {
            try {
                MinecraftInstanceClient client = MinecraftInstanceClient.load(configuration);
                String result = switch (command.action()) {
                    case "templates" -> "Configured templates: " + String.join(", ", client.templates());
                    case "list" -> {
                        List<String> ids = client.instances(command.template());
                        yield "Instances for " + command.template() + ": " + (ids.isEmpty() ? "none" : String.join(", ", ids));
                    }
                    case "spawn" -> "Instance starting: " + client.spawn(command.template(), command.requestId());
                    case "delete" -> "Instance deleted: " + client.delete(command.template(), command.instanceId());
                    default -> throw new IllegalArgumentException("Unknown command");
                };
                invocation.source().sendMessage(Component.text(result));
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                invocation.source().sendMessage(Component.text("Vestri request interrupted; check instance state before retrying."));
            } catch (IOException failure) {
                invocation.source().sendMessage(Component.text("Vestri command failed: " + failure.getMessage()));
            } catch (RuntimeException failure) {
                invocation.source().sendMessage(Component.text("Vestri command failed: invalid configuration or API response."));
            }
        });
    }

    static LifecycleRequest parse(String[] arguments) {
        return LifecycleRequest.parse(arguments);
    }
}