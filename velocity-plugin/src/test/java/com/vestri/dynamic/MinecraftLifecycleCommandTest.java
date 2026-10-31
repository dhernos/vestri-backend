package com.vestri.dynamic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.velocitypowered.api.command.SimpleCommand.Invocation;
import com.velocitypowered.api.proxy.ConsoleCommandSource;
import com.velocitypowered.api.proxy.Player;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import net.kyori.adventure.text.Component;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MinecraftLifecycleCommandTest {
    @TempDir
    Path directory;

    @Test
    void parsesMultiwordNamesAndStableRetryIds() {
        UUID requestId = UUID.randomUUID();
        var parsed = MinecraftLifecycleCommand.parse(new String[]{"spawn", "Bed", "Wars", "--request-id", requestId.toString()});
        assertEquals("Bed Wars", parsed.template());
        assertEquals(requestId, parsed.requestId());
        assertNotNull(MinecraftLifecycleCommand.parse(new String[]{"spawn", "Bed Wars"}).requestId());
        assertEquals("Bed Wars", MinecraftLifecycleCommand.parse(new String[]{"list", "\"Bed", "Wars\""}).template());
    }

    @Test
    void requiresConfirmationAndValidActionOptions() {
        for (String[] arguments : new String[][]{
                {}, {"delete", "Bed Wars"}, {"spawn", "Bed Wars", "--confirm"},
                {"list", "Bed Wars", "--instance", UUID.randomUUID().toString()},
                {"spawn", "Bed Wars", "--request-id"}, {"delete", "--confirm"},
                {"spawn", "test", "--request-id", "1-1-1-1-1"}}) {
            assertThrows(IllegalArgumentException.class, () -> MinecraftLifecycleCommand.parse(arguments));
        }
        UUID instance = UUID.randomUUID();
        assertEquals(instance, MinecraftLifecycleCommand.parse(new String[]{"delete", "Bed Wars", "--instance", instance.toString(), "--confirm"}).instanceId());
    }

    @Test
    void restrictsLifecycleOperationsToConsoleAndSchedulesOffThread() {
        List<Runnable> scheduled = new ArrayList<>();
        MinecraftLifecycleCommand command = new MinecraftLifecycleCommand(scheduled::add, Path.of("missing-config.json"));
        Invocation player = mock(Invocation.class);
        when(player.source()).thenReturn(mock(Player.class));
        assertFalse(command.hasPermission(player));
        command.execute(player);
        assertEquals(0, scheduled.size());

        Invocation console = mock(Invocation.class);
        when(console.source()).thenReturn(mock(ConsoleCommandSource.class));
        when(console.arguments()).thenReturn(new String[]{"templates"});
        assertTrue(command.hasPermission(console));
        command.execute(console);
        assertEquals(1, scheduled.size());
    }

    @Test
    void executesScheduledCommandWithConfigurationFromDisk() throws Exception {
        Path config = directory.resolve("config.json");
        Files.writeString(config, "{\"backendUrl\":\"https://backend.example\",\"templates\":{\"Bed Wars\":\"vmc_"
                + "a".repeat(64) + "\"}}");
        List<Runnable> scheduled = new ArrayList<>();
        MinecraftLifecycleCommand command = new MinecraftLifecycleCommand(scheduled::add, config);
        Invocation invocation = mock(Invocation.class);
        ConsoleCommandSource console = mock(ConsoleCommandSource.class);
        when(invocation.source()).thenReturn(console);
        when(invocation.arguments()).thenReturn(new String[]{"templates"});

        command.execute(invocation);
        scheduled.get(0).run();

        verify(console).sendMessage(Component.text("Configured templates: bed wars"));
        when(invocation.arguments()).thenReturn(new String[]{"delete", "Bed Wars"});
        command.execute(invocation);
        assertEquals(1, scheduled.size());
    }
}