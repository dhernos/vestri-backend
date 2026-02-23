package server

import (
	"strings"
	"testing"
)

func TestRemoveVelocityTomlServerEntryInline(t *testing.T) {
	content := "servers = { alpha = \"127.0.0.1:25565\", beta = \"127.0.0.1:25566\" }\ntry = [\"alpha\"]\n"
	out := removeVelocityTomlServerEntry(content, "beta")

	entries := parseVelocityTomlServerEntries(out)
	if len(entries) != 1 {
		t.Fatalf("expected one server entry, got %d", len(entries))
	}
	if _, exists := entries["beta"]; exists {
		t.Fatal("expected beta entry to be removed")
	}
	if _, exists := entries["alpha"]; !exists {
		t.Fatal("expected alpha entry to remain")
	}
	if !strings.Contains(out, "[servers]") {
		t.Fatalf("expected [servers] section, got %q", out)
	}
	if !strings.Contains(out, "[forced-hosts]") {
		t.Fatalf("expected [forced-hosts] section, got %q", out)
	}
}

func TestRemoveVelocityTomlTryServerFromList(t *testing.T) {
	content := "[servers]\nalpha = \"127.0.0.1:25565\"\nbeta = \"127.0.0.1:25566\"\ntry = [\"alpha\", \"beta\"]\n"
	out := removeVelocityTomlTryServer(content, "beta")

	values := parseVelocityTomlTryServers(out)
	if len(values) != 1 || values[0] != "alpha" {
		t.Fatalf("expected try list to keep only alpha, got %v", values)
	}
}

func TestRemoveVelocityTomlTryServerToEmptyArray(t *testing.T) {
	content := "servers = {}\ntry = [\"alpha\"]\n"
	out := removeVelocityTomlTryServer(content, "alpha")

	if !strings.Contains(out, "try = []") {
		t.Fatalf("expected try to be empty array, got %q", out)
	}
}

func TestUpsertVelocityTomlTryServerReplacesInvalidFallbackAndClearsForcedHosts(t *testing.T) {
	content := "[servers]\nminecraft-vanilla = \"vestri-minecraft-vanilla:25565\"\ntry = [\"lobby\"]\n\n[forced-hosts]\n\"lobby.example.com\" = [\"lobby\"]\n\"factions.example.com\" = [\"factions\"]\n\"minigames.example.com\" = [\"minigames\"]\n"
	out := upsertVelocityTomlTryServer(content, "minecraft-vanilla")

	values := parseVelocityTomlTryServers(out)
	if len(values) != 1 || values[0] != "minecraft-vanilla" {
		t.Fatalf("expected try list to contain minecraft-vanilla, got %v", values)
	}
	if strings.Contains(out, "lobby.example.com") || strings.Contains(out, "factions.example.com") || strings.Contains(out, "minigames.example.com") {
		t.Fatalf("expected forced-host mappings to be cleared, got %q", out)
	}
	if !strings.Contains(out, "[forced-hosts]") {
		t.Fatalf("expected empty [forced-hosts] section, got %q", out)
	}
}
