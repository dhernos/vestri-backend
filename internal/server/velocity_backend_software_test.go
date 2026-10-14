package server

import (
	"testing"

	"yourapp/internal/auth"
)

func TestSupportsVelocityBackendSoftware(t *testing.T) {
	testCases := map[string]bool{
		"PAPER":    true,
		"purpur":   true,
		"spigot":   true,
		"bukkit":   true,
		"vanilla":  false,
		"fabric":   false,
		"sponge":   false,
		"velocity": false,
		"forge":    false,
		"neoforge": false,
		"":         false,
	}

	for input, expected := range testCases {
		got := supportsVelocityBackendSoftware(input)
		if got != expected {
			t.Fatalf("expected %v for %q, got %v", expected, input, got)
		}
	}
}

func TestValidateVelocityBackendSoftware(t *testing.T) {
	if err := validateVelocityBackendSoftware("paper"); err != nil {
		t.Fatalf("expected paper to be supported, got error: %v", err)
	}

	if err := validateVelocityBackendSoftware("vanilla"); err == nil {
		t.Fatal("expected vanilla to be rejected for velocity backends")
	}
}

func TestVelocityBackendPluginPath(t *testing.T) {
	for _, software := range []string{"PAPER", "PURPUR", "SPIGOT", "BUKKIT"} {
		server := auth.GameServer{
			Slug:     "lobby",
			RootPath: "lobby",
			Metadata: []byte(`{"softwareVersion":"` + software + `"}`),
		}
		got, err := velocityBackendPluginPath(server)
		if err != nil {
			t.Fatalf("expected %s plugin path, got error: %v", software, err)
		}
		if got != "lobby/data/plugins" {
			t.Fatalf("expected lobby/data/plugins for %s, got %q", software, got)
		}
	}

	server := auth.GameServer{
		Slug:     "vanilla",
		RootPath: "vanilla",
		Metadata: []byte(`{"softwareVersion":"VANILLA"}`),
	}
	if _, err := velocityBackendPluginPath(server); err == nil {
		t.Fatal("expected vanilla backend to be rejected for plugin apply")
	}
}
