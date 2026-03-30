package server

import "testing"

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
