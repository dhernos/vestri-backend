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

func TestVelocityBackendWhitelistPolicy(t *testing.T) {
	testCases := []struct {
		name        string
		hasBackends bool
		want        string
	}{
		{name: "first backend is the entry point", want: "motd=Lobby\nwhite-list=true\n"},
		{name: "later backends do not enforce whitelist", hasBackends: true, want: "motd=Lobby\nwhite-list=false\n"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			value := "false"
			if velocityBackendWhitelistEnabled(testCase.hasBackends) {
				value = "true"
			}
			got := upsertJavaPropertiesValue("motd=Lobby\nwhite-list=true\n", "white-list", value)
			if got != testCase.want {
				t.Fatalf("server.properties = %q, want %q", got, testCase.want)
			}
		})
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
