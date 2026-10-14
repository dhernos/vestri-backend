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

func TestVelocityStagingArchiveRelativePath(t *testing.T) {
	testCases := []struct {
		name      string
		entryName string
		want      string
		include   bool
		wantError bool
	}{
		{name: "strips staging folder root", entryName: "vestri-plugin-staging/ExtraPlugin.jar", want: "ExtraPlugin.jar", include: true},
		{name: "strips software folder root", entryName: "paper/ExtraPlugin.jar", want: "ExtraPlugin.jar", include: true},
		{name: "keeps nested software-named folder", entryName: "paper/paper/config.yml", want: "paper/config.yml", include: true},
		{name: "keeps nested config paths", entryName: "paper/config/paper/global.yml", want: "config/paper/global.yml", include: true},
		{name: "keeps nested plugin paths", entryName: "LuckPerms/translations/de.yml", want: "LuckPerms/translations/de.yml", include: true},
		{name: "skips staging directory entry", entryName: "vestri-plugin-staging/", include: false},
		{name: "rejects traversal", entryName: "../outside.jar", wantError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, include, err := velocityStagingArchiveRelativePath(testCase.entryName, "proxy/data/vestri-plugin-staging/paper")
			if (err != nil) != testCase.wantError {
				t.Fatalf("expected error=%v, got %v", testCase.wantError, err)
			}
			if got != testCase.want {
				t.Fatalf("expected relative path %q, got %q", testCase.want, got)
			}
			if include != testCase.include {
				t.Fatalf("expected include=%v, got %v", testCase.include, include)
			}
		})
	}
}

func TestVelocityPluginSoftwareFolder(t *testing.T) {
	testCases := map[string]string{
		"PAPER":   "paper",
		"purpur":  "purpur",
		"Spigot":  "spigot",
		"BUKKIT":  "bukkit",
		"VANILLA": "",
		"unknown": "",
	}
	for software, expected := range testCases {
		if got := velocityPluginSoftwareFolder(software); got != expected {
			t.Errorf("expected %q for %q, got %q", expected, software, got)
		}
	}
}

func TestResolveVelocityGroupStagingPath(t *testing.T) {
	testCases := []struct {
		name              string
		path              string
		allowSoftwareRoot bool
		want              string
		wantError         bool
	}{
		{name: "allows listing root", path: "", allowSoftwareRoot: true, want: "proxy/data/vestri-plugin-staging"},
		{name: "allows listing software folder", path: "paper", allowSoftwareRoot: true, want: "proxy/data/vestri-plugin-staging/paper"},
		{name: "allows nested changes", path: "paper/config/plugin.yml", want: "proxy/data/vestri-plugin-staging/paper/config/plugin.yml"},
		{name: "rejects root changes", path: "", wantError: true},
		{name: "rejects software root changes", path: "paper", wantError: true},
		{name: "rejects unsupported software folder", path: "vanilla/plugin.jar", wantError: true},
		{name: "rejects path escape", path: "paper/../../outside.jar", wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, _, err := resolveVelocityGroupStagingPath("proxy", testCase.path, testCase.allowSoftwareRoot)
			if (err != nil) != testCase.wantError {
				t.Fatalf("expected error=%v, got %v", testCase.wantError, err)
			}
			if err == nil && got != testCase.want {
				t.Fatalf("expected path %q, got %q", testCase.want, got)
			}
		})
	}
}
