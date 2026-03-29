package server

import (
	"context"
	"strings"
	"testing"
)

func TestResolveMinecraftComposeTemplateUsesVanillaForVelocity(t *testing.T) {
	templates, err := gameServerTemplates()
	if err != nil {
		t.Fatalf("failed to load templates: %v", err)
	}
	var template *gameServerTemplate
	for i := range templates {
		if strings.EqualFold(strings.TrimSpace(templates[i].Kind), gameServerKindVelocity) {
			candidate := templates[i]
			template = &candidate
			break
		}
	}
	if template == nil {
		t.Fatal("velocity template is missing")
	}

	resolved, err := resolveMinecraftComposeTemplate(template)
	if err != nil {
		t.Fatalf("failed to resolve compose template: %v", err)
	}
	if resolved == nil {
		t.Fatal("resolved compose template is nil")
	}
	if !strings.EqualFold(strings.TrimSpace(resolved.ID), vanillaTemplateID) {
		t.Fatalf("expected compose template %q, got %q", vanillaTemplateID, resolved.ID)
	}
}

func TestMinecraftServerJarFileNameForArtifactPreservesArtifactName(t *testing.T) {
	artifact := &minecraftServerArtifact{FileName: "velocity-3.4.0.jar"}
	name, err := minecraftServerJarFileNameForArtifact(artifact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "velocity-3.4.0.jar" {
		t.Fatalf("expected velocity-3.4.0.jar, got %q", name)
	}
}

func TestMinecraftServerJarFileNameForArtifactRejectsEmptyName(t *testing.T) {
	artifact := &minecraftServerArtifact{FileName: "   "}
	_, err := minecraftServerJarFileNameForArtifact(artifact)
	if err == nil {
		t.Fatal("expected error for empty artifact file name")
	}
}

func TestEnsureMinecraftRequiredConfigFilesAddsEULAWhenMissing(t *testing.T) {
	configFiles := []gameServerTemplateConfigFile{
		{
			ID:             "server-properties",
			Title:          "server.properties",
			Path:           "data/server.properties",
			Format:         "properties",
			DefaultContent: "motd=test\n",
		},
	}

	out := ensureMinecraftRequiredConfigFiles(configFiles)
	if len(out) != 2 {
		t.Fatalf("expected 2 config files, got %d", len(out))
	}

	last := out[len(out)-1]
	if !strings.EqualFold(strings.TrimSpace(last.Path), minecraftEULAFilePath) {
		t.Fatalf("expected last config path %q, got %q", minecraftEULAFilePath, last.Path)
	}
	if strings.TrimSpace(last.DefaultContent) != "eula=true" {
		t.Fatalf("expected eula default content, got %q", last.DefaultContent)
	}
}

func TestEnsureMinecraftRequiredConfigFilesDoesNotDuplicateEULA(t *testing.T) {
	configFiles := []gameServerTemplateConfigFile{
		{
			ID:             minecraftEULAConfigID,
			Title:          minecraftEULAFileTitle,
			Path:           minecraftEULAFilePath,
			Format:         "text",
			DefaultContent: minecraftEULAContent,
		},
	}

	out := ensureMinecraftRequiredConfigFiles(configFiles)
	if len(out) != 1 {
		t.Fatalf("expected no duplicate eula file, got %d entries", len(out))
	}
}

func TestNormalizeMinecraftSoftwareSupportsExtendedSoftware(t *testing.T) {
	testCases := map[string]string{
		"vanilla":  minecraftSoftwareVanilla,
		"paper":    minecraftSoftwarePaper,
		"purpur":   minecraftSoftwarePurpur,
		"spigot":   minecraftSoftwareSpigot,
		"bukkit":   minecraftSoftwareBukkit,
		"fabric":   minecraftSoftwareFabric,
		"forge":    minecraftSoftwareForge,
		"neoforge": minecraftSoftwareNeoForge,
		"sponge":   minecraftSoftwareSponge,
		"velocity": minecraftSoftwareVelocity,
	}

	for input, expected := range testCases {
		got := normalizeMinecraftSoftware(input)
		if got != expected {
			t.Fatalf("expected %q for %q, got %q", expected, input, got)
		}
	}
}

func TestExtractForgeGameVersion(t *testing.T) {
	testCases := map[string]string{
		"1.21.4-54.1.6": "1.21.4",
		"26.1-62.0.8":   "26.1",
		"invalid":       "",
		"":              "",
	}

	for input, expected := range testCases {
		got := extractForgeGameVersion(input)
		if got != expected {
			t.Fatalf("expected %q for %q, got %q", expected, input, got)
		}
	}
}

func TestExtractNeoForgeGameVersion(t *testing.T) {
	testCases := map[string]string{
		"21.1.222":                  "21.1",
		"26.1.0.11-beta":            "26.1",
		"26.1.0.0-alpha.3+snapshot": "26.1",
		"invalid":                   "",
		"":                          "",
	}

	for input, expected := range testCases {
		got := extractNeoForgeGameVersion(input)
		if got != expected {
			t.Fatalf("expected %q for %q, got %q", expected, input, got)
		}
	}
}

func TestLatestBuildVersionForMinecraftGameSupportsVersionAliases(t *testing.T) {
	forgeVersions := []string{
		"1.21.4-54.0.9",
		"1.21.4-54.1.6",
		"1.21.3-53.1.0",
	}
	gotForge := latestBuildVersionForMinecraftGame(forgeVersions, "1.21.4", extractForgeGameVersion)
	if gotForge != "1.21.4-54.1.6" {
		t.Fatalf("expected latest forge build 1.21.4-54.1.6, got %q", gotForge)
	}

	neoForgeVersions := []string{
		"21.4.157",
		"21.4.156",
		"21.1.222",
	}
	gotNeoForge := latestBuildVersionForMinecraftGame(neoForgeVersions, "1.21.4", extractNeoForgeGameVersion)
	if gotNeoForge != "21.4.157" {
		t.Fatalf("expected latest neoforge build 21.4.157, got %q", gotNeoForge)
	}
}

func TestSelectPreferredSpongeJarAssetPrefersUniversal(t *testing.T) {
	assets := []spongeVersionAsset{
		{
			Classifier: "",
			Extension:  "jar",
			DownloadURL: "https://repo.spongepowered.org/repository/maven-releases/org/spongepowered/" +
				"spongevanilla/1.21.4-14.0.1-RC2560/spongevanilla-1.21.4-14.0.1-RC2560.jar",
		},
		{
			Classifier: "universal",
			Extension:  "jar",
			DownloadURL: "https://repo.spongepowered.org/repository/maven-releases/org/spongepowered/" +
				"spongevanilla/1.21.4-14.0.1-RC2560/spongevanilla-1.21.4-14.0.1-RC2560-universal.jar",
		},
	}

	downloadURL, fileName := selectPreferredSpongeJarAsset(assets, "1.21.4-14.0.1-RC2560")
	if downloadURL == "" {
		t.Fatal("expected download url")
	}
	if !strings.HasSuffix(downloadURL, "-universal.jar") {
		t.Fatalf("expected universal jar url, got %q", downloadURL)
	}
	if fileName != "spongevanilla-1.21.4-14.0.1-RC2560-universal.jar" {
		t.Fatalf("unexpected file name %q", fileName)
	}
}

func TestCompareLooseVersionStringsPrefersReleaseOverPrerelease(t *testing.T) {
	if compareLooseVersionStrings("21.11.42", "21.11.42-beta") <= 0 {
		t.Fatalf("expected release to be newer than prerelease")
	}
}

func TestResolveSpigotServerArtifactUsesExpectedDownloadURL(t *testing.T) {
	artifact, err := resolveSpigotServerArtifact(context.Background(), "1.21.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if artifact == nil {
		t.Fatal("expected artifact")
	}
	if artifact.Software != minecraftSoftwareSpigot {
		t.Fatalf("expected software %q, got %q", minecraftSoftwareSpigot, artifact.Software)
	}
	if artifact.DownloadURL != "https://download.getbukkit.org/spigot/spigot-1.21.4.jar" {
		t.Fatalf("expected getbukkit spigot download url, got %q", artifact.DownloadURL)
	}
}

func TestResolveBukkitServerArtifactUsesExpectedDownloadURL(t *testing.T) {
	artifact, err := resolveBukkitServerArtifact(context.Background(), "1.21.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if artifact == nil {
		t.Fatal("expected artifact")
	}
	if artifact.Software != minecraftSoftwareBukkit {
		t.Fatalf("expected software %q, got %q", minecraftSoftwareBukkit, artifact.Software)
	}
	if artifact.DownloadURL != "https://download.getbukkit.org/craftbukkit/craftbukkit-1.21.4.jar" {
		t.Fatalf("expected getbukkit bukkit download url, got %q", artifact.DownloadURL)
	}
}
