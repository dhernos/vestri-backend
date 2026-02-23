package server

import (
	"strings"
	"testing"
)

func TestResolveMinecraftComposeTemplateUsesVanillaForVelocity(t *testing.T) {
	template, err := gameServerTemplateByID(velocityTemplateID)
	if err != nil {
		t.Fatalf("failed to load velocity template: %v", err)
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
