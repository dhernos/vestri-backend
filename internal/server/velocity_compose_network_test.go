package server

import (
	"context"
	"strings"
	"testing"
)

func TestBuildVelocityStandaloneComposeUsesManagedNetwork(t *testing.T) {
	template := &gameServerTemplate{
		ID:              vanillaTemplateID,
		Game:            "minecraft",
		TemplateVersion: "1",
		ComposeInline:   "services:\n  minecraft:\n    image: test\n",
	}

	out, err := buildVelocityStandaloneCompose(context.Background(), template, map[string]string{
		"VELOCITY_NETWORK": "vestri-velocity-test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "networks:\n  velocity:") {
		t.Fatalf("expected velocity network block, got:\n%s", out)
	}
	if strings.Contains(out, "external: true") {
		t.Fatalf("standalone compose must not declare external network:\n%s", out)
	}
	if !strings.Contains(out, `name: "vestri-velocity-test"`) {
		t.Fatalf("expected named velocity network, got:\n%s", out)
	}
	if !strings.Contains(out, `TYPE: "VELOCITY"`) {
		t.Fatalf("expected velocity TYPE environment, got:\n%s", out)
	}
	if !strings.Contains(out, `- "./data:/server"`) {
		t.Fatalf("expected data bind mount, got:\n%s", out)
	}
}

func TestBuildVelocityBackendComposeUsesExternalNetwork(t *testing.T) {
	template := &gameServerTemplate{
		ID:              vanillaTemplateID,
		Game:            "minecraft",
		TemplateVersion: "1",
		ComposeInline:   "services:\n  minecraft:\n    image: test\n",
	}

	out, err := buildVelocityBackendCompose(context.Background(), template, map[string]string{
		"VELOCITY_NETWORK": "vestri-velocity-test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "external: true") {
		t.Fatalf("backend compose must declare external network:\n%s", out)
	}
	if !strings.Contains(out, `name: "vestri-velocity-test"`) {
		t.Fatalf("expected external velocity network name, got:\n%s", out)
	}
}

func TestEnsureComposeNamedNetworkReplacesExternalBlock(t *testing.T) {
	in := "services:\n  minecraft:\n    image: test\nnetworks:\n  velocity:\n    external: true\n    name: \"old\"\n"
	out := ensureComposeNamedNetwork(in, "velocity", "new-name")

	if strings.Contains(out, "external: true") {
		t.Fatalf("expected external flag to be removed, got:\n%s", out)
	}
	if !strings.Contains(out, `name: "new-name"`) {
		t.Fatalf("expected updated network name, got:\n%s", out)
	}
}

func TestEnsureComposeServiceEnvironmentValueInsertsAndUpdates(t *testing.T) {
	base := "services:\n  minecraft:\n    image: test\n"
	withInsert := ensureComposeServiceEnvironmentValue(base, "minecraft", "TYPE", "VELOCITY")
	if !strings.Contains(withInsert, `TYPE: "VELOCITY"`) {
		t.Fatalf("expected TYPE env after insert, got:\n%s", withInsert)
	}

	updated := ensureComposeServiceEnvironmentValue(withInsert, "minecraft", "TYPE", "VELOCITY-NEW")
	if !strings.Contains(updated, `TYPE: "VELOCITY-NEW"`) {
		t.Fatalf("expected TYPE env update, got:\n%s", updated)
	}
	if strings.Contains(updated, `TYPE: "VELOCITY"`) {
		t.Fatalf("expected old TYPE value to be replaced, got:\n%s", updated)
	}
}

func TestEnsureComposeServiceBindVolumeInsertsOnce(t *testing.T) {
	base := "services:\n  minecraft:\n    image: test\n"
	withInsert := ensureComposeServiceBindVolume(base, "minecraft", "./data:/server")
	if !strings.Contains(withInsert, `- "./data:/server"`) {
		t.Fatalf("expected bind mount after insert, got:\n%s", withInsert)
	}

	withSame := ensureComposeServiceBindVolume(withInsert, "minecraft", "./data:/server")
	if strings.Count(withSame, `- "./data:/server"`) != 1 {
		t.Fatalf("expected exactly one bind mount entry, got:\n%s", withSame)
	}
}
