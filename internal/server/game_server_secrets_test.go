package server

import (
	"strings"
	"testing"

	"yourapp/internal/auth"
)

func TestGameServerSecretsComposeRef(t *testing.T) {
	server := &auth.GameServer{ID: "abc", ComposePath: "my-server/docker-compose.yml"}
	if got := gameServerSecretsComposeRef(server); got != "../.vestri-secrets/abc.env" {
		t.Fatalf("compose ref = %q", got)
	}
}

func TestValidateGameServerSecret(t *testing.T) {
	if err := validateGameServerSecret("TOKEN", "a1b2$c3"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, test := range []struct{ key, value string }{
		{"1TOKEN", "x"},
		{"TO-KEN", "x"},
		{"TOKEN", ""},
		{"TOKEN", "it's"},
		{"TOKEN", "a\nB=c"},
	} {
		if validateGameServerSecret(test.key, test.value) == nil {
			t.Errorf("expected %q=%q to be rejected", test.key, test.value)
		}
	}
}

func TestGameServerSecretLines(t *testing.T) {
	content := "USERNAME='me'\nTOKEN='abc'\n"
	if keys := parseGameServerSecretKeys(content); strings.Join(keys, ",") != "USERNAME,TOKEN" {
		t.Fatalf("keys = %v", keys)
	}
	updated, removed := removeGameServerSecretLine(content, "USERNAME")
	if !removed || updated != "TOKEN='abc'\n" {
		t.Fatalf("remove = %q, %v", updated, removed)
	}
	if _, removed := removeGameServerSecretLine(updated, "MISSING"); removed {
		t.Fatal("unexpected removal")
	}
}

func TestEnsureComposeAllServicesEnvFile(t *testing.T) {
	base := "services:\n  factorio:\n    image: test\n    restart: unless-stopped\n"
	ref := "../.vestri-secrets/abc.env"
	out := ensureComposeAllServicesEnvFile(base, ref)
	want := "services:\n  factorio:\n    image: test\n    restart: unless-stopped\n    env_file:\n      - \"../.vestri-secrets/abc.env\"\n"
	if out != want {
		t.Fatalf("unexpected compose:\n%s", out)
	}
	if again := ensureComposeAllServicesEnvFile(out, ref); again != out {
		t.Fatalf("expected idempotent update, got:\n%s", again)
	}

	inline := "services:\n  app:\n    image: test\n    env_file: .env\n    restart: always\n"
	out = ensureComposeAllServicesEnvFile(inline, ref)
	if !strings.Contains(out, "    env_file:\n      - .env\n      - \"../.vestri-secrets/abc.env\"\n    restart: always") {
		t.Fatalf("unexpected inline conversion:\n%s", out)
	}
}
