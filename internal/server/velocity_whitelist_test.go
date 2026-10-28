package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"yourapp/internal/auth"
)

type minecraftProfileTestTransport func(*http.Request) (*http.Response, error)

func (transport minecraftProfileTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

func TestResolveMinecraftWhitelistProfile(t *testing.T) {
	originalClient := minecraftProfileClient
	t.Cleanup(func() { minecraftProfileClient = originalClient })
	for _, test := range []struct {
		name     string
		username string
		status   int
		body     string
		wantErr  bool
	}{
		{name: "online UUID and canonical name", username: "notch", status: http.StatusOK, body: `{"id":"069a79f444e94726a5befca90e38aaf5","name":"Notch"}`},
		{name: "unknown player", username: "Notch", status: http.StatusNotFound, wantErr: true},
		{name: "no profile", username: "Notch", status: http.StatusNoContent, wantErr: true},
		{name: "rate limited", username: "Notch", status: http.StatusTooManyRequests, wantErr: true},
		{name: "invalid JSON", username: "Notch", status: http.StatusOK, body: `{`, wantErr: true},
		{name: "missing UUID", username: "Notch", status: http.StatusOK, body: `{"name":"Notch"}`, wantErr: true},
		{name: "wrong player", username: "Notch", status: http.StatusOK, body: `{"id":"069a79f444e94726a5befca90e38aaf5","name":"Other"}`, wantErr: true},
		{name: "reject URL input", username: "../profiles", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			minecraftProfileClient = &http.Client{Transport: minecraftProfileTestTransport(func(req *http.Request) (*http.Response, error) {
				called = true
				if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "api.mojang.com" || req.URL.Path != "/users/profiles/minecraft/"+test.username {
					t.Fatalf("unexpected profile request: %s %s", req.Method, req.URL)
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})}
			entry, err := resolveMinecraftWhitelistProfile(context.Background(), test.username)
			if (err != nil) != test.wantErr {
				t.Fatalf("unexpected result: %v, %v", entry, err)
			}
			if !test.wantErr && (entry.Name != "Notch" || entry.UUID != "069a79f4-44e9-4726-a5be-fca90e38aaf5") {
				t.Fatalf("expected official online profile, got %v", entry)
			}
			if !minecraftUsernamePattern.MatchString(test.username) && called {
				t.Fatal("invalid username must not cause an external request")
			}
		})
	}
}

func TestMinecraftProfileUUID(t *testing.T) {
	got, err := minecraftProfileUUID("069A79F444E94726A5BEFCA90E38AAF5")
	if err != nil || got != "069a79f4-44e9-4726-a5be-fca90e38aaf5" {
		t.Fatalf("unexpected UUID: %q, %v", got, err)
	}
	for _, value := range []string{"", "offline-player", "zz9a79f444e94726a5befca90e38aaf5"} {
		if _, err := minecraftProfileUUID(value); err == nil {
			t.Fatalf("accepted invalid UUID %q", value)
		}
	}
}

func TestVelocityWhitelistMainServerRequiresConfiguredChild(t *testing.T) {
	servers := []auth.GameServer{
		{Name: "Other", Slug: "other", Metadata: []byte(`{"parentServerId":"proxy"}`)},
		{Name: "Main", Slug: "main", Metadata: []byte(`{"parentServerId":"different-proxy"}`)},
		{Name: "Lobby", Slug: "main", Metadata: []byte(`{"parentServerId":"proxy"}`)},
	}
	config := "[servers]\nmain = \"main:25565\"\nother = \"other:25565\"\ntry = [\"main\", \"other\"]\n"
	got := velocityWhitelistMainServer("proxy", config, servers)
	if got == nil || got != &servers[2] {
		t.Fatalf("expected configured child, got %v", got)
	}
	if velocityWhitelistMainServer("proxy", config, servers[:2]) != nil {
		t.Fatal("must not fall back to another child or another proxy's server")
	}
	if velocityWhitelistMainServer("proxy", "", servers) != nil {
		t.Fatal("must require a configured main server")
	}
}

func TestParseMinecraftWhitelist(t *testing.T) {
	if entries, err := parseMinecraftWhitelist("", true); err != nil || entries == nil || len(entries) != 0 {
		t.Fatalf("expected empty missing whitelist, got %v, %v", entries, err)
	}
	for _, value := range []string{"", "null", "{}", "[", `[{"uuid":"invalid","name":"Notch"}]`} {
		if _, err := parseMinecraftWhitelist(value, false); err == nil {
			t.Fatalf("accepted invalid existing whitelist %q", value)
		}
	}
	if _, err := parseMinecraftWhitelist(`[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch"}]`, false); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateMinecraftWhitelist(t *testing.T) {
	entry := minecraftWhitelistEntry{UUID: "069a79f4-44e9-4726-a5be-fca90e38aaf5", Name: "Notch"}
	other := minecraftWhitelistEntry{UUID: "853c80ef-3c37-49fd-aa49-938b674adae6", Name: "jeb_"}
	entries := []minecraftWhitelistEntry{other, {UUID: entry.UUID, Name: "OldName"}}
	updated := updateMinecraftWhitelist(entries, entry, false)
	if len(updated) != 2 || updated[0] != other || updated[1] != entry {
		t.Fatalf("must preserve other players and update duplicate UUID: %v", updated)
	}
	updated = updateMinecraftWhitelist(updated, entry, true)
	if len(updated) != 1 || updated[0] != other {
		t.Fatalf("must remove only requested UUID: %v", updated)
	}
	if result := updateMinecraftWhitelist([]minecraftWhitelistEntry{entry}, entry, true); result == nil || len(result) != 0 {
		t.Fatalf("empty whitelist must encode as array, got %v", result)
	}
	wrongUUID := minecraftWhitelistEntry{UUID: "00000000-0000-0000-0000-000000000000", Name: "notch"}
	corrected := updateMinecraftWhitelist([]minecraftWhitelistEntry{other, wrongUUID}, entry, false)
	if len(corrected) != 2 || corrected[0] != other || corrected[1] != entry {
		t.Fatalf("must replace an existing offline UUID for the same username: %v", corrected)
	}
}
