package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"yourapp/internal/auth"
)

func TestMinecraftAPIKeyDigest(t *testing.T) {
	token := "vmc_" + strings.Repeat("ab", 32)
	digest, valid := minecraftAPIKeyDigest(token)
	want := sha256.Sum256([]byte(token))
	if !valid || digest != hex.EncodeToString(want[:]) || strings.Contains(digest, token) {
		t.Fatalf("digest = %q, valid = %v", digest, valid)
	}
	for _, invalid := range []string{"", "worker-key", "Bearer " + token, token + "x", "vmc_" + strings.Repeat("zz", 32), "vmc_" + strings.Repeat("ab", 31)} {
		if _, ok := minecraftAPIKeyDigest(invalid); ok {
			t.Errorf("accepted invalid token %q", invalid)
		}
	}
}

func TestMinecraftAPIRejectsMissingKey(t *testing.T) {
	router := (&Server{}).Router()
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		target := "/api/minecraft/v1/instances/"
		if method == http.MethodDelete {
			target += "some-server"
		}
		request := httptest.NewRequest(method, target, strings.NewReader(`{"requestId":"dummy"}`))
		request.AddCookie(&http.Cookie{Name: "session_id", Value: "dummy-panel-cookie"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want 401", method, response.Code)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Error("API authentication responses must not be cached")
		}
	}
}

func TestMinecraftKeyInstanceOwnership(t *testing.T) {
	key := &auth.MinecraftAPIKey{ID: "key-a", TemplateID: "bedwars"}
	tests := []struct {
		name     string
		key      *auth.MinecraftAPIKey
		instance auth.MinecraftInstance
		want     bool
	}{
		{"own instance", key, auth.MinecraftInstance{KeyID: "key-a", TemplateID: "bedwars"}, true},
		{"another key", key, auth.MinecraftInstance{KeyID: "key-b", TemplateID: "bedwars"}, false},
		{"another template", key, auth.MinecraftInstance{KeyID: "key-a", TemplateID: "speedrun"}, false},
		{"panel instance", key, auth.MinecraftInstance{TemplateID: "bedwars"}, false},
		{"no key", nil, auth.MinecraftInstance{TemplateID: "bedwars"}, false},
		{"empty key", &auth.MinecraftAPIKey{TemplateID: "bedwars"}, auth.MinecraftInstance{TemplateID: "bedwars"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := minecraftKeyCanAccessInstance(test.key, test.instance); got != test.want {
				t.Errorf("access = %v, want %v", got, test.want)
			}
		})
	}
}

func TestMinecraftInstanceWorldProperties(t *testing.T) {
	original := "level-name=old-map\nlevel-seed=12345\nserver-port=25570\nmax-players=16\n"
	for _, random := range []bool{false, true} {
		got := minecraftInstanceProperties(original, random)
		for _, required := range []string{"level-name=world", "server-port=25565", "max-players=16"} {
			if !strings.Contains(got, required+"\n") {
				t.Errorf("properties missing %q: %q", required, got)
			}
		}
		if random && strings.Contains(got, "12345") {
			t.Error("random world inherited a fixed seed")
		}
		if !random && !strings.Contains(got, "level-seed=12345") {
			t.Error("fixed world lost its configured seed")
		}
		if got != minecraftInstanceProperties(got, random) {
			t.Error("property normalization is not idempotent")
		}
	}
}

func TestMinecraftResourcePaths(t *testing.T) {
	for _, kind := range []string{"bases", "worlds", "plugin-packs", "templates"} {
		if !validMinecraftResourceKind(kind) {
			t.Errorf("rejected kind %q", kind)
		}
		resource := &auth.MinecraftResource{ID: "resource-a", NodeID: "node-a", Kind: kind}
		want := ".vestri-minecraft/node-a/" + kind + "/resource-a/data"
		if got := minecraftResourceDataPath(resource); got != want {
			t.Errorf("data path = %q, want %q", got, want)
		}
	}
	for _, invalid := range []string{"", "../worlds", "servers", "keys"} {
		if validMinecraftResourceKind(invalid) {
			t.Errorf("accepted invalid kind %q", invalid)
		}
	}
}

func TestMinecraftDirectoryCopyNeverStartsServer(t *testing.T) {
	type workerCall struct {
		Endpoint string
		Payload  map[string]interface{}
	}
	var calls []workerCall
	workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		calls = append(calls, workerCall{Endpoint: request.URL.Path, Payload: payload})
		response.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(workerServer.Close)
	baseURL, _ := url.Parse(workerServer.URL)
	server := &Server{}
	worker := pluginWorker{server: server, baseURL: baseURL, apiKey: "dummy-worker-key"}
	if err := server.copyMinecraftDirectory(context.Background(), worker, ".vestri-minecraft/node-a/bases/base-a/data", ".vestri-minecraft/node-a/templates/game-a/data"); err != nil {
		t.Fatal(err)
	}
	want := []workerCall{
		{Endpoint: "/fs/mkdir", Payload: map[string]interface{}{"path": ".vestri-minecraft/node-a/templates/game-a", "recursive": true}},
		{Endpoint: "/fs/transfer", Payload: map[string]interface{}{"source": ".vestri-minecraft/node-a/bases/base-a/data", "dest": ".vestri-minecraft/node-a/templates/game-a/data", "operation": "copy"}},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("worker calls = %#v, want %#v", calls, want)
	}
}
