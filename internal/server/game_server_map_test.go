package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"yourapp/internal/auth"
)

func TestSupportsBlueMap(t *testing.T) {
	for _, tt := range []struct {
		name, game, software, kind string
		want                       bool
	}{
		{"paper", "minecraft", "PAPER", gameServerKindStandalone, true},
		{"purpur subserver", "minecraft", "PURPUR", gameServerKindVelocityBackend, true},
		{"case normalized", "Minecraft", " paper ", gameServerKindStandalone, true},
		{"proxy", "minecraft", "PAPER", gameServerKindVelocity, false},
		{"vanilla", "minecraft", "VANILLA", gameServerKindStandalone, false},
		{"other game", "satisfactory", "PAPER", gameServerKindStandalone, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(gameServerStoredMetadata{Game: tt.game, SoftwareVersion: tt.software, Kind: tt.kind})
			if err != nil {
				t.Fatal(err)
			}
			if got := supportsBlueMap(&auth.GameServer{Metadata: raw}); got != tt.want {
				t.Fatalf("supportsBlueMap=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapRoutesRequireSession(t *testing.T) {
	handler := (&Server{}).Router()
	for _, route := range []string{
		"/api/nodes/node/servers/server/map/status",
		"/api/nodes/node/servers/server/map/view/",
		"/api/nodes/node/servers/server/map/view/maps/world/tiles/0.json",
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s returned %d, want 401", route, rec.Code)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("unauthorized response lost its default frame policy: %q", got)
		}
	}
}

func TestSignedMapProxyPreservesEncodedPathsAndResponse(t *testing.T) {
	const apiKey = "worker-secret"
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := signWorkerRequest(apiKey, r.Header.Get("X-Request-Timestamp"), r.Header.Get("X-Request-Nonce"), r.Method, r.URL.RequestURI())
		if r.Header.Get("X-Request-Signature") != expected {
			t.Error("signature does not match the encoded worker request URI")
		}
		if r.URL.Path != "/worker/stack/bluemap/view/maps/My World/tile.json" {
			t.Errorf("wrong worker path: %s", r.URL)
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("panel session reached worker")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "compressed-tile-bytes")
	}))
	defer worker.Close()
	baseURL, _ := url.Parse(worker.URL + "/worker")
	req := httptest.NewRequest(http.MethodGet, "/api/nodes/node/servers/server/map/view/maps/My%20World/tile.json", nil)
	req.Header.Set("Cookie", "session_id=private")
	rec := httptest.NewRecorder()
	handler := secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(&Server{}).proxySignedWorkerGET(w, r, baseURL, apiKey,
			"/stack/bluemap/view/maps/My%20World/tile.json?root=server&stack=server", false,
			func(resp *http.Response) error {
				setBlueMapResponseHeaders(w.Header(), resp.Header)
				return nil
			})
	}))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "compressed-tile-bytes" {
		t.Fatalf("proxy response changed: %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Fatal("map response headers were not preserved")
	}
	if values := rec.Header().Values("Content-Security-Policy"); len(values) != 1 || values[0] != blueMapContentSecurityPolicy {
		t.Fatalf("map must have exactly one embedding-compatible CSP, got %q", values)
	}
	if values := rec.Header().Values("X-Frame-Options"); len(values) != 1 || values[0] != "SAMEORIGIN" {
		t.Fatalf("map must have exactly one SAMEORIGIN frame policy, got %q", values)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("map lost unrelated security headers: %q", got)
	}
}

func TestBlueMapHeadersDoNotChangeOrdinaryResponses(t *testing.T) {
	rec := httptest.NewRecorder()
	secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("ordinary response frame policy changed: %q", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("ordinary response CSP changed: %q", got)
	}
}
