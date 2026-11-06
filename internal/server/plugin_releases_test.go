package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type pluginRoundTripper func(*http.Request) (*http.Response, error)

func (transport pluginRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

func TestParsePluginSource(t *testing.T) {
	for _, raw := range []string{"https://modrinth.com/plugin/luckperms", "https://hangar.papermc.io/ViaVersion/ViaVersion/versions", "https://modrinth.com/plugin/luckperms/version/test", "https://hangarcdn.papermc.io/plugins/ViaVersion/ViaVersion/versions/5.12.2/PAPER/ViaVersion-5.12.2.jar"} {
		if _, err := parsePluginSource(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://modrinth.com/plugin/test", "https://localhost/plugin/test", "https://modrinth.com:8443/plugin/test", "https://modrinth.com/mod/test", "https://hangar.papermc.io/../test", "https://modrinth.com/plugin/a%2Fb", "https://hangarcdn.papermc.io/plugins/ViaVersion/ViaVersion/versions/5.12.2/WATERFALL/ViaVersion.jar", "https://hangarcdn.papermc.io/plugins/ViaVersion/ViaVersion/versions/5.12.2/PAPER/../ViaVersion.jar", "https://hangarcdn.papermc.io/plugins/ViaVersion/ViaVersion/versions/5.12.2/PAPER/ViaVersion.jar?download=1"} {
		if _, err := parsePluginSource(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestPinnedHangarPluginRelease(t *testing.T) {
	original := pluginHTTPClient
	t.Cleanup(func() { pluginHTTPClient = original })
	source, err := parsePluginSource("https://hangarcdn.papermc.io/plugins/ViaVersion/ViaVersion/versions/5.12.2/PAPER/ViaVersion-5.12.2.jar")
	if err != nil {
		t.Fatal(err)
	}
	pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "hangar.papermc.io" || req.URL.Path != "/api/v1/projects/ViaVersion/ViaVersion/versions/5.12.2" {
			t.Fatalf("unexpected Hangar metadata request: %s", req.URL)
		}
		body := `{"name":"5.12.2","downloads":{"PAPER":{"fileInfo":{"name":"ViaVersion-5.12.2.jar","sha256Hash":"verified-hash"},"downloadUrl":"https://hangarcdn.papermc.io/plugins/ViaVersion/ViaVersion/versions/5.12.2/PAPER/ViaVersion-5.12.2.jar"}}}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	release, targetRefs, err := latestPluginRelease(context.Background(), source, []pluginCompatibilityTarget{
		{ServerRef: "paper-1", Platform: "PAPER", Version: "1.8"},
		{ServerRef: "proxy", Platform: "VELOCITY", Version: "3.4"},
	})
	want := pluginRelease{Version: "5.12.2", Filename: "ViaVersion-5.12.2.jar", URL: source.DownloadURL, SHA256: "verified-hash"}
	if err != nil || release != want || !reflect.DeepEqual(targetRefs, []string{"paper-1"}) {
		t.Fatalf("release = %+v, targetRefs = %v, error = %v; want %+v for PAPER only", release, targetRefs, err, want)
	}
}

func TestLatestPaperPluginRelease(t *testing.T) {
	original := pluginHTTPClient
	t.Cleanup(func() { pluginHTTPClient = original })
	pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(req *http.Request) (*http.Response, error) {
		var loaders []string
		if err := json.Unmarshal([]byte(req.URL.Query().Get("loaders")), &loaders); err != nil {
			t.Fatal(err)
		}
		if req.URL.Query().Has("game_versions") || !reflect.DeepEqual(loaders, []string{"paper", "velocity"}) {
			t.Fatalf("unexpected version filter or loaders: %s", req.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[
			{"id":"paper-one-version","version_type":"release","loaders":["paper","velocity"],"game_versions":["1.21.1"],"files":[{"primary":true,"filename":"paper.jar","url":"https://cdn.modrinth.com/data/test/paper.jar","hashes":{"sha512":"abc"}}]}
		]`))}, nil
	})}
	release, targetRefs, err := latestPluginRelease(context.Background(), pluginSource{Provider: "modrinth", Project: "test"}, []pluginCompatibilityTarget{
		{ServerRef: "paper-1", Platform: "PAPER", Version: "26.2"},
		{ServerRef: "paper-2", Platform: "PAPER", Version: "26.2.2"},
		{ServerRef: "paper-other-line", Platform: "PAPER", Version: "26.3"},
		{ServerRef: "paper-latest", Platform: "PAPER", Version: "latest"},
		{ServerRef: "proxy", Platform: "VELOCITY", Version: ""},
	})
	if err != nil || release.Version != "paper-one-version" || release.Filename != "paper.jar" || !reflect.DeepEqual(targetRefs, []string{"paper-1", "paper-2", "paper-latest", "paper-other-line", "proxy"}) {
		t.Fatalf("release = %+v, targetRefs = %v, error = %v", release, targetRefs, err)
	}
}
