package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type pluginRoundTripper func(*http.Request) (*http.Response, error)

func (transport pluginRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

func TestParsePluginSource(t *testing.T) {
	for _, raw := range []string{"https://modrinth.com/plugin/luckperms", "https://hangar.papermc.io/ViaVersion/ViaVersion/versions", "https://modrinth.com/plugin/luckperms/version/test"} {
		if _, err := parsePluginSource(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://modrinth.com/plugin/test", "https://localhost/plugin/test", "https://modrinth.com:8443/plugin/test", "https://modrinth.com/mod/test", "https://hangar.papermc.io/../test", "https://modrinth.com/plugin/a%2Fb"} {
		if _, err := parsePluginSource(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestLatestPaperPluginRelease(t *testing.T) {
	original := pluginHTTPClient
	t.Cleanup(func() { pluginHTTPClient = original })
	pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("loaders") != `["paper"]` || req.URL.Query().Get("game_versions") != `["1.21.1"]` {
			t.Fatalf("missing compatibility filters: %s", req.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[
			{"id":"beta","version_type":"beta","files":[{"primary":true,"filename":"beta.jar"}]},
			{"id":"stable","version_type":"release","files":[{"primary":true,"filename":"plugin-2.jar","url":"https://cdn.modrinth.com/data/test/plugin-2.jar","hashes":{"sha512":"abc"}}]}
		]`))}, nil
	})}
	release, err := latestPluginRelease(context.Background(), pluginSource{Provider: "modrinth", Project: "test"}, "1.21.1")
	if err != nil || release.Version != "stable" || release.Filename != "plugin-2.jar" {
		t.Fatalf("release = %+v, error = %v", release, err)
	}
}
