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
		var loaders []string
		if err := json.Unmarshal([]byte(req.URL.Query().Get("loaders")), &loaders); err != nil {
			t.Fatal(err)
		}
		if req.URL.Query().Has("game_versions") || !reflect.DeepEqual(loaders, []string{"paper", "velocity"}) {
			t.Fatalf("missing compatibility filters: %s", req.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[
			{"id":"paper-one-version","version_type":"release","loaders":["paper"],"game_versions":["26.2.1"],"files":[{"primary":true,"filename":"paper.jar","url":"https://cdn.modrinth.com/data/test/paper.jar","hashes":{"sha512":"abc"}}]}
		]`))}, nil
	})}
	release, targetRefs, err := latestPluginRelease(context.Background(), pluginSource{Provider: "modrinth", Project: "test"}, []pluginCompatibilityTarget{
		{ServerRef: "paper-1", Platform: "PAPER", Version: "26.2"},
		{ServerRef: "paper-2", Platform: "PAPER", Version: "26.2.2"},
		{ServerRef: "paper-other-line", Platform: "PAPER", Version: "26.3"},
		{ServerRef: "proxy", Platform: "VELOCITY", Version: "3.4.0"},
	})
	if err != nil || release.Version != "paper-one-version" || release.Filename != "paper.jar" || !reflect.DeepEqual(targetRefs, []string{"paper-1", "paper-2"}) {
		t.Fatalf("release = %+v, targetRefs = %v, error = %v", release, targetRefs, err)
	}
}

func TestPluginVersionLine(t *testing.T) {
	tests := []struct {
		left, right string
		want        bool
	}{
		{left: "26.2", right: "26.2.1", want: true},
		{left: "26.2.1", right: "26.2.2", want: true},
		{left: "1.21.11", right: "1.21", want: true},
		{left: "26.2.1", right: "26.3.0", want: false},
		{left: "latest", right: "26.2.1", want: false},
	}
	for _, test := range tests {
		if got := containsPluginVersionLine([]string{test.left}, test.right); got != test.want {
			t.Errorf("containsPluginVersionLine(%q, %q) = %t, want %t", test.left, test.right, got, test.want)
		}
	}
}
