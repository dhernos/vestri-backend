package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"yourapp/internal/auth"
)

func TestPluginServerTargets(t *testing.T) {
	candidates := []auth.GameServer{{ID: "proxy"}, {ID: "paper"}}
	for _, test := range []struct {
		name    string
		ids     []string
		want    []auth.GameServer
		invalid bool
	}{
		{name: "omitted", want: []auth.GameServer{}},
		{name: "empty", ids: []string{}, want: []auth.GameServer{}},
		{name: "one non UUID", ids: []string{"paper"}, want: candidates[1:]},
		{name: "all", ids: []string{"proxy", "paper"}, want: candidates},
		{name: "empty ID", ids: []string{""}, invalid: true},
		{name: "duplicate", ids: []string{"paper", "paper"}, invalid: true},
		{name: "unknown", ids: []string{"unknown"}, invalid: true},
		{name: "wrong scope", ids: []string{"other-proxy-child"}, invalid: true},
		{name: "permission excluded", ids: []string{"inaccessible-paper"}, invalid: true},
		{name: "template ref", ids: []string{"template:paper"}, invalid: true},
		{name: "too many", ids: make([]string, maxGroupApplyServers+2), invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			choices, selected, err := pluginServerTargets("update", candidates, test.ids)
			if test.invalid {
				if err == nil {
					t.Fatal("expected selection error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(choices) != len(candidates) || !reflect.DeepEqual(selected, test.want) {
				t.Fatalf("choices = %+v, selected = %+v, want %+v", choices, selected, test.want)
			}
		})
	}
	for _, operation := range []string{"import", "remove"} {
		if _, _, err := pluginServerTargets(operation, candidates, []string{"paper"}); err == nil {
			t.Fatalf("%s accepted serverIds", operation)
		}
		if _, _, err := pluginServerTargets(operation, candidates, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPluginServerChoices(t *testing.T) {
	candidates := []auth.GameServer{
		{ID: "proxy", Name: "Proxy", Metadata: json.RawMessage(`{"kind":"velocity","gameVersion":" 3.4.0 "}`)},
		{ID: "paper", Name: "Arena", Metadata: json.RawMessage(`{"softwareVersion":" purpur ","gameVersion":"1.21.1"}`)},
	}
	choices, _, err := pluginServerTargets("list", candidates, nil)
	want := []pluginServerChoice{
		{ID: "paper", Name: "Arena", Platform: "PAPER", Version: "1.21.1"},
		{ID: "proxy", Name: "Proxy", Platform: "VELOCITY", Version: "3.4.0"},
	}
	if err != nil || !reflect.DeepEqual(choices, want) {
		t.Fatalf("choices = %+v, error = %v", choices, err)
	}
	body, err := json.Marshal(choices)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `[{"id":"paper","name":"Arena","platform":"PAPER","version":"1.21.1"},{"id":"proxy","name":"Proxy","platform":"VELOCITY","version":"3.4.0"}]` {
		t.Fatalf("response fields = %s", body)
	}
	var maximum []auth.GameServer
	var ids []string
	for index := 0; index < maxGroupApplyServers+1; index++ {
		id := fmt.Sprintf("server-%d", index)
		maximum = append(maximum, auth.GameServer{ID: id})
		ids = append(ids, id)
	}
	if _, selected, err := pluginServerTargets("update", maximum, ids); err != nil || len(selected) != len(ids) {
		t.Fatalf("maximum selection rejected: %v", err)
	}
}

func TestPluginServerSelectionResolvedLoaders(t *testing.T) {
	original := pluginHTTPClient
	t.Cleanup(func() { pluginHTTPClient = original })
	candidates := []auth.GameServer{{ID: "proxy"}, {ID: "paper"}}
	compatibility := []pluginCompatibilityTarget{{ServerRef: "proxy", Platform: "VELOCITY"}, {ServerRef: "paper", Platform: "PAPER", Version: "1.21.1"}}
	for _, loaders := range [][]string{{"paper"}, {"velocity"}, {"paper", "velocity"}} {
		t.Run(strings.Join(loaders, "+"), func(t *testing.T) {
			requests := 0
			pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(request *http.Request) (*http.Response, error) {
				requests++
				if request.URL.Host != "api.modrinth.com" || !strings.HasSuffix(request.URL.Path, "/version") {
					t.Errorf("unexpected download: %s", request.URL)
				}
				var requestedLoaders []string
				if err := json.Unmarshal([]byte(request.URL.Query().Get("loaders")), &requestedLoaders); err != nil || !reflect.DeepEqual(requestedLoaders, []string{"velocity", "paper"}) {
					t.Errorf("resolver must retain all accessible candidates: %s", request.URL)
				}
				body, _ := json.Marshal([]interface{}{map[string]interface{}{"id": "newest", "version_type": "release", "loaders": loaders, "files": []interface{}{map[string]interface{}{"primary": true, "filename": "Example.jar", "url": "https://cdn.modrinth.com/data/test/Example.jar", "hashes": map[string]string{"sha512": "verified"}}}}})
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}
			for _, ids := range [][]string{nil, {}, {"paper"}, {"proxy", "paper"}} {
				_, selected, err := pluginServerTargets("update", candidates, ids)
				if err != nil {
					t.Fatal(err)
				}
				release, refs, err := latestPluginRelease(context.Background(), pluginSource{Provider: "modrinth", Project: "test"}, compatibility)
				if err != nil || release.Version != "newest" {
					t.Fatalf("staging resolution: release=%+v error=%v", release, err)
				}
				compatible := true
				for _, target := range selected {
					platform := "paper"
					if target.ID == "proxy" {
						platform = "velocity"
					}
					compatible = compatible && containsPluginValue(loaders, platform)
				}
				err = requirePluginServerCompatibility(selected, refs)
				if (err == nil) != compatible || err != nil && !strings.Contains(err.Error(), "incompatible with the resolved plugin release") {
					t.Fatalf("selection %v: refs=%v error=%v", ids, refs, err)
				}
			}
			if requests != 4 {
				t.Fatalf("provider requests = %d, want four resolutions and no downloads", requests)
			}
		})
	}
}
