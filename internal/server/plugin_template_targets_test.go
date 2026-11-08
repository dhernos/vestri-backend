package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"yourapp/internal/auth"
)

func TestPluginTemplateTargets(t *testing.T) {
	const templateID = "11111111-1111-4111-8111-111111111111"
	const baseID = "22222222-2222-4222-8222-222222222222"
	template := auth.MinecraftResource{ID: templateID, NodeID: "node", Kind: "templates", Name: "Arena", Spec: json.RawMessage(`{"baseId":"` + baseID + `","software":"VELOCITY","version":"stale","parentId":"another-proxy"}`)}
	base := auth.MinecraftResource{ID: baseID, NodeID: "node", Kind: "bases", Spec: json.RawMessage(`{"software":"PURPUR","version":"1.21.1"}`)}
	choices, targets, compatibility, err := pluginTemplateTargets("node", []auth.MinecraftResource{template, base}, []string{templateID})
	if err != nil || len(choices) != 1 || len(targets) != 1 || len(compatibility) != 1 {
		t.Fatalf("selection: choices=%v targets=%v compatibility=%v error=%v", choices, targets, compatibility, err)
	}
	if choices[0] != (pluginTemplateChoice{ID: templateID, Name: "Arena", Platform: "PAPER", Version: "1.21.1"}) || compatibility[0].ServerRef != "template:"+templateID || targets[0].RootPath != ".vestri-minecraft/node/templates/"+templateID {
		t.Fatalf("effective base or materialized path incorrect: %v %v %v", choices, targets, compatibility)
	}
	if err := requirePluginTemplateCompatibility(compatibility, []string{"proxy"}); err == nil {
		t.Fatal("release without Paper support must reject selected template")
	}
	if err := requirePluginTemplateCompatibility(compatibility, []string{targets[0].ID}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*auth.MinecraftResource, *auth.MinecraftResource)
	}{
		{"wrong node", func(template, base *auth.MinecraftResource) { template.NodeID = "other" }},
		{"wrong kind", func(template, base *auth.MinecraftResource) { template.Kind = "worlds" }},
		{"wrong base node", func(template, base *auth.MinecraftResource) { base.NodeID = "other" }},
		{"wrong base kind", func(template, base *auth.MinecraftResource) { base.Kind = "templates" }},
		{"missing base", func(template, base *auth.MinecraftResource) { base.ID = "missing" }},
		{"invalid template spec", func(template, base *auth.MinecraftResource) { template.Spec = json.RawMessage(`{`) }},
		{"invalid base spec", func(template, base *auth.MinecraftResource) { base.Spec = json.RawMessage(`{`) }},
		{"empty base cannot inherit template metadata", func(template, base *auth.MinecraftResource) {
			template.Spec = json.RawMessage(`{"baseId":"` + baseID + `","software":"PAPER","version":"1.21.1"}`)
			base.Spec = json.RawMessage(`{}`)
		}},
		{"incompatible software", func(template, base *auth.MinecraftResource) {
			base.Spec = json.RawMessage(`{"software":"VELOCITY","version":"1.21.1"}`)
		}},
		{"invalid version", func(template, base *auth.MinecraftResource) {
			base.Spec = json.RawMessage(`{"software":"PAPER","version":"latest"}`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, candidateBase := template, base
			test.change(&candidate, &candidateBase)
			if _, _, _, err := pluginTemplateTargets("node", []auth.MinecraftResource{candidate, candidateBase}, []string{templateID}); err == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
}

func TestPluginTemplateSelectionValidation(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, operation := range []string{"import", "remove"} {
		if err := validatePluginTemplateSelection(operation, []string{id}); err == nil {
			t.Fatalf("%s accepted templates", operation)
		}
		if err := validatePluginTemplateSelection(operation, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, ids := range [][]string{{"../escape"}, {""}, {id, id}, make([]string, maxGroupApplyServers+1)} {
		if _, _, _, err := pluginTemplateTargets("node", nil, ids); err == nil {
			t.Fatalf("invalid IDs accepted: %v", ids)
		}
	}
	if _, _, _, err := pluginTemplateTargets("node", nil, []string{id}); err == nil {
		t.Fatal("unknown template accepted")
	}
}

func TestPluginTemplateExistingInstallations(t *testing.T) {
	plugin := trackedPlugin{Installed: pluginRelease{Filename: "Example-2.jar"}, Filenames: []string{"Example-1.jar", "Example-3.jar"}}
	var resources []auth.MinecraftResource
	var ids []string
	directories := make(map[string]string)
	for _, entries := range []string{
		`[{"name":"Example-2.jar","type":"file"}]`,
		`[{"name":"Example-1.jar","type":"file"}]`,
		`[{"name":"Example-3.jar","type":"file"}]`,
		`[{"name":"Other.jar","type":"file"}]`,
		`[{"name":"Example-1.jar","type":"dir"}]`,
		`[{"name":"Example-2-backup.jar","type":"file"}]`,
		`[]`,
		"",
	} {
		resource := auth.MinecraftResource{ID: uuid.NewString(), NodeID: "node", Kind: "templates", Spec: json.RawMessage(`{"software":"PAPER","version":"1.21.1"}`)}
		resources = append(resources, resource)
		ids = append(ids, resource.ID)
		if entries != "" {
			directories[path.Join(minecraftResourceDataPath(&resource), "plugins")] = entries
		}
	}
	_, targets, compatibility, err := pluginTemplateTargets("node", resources, ids)
	if err != nil {
		t.Fatal(err)
	}
	var copies, deletes []string
	workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/fs/list" {
			body, ok := directories[request.URL.Query().Get("path")]
			if !ok {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = response.Write([]byte(body))
			return
		}
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		switch request.URL.Path {
		case "/fs/copy":
			copies = append(copies, payload["dest"])
		case "/fs/delete":
			deletes = append(deletes, payload["path"])
		default:
			t.Errorf("unexpected worker request: %s", request.URL.Path)
		}
	}))
	defer workerServer.Close()
	baseURL, _ := url.Parse(workerServer.URL)
	worker := pluginWorker{server: &Server{}, baseURL: baseURL}
	refs := make([]string, 0, len(compatibility))
	for _, target := range compatibility {
		refs = append(refs, target.ServerRef)
	}
	selected, err := worker.installedTargets(context.Background(), pluginTargetsForRefs(targets, refs), plugin)
	if err != nil || !reflect.DeepEqual(selected, targets[:3]) {
		t.Fatalf("existing template installations = %v, error=%v", selected, err)
	}
	var wantCopies, wantDeletes []string
	for _, target := range selected {
		directory := path.Join(target.RootPath, backendPluginsRelativePath)
		if err := worker.replace(context.Background(), "download.jar", directory, "Example-3.jar", plugin.Filenames); err != nil {
			t.Fatal(err)
		}
		wantCopies = append(wantCopies, path.Join(directory, "Example-3.jar"))
		wantDeletes = append(wantDeletes, path.Join(directory, "Example-1.jar"))
	}
	if !reflect.DeepEqual(copies, wantCopies) || !reflect.DeepEqual(deletes, wantDeletes) {
		t.Fatalf("template deployment paths: copies=%v deletes=%v", copies, deletes)
	}
}

func TestPluginTemplatePreflightFailsClosed(t *testing.T) {
	for _, body := range []string{"forbidden", "failure", `{`} {
		t.Run(body, func(t *testing.T) {
			resource := auth.MinecraftResource{ID: uuid.NewString(), NodeID: "node", Kind: "templates", Spec: json.RawMessage(`{"software":"PAPER","version":"1.21.1"}`)}
			_, targets, _, err := pluginTemplateTargets("node", []auth.MinecraftResource{resource}, []string{resource.ID})
			if err != nil {
				t.Fatal(err)
			}
			workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet || request.URL.Path != "/fs/list" {
					t.Fatalf("preflight mutated files: %s %s", request.Method, request.URL.Path)
				}
				if request.URL.Query().Get("path") == "proxy/data/plugins" {
					_, _ = response.Write([]byte(`[{"name":"Example.jar","type":"file"}]`))
					return
				}
				if request.URL.Query().Get("path") != path.Join(minecraftResourceDataPath(&resource), "plugins") {
					t.Errorf("wrong template inspection path: %s", request.URL)
				}
				if body == "forbidden" {
					response.WriteHeader(http.StatusForbidden)
				} else if body == "failure" {
					response.WriteHeader(http.StatusInternalServerError)
				}
				_, _ = response.Write([]byte(body))
			}))
			defer workerServer.Close()
			baseURL, _ := url.Parse(workerServer.URL)
			worker := pluginWorker{server: &Server{}, baseURL: baseURL}
			selected, err := worker.installedTargets(context.Background(), append([]auth.GameServer{{ID: "proxy", RootPath: "proxy"}}, targets...), trackedPlugin{Installed: pluginRelease{Filename: "Example.jar"}})
			if err == nil || selected != nil {
				t.Fatalf("partial preflight must abort all deployment: selected=%v error=%v", selected, err)
			}
		})
	}
}

func TestPluginTemplateResolvedLoaders(t *testing.T) {
	original := pluginHTTPClient
	t.Cleanup(func() { pluginHTTPClient = original })
	resource := auth.MinecraftResource{ID: uuid.NewString(), NodeID: "node", Kind: "templates", Spec: json.RawMessage(`{"software":"PURPUR","version":"1.21.1"}`)}
	_, _, selectedCompatibility, err := pluginTemplateTargets("node", []auth.MinecraftResource{resource}, []string{resource.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, loaders := range [][]string{{"velocity"}, {"paper"}, {"velocity", "paper"}} {
		t.Run(strings.Join(loaders, "+"), func(t *testing.T) {
			pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(request *http.Request) (*http.Response, error) {
				if request.URL.Host != "api.modrinth.com" || !strings.HasSuffix(request.URL.Path, "/version") {
					t.Fatalf("unexpected request (no download allowed): %s", request.URL)
				}
				var requestedLoaders []string
				if err := json.Unmarshal([]byte(request.URL.Query().Get("loaders")), &requestedLoaders); err != nil || !reflect.DeepEqual(requestedLoaders, []string{"velocity", "paper"}) {
					t.Fatalf("selected template missing from resolver union: %s", request.URL)
				}
				body, _ := json.Marshal([]interface{}{map[string]interface{}{"id": "latest", "version_type": "release", "loaders": loaders, "files": []interface{}{map[string]interface{}{"primary": true, "filename": "Example.jar", "url": "https://cdn.modrinth.com/data/test/Example.jar", "hashes": map[string]string{"sha512": "verified"}}}}})
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}
			union := append([]pluginCompatibilityTarget{{ServerRef: "proxy", Platform: "VELOCITY"}}, selectedCompatibility...)
			_, refs, err := latestPluginRelease(context.Background(), pluginSource{Provider: "modrinth", Project: "test"}, union)
			if err != nil {
				t.Fatal(err)
			}
			compatible := containsPluginValue(loaders, "paper")
			if err := requirePluginTemplateCompatibility(selectedCompatibility, refs); (err == nil) != compatible {
				t.Fatalf("actual loader compatibility: refs=%v error=%v", refs, err)
			}
		})
	}
}
