package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"reflect"
	"testing"

	"yourapp/internal/auth"
)

func TestPluginUpdatesOnlyTargetExistingInstallations(t *testing.T) {
	plugin := trackedPlugin{
		Installed: pluginRelease{Filename: "Example-2.jar"},
		Filenames: []string{"Example-1.jar", "Example-3.jar"},
	}
	directories := map[string]string{
		"proxy/data/plugins":       `[{"name":"Example-1.jar","type":"file"}]`,
		"paper/data/plugins":       `[{"name":"Example-2.jar","type":"file"}]`,
		"partial/data/plugins":     `[{"name":"Example-3.jar","type":"file"}]`,
		"unrelated/data/plugins":   `[{"name":"Other.jar","type":"file"}]`,
		"directory/data/plugins":   `[{"name":"Example-1.jar","type":"dir"}]`,
		"similar/data/plugins":     `[{"name":"Example-1-backup.jar","type":"file"}]`,
		"unsupported/data/plugins": `[{"name":"Example-1.jar","type":"file"}]`,
	}
	var requests []string
	workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/fs/list" {
			t.Errorf("unexpected mutation: %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		directory := request.URL.Query().Get("path")
		requests = append(requests, directory)
		body, exists := directories[directory]
		if !exists {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = response.Write([]byte(body))
	}))
	defer workerServer.Close()
	baseURL, err := url.Parse(workerServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	worker := pluginWorker{server: &Server{}, baseURL: baseURL, apiKey: "worker-key"}
	var candidates []auth.GameServer
	var compatible []string
	for _, name := range []string{"proxy", "paper", "partial", "unrelated", "directory", "similar", "missing", "unsupported"} {
		candidates = append(candidates, auth.GameServer{ID: name, RootPath: name})
		if name != "unsupported" {
			compatible = append(compatible, name)
		}
	}
	selected, err := worker.installedTargets(context.Background(), pluginTargetsForRefs(candidates, compatible), plugin)
	if err != nil {
		t.Fatal(err)
	}
	var selectedIDs []string
	for _, target := range selected {
		selectedIDs = append(selectedIDs, target.ID)
	}
	if !reflect.DeepEqual(selectedIDs, []string{"proxy", "paper", "partial"}) {
		t.Fatalf("update targets = %v", selectedIDs)
	}
	for _, directory := range requests {
		if directory == path.Join("unsupported", backendPluginsRelativePath) {
			t.Fatal("inspected incompatible server")
		}
	}
	delete(directories, "proxy/data/plugins")
	directories["paper/data/plugins"] = `[]`
	directories["partial/data/plugins"] = `[]`
	selected, err = worker.installedTargets(context.Background(), candidates[:3], plugin)
	if err != nil || len(selected) != 0 {
		t.Fatalf("removed plugins must not be reinstalled: targets=%v error=%v", selected, err)
	}
}

func TestPluginUpdateInspectionFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "forbidden", status: http.StatusForbidden},
		{name: "worker failure", status: http.StatusInternalServerError},
		{name: "malformed listing", status: http.StatusOK, body: `{`},
	} {
		t.Run(test.name, func(t *testing.T) {
			workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.WriteHeader(test.status)
				_, _ = response.Write([]byte(test.body))
			}))
			defer workerServer.Close()
			baseURL, _ := url.Parse(workerServer.URL)
			worker := pluginWorker{server: &Server{}, baseURL: baseURL}
			selected, err := worker.installedTargets(context.Background(), []auth.GameServer{{ID: "paper", RootPath: "paper"}},
				trackedPlugin{Installed: pluginRelease{Filename: "Example.jar"}})
			if err == nil || selected != nil {
				encoded, _ := json.Marshal(selected)
				t.Fatalf("inspection failure must abort selection: targets=%s error=%v", encoded, err)
			}
		})
	}
}

func TestPluginUpdateSelectedServersAndTemplates(t *testing.T) {
	const templateID = "11111111-1111-4111-8111-111111111111"
	resource := auth.MinecraftResource{ID: templateID, NodeID: "node", Kind: "templates", Spec: json.RawMessage(`{"software":"PAPER","version":"1.21.1"}`)}
	_, templates, _, err := pluginTemplateTargets("node", []auth.MinecraftResource{resource}, []string{templateID})
	if err != nil {
		t.Fatal(err)
	}
	candidates := []auth.GameServer{{ID: "proxy", RootPath: "proxy"}, {ID: "paper", RootPath: "paper"}, {ID: "unselected", RootPath: "unselected"}}
	for _, present := range []bool{true, false} {
		for _, ids := range [][]string{nil, {}, {"paper"}, {"proxy", "paper"}} {
			_, servers, err := pluginServerTargets("update", candidates, ids)
			if err != nil {
				t.Fatal(err)
			}
			targets := append(servers, templates...)
			var lists, copies, deletes []string
			workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodGet && request.URL.Path == "/fs/list" {
					lists = append(lists, request.URL.Query().Get("path"))
					if present {
						_, _ = response.Write([]byte(`[{"name":"Example-1.jar","type":"file"}]`))
					} else {
						_, _ = response.Write([]byte(`[]`))
					}
					return
				}
				if len(lists) != len(targets) {
					t.Error("write before all selected targets were inspected")
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
					t.Errorf("unexpected worker request: %s", request.URL)
				}
			}))
			baseURL, _ := url.Parse(workerServer.URL)
			worker := pluginWorker{server: &Server{}, baseURL: baseURL}
			plugin := trackedPlugin{Installed: pluginRelease{Filename: "Example-1.jar"}, Filenames: []string{"Example-1.jar"}}
			installed, err := worker.installedTargets(context.Background(), pluginTargetsForRefs(targets, []string{"proxy", "paper", "unselected", "template:" + templateID}), plugin)
			if err != nil {
				workerServer.Close()
				t.Fatal(err)
			}
			var wantLists, wantCopies, wantDeletes []string
			for _, target := range targets {
				directory := path.Join(target.RootPath, backendPluginsRelativePath)
				wantLists = append(wantLists, directory)
				if present {
					wantCopies = append(wantCopies, path.Join(directory, "Example-2.jar"))
					wantDeletes = append(wantDeletes, path.Join(directory, "Example-1.jar"))
				}
			}
			for _, target := range installed {
				if err := worker.replace(context.Background(), "download.jar", path.Join(target.RootPath, backendPluginsRelativePath), "Example-2.jar", plugin.Filenames); err != nil {
					t.Fatal(err)
				}
			}
			workerServer.Close()
			if !reflect.DeepEqual(lists, wantLists) || !reflect.DeepEqual(copies, wantCopies) || !reflect.DeepEqual(deletes, wantDeletes) {
				t.Fatalf("present=%v ids=%v: lists=%v copies=%v deletes=%v; want %v %v %v", present, ids, lists, copies, deletes, wantLists, wantCopies, wantDeletes)
			}
		}
	}
}

func TestPluginUpdateStagingOnlySkipsServerInspection(t *testing.T) {
	workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		t.Errorf("staging-only preflight contacted worker: %s %s", request.Method, request.URL)
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer workerServer.Close()
	baseURL, _ := url.Parse(workerServer.URL)
	worker := pluginWorker{server: &Server{}, baseURL: baseURL}
	for _, ids := range [][]string{nil, {}} {
		_, selected, err := pluginServerTargets("update", []auth.GameServer{{ID: "proxy"}, {ID: "paper"}}, ids)
		if err != nil {
			t.Fatal(err)
		}
		installed, err := worker.installedTargets(context.Background(), pluginTargetsForRefs(selected, []string{"proxy", "paper"}), trackedPlugin{Installed: pluginRelease{Filename: "Example.jar"}})
		if err != nil || len(installed) != 0 {
			t.Fatalf("staging-only preflight: installed=%v error=%v", installed, err)
		}
	}
}
