package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"testing"

	"yourapp/internal/auth"
)

func TestMinecraftPluginLibraryPath(t *testing.T) {
	if got := minecraftPluginLibraryPath("node-a"); got != ".vestri-minecraft/node-a/plugins" {
		t.Fatalf("library path = %q", got)
	}
	if minecraftPluginLibraryPath("node-a") == minecraftPluginLibraryPath("node-b") {
		t.Fatal("different nodes must have isolated plugin libraries")
	}
	worker := pluginWorker{root: minecraftLibraryPath("node-a")}
	if got := worker.manifestPath(); got != ".vestri-minecraft/node-a/tracked-plugins.json" {
		t.Fatalf("manifest path = %q", got)
	}
	if _, err := resolveServerScopedPath(minecraftLibraryPath("node-a"), "../node-b/plugins", false); err == nil {
		t.Fatal("paths must not escape to another node's library")
	}
	if slugify(".vestri-minecraft") == ".vestri-minecraft" {
		t.Fatal("shared library directory must not be a valid regular server slug")
	}
}

func TestMinecraftLibraryPermissions(t *testing.T) {
	for _, role := range []string{auth.NodeAccessOwner, auth.NodeAccessAdmin, auth.NodeAccessOperator, auth.NodeAccessViewer, ""} {
		want := role == auth.NodeAccessOwner || role == auth.NodeAccessAdmin
		if got := canManageNodeMinecraftLibrary(role); got != want {
			t.Errorf("canManageNodeMinecraftLibrary(%q) = %v, want %v", role, got, want)
		}
	}
}

func TestNodeMinecraftFilesScope(t *testing.T) {
	handler := withNodeMinecraftFilesScope(func(response http.ResponseWriter, request *http.Request) {
		if !groupFilesScoped(request.Context()) {
			t.Error("node library must retain group file protections")
		}
		if scoped, _ := request.Context().Value(nodeMinecraftFilesScopeKey{}).(bool); !scoped {
			t.Error("node library must not require a Velocity server reference")
		}
		response.WriteHeader(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	handler(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestPluginManifestSaveAtomic(t *testing.T) {
	type workerRequest struct {
		Method   string
		Endpoint string
		Payload  map[string]interface{}
	}
	manifest := pluginManifest{Plugins: []trackedPlugin{{
		ID:          "example",
		Source:      pluginSource{Provider: "modrinth", Project: "example"},
		GameVersion: "1.21.1",
		Installed:   pluginRelease{Version: "2", Filename: "Example-2.jar"},
		Latest:      pluginRelease{Version: "3", Filename: "Example-3.jar"},
		Filenames:   []string{"Example-1.jar", "Example-2.jar", "Example-3.jar"},
		Pending:     true,
	}}}
	tests := []struct {
		name        string
		writeStatus int
		copyStatus  int
		wantError   string
	}{
		{name: "success", writeStatus: http.StatusOK, copyStatus: http.StatusOK},
		{name: "write failure preserves manifest", writeStatus: http.StatusInternalServerError, copyStatus: http.StatusOK, wantError: "worker /fs/write failed (HTTP 500)"},
		{name: "copy failure still cleans up", writeStatus: http.StatusOK, copyStatus: http.StatusInternalServerError, wantError: "worker /fs/copy failed (HTTP 500)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var mutex sync.Mutex
			var requests []workerRequest
			files := make(map[string]string)
			workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				var payload map[string]interface{}
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
					t.Errorf("decode worker payload: %v", err)
					response.WriteHeader(http.StatusBadRequest)
					return
				}
				mutex.Lock()
				defer mutex.Unlock()
				requests = append(requests, workerRequest{Method: request.Method, Endpoint: request.URL.Path, Payload: payload})
				responseStatus := http.StatusOK
				filename, _ := payload["path"].(string)
				switch request.URL.Path {
				case "/fs/mkdir":
					responseStatus = http.StatusCreated
				case "/fs/write":
					responseStatus = test.writeStatus
					if responseStatus == http.StatusOK {
						files[filename], _ = payload["content"].(string)
					}
				case "/fs/copy":
					responseStatus = test.copyStatus
					if responseStatus == http.StatusOK {
						source, _ := payload["source"].(string)
						destination, _ := payload["dest"].(string)
						files[destination] = files[source]
					}
				case "/fs/delete":
					delete(files, filename)
				default:
					responseStatus = http.StatusNotFound
				}
				response.WriteHeader(responseStatus)
			}))
			t.Cleanup(workerServer.Close)
			baseURL, err := url.Parse(workerServer.URL)
			if err != nil {
				t.Fatal(err)
			}
			worker := pluginWorker{server: &Server{}, baseURL: baseURL, apiKey: "test-worker-key", root: "/servers/paper"}
			manifestPath := worker.manifestPath()
			originalContent := `{"plugins":[]}`
			files[manifestPath] = originalContent
			temporaryPaths := make(map[string]bool)
			for attempt := 0; attempt < 2; attempt++ {
				err := worker.save(context.Background(), manifest)
				if test.wantError == "" {
					if err != nil {
						t.Fatalf("save: %v", err)
					}
				} else if err == nil || err.Error() != test.wantError {
					t.Errorf("save error = %v, want %q", err, test.wantError)
				}
				mutex.Lock()
				gotRequests := requests
				requests = nil
				remainingFiles := make(map[string]string, len(files))
				for filename, content := range files {
					remainingFiles[filename] = content
				}
				mutex.Unlock()
				if len(gotRequests) < 2 {
					t.Fatalf("worker requests = %#v, want mkdir then write", gotRequests)
				}
				temporary, _ := gotRequests[1].Payload["path"].(string)
				if path.Dir(temporary) != path.Dir(manifestPath) || !strings.HasPrefix(temporary, manifestPath+".") || !strings.HasSuffix(temporary, ".tmp") || len(temporary) <= len(manifestPath)+len("..tmp") {
					t.Errorf("temporary path = %q, want unique .tmp beside %q", temporary, manifestPath)
				}
				if temporaryPaths[temporary] {
					t.Errorf("temporary path reused: %q", temporary)
				}
				temporaryPaths[temporary] = true
				content, _ := gotRequests[1].Payload["content"].(string)
				var written pluginManifest
				if err := json.Unmarshal([]byte(content), &written); err != nil {
					t.Fatalf("decode written manifest: %v", err)
				}
				if !reflect.DeepEqual(written, manifest) {
					t.Errorf("written manifest = %+v, want %+v", written, manifest)
				}
				wantRequests := []workerRequest{
					{Method: http.MethodPost, Endpoint: "/fs/mkdir", Payload: map[string]interface{}{"path": path.Dir(manifestPath), "recursive": true}},
					{Method: http.MethodPost, Endpoint: "/fs/write", Payload: map[string]interface{}{"path": temporary, "content": content}},
				}
				if test.writeStatus == http.StatusOK {
					wantRequests = append(wantRequests, workerRequest{Method: http.MethodPost, Endpoint: "/fs/copy", Payload: map[string]interface{}{"source": temporary, "dest": manifestPath}})
				}
				wantRequests = append(wantRequests, workerRequest{Method: http.MethodPost, Endpoint: "/fs/delete", Payload: map[string]interface{}{"path": temporary}})
				if !reflect.DeepEqual(gotRequests, wantRequests) {
					t.Errorf("worker requests = %#v, want %#v", gotRequests, wantRequests)
				}
				wantContent := originalContent
				if test.wantError == "" {
					wantContent = content
				}
				if !reflect.DeepEqual(remainingFiles, map[string]string{manifestPath: wantContent}) {
					t.Errorf("worker files = %#v, want only manifest with content %q", remainingFiles, wantContent)
				}
			}
		})
	}
}

func TestPluginWorkerReplace(t *testing.T) {
	type workerRequest struct {
		Method   string
		Endpoint string
		Payload  map[string]string
	}
	copyRequest := workerRequest{
		Method: http.MethodPost, Endpoint: "/fs/copy",
		Payload: map[string]string{"source": "/staging/download.jar", "dest": "/servers/paper/plugins/Example-3.jar"},
	}
	deleteRequest := func(filename string) workerRequest {
		return workerRequest{
			Method: http.MethodPost, Endpoint: "/fs/delete",
			Payload: map[string]string{"path": "/servers/paper/plugins/" + filename},
		}
	}
	tests := []struct {
		name         string
		filename     string
		history      []string
		copyStatus   int
		deleteStatus int
		wantError    string
		wantRequests []workerRequest
	}{
		{
			name:     "copies before deleting exact historic filenames and skips current",
			filename: "Example-3.jar", history: []string{"Example-1.jar", "Example-3.jar", "Example legacy.JAR"},
			wantRequests: []workerRequest{copyRequest, deleteRequest("Example-1.jar"), deleteRequest("Example legacy.JAR")},
		},
		{
			name:     "current filename alone is not deleted",
			filename: "Example-3.jar", history: []string{"Example-3.jar"},
			wantRequests: []workerRequest{copyRequest},
		},
		{
			name:     "missing historic files do not stop remaining deletes",
			filename: "Example-3.jar", history: []string{"Example-1.jar", "Example-2.jar"},
			deleteStatus: http.StatusNotFound,
			wantRequests: []workerRequest{copyRequest, deleteRequest("Example-1.jar"), deleteRequest("Example-2.jar")},
		},
		{
			name:     "copy failure prevents all deletes",
			filename: "Example-3.jar", history: []string{"Example-1.jar", "Example-2.jar"},
			copyStatus: http.StatusInternalServerError, wantError: "worker /fs/copy failed (HTTP 500)",
			wantRequests: []workerRequest{copyRequest},
		},
		{
			name:     "delete failure is returned and stops remaining deletes",
			filename: "Example-3.jar", history: []string{"Example-1.jar", "Example-2.jar"},
			deleteStatus: http.StatusForbidden, wantError: "worker /fs/delete failed (HTTP 403)",
			wantRequests: []workerRequest{copyRequest, deleteRequest("Example-1.jar")},
		},
		{
			name:     "invalid current filename sends no requests",
			filename: "../Example-3.jar", history: []string{"Example-1.jar"},
			wantError: "invalid plugin filename",
		},
		{
			name:     "traversal in later history sends no requests",
			filename: "Example-3.jar", history: []string{"Example-1.jar", "../outside.jar"},
			wantError: "invalid plugin history",
		},
		{
			name:     "absolute historic path sends no requests",
			filename: "Example-3.jar", history: []string{"/outside.jar"},
			wantError: "invalid plugin history",
		},
		{
			name:     "non JAR history sends no requests",
			filename: "Example-3.jar", history: []string{"config.yml"},
			wantError: "invalid plugin history",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var mutex sync.Mutex
			var requests []workerRequest
			workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				var payload map[string]string
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
					t.Errorf("decode worker payload: %v", err)
					response.WriteHeader(http.StatusBadRequest)
					return
				}
				mutex.Lock()
				requests = append(requests, workerRequest{Method: request.Method, Endpoint: request.URL.Path, Payload: payload})
				mutex.Unlock()
				responseStatus := http.StatusOK
				switch request.URL.Path {
				case "/fs/copy":
					if test.copyStatus != 0 {
						responseStatus = test.copyStatus
					}
				case "/fs/delete":
					if test.deleteStatus != 0 {
						responseStatus = test.deleteStatus
					}
				default:
					responseStatus = http.StatusNotFound
				}
				response.WriteHeader(responseStatus)
			}))
			t.Cleanup(workerServer.Close)
			baseURL, err := url.Parse(workerServer.URL)
			if err != nil {
				t.Fatal(err)
			}
			worker := pluginWorker{server: &Server{}, baseURL: baseURL, apiKey: "test-worker-key"}
			err = worker.replace(context.Background(), "/staging/download.jar", "/servers/paper/plugins", test.filename, test.history)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("replace: %v", err)
				}
			} else if err == nil || err.Error() != test.wantError {
				t.Errorf("replace error = %v, want %q", err, test.wantError)
			}
			mutex.Lock()
			defer mutex.Unlock()
			if !reflect.DeepEqual(requests, test.wantRequests) {
				t.Errorf("worker requests = %#v, want %#v", requests, test.wantRequests)
			}
		})
	}
}

func TestDownloadVerifiedPlugin(t *testing.T) {
	makeJAR := func(descriptor string) []byte {
		t.Helper()
		var buffer bytes.Buffer
		archive := zip.NewWriter(&buffer)
		entry, err := archive.Create(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, "name: Example\nversion: '1.0'\nmain: example.Plugin\n"); err != nil {
			t.Fatal(err)
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	validJAR := makeJAR("plugin.yml")
	validVelocityJAR := makeJAR("velocity-plugin.json")
	missingDescriptor := makeJAR("nested/plugin.yml")
	tests := []struct {
		name         string
		body         []byte
		checksum     string
		downloadURL  string
		wantError    string
		wantRequests int
	}{
		{name: "valid SHA512 JAR", body: validJAR, checksum: "sha512", wantRequests: 1},
		{name: "valid Velocity JAR", body: validVelocityJAR, checksum: "sha256", wantRequests: 1},
		{name: "valid SHA256 JAR", body: validJAR, checksum: "sha256", wantRequests: 1},
		{name: "valid JAR with both checksums", body: validJAR, checksum: "both", wantRequests: 1},
		{name: "wrong SHA512", body: validJAR, checksum: "wrong-sha512", wantError: "plugin checksum verification failed", wantRequests: 1},
		{name: "wrong SHA256 despite valid SHA512", body: validJAR, checksum: "wrong-sha256", wantError: "plugin checksum verification failed", wantRequests: 1},
		{name: "missing checksum", body: validJAR, wantError: "missing plugin checksum", wantRequests: 1},
		{name: "missing root descriptor", body: missingDescriptor, checksum: "sha512", wantError: "JAR is missing its Paper/Bukkit/Velocity plugin descriptor", wantRequests: 1},
		{name: "not a ZIP", body: []byte("not a JAR"), checksum: "sha256", wantError: "download is not a valid plugin JAR", wantRequests: 1},
		{name: "untrusted host", body: validJAR, checksum: "sha512", downloadURL: "https://example.com/plugin.jar", wantError: "untrusted plugin download URL"},
		{name: "insecure URL", body: validJAR, checksum: "sha512", downloadURL: "http://cdn.modrinth.com/plugin.jar", wantError: "untrusted plugin download URL"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			temporaryDirectory := t.TempDir()
			t.Setenv("TMPDIR", temporaryDirectory)
			release := pluginRelease{URL: "https://cdn.modrinth.com/data/example/plugin.jar", Filename: "plugin.jar"}
			if test.downloadURL != "" {
				release.URL = test.downloadURL
			}
			hash512, hash256 := sha512.Sum512(test.body), sha256.Sum256(test.body)
			switch test.checksum {
			case "sha512":
				release.SHA512 = strings.ToUpper(hex.EncodeToString(hash512[:]))
			case "sha256":
				release.SHA256 = hex.EncodeToString(hash256[:])
			case "both", "wrong-sha256":
				release.SHA512 = hex.EncodeToString(hash512[:])
				release.SHA256 = hex.EncodeToString(hash256[:])
				if test.checksum == "wrong-sha256" {
					release.SHA256 = strings.Repeat("0", 64)
				}
			case "wrong-sha512":
				release.SHA512 = strings.Repeat("0", 128)
			}
			original := pluginHTTPClient
			t.Cleanup(func() { pluginHTTPClient = original })
			requests := 0
			pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(request *http.Request) (*http.Response, error) {
				requests++
				if request.Method != http.MethodGet || request.URL.String() != release.URL {
					t.Errorf("unexpected download request: %s %s", request.Method, request.URL)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(test.body))}, nil
			})}
			file, err := downloadVerifiedPlugin(context.Background(), release)
			if file != nil {
				t.Cleanup(func() {
					file.Close()
					os.Remove(file.Name())
				})
			}
			if requests != test.wantRequests {
				t.Errorf("download requests = %d, want %d", requests, test.wantRequests)
			}
			if test.wantError != "" {
				if err == nil || err.Error() != test.wantError {
					t.Errorf("download error = %v, want %q", err, test.wantError)
				}
				if file != nil {
					t.Error("failed verification returned a file")
				}
				entries, readErr := os.ReadDir(temporaryDirectory)
				if readErr != nil || len(entries) != 0 {
					t.Errorf("failed download left temporary files: %v, error: %v", entries, readErr)
				}
				return
			}
			if err != nil || file == nil {
				t.Fatalf("download file = %v, error = %v", file, err)
			}
			contents, err := io.ReadAll(io.NewSectionReader(file, 0, int64(len(test.body))))
			if err != nil || !bytes.Equal(contents, test.body) {
				t.Errorf("downloaded bytes differ from JAR, error: %v", err)
			}
		})
	}
}

func TestLatestHangarPluginRelease(t *testing.T) {
	original := pluginHTTPClient
	t.Cleanup(func() { pluginHTTPClient = original })
	requests := 0
	pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(request *http.Request) (*http.Response, error) {
		requests++
		var body string
		switch {
		case request.URL.Host == "hangar.papermc.io":
			wantQuery := url.Values{"limit": {"25"}, "channel": {"Release"}}
			if request.Method != http.MethodGet || request.URL.Path != "/api/v1/projects/martijnpu/PrefiX/versions" || !reflect.DeepEqual(request.URL.Query(), wantQuery) {
				t.Errorf("unexpected Hangar metadata request: %s %s", request.Method, request.URL)
			}
			body = `{"result":[{"name":"7.7","channel":{"name":"Release"},"platformDependencies":{"PAPER":["1.21.1"]},"downloads":{"PAPER":{"fileInfo":null,"externalUrl":"https://cdn.modrinth.com/data/oTIEBNzO/versions/n5Z6ELrs/PrefiX-7.7.jar?mr_download_reason=standalone","downloadUrl":null}}}]}`
		case request.URL.Host == "api.modrinth.com":
			if request.Method != http.MethodGet || request.URL.Path != "/v2/version/n5Z6ELrs" {
				t.Errorf("unexpected Modrinth metadata request: %s %s", request.Method, request.URL)
			}
			body = `{"files":[{"filename":"PrefiX-7.7.jar","url":"https://cdn.modrinth.com/data/oTIEBNzO/versions/n5Z6ELrs/PrefiX-7.7.jar","hashes":{"sha512":"verified-hash"}}]}`
		default:
			t.Errorf("unexpected metadata host: %s", request.URL.Host)
			return nil, fmt.Errorf("unexpected metadata host")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	release, targetRefs, err := latestPluginRelease(context.Background(), pluginSource{Provider: "hangar", Project: "martijnpu/PrefiX"}, []pluginCompatibilityTarget{
		{ServerRef: "paper-1", Platform: "PAPER", Version: "26.2"},
		{ServerRef: "paper-2", Platform: "PAPER", Version: "26.2.2"},
		{ServerRef: "paper-latest", Platform: "PAPER", Version: "latest"},
		{ServerRef: "proxy", Platform: "VELOCITY", Version: "3.4.0"},
	})
	want := pluginRelease{Version: "7.7", Filename: "PrefiX-7.7.jar", URL: "https://cdn.modrinth.com/data/oTIEBNzO/versions/n5Z6ELrs/PrefiX-7.7.jar", SHA512: "verified-hash"}
	if err != nil || release != want || !reflect.DeepEqual(targetRefs, []string{"paper-1", "paper-2", "paper-latest"}) {
		t.Fatalf("release = %+v, targetRefs = %v, error = %v; want %+v and all Paper targets", release, targetRefs, err, want)
	}
	if requests != 2 {
		t.Errorf("metadata requests = %d, want 2", requests)
	}
}
