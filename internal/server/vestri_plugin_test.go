package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
)

func TestVestriPluginPlatforms(t *testing.T) {
	tests := []struct {
		software string
		kind     string
		want     bool
	}{
		{software: "VELOCITY", kind: gameServerKindVelocity, want: true},
		{software: "velocity", kind: gameServerKindVelocity, want: true},
		{software: "PAPER", kind: gameServerKindVelocityBackend, want: true},
		{software: "PURPUR", kind: gameServerKindVelocityBackend, want: true},
		{software: "SPIGOT", kind: gameServerKindVelocityBackend, want: true},
		{software: "BUKKIT", kind: gameServerKindVelocityBackend, want: true},
		{software: "PAPER", kind: gameServerKindStandalone},
		{software: "VANILLA", kind: gameServerKindVelocityBackend},
		{software: "VELOCITY", kind: gameServerKindStandalone},
		{software: "PAPER", kind: gameServerKindVelocity},
	}
	for _, test := range tests {
		if got := needsVestriPlugin(test.software, test.kind); got != test.want {
			t.Errorf("needsVestriPlugin(%q, %q) = %v, want %v", test.software, test.kind, got, test.want)
		}
	}
}

func TestTrackedVestriPluginRelease(t *testing.T) {
	original := pluginHTTPClient
	t.Cleanup(func() { pluginHTTPClient = original })
	checksum := strings.Repeat("a", 64)
	pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(req *http.Request) (*http.Response, error) {
		body, _ := json.Marshal(map[string]interface{}{"tag_name": "latest", "assets": []map[string]string{{
			"name":                 "vestri-dynamic-servers-1.0.0.jar",
			"browser_download_url": "https://github.com/dhernos/vestri-plugin/releases/download/latest/vestri-dynamic-servers-1.0.0.jar",
			"digest":               "sha256:" + checksum,
		}}})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	source, err := parsePluginSource("https://github.com/dhernos/vestri-plugin/releases/tag/latest")
	if err != nil || source != vestriPluginSource() {
		t.Fatalf("source = %+v, error = %v", source, err)
	}
	targets := []pluginCompatibilityTarget{{ServerRef: "paper", Platform: "PAPER"},
		{ServerRef: "proxy", Platform: "VELOCITY"}, {ServerRef: "fabric", Platform: "FABRIC"}}
	first, refs, err := latestPluginRelease(context.Background(), source, targets)
	if err != nil || first.Filename != vestriPluginFilename || len(refs) != 2 {
		t.Fatalf("release = %+v, refs = %v, error = %v", first, refs, err)
	}
	checksum = strings.Repeat("b", 64)
	second, _, err := latestPluginRelease(context.Background(), source, targets)
	if err != nil || first.Version == second.Version {
		t.Fatalf("mutable latest tag must detect new checksum: %+v, error = %v", second, err)
	}
	if _, _, err := latestPluginRelease(context.Background(), pluginSource{Provider: "github", Project: "other/plugin"}, targets); err == nil {
		t.Fatal("accepted an unrelated GitHub plugin source")
	}
}

func TestResolveVestriPluginRelease(t *testing.T) {
	original := pluginHTTPClient
	t.Cleanup(func() { pluginHTTPClient = original })
	asset := map[string]string{"name": "vestri-dynamic-servers-2.0.0.jar",
		"browser_download_url": "https://github.com/dhernos/vestri-plugin/releases/download/latest/vestri-dynamic-servers-2.0.0.jar",
		"digest":               "sha256:" + strings.Repeat("a", 64)}
	tests := []struct {
		name   string
		tag    string
		assets []map[string]string
		fail   bool
	}{
		{"valid versioned JAR", "latest", []map[string]string{asset}, false},
		{"missing JAR", "latest", nil, true},
		{"wrong tag", "v2.0.0", []map[string]string{asset}, true},
		{"multiple JARs", "latest", []map[string]string{asset, asset}, true},
		{"missing digest", "latest", []map[string]string{{"name": asset["name"], "browser_download_url": asset["browser_download_url"]}}, true},
		{"foreign download", "latest", []map[string]string{{"name": asset["name"], "browser_download_url": "https://example.com/plugin.jar", "digest": asset["digest"]}}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]interface{}{"tag_name": test.tag, "assets": test.assets})
			pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() != vestriPluginReleaseAPI {
					t.Errorf("unexpected release endpoint %s", req.URL)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}
			release, err := resolveVestriPluginRelease(context.Background())
			if (err != nil) != test.fail {
				t.Fatalf("release = %+v, error = %v", release, err)
			}
			if !test.fail && (release.Filename != asset["name"] || release.SHA256 != strings.Repeat("a", 64)) {
				t.Fatalf("unexpected release %+v", release)
			}
		})
	}
}

func TestEnsureVestriPlugin(t *testing.T) {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, name := range []string{"plugin.yml", "velocity-plugin.json"} {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("plugin descriptor")); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	jar := buffer.Bytes()
	digest := sha256.Sum256(jar)
	assetName := "vestri-dynamic-servers-2.0.0.jar"
	assetURL := "https://github.com/dhernos/vestri-plugin/releases/download/latest/" + assetName
	tests := []struct {
		name         string
		software     string
		kind         string
		existing     bool
		badChecksum  bool
		uploadStatus int
		copyStatus   int
		saveStatus   int
		badManifest  bool
		pending      bool
		missingStage bool
		fail         bool
	}{
		{name: "Paper backend installs and skips next start", software: "PAPER", kind: gameServerKindVelocityBackend},
		{name: "Velocity installs and skips next start", software: "VELOCITY", kind: gameServerKindVelocity},
		{name: "already installed avoids GitHub", software: "PAPER", kind: gameServerKindVelocityBackend, existing: true},
		{name: "Vanilla backend skips all work", software: "VANILLA", kind: gameServerKindVelocityBackend},
		{name: "standalone Paper skips all work", software: "PAPER", kind: gameServerKindStandalone},
		{name: "checksum failure preserves old plugin", software: "PAPER", kind: gameServerKindVelocityBackend, badChecksum: true, fail: true},
		{name: "upload failure preserves old plugin", software: "PAPER", kind: gameServerKindVelocityBackend, uploadStatus: 500, fail: true},
		{name: "copy failure preserves old plugin", software: "VELOCITY", kind: gameServerKindVelocity, copyStatus: 500, fail: true},
		{name: "tracking save failure preserves old plugin", software: "PAPER", kind: gameServerKindVelocityBackend, saveStatus: 500, fail: true},
		{name: "invalid tracking fails closed", software: "PAPER", kind: gameServerKindVelocityBackend, badManifest: true, fail: true},
		{name: "pending update is not overwritten", software: "PAPER", kind: gameServerKindVelocityBackend, pending: true, fail: true},
		{name: "missing tracked staged file fails closed", software: "VELOCITY", kind: gameServerKindVelocity, missingStage: true, fail: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := pluginHTTPClient
			t.Cleanup(func() { pluginHTTPClient = original })
			downloads := 0
			pluginHTTPClient = &http.Client{Transport: pluginRoundTripper(func(req *http.Request) (*http.Response, error) {
				downloads++
				var body []byte
				switch req.URL.String() {
				case vestriPluginReleaseAPI:
					checksum := hex.EncodeToString(digest[:])
					if test.badChecksum {
						checksum = strings.Repeat("0", 64)
					}
					body, _ = json.Marshal(map[string]interface{}{"tag_name": "latest", "assets": []map[string]string{
						{"name": assetName, "browser_download_url": assetURL, "digest": "sha256:" + checksum},
					}})
				case assetURL:
					body = jar
				default:
					t.Errorf("unexpected download URL %s", req.URL)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			root := "minecraft-test"
			nodeID := "node-test"
			destination := path.Join(root, "data/plugins", vestriPluginFilename)
			oldPath := path.Join(root, "data/plugins/vestri-dynamic-servers-1.0.0.jar")
			files := map[string][]byte{oldPath: []byte("old version")}
			manifestPath := path.Join(minecraftLibraryPath(nodeID), "tracked-plugins.json")
			unrelated := trackedPlugin{ID: "modrinth:other", Source: pluginSource{Provider: "modrinth", Project: "other"},
				Installed: pluginRelease{Filename: "OtherPlugin.jar"}, Filenames: []string{"OtherPlugin.jar"}}
			files[manifestPath], _ = json.Marshal(pluginManifest{Plugins: []trackedPlugin{unrelated}})
			if test.badManifest {
				files[manifestPath] = []byte("{invalid")
			}
			if test.pending || test.missingStage {
				files[manifestPath], _ = json.Marshal(pluginManifest{Plugins: []trackedPlugin{unrelated, {
					ID: "github:dhernos/vestri-plugin", Source: vestriPluginSource(),
					Installed: pluginRelease{Filename: vestriPluginFilename}, Filenames: []string{vestriPluginFilename}, Pending: test.pending,
				}}})
			}
			files[path.Join(minecraftPluginLibraryPath(nodeID), "OtherPlugin.jar")] = []byte("unrelated plugin")
			originalManifest := bytes.Clone(files[manifestPath])
			if test.existing {
				files[destination] = jar
			}
			var mutex sync.Mutex
			requests := 0
			workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				mutex.Lock()
				defer mutex.Unlock()
				requests++
				if request.Header.Get("X-API-Key") != "worker-test-key" {
					t.Error("worker request missing authentication")
				}
				if request.URL.Path == "/fs/list" {
					directory := request.URL.Query().Get("path")
					var entries []map[string]interface{}
					for filename := range files {
						if path.Dir(filename) == directory {
							entries = append(entries, map[string]interface{}{"name": path.Base(filename), "type": "file"})
						}
					}
					_ = json.NewEncoder(response).Encode(entries)
					return
				}
				if request.URL.Path == "/fs/read" {
					content, exists := files[request.URL.Query().Get("path")]
					if !exists {
						response.WriteHeader(http.StatusNotFound)
					} else {
						_, _ = response.Write(content)
					}
					return
				}
				if request.URL.Path == "/fs/upload" {
					if err := request.ParseMultipartForm(1 << 20); err != nil {
						t.Errorf("invalid multipart upload: %v", err)
						response.WriteHeader(400)
						return
					}
					defer request.MultipartForm.RemoveAll()
					file, _, err := request.FormFile("file")
					if err != nil {
						t.Errorf("missing uploaded file: %v", err)
						response.WriteHeader(400)
						return
					}
					defer file.Close()
					contents, _ := io.ReadAll(file)
					if !bytes.Equal(contents, jar) {
						t.Error("worker received different JAR contents")
					}
					if test.uploadStatus != 0 {
						response.WriteHeader(test.uploadStatus)
						return
					}
					files[request.FormValue("path")] = contents
					return
				}
				var payload map[string]interface{}
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
					t.Errorf("invalid worker payload: %v", err)
					response.WriteHeader(400)
					return
				}
				switch request.URL.Path {
				case "/fs/mkdir":
					response.WriteHeader(http.StatusCreated)
				case "/fs/write":
					if test.saveStatus != 0 {
						response.WriteHeader(test.saveStatus)
						return
					}
					files[payload["path"].(string)] = []byte(payload["content"].(string))
				case "/fs/copy":
					if test.copyStatus != 0 {
						response.WriteHeader(test.copyStatus)
						return
					}
					files[payload["dest"].(string)] = files[payload["source"].(string)]
				case "/fs/delete":
					delete(files, payload["path"].(string))
				default:
					t.Errorf("unexpected worker endpoint %s", request.URL.Path)
					response.WriteHeader(404)
				}
			}))
			t.Cleanup(workerServer.Close)
			baseURL, _ := url.Parse(workerServer.URL)
			server := &Server{}
			err := server.ensureVestriPlugin(context.Background(), baseURL, "worker-test-key", nodeID, root, test.software, test.kind)
			if (err != nil) != test.fail {
				t.Fatalf("install error = %v, want failure %v", err, test.fail)
			}
			mutex.Lock()
			if !needsVestriPlugin(test.software, test.kind) {
				if requests != 0 || downloads != 0 {
					t.Error("ineligible server caused network/filesystem calls")
				}
			} else if test.fail {
				if _, exists := files[destination]; exists {
					t.Error("failed install deployed a plugin")
				}
				if _, exists := files[oldPath]; !exists {
					t.Error("failed install removed old plugin")
				}
				if !bytes.Equal(files[manifestPath], originalManifest) {
					t.Error("failed automatic registration changed existing tracking")
				}
			} else if !bytes.Equal(files[destination], jar) {
				t.Error("installed plugin does not match verified release")
			}
			if !test.fail && needsVestriPlugin(test.software, test.kind) {
				if _, exists := files[oldPath]; exists {
					t.Error("installation left a duplicate old Vestri plugin")
				}
				if !bytes.Equal(files[path.Join(minecraftPluginLibraryPath(nodeID), vestriPluginFilename)], jar) {
					t.Error("plugin was not copied into node staging")
				}
				var manifest pluginManifest
				if err := json.Unmarshal(files[manifestPath], &manifest); err != nil || len(manifest.Plugins) != 2 {
					t.Errorf("missing plugin tracking: %+v, error = %v", manifest, err)
				}
				plugin := manifest.Plugins[len(manifest.Plugins)-1]
				if plugin.Source != vestriPluginSource() || plugin.Installed.Filename != vestriPluginFilename {
					t.Errorf("unexpected tracking entry %+v", plugin)
				}
				if test.existing && plugin.Installed.Version != "unknown" {
					t.Error("adoption must not pretend an existing JAR is the latest release")
				}
				if manifest.Plugins[0].ID != unrelated.ID || string(files[path.Join(minecraftPluginLibraryPath(nodeID), "OtherPlugin.jar")]) != "unrelated plugin" {
					t.Error("automatic tracking changed an unrelated plugin")
				}
			}
			for filename := range files {
				if strings.Contains(filename, "/downloads/") || strings.HasSuffix(filename, ".tmp") {
					t.Errorf("staged download was not cleaned up: %s", filename)
				}
			}
			mutex.Unlock()
			if !test.fail {
				before := downloads
				if err := server.ensureVestriPlugin(context.Background(), baseURL, "worker-test-key", nodeID, root, test.software, test.kind); err != nil {
					t.Fatal(err)
				}
				if downloads != before {
					t.Error("repeat start re-downloaded installed plugin")
				}
				if needsVestriPlugin(test.software, test.kind) {
					secondRoot := "second-server"
					if err := server.ensureVestriPlugin(context.Background(), baseURL, "worker-test-key", nodeID, secondRoot, test.software, test.kind); err != nil {
						t.Fatal(err)
					}
					mutex.Lock()
					if !bytes.Equal(files[path.Join(secondRoot, "data/plugins", vestriPluginFilename)], jar) {
						t.Error("new server did not reuse the staged plugin")
					}
					var manifest pluginManifest
					_ = json.Unmarshal(files[manifestPath], &manifest)
					if len(manifest.Plugins) != 2 {
						t.Error("new server created duplicate tracking entries")
					}
					updatedBytes := []byte("new staged version")
					files[path.Join(minecraftPluginLibraryPath(nodeID), vestriPluginFilename)] = updatedBytes
					manifest.Plugins[1].Installed.Version = "updated-release"
					files[manifestPath], _ = json.Marshal(manifest)
					mutex.Unlock()
					if err := server.ensureVestriPlugin(context.Background(), baseURL, "worker-test-key", nodeID, root, test.software, test.kind); err != nil {
						t.Fatal(err)
					}
					thirdRoot := "third-server"
					if err := server.ensureVestriPlugin(context.Background(), baseURL, "worker-test-key", nodeID, thirdRoot, test.software, test.kind); err != nil {
						t.Fatal(err)
					}
					mutex.Lock()
					if !bytes.Equal(files[path.Join(thirdRoot, "data/plugins", vestriPluginFilename)], updatedBytes) ||
						!bytes.Equal(files[path.Join(minecraftPluginLibraryPath(nodeID), vestriPluginFilename)], updatedBytes) {
						t.Error("automatic installation downgraded the updated staging copy")
					}
					mutex.Unlock()
					if downloads != before {
						t.Error("new servers should reuse staging without GitHub requests")
					}
				}
			}
			if test.existing && downloads != 0 {
				t.Error("installed plugin should not require GitHub availability")
			}
			if (test.badManifest || test.pending || test.missingStage) && downloads != 0 {
				t.Error("broken tracking must not be overwritten by a fresh download")
			}
		})
	}
}

func TestVestriPluginDownloadHosts(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://github.com/dhernos/vestri-plugin/releases/download/latest/plugin.jar":            true,
		"https://release-assets.githubusercontent.com/github-production-release-asset/plugin.jar": true,
		"https://github.com/another/plugin/releases/download/latest/plugin.jar":                   false,
		"https://github.com/dhernos/vestri-plugin/releases/download/v1/plugin.jar":                false,
		"http://github.com/dhernos/vestri-plugin/releases/download/latest/plugin.jar":             false,
		"https://release-assets.githubusercontent.com.attacker.example/plugin.jar":                false,
	} {
		target, _ := url.Parse(raw)
		if got := trustedPluginDownloadURL(target); got != want {
			t.Errorf("trustedPluginDownloadURL(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestLiveVestriPluginRelease(t *testing.T) {
	if os.Getenv("VESTRI_PLUGIN_RELEASE_TEST") != "1" {
		t.Skip("set VESTRI_PLUGIN_RELEASE_TEST=1 to verify the published GitHub release")
	}
	release, err := resolveVestriPluginRelease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	file, err := downloadVerifiedPlugin(context.Background(), release)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	defer os.Remove(file.Name())
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(file, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	paper, velocity := false, false
	for _, entry := range archive.File {
		paper = paper || entry.Name == "plugin.yml" || entry.Name == "paper-plugin.yml"
		velocity = velocity || entry.Name == "velocity-plugin.json"
	}
	if !paper || !velocity {
		t.Fatal("published JAR does not contain both Paper and Velocity descriptors")
	}
	t.Logf("Verified %s (%d bytes), SHA256 %s", release.Filename, info.Size(), release.SHA256)
}
