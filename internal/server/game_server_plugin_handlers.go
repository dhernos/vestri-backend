package server

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"yourapp/internal/auth"
)

const pluginCheckInterval = 6 * time.Hour
const maxTrackedPlugins = 100
const maxPluginDownloadBytes = 128 << 20

type trackedPlugin struct {
	ID              string        `json:"id"`
	Source          pluginSource  `json:"source"`
	GameVersion     string        `json:"gameVersion"`
	VelocityVersion string        `json:"velocityVersion,omitempty"`
	Installed       pluginRelease `json:"installed"`
	Latest          pluginRelease `json:"latest"`
	Filenames       []string      `json:"filenames"`
	CheckedAt       time.Time     `json:"checkedAt"`
	CheckError      string        `json:"checkError,omitempty"`
	Pending         bool          `json:"pending"`
}

type pluginManifest struct {
	Plugins []trackedPlugin `json:"plugins"`
}

type pluginWorker struct {
	server  *Server
	baseURL *url.URL
	apiKey  string
	root    string
}

func (worker pluginWorker) request(ctx context.Context, endpoint string, payload interface{}) error {
	code, _, err := worker.server.callWorkerJSON(ctx, worker.baseURL, worker.apiKey, http.MethodPost, endpoint, payload)
	if err != nil {
		return err
	}
	if endpoint == "/fs/delete" && code == http.StatusNotFound {
		return nil
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("worker %s failed (HTTP %d)", endpoint, code)
	}
	return nil
}

func (worker pluginWorker) manifestPath() string {
	return path.Join(worker.root, velocityPluginStagingRelativePath, "tracked-plugins.json")
}

func validPluginFilename(name string) bool {
	return safeSatisfactoryDirectoryName(name) && path.Base(name) == name && strings.HasSuffix(strings.ToLower(name), ".jar")
}

func (worker pluginWorker) load(ctx context.Context) (pluginManifest, error) {
	manifest := pluginManifest{Plugins: []trackedPlugin{}}
	code, body, err := worker.server.callWorkerJSON(ctx, worker.baseURL, worker.apiKey, http.MethodGet, "/fs/read?path="+url.QueryEscape(worker.manifestPath()), nil)
	if err != nil {
		return manifest, err
	}
	if code == http.StatusNotFound {
		return manifest, nil
	}
	if code != http.StatusOK {
		return manifest, fmt.Errorf("failed to read plugin tracking manifest (HTTP %d)", code)
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return manifest, fmt.Errorf("plugin tracking manifest is invalid")
	}
	if len(manifest.Plugins) > maxTrackedPlugins {
		return manifest, fmt.Errorf("too many tracked plugins")
	}
	for _, plugin := range manifest.Plugins {
		if !validPluginFilename(plugin.Installed.Filename) {
			return manifest, fmt.Errorf("invalid tracked plugin filename")
		}
		for _, filename := range plugin.Filenames {
			if !validPluginFilename(filename) {
				return manifest, fmt.Errorf("invalid tracked plugin history")
			}
		}
	}
	if manifest.Plugins == nil {
		manifest.Plugins = []trackedPlugin{}
	}
	return manifest, nil
}

func (worker pluginWorker) save(ctx context.Context, manifest pluginManifest) error {
	if err := worker.server.workerMkdirAll(ctx, worker.baseURL, worker.apiKey, path.Dir(worker.manifestPath())); err != nil {
		return err
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	temporary := worker.manifestPath() + "." + auth.NewSessionID() + ".tmp"
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = worker.request(cleanupCtx, "/fs/delete", map[string]string{"path": temporary})
	}()
	if err := worker.request(ctx, "/fs/write", map[string]string{"path": temporary, "content": string(body)}); err != nil {
		return err
	}
	return worker.request(ctx, "/fs/copy", map[string]string{"source": temporary, "dest": worker.manifestPath()})
}

func (s *Server) lockPluginGroup(ctx context.Context, serverID string) (func(), error) {
	if s.Redis == nil {
		return nil, fmt.Errorf("plugin locking is unavailable")
	}
	key, token := "plugins:lock:"+serverID, auth.NewSessionID()
	locked, err := s.Redis.SetNX(ctx, key, token, 10*time.Minute).Result()
	if err != nil {
		return nil, fmt.Errorf("plugin locking is unavailable")
	}
	if !locked {
		return nil, fmt.Errorf("another plugin operation is in progress; try again shortly")
	}
	return func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Redis.Eval(unlockCtx, `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`, []string{key}, token)
	}, nil
}

func (s *Server) paperPluginTargets(ctx context.Context, userID string, node *auth.WorkerNode, parentID, velocityVersion string) ([]auth.GameServer, string, string, error) {
	velocityVersion = strings.TrimSpace(velocityVersion)
	if velocityVersion == "" || strings.EqualFold(velocityVersion, "latest") {
		return nil, "", "", fmt.Errorf("set an explicit Velocity version first")
	}
	servers, err := s.Users.ListGameServersForNode(ctx, node.ID)
	if err != nil {
		return nil, "", "", err
	}
	var targets []auth.GameServer
	gameVersion := ""
	for _, candidate := range servers {
		metadata := parseGameServerMetadata(candidate.Metadata)
		software := strings.ToUpper(strings.TrimSpace(metadata.SoftwareVersion))
		if metadata.ParentServerID != parentID || (software != "PAPER" && software != "PURPUR") {
			continue
		}
		access, err := s.Users.FindAccessibleGameServerByRefForNode(ctx, userID, node, candidate.ID)
		if err != nil {
			return nil, "", "", err
		}
		if access == nil || !canManageGameServerFiles(access.AccessRole) {
			return nil, "", "", fmt.Errorf("file-management permission is required on every Paper/Purpur subserver")
		}
		version := strings.TrimSpace(metadata.GameVersion)
		if version == "" || strings.EqualFold(version, "latest") {
			return nil, "", "", fmt.Errorf("set an explicit Minecraft version on every Paper/Purpur subserver first")
		}
		if gameVersion != "" && gameVersion != version {
			return nil, "", "", fmt.Errorf("Paper/Purpur subservers must use the same Minecraft version for a shared plugin release")
		}
		gameVersion = version
		targets = append(targets, candidate)
	}
	if len(targets) > maxGroupApplyServers {
		return nil, "", "", fmt.Errorf("too many subservers")
	}
	if len(targets) == 0 {
		return nil, "", "", fmt.Errorf("add a Paper or Purpur subserver with an explicit Minecraft version first")
	}
	return targets, gameVersion, velocityVersion, nil
}

func (s *Server) handleTrackedPlugins(w http.ResponseWriter, r *http.Request) {
	s.handlePluginOperation(w, r, "list")
}

func (s *Server) handleImportPlugin(w http.ResponseWriter, r *http.Request) {
	s.handlePluginOperation(w, r, "import")
}

func (s *Server) handleUpdatePlugin(w http.ResponseWriter, r *http.Request) {
	s.handlePluginOperation(w, r, "update")
}

func (s *Server) handleRemovePluginTracking(w http.ResponseWriter, r *http.Request) {
	s.handlePluginOperation(w, r, "remove")
}

func (s *Server) handlePluginOperation(w http.ResponseWriter, r *http.Request, operation string) {
	sess, node, parent, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(role) {
		writeError(w, http.StatusForbidden, "Server permission denied for plugin management")
		return
	}
	if !isVelocityServer(parent) {
		writeError(w, http.StatusBadRequest, "Plugin staging is only available for Velocity servers")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	unlock, err := s.lockPluginGroup(ctx, parent.ID)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	defer unlock()
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	worker := pluginWorker{server: s, baseURL: baseURL, apiKey: apiKey, root: parent.RootPath}
	manifest, err := worker.load(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if operation == "list" {
		velocityVersion := strings.TrimSpace(parseGameServerMetadata(parent.Metadata).GameVersion)
		changed := false
		for index := range manifest.Plugins {
			plugin := &manifest.Plugins[index]
			versionChanged := plugin.VelocityVersion != velocityVersion
			plugin.VelocityVersion = velocityVersion
			if !versionChanged && time.Since(plugin.CheckedAt) < pluginCheckInterval {
				continue
			}
			if velocityVersion == "" || strings.EqualFold(velocityVersion, "latest") {
				plugin.CheckError = "set an explicit Velocity version first"
				plugin.CheckedAt = time.Now().UTC()
				changed = true
				continue
			}
			release, checkErr := latestPluginRelease(ctx, plugin.Source, plugin.GameVersion, velocityVersion)
			plugin.CheckedAt = time.Now().UTC()
			plugin.CheckError = ""
			if checkErr != nil {
				plugin.CheckError = checkErr.Error()
			} else {
				plugin.Latest = release
			}
			changed = true
		}
		if changed {
			if err := worker.save(ctx, manifest); err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
		}
		writeJSON(w, http.StatusOK, manifest)
		return
	}
	var request struct {
		URL string `json:"url"`
		ID  string `json:"id"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if operation == "remove" {
		found := false
		for index, plugin := range manifest.Plugins {
			if plugin.ID == request.ID {
				manifest.Plugins = append(manifest.Plugins[:index], manifest.Plugins[index+1:]...)
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusNotFound, "Tracked plugin not found")
			return
		}
		if err := worker.save(ctx, manifest); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, manifest)
		return
	}
	velocityVersion := strings.TrimSpace(parseGameServerMetadata(parent.Metadata).GameVersion)
	targets, gameVersion, velocityVersion, err := s.paperPluginTargets(ctx, sess.UserID, node, parent.ID, velocityVersion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	index := -1
	var plugin trackedPlugin
	if operation == "import" {
		source, err := parsePluginSource(request.URL)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		plugin = trackedPlugin{ID: source.Provider + ":" + strings.ToLower(source.Project), Source: source, GameVersion: gameVersion, VelocityVersion: velocityVersion}
		for _, existing := range manifest.Plugins {
			if existing.ID == plugin.ID {
				writeError(w, http.StatusConflict, "Plugin is already tracked; use its update button")
				return
			}
		}
		if len(manifest.Plugins) >= maxTrackedPlugins {
			writeError(w, http.StatusBadRequest, "Too many tracked plugins")
			return
		}
	} else {
		for candidate, existing := range manifest.Plugins {
			if existing.ID == request.ID {
				index, plugin = candidate, existing
				break
			}
		}
		if index < 0 {
			writeError(w, http.StatusNotFound, "Tracked plugin not found")
			return
		}
		plugin.GameVersion = gameVersion
		plugin.VelocityVersion = velocityVersion
	}
	release, err := latestPluginRelease(ctx, plugin.Source, gameVersion, velocityVersion)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	for _, existing := range manifest.Plugins {
		if existing.ID == plugin.ID {
			continue
		}
		for _, filename := range existing.Filenames {
			if filename == release.Filename {
				writeError(w, http.StatusConflict, "Release filename conflicts with another tracked plugin")
				return
			}
		}
	}
	temporary, err := downloadVerifiedPlugin(ctx, release)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	tempPath := path.Join(parent.RootPath, velocityPluginStagingRelativePath, "downloads", auth.NewSessionID()+".jar")
	if err := worker.upload(ctx, temporary, tempPath); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = worker.request(cleanupCtx, "/fs/delete", map[string]string{"path": tempPath})
	}()
	plugin.Latest, plugin.CheckedAt, plugin.CheckError = release, time.Now().UTC(), ""
	if !containsPluginFilename(plugin.Filenames, release.Filename) {
		plugin.Filenames = append(plugin.Filenames, release.Filename)
	}
	if operation == "import" {
		plugin.Installed = release
		manifest.Plugins = append(manifest.Plugins, plugin)
		index = len(manifest.Plugins) - 1
	}
	plugin.Pending = true
	manifest.Plugins[index] = plugin
	if err := worker.save(ctx, manifest); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	staging := path.Join(parent.RootPath, velocityPluginStagingRelativePath, stagingPluginsDirName)
	if err := worker.replace(ctx, tempPath, staging, release.Filename, plugin.Filenames); err != nil {
		writeError(w, http.StatusBadGateway, "Plugin staging failed; retry the update: "+err.Error())
		return
	}
	if operation == "update" {
		for _, target := range targets {
			if err := worker.replace(ctx, tempPath, path.Join(target.RootPath, backendPluginsRelativePath), release.Filename, plugin.Filenames); err != nil {
				writeError(w, http.StatusBadGateway, "Plugin deployment partially completed; retry the update: "+err.Error())
				return
			}
		}
	}
	plugin.Installed, plugin.Pending = release, false
	manifest.Plugins[index] = plugin
	if err := worker.save(ctx, manifest); err != nil {
		writeError(w, http.StatusBadGateway, "Plugin files changed, but tracking could not be saved; retry the update")
		return
	}
	writeJSON(w, http.StatusOK, manifest)
}

func containsPluginFilename(names []string, name string) bool {
	for _, existing := range names {
		if existing == name {
			return true
		}
	}
	return false
}

func (worker pluginWorker) replace(ctx context.Context, source, directory, filename string, history []string) error {
	if !validPluginFilename(filename) {
		return fmt.Errorf("invalid plugin filename")
	}
	for _, old := range history {
		if !validPluginFilename(old) {
			return fmt.Errorf("invalid plugin history")
		}
	}
	if err := worker.request(ctx, "/fs/copy", map[string]string{"source": source, "dest": path.Join(directory, filename)}); err != nil {
		return err
	}
	for _, old := range history {
		if old == filename {
			continue
		}
		if err := worker.request(ctx, "/fs/delete", map[string]string{"path": path.Join(directory, old)}); err != nil {
			return err
		}
	}
	return nil
}

func downloadVerifiedPlugin(ctx context.Context, release pluginRelease) (*os.File, error) {
	target, err := url.Parse(release.URL)
	if err != nil || !trustedPluginDownloadURL(target) {
		return nil, fmt.Errorf("untrusted plugin download URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, release.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Vestri/1 (Minecraft plugin manager)")
	resp, err := pluginHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("plugin download returned HTTP %d", resp.StatusCode)
	}
	temporary, err := os.CreateTemp("", "vestri-plugin-*.jar")
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			temporary.Close()
			os.Remove(temporary.Name())
		}
	}()
	hash512, hash256 := sha512.New(), sha256.New()
	size, err := io.Copy(io.MultiWriter(temporary, hash512, hash256), io.LimitReader(resp.Body, maxPluginDownloadBytes+1))
	if err != nil {
		return nil, err
	}
	if size > maxPluginDownloadBytes {
		return nil, fmt.Errorf("plugin exceeds the 128 MiB download limit")
	}
	if release.SHA512 == "" && release.SHA256 == "" {
		return nil, fmt.Errorf("missing plugin checksum")
	}
	if release.SHA512 != "" && !strings.EqualFold(release.SHA512, hex.EncodeToString(hash512.Sum(nil))) || release.SHA256 != "" && !strings.EqualFold(release.SHA256, hex.EncodeToString(hash256.Sum(nil))) {
		return nil, fmt.Errorf("plugin checksum verification failed")
	}
	archive, err := zip.NewReader(temporary, size)
	if err != nil {
		return nil, fmt.Errorf("download is not a valid plugin JAR")
	}
	valid := false
	for _, entry := range archive.File {
		if entry.Name == "plugin.yml" || entry.Name == "paper-plugin.yml" {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf("JAR is missing its Paper/Bukkit plugin descriptor")
	}
	keep = true
	return temporary, nil
}

func (worker pluginWorker) upload(ctx context.Context, file *os.File, target string) error {
	if err := worker.server.workerMkdirAll(ctx, worker.baseURL, worker.apiKey, path.Dir(target)); err != nil {
		return err
	}
	reader, writer := io.Pipe()
	form := multipart.NewWriter(writer)
	defer reader.Close()
	completed := make(chan error, 1)
	go func() { completed <- streamUploadMultipartToWorker(form, writer, file, target, "plugin.jar") }()
	response, err := worker.server.callWorkerStream(ctx, worker.baseURL, worker.apiKey, http.MethodPost, "/fs/upload", "", form.FormDataContentType(), reader)
	if err != nil {
		reader.CloseWithError(err)
		<-completed
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		reader.Close()
		<-completed
		return fmt.Errorf("worker plugin upload failed (HTTP %d)", response.StatusCode)
	}
	return <-completed
}
