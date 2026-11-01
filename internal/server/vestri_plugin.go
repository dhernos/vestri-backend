package server

import (
	"archive/zip"
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"yourapp/internal/auth"
)

const vestriPluginFilename = "vestri-dynamic-servers.jar"
const vestriPluginReleaseAPI = "https://api.github.com/repos/dhernos/vestri-plugin/releases/tags/latest"

func vestriPluginSource() pluginSource {
	return pluginSource{Provider: "github", Project: "dhernos/vestri-plugin"}
}

func needsVestriPlugin(software string) bool {
	switch normalizeMinecraftSoftware(software) {
	case minecraftSoftwarePaper, minecraftSoftwareVelocity:
		return true
	default:
		return false
	}
}

func resolveVestriPluginRelease(ctx context.Context) (pluginRelease, error) {
	var response struct {
		TagName string `json:"tag_name"`
		Draft   bool   `json:"draft"`
		Assets  []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := pluginAPIJSON(ctx, vestriPluginReleaseAPI, &response); err != nil {
		return pluginRelease{}, err
	}
	if response.TagName != "latest" || response.Draft {
		return pluginRelease{}, fmt.Errorf("Vestri plugin latest release is unavailable")
	}
	var release pluginRelease
	for _, asset := range response.Assets {
		if !strings.HasSuffix(strings.ToLower(asset.Name), ".jar") {
			continue
		}
		if release.URL != "" {
			return pluginRelease{}, fmt.Errorf("Vestri plugin release contains multiple JARs")
		}
		target, err := url.Parse(asset.URL)
		if !validPluginFilename(asset.Name) || err != nil || target.Scheme != "https" || target.Host != "github.com" ||
			target.User != nil || target.RawQuery != "" || target.Fragment != "" ||
			target.Path != "/dhernos/vestri-plugin/releases/download/latest/"+asset.Name {
			return pluginRelease{}, fmt.Errorf("invalid Vestri plugin release asset")
		}
		checksum := strings.TrimPrefix(asset.Digest, "sha256:")
		if !strings.HasPrefix(asset.Digest, "sha256:") || len(checksum) != 64 {
			return pluginRelease{}, fmt.Errorf("Vestri plugin release requires a SHA256 digest")
		}
		if _, err := hex.DecodeString(checksum); err != nil {
			return pluginRelease{}, fmt.Errorf("invalid Vestri plugin SHA256 digest")
		}
		release = pluginRelease{Version: asset.Name + "@" + checksum, Filename: asset.Name, URL: asset.URL, SHA256: checksum}
	}
	if release.URL == "" {
		return pluginRelease{}, fmt.Errorf("Vestri plugin release has no JAR asset")
	}
	return release, nil
}

func (s *Server) ensureVestriPlugin(ctx context.Context, baseURL *url.URL, apiKey, nodeID, rootPath, software string) error {
	if !needsVestriPlugin(software) {
		return nil
	}
	directory := path.Join(rootPath, backendPluginsRelativePath)
	if err := s.workerMkdirAll(ctx, baseURL, apiKey, directory); err != nil {
		return err
	}
	entries, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, directory)
	if err != nil {
		return err
	}
	worker := pluginWorker{server: s, baseURL: baseURL, apiKey: apiKey, root: minecraftLibraryPath(nodeID)}
	manifest, err := worker.load(ctx)
	if err != nil {
		return err
	}
	history := []string{}
	installed := false
	for _, entry := range entries {
		if entry.Name == vestriPluginFilename && entry.Type == "file" {
			installed = true
		}
		if entry.Type == "file" && strings.HasPrefix(entry.Name, "vestri-dynamic-servers-") && validPluginFilename(entry.Name) {
			history = append(history, entry.Name)
		}
	}
	staging := minecraftPluginLibraryPath(nodeID)
	for _, plugin := range manifest.Plugins {
		if plugin.ID != "github:dhernos/vestri-plugin" {
			continue
		}
		if plugin.Source != vestriPluginSource() || plugin.Installed.Filename != vestriPluginFilename {
			return fmt.Errorf("invalid Vestri plugin tracking entry")
		}
		if plugin.Pending {
			return fmt.Errorf("Vestri plugin update is pending; retry its update in plugin staging")
		}
		stagedEntries, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, staging)
		if err != nil {
			return err
		}
		for _, entry := range stagedEntries {
			if entry.Name == vestriPluginFilename && entry.Type == "file" {
				if installed {
					for _, filename := range history {
						if err := worker.request(ctx, "/fs/delete", map[string]string{"path": path.Join(directory, filename)}); err != nil {
							return err
						}
					}
					return nil
				}
				return worker.replace(ctx, path.Join(staging, vestriPluginFilename), directory, vestriPluginFilename, history)
			}
		}
		return fmt.Errorf("tracked Vestri plugin is missing from staging; retry its update in plugin staging")
	}
	if len(manifest.Plugins) >= maxTrackedPlugins {
		return fmt.Errorf("too many tracked plugins to register Vestri plugin")
	}
	for _, plugin := range manifest.Plugins {
		if containsPluginFilename(plugin.Filenames, vestriPluginFilename) || plugin.Installed.Filename == vestriPluginFilename {
			return fmt.Errorf("Vestri plugin filename conflicts with another tracked plugin")
		}
	}
	if installed {
		release := pluginRelease{Version: "unknown", Filename: vestriPluginFilename}
		if err := registerVestriPlugin(ctx, worker, nodeID, manifest, path.Join(directory, vestriPluginFilename), release, history); err != nil {
			return err
		}
		for _, filename := range history {
			if err := worker.request(ctx, "/fs/delete", map[string]string{"path": path.Join(directory, filename)}); err != nil {
				return err
			}
		}
		return nil
	}
	release, err := resolveVestriPluginRelease(ctx)
	if err != nil {
		return err
	}
	file, err := downloadVerifiedPlugin(ctx, release)
	if err != nil {
		return err
	}
	defer file.Close()
	defer os.Remove(file.Name())
	info, err := file.Stat()
	if err != nil {
		return err
	}
	archive, err := zip.NewReader(file, info.Size())
	if err != nil {
		return err
	}
	paper, velocity := false, false
	for _, entry := range archive.File {
		paper = paper || entry.Name == "plugin.yml" || entry.Name == "paper-plugin.yml"
		velocity = velocity || entry.Name == "velocity-plugin.json"
	}
	if !paper || !velocity {
		return fmt.Errorf("Vestri plugin JAR must support both Paper and Velocity")
	}
	staged := path.Join(worker.root, "downloads", auth.NewSessionID()+".jar")
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = worker.request(cleanupCtx, "/fs/delete", map[string]string{"path": staged})
	}()
	if err := worker.upload(ctx, file, staged); err != nil {
		return err
	}
	release.Filename = vestriPluginFilename
	if err := registerVestriPlugin(ctx, worker, nodeID, manifest, staged, release, history); err != nil {
		return err
	}
	return worker.replace(ctx, path.Join(staging, vestriPluginFilename), directory, vestriPluginFilename, history)
}

func registerVestriPlugin(ctx context.Context, worker pluginWorker, nodeID string, manifest pluginManifest,
	source string, release pluginRelease, history []string) error {
	filenames := append([]string{vestriPluginFilename}, history...)
	if err := worker.server.workerMkdirAll(ctx, worker.baseURL, worker.apiKey, minecraftPluginLibraryPath(nodeID)); err != nil {
		return err
	}
	if err := worker.replace(ctx, source, minecraftPluginLibraryPath(nodeID), vestriPluginFilename, filenames); err != nil {
		return err
	}
	plugin := trackedPlugin{ID: "github:dhernos/vestri-plugin", Source: vestriPluginSource(),
		Installed: release, Latest: release, Filenames: filenames}
	if release.SHA256 != "" {
		plugin.CheckedAt = time.Now().UTC()
	}
	manifest.Plugins = append(manifest.Plugins, plugin)
	return worker.save(ctx, manifest)
}
