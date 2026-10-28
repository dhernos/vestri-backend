package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type pluginSource struct {
	Provider string `json:"provider"`
	Project  string `json:"project"`
}

type pluginRelease struct {
	Version  string `json:"version"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
	SHA512   string `json:"sha512,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

var pluginHTTPClient = &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 || !trustedPluginDownloadURL(req.URL) {
		return fmt.Errorf("untrusted plugin download redirect")
	}
	return nil
}}

func parsePluginSource(raw string) (pluginSource, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" || parsed.RawPath != "" {
		return pluginSource{}, fmt.Errorf("use an HTTPS Modrinth or Hangar plugin project link")
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	validPart := func(value string) bool {
		if value == "" || len(value) > 100 {
			return false
		}
		for _, char := range value {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
				return false
			}
		}
		return true
	}
	switch strings.ToLower(parsed.Host) {
	case "modrinth.com", "www.modrinth.com":
		if len(parts) >= 2 && parts[0] == "plugin" && validPart(parts[1]) {
			return pluginSource{Provider: "modrinth", Project: parts[1]}, nil
		}
	case "hangar.papermc.io":
		if len(parts) >= 2 && validPart(parts[0]) && validPart(parts[1]) {
			return pluginSource{Provider: "hangar", Project: parts[0] + "/" + parts[1]}, nil
		}
	}
	return pluginSource{}, fmt.Errorf("use a Modrinth /plugin/project or Hangar /author/project link")
}

func trustedPluginDownloadURL(target *url.URL) bool {
	if target.Scheme != "https" || target.User != nil || target.Port() != "" {
		return false
	}
	switch strings.ToLower(target.Host) {
	case "cdn.modrinth.com", "hangar.papermc.io", "hangarcdn.papermc.io":
		return true
	}
	return false
}

func pluginAPIJSON(ctx context.Context, endpoint string, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Vestri/1 (Minecraft plugin manager)")
	resp, err := pluginHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("plugin provider returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(dest)
}

func latestPluginRelease(ctx context.Context, source pluginSource, minecraftVersion string) (pluginRelease, error) {
	var release pluginRelease
	switch source.Provider {
	case "modrinth":
		query := url.Values{"loaders": {`["paper"]`}}
		if minecraftVersion != "" {
			versions, _ := json.Marshal([]string{minecraftVersion})
			query.Set("game_versions", string(versions))
		}
		var versions []struct {
			ID          string `json:"id"`
			VersionType string `json:"version_type"`
			Files       []struct {
				Filename string `json:"filename"`
				URL      string `json:"url"`
				Primary  bool   `json:"primary"`
				Hashes   struct {
					SHA512 string `json:"sha512"`
				} `json:"hashes"`
			} `json:"files"`
		}
		if err := pluginAPIJSON(ctx, "https://api.modrinth.com/v2/project/"+url.PathEscape(source.Project)+"/version?"+query.Encode(), &versions); err != nil {
			return release, err
		}
		for _, version := range versions {
			if version.VersionType != "release" {
				continue
			}
			for _, file := range version.Files {
				if file.Primary && strings.HasSuffix(strings.ToLower(file.Filename), ".jar") {
					release = pluginRelease{Version: version.ID, Filename: file.Filename, URL: file.URL, SHA512: file.Hashes.SHA512}
					break
				}
			}
			if release.Version != "" {
				break
			}
		}
	case "hangar":
		var versions struct {
			Result []struct {
				Name    string `json:"name"`
				Channel struct {
					Name string `json:"name"`
				} `json:"channel"`
				PlatformDependencies map[string][]string `json:"platformDependencies"`
				Downloads            map[string]struct {
					DownloadURL string `json:"downloadUrl"`
					FileInfo    struct {
						Name   string `json:"name"`
						SHA256 string `json:"sha256Hash"`
					} `json:"fileInfo"`
				} `json:"downloads"`
			} `json:"result"`
		}
		query := url.Values{"limit": {"25"}, "platform": {"PAPER"}, "channel": {"Release"}}
		if minecraftVersion != "" {
			query.Set("platformVersion", minecraftVersion)
		}
		if err := pluginAPIJSON(ctx, "https://hangar.papermc.io/api/v1/projects/"+source.Project+"/versions?"+query.Encode(), &versions); err != nil {
			return release, err
		}
		for _, version := range versions.Result {
			if !strings.EqualFold(version.Channel.Name, "release") {
				continue
			}
			download, found := version.Downloads["PAPER"]
			if !found {
				continue
			}
			if minecraftVersion != "" {
				compatible := false
				for _, supported := range version.PlatformDependencies["PAPER"] {
					if supported == minecraftVersion {
						compatible = true
					}
				}
				if !compatible {
					continue
				}
			}
			release = pluginRelease{Version: version.Name, Filename: download.FileInfo.Name, URL: download.DownloadURL, SHA256: download.FileInfo.SHA256}
			break
		}
	default:
		return release, fmt.Errorf("unsupported plugin provider")
	}
	if release.Version == "" {
		return release, fmt.Errorf("no stable Paper release found for this Minecraft version")
	}
	if !safeSatisfactoryDirectoryName(release.Filename) || path.Base(release.Filename) != release.Filename || !strings.HasSuffix(strings.ToLower(release.Filename), ".jar") {
		return pluginRelease{}, fmt.Errorf("provider returned an invalid plugin filename")
	}
	downloadURL, err := url.Parse(release.URL)
	if err != nil || !trustedPluginDownloadURL(downloadURL) {
		return pluginRelease{}, fmt.Errorf("provider returned an unsupported download host")
	}
	if release.SHA512 == "" && release.SHA256 == "" {
		return pluginRelease{}, fmt.Errorf("provider did not supply a plugin checksum")
	}
	return release, nil
}
