package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

type pluginSource struct {
	Provider    string `json:"provider"`
	Project     string `json:"project"`
	Version     string `json:"version,omitempty"`
	Platform    string `json:"platform,omitempty"`
	DownloadURL string `json:"downloadUrl,omitempty"`
}

type pluginRelease struct {
	Version  string `json:"version"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
	SHA512   string `json:"sha512,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

type pluginCompatibilityTarget struct {
	ServerRef string `json:"serverRef"`
	Platform  string `json:"platform"`
	Version   string `json:"version"`
}

type hangarFileInfo struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256Hash"`
}

type hangarDownload struct {
	DownloadURL string          `json:"downloadUrl"`
	ExternalURL string          `json:"externalUrl"`
	FileInfo    *hangarFileInfo `json:"fileInfo"`
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
	validArtifactPart := func(value string) bool {
		if value == "" || len(value) > 150 || value == "." || value == ".." {
			return false
		}
		for _, char := range value {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.') {
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
	case "hangarcdn.papermc.io":
		if parsed.RawQuery != "" || parsed.Fragment != "" || len(parts) != 7 || parts[0] != "plugins" || parts[3] != "versions" || !validPart(parts[1]) || !validPart(parts[2]) || !validArtifactPart(parts[4]) || !validPart(parts[5]) || !validArtifactPart(parts[6]) || !strings.HasSuffix(strings.ToLower(parts[6]), ".jar") {
			break
		}
		platform := strings.ToUpper(parts[5])
		if platform != "PAPER" && platform != "VELOCITY" {
			break
		}
		return pluginSource{
			Provider:    "hangar",
			Project:     parts[1] + "/" + parts[2],
			Version:     parts[4],
			Platform:    platform,
			DownloadURL: parsed.String(),
		}, nil
	}
	return pluginSource{}, fmt.Errorf("use a Modrinth /plugin/project, Hangar /author/project, or Hangar CDN JAR link")
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

func latestPluginRelease(ctx context.Context, source pluginSource, targets []pluginCompatibilityTarget) (pluginRelease, []string, error) {
	var release pluginRelease
	var compatibleRefs []string
	if len(targets) == 0 {
		return release, nil, fmt.Errorf("no versioned plugin targets are available")
	}
	if source.Version != "" {
		if source.Provider != "hangar" || source.Platform == "" || source.DownloadURL == "" {
			return release, nil, fmt.Errorf("invalid pinned Hangar plugin source")
		}
		var version struct {
			Name      string                    `json:"name"`
			Downloads map[string]hangarDownload `json:"downloads"`
		}
		endpoint := "https://hangar.papermc.io/api/v1/projects/" + source.Project + "/versions/" + url.PathEscape(source.Version)
		if err := pluginAPIJSON(ctx, endpoint, &version); err != nil {
			return release, nil, err
		}
		if version.Name != source.Version {
			return release, nil, fmt.Errorf("Hangar returned a different plugin version than requested")
		}
		download, found := version.Downloads[source.Platform]
		if !found {
			return release, nil, fmt.Errorf("pinned Hangar version has no %s download", source.Platform)
		}
		resolved, err := resolveHangarDownload(ctx, download.FileInfo, download.DownloadURL, download.ExternalURL)
		if err != nil {
			return release, nil, err
		}
		if resolved.URL != source.DownloadURL {
			return release, nil, fmt.Errorf("Hangar version does not match the supplied download link")
		}
		release = pluginRelease{Version: version.Name, Filename: resolved.Filename, URL: resolved.URL, SHA256: resolved.SHA256, SHA512: resolved.SHA512}
		for _, target := range targets {
			if strings.EqualFold(target.Platform, source.Platform) {
				compatibleRefs = append(compatibleRefs, target.ServerRef)
			}
		}
		if len(compatibleRefs) == 0 {
			return pluginRelease{}, nil, fmt.Errorf("no configured server supports the pinned Hangar platform")
		}
	} else {
		switch source.Provider {
		case "modrinth":
			loaders := make([]string, 0, len(targets))
			for _, target := range targets {
				loader := strings.ToLower(target.Platform)
				if !containsPluginValue(loaders, loader) {
					loaders = append(loaders, loader)
				}
			}
			loaderFilter, _ := json.Marshal(loaders)
			query := url.Values{"loaders": {string(loaderFilter)}}
			var versions []struct {
				ID           string   `json:"id"`
				VersionType  string   `json:"version_type"`
				Loaders      []string `json:"loaders"`
				GameVersions []string `json:"game_versions"`
				Files        []struct {
					Filename string `json:"filename"`
					URL      string `json:"url"`
					Primary  bool   `json:"primary"`
					Hashes   struct {
						SHA512 string `json:"sha512"`
					} `json:"hashes"`
				} `json:"files"`
			}
			if err := pluginAPIJSON(ctx, "https://api.modrinth.com/v2/project/"+url.PathEscape(source.Project)+"/version?"+query.Encode(), &versions); err != nil {
				return release, nil, err
			}
			for _, version := range versions {
				if version.VersionType != "release" {
					continue
				}
				candidateRefs := make([]string, 0, len(targets))
				for _, target := range targets {
					loader := strings.ToLower(target.Platform)
					if containsPluginValue(version.Loaders, loader) {
						candidateRefs = append(candidateRefs, target.ServerRef)
					}
				}
				if len(candidateRefs) == 0 {
					continue
				}
				for _, file := range version.Files {
					if file.Primary && strings.HasSuffix(strings.ToLower(file.Filename), ".jar") {
						release = pluginRelease{Version: version.ID, Filename: file.Filename, URL: file.URL, SHA512: file.Hashes.SHA512}
						break
					}
				}
				if release.Version != "" {
					compatibleRefs = candidateRefs
					break
				}
			}
		case "hangar":
			type hangarReleaseResponse struct {
				Result []struct {
					Name    string `json:"name"`
					Channel struct {
						Name string `json:"name"`
					} `json:"channel"`
					PlatformDependencies map[string][]string       `json:"platformDependencies"`
					Downloads            map[string]hangarDownload `json:"downloads"`
				} `json:"result"`
			}
			var versions hangarReleaseResponse
			query := url.Values{"limit": {"25"}, "channel": {"Release"}}
			endpoint := "https://hangar.papermc.io/api/v1/projects/" + source.Project + "/versions?" + query.Encode()
			if err := pluginAPIJSON(ctx, endpoint, &versions); err != nil {
				return release, nil, err
			}
			for _, version := range versions.Result {
				if !strings.EqualFold(version.Channel.Name, "release") {
					continue
				}
				var candidate pluginRelease
				candidateRefs := make([]string, 0, len(targets))
				resolvedDownloads := make(map[string]pluginRelease)
				for _, target := range targets {
					platform := strings.ToUpper(target.Platform)
					download, found := version.Downloads[platform]
					if !found {
						continue
					}
					resolved, cached := resolvedDownloads[platform]
					if !cached {
						var err error
						resolved, err = resolveHangarDownload(ctx, download.FileInfo, download.DownloadURL, download.ExternalURL)
						if err != nil {
							return release, nil, err
						}
						resolvedDownloads[platform] = resolved
					}
					if candidate.Version == "" {
						candidate = pluginRelease{Version: version.Name, Filename: resolved.Filename, URL: resolved.URL, SHA256: resolved.SHA256, SHA512: resolved.SHA512}
					}
					if resolved.Filename == candidate.Filename && resolved.URL == candidate.URL && resolved.SHA256 == candidate.SHA256 && resolved.SHA512 == candidate.SHA512 {
						candidateRefs = append(candidateRefs, target.ServerRef)
					}
				}
				if candidate.Version != "" {
					release, compatibleRefs = candidate, candidateRefs
					break
				}
			}
		default:
			return release, nil, fmt.Errorf("unsupported plugin provider")
		}
	}
	if release.Version == "" {
		return release, nil, fmt.Errorf("no stable plugin release supports any configured server")
	}
	if !safeSatisfactoryDirectoryName(release.Filename) || path.Base(release.Filename) != release.Filename || !strings.HasSuffix(strings.ToLower(release.Filename), ".jar") {
		return pluginRelease{}, nil, fmt.Errorf("provider returned an invalid plugin filename")
	}
	downloadURL, err := url.Parse(release.URL)
	if err != nil || !trustedPluginDownloadURL(downloadURL) {
		return pluginRelease{}, nil, fmt.Errorf("provider returned an unsupported download host")
	}
	if release.SHA512 == "" && release.SHA256 == "" {
		return pluginRelease{}, nil, fmt.Errorf("provider did not supply a plugin checksum")
	}
	sort.Strings(compatibleRefs)
	return release, compatibleRefs, nil
}

func resolveHangarDownload(ctx context.Context, fileInfo *hangarFileInfo, downloadURL, externalURL string) (pluginRelease, error) {
	resolved := pluginRelease{URL: strings.TrimSpace(downloadURL)}
	if fileInfo != nil {
		resolved.Filename = strings.TrimSpace(fileInfo.Name)
		resolved.SHA256 = strings.TrimSpace(fileInfo.SHA256)
	}
	if resolved.URL == "" {
		resolved.URL = strings.TrimSpace(externalURL)
	}
	parsed, err := url.Parse(resolved.URL)
	if err != nil || !trustedPluginDownloadURL(parsed) {
		return pluginRelease{}, fmt.Errorf("Hangar returned an unsupported plugin download URL")
	}
	if resolved.Filename == "" {
		resolved.Filename = path.Base(parsed.Path)
	}
	if resolved.SHA256 != "" {
		return resolved, nil
	}
	if strings.EqualFold(parsed.Hostname(), "cdn.modrinth.com") {
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) < 5 || parts[0] != "data" || parts[2] != "versions" || parts[3] == "" {
			return pluginRelease{}, fmt.Errorf("Hangar external plugin download has no verifiable Modrinth version")
		}
		var version struct {
			Files []struct {
				Filename string `json:"filename"`
				URL      string `json:"url"`
				Hashes   struct {
					SHA512 string `json:"sha512"`
				} `json:"hashes"`
			} `json:"files"`
		}
		if err := pluginAPIJSON(ctx, "https://api.modrinth.com/v2/version/"+url.PathEscape(parts[3]), &version); err != nil {
			return pluginRelease{}, err
		}
		for _, file := range version.Files {
			if file.Filename == resolved.Filename && file.Hashes.SHA512 != "" {
				resolved.URL = file.URL
				resolved.SHA512 = file.Hashes.SHA512
				return resolved, nil
			}
		}
	}
	return pluginRelease{}, fmt.Errorf("plugin download did not include a verifiable checksum")
}

func containsPluginValue(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}
