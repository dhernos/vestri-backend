package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMinecraftRuntimeImage    = "vestri/minecraft-empty:latest"
	minecraftServerDataDir          = "data"
	defaultMinecraftServerJarFile   = "server.jar"
	defaultMinecraftJavaArgs        = "-Xms1G -Xmx2G"
	defaultMinecraftServerStartArgs = "nogui"
	minecraftVersionCacheTTL        = 20 * time.Minute
	maxExternalAPIResponseBytes     = 4 << 20
	maxMinecraftJarDownloadBytes    = 256 << 20
	defaultMinecraftServerJarPrefix = "/server/"
)

const (
	minecraftSoftwareVanilla = "VANILLA"
	minecraftSoftwarePaper   = "PAPER"
	minecraftSoftwarePurpur  = "PURPUR"
)

const (
	mojangVersionManifestURL = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
	paperVersionsURL         = "https://api.papermc.io/v2/projects/paper"
	purpurVersionsURL        = "https://api.purpurmc.org/v2/purpur"
)

var (
	stableMinecraftVersionPattern = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)
	externalAPIFetchClient        = &http.Client{Timeout: 30 * time.Second}
	minecraftVersionCache         = softwareVersionListCache{
		entries: make(map[string]softwareVersionListCacheEntry),
	}
)

type softwareVersionListCache struct {
	mu      sync.Mutex
	entries map[string]softwareVersionListCacheEntry
}

type softwareVersionListCacheEntry struct {
	Values    []string
	FetchedAt time.Time
	ErrText   string
}

type minecraftServerArtifact struct {
	Software    string
	Version     string
	DownloadURL string
	FileName    string
}

func cloneTemplateVersions(value *gameServerTemplateVersions) *gameServerTemplateVersions {
	if value == nil {
		return nil
	}
	return &gameServerTemplateVersions{
		Software: cloneTemplateVersionField(value.Software),
		Game:     cloneTemplateVersionField(value.Game),
	}
}

func cloneTemplateVersionField(value *gameServerTemplateVersionField) *gameServerTemplateVersionField {
	if value == nil {
		return nil
	}
	cloned := *value
	if len(value.Options) > 0 {
		cloned.Options = append([]string(nil), value.Options...)
	} else {
		cloned.Options = nil
	}
	if len(value.OptionsBySoftware) > 0 {
		cloned.OptionsBySoftware = make(map[string][]string, len(value.OptionsBySoftware))
		for key, options := range value.OptionsBySoftware {
			cloned.OptionsBySoftware[key] = append([]string(nil), options...)
		}
	} else {
		cloned.OptionsBySoftware = nil
	}
	return &cloned
}

func (s *Server) enrichTemplateVersionConfig(ctx context.Context, template *gameServerTemplate) {
	if template == nil || template.VersionConfig == nil {
		return
	}
	if strings.TrimSpace(strings.ToLower(template.Game)) != "minecraft" {
		return
	}

	softwareField := template.VersionConfig.Software
	gameField := template.VersionConfig.Game
	if softwareField == nil || gameField == nil {
		return
	}

	softwareOptions := normalizeTemplateVersionOptions(softwareField.Options)
	if len(softwareOptions) == 0 {
		return
	}

	optionsBySoftware := make(map[string][]string, len(softwareOptions))
	for _, softwareOption := range softwareOptions {
		normalizedSoftware := normalizeMinecraftSoftware(softwareOption)
		if normalizedSoftware == "" {
			continue
		}

		versions, err := listMinecraftVersionsForSoftware(ctx, normalizedSoftware)
		if err != nil || len(versions) == 0 {
			continue
		}
		optionsBySoftware[normalizedSoftware] = versions
	}
	if len(optionsBySoftware) == 0 {
		return
	}

	gameField.OptionsBySoftware = optionsBySoftware

	defaultSoftware := normalizeMinecraftSoftware(softwareField.Default)
	if defaultSoftware == "" {
		defaultSoftware = normalizeMinecraftSoftware(softwareOptions[0])
	}
	defaultOptions := append([]string(nil), optionsBySoftware[defaultSoftware]...)
	if len(defaultOptions) == 0 {
		for _, softwareOption := range softwareOptions {
			normalizedSoftware := normalizeMinecraftSoftware(softwareOption)
			if len(optionsBySoftware[normalizedSoftware]) == 0 {
				continue
			}
			defaultOptions = append([]string(nil), optionsBySoftware[normalizedSoftware]...)
			defaultSoftware = normalizedSoftware
			break
		}
	}

	gameField.Options = defaultOptions
	if len(defaultOptions) > 0 {
		gameField.Default = defaultOptions[0]
	}

	if softwareField.Default == "" && defaultSoftware != "" {
		softwareField.Default = defaultSoftware
	}
}

func shouldProvisionMinecraftServerArtifact(template *gameServerTemplate) bool {
	if template == nil {
		return false
	}
	if isVelocityTemplateID(template.ID) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(template.Game), "minecraft")
}

func normalizeMinecraftSoftware(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case minecraftSoftwareVanilla:
		return minecraftSoftwareVanilla
	case minecraftSoftwarePaper:
		return minecraftSoftwarePaper
	case minecraftSoftwarePurpur:
		return minecraftSoftwarePurpur
	default:
		return ""
	}
}

func listMinecraftVersionsForSoftware(ctx context.Context, software string) ([]string, error) {
	normalizedSoftware := normalizeMinecraftSoftware(software)
	if normalizedSoftware == "" {
		return nil, fmt.Errorf("unsupported minecraft software: %s", software)
	}

	return minecraftVersionCache.getOrFetch(ctx, normalizedSoftware, func(fetchCtx context.Context) ([]string, error) {
		switch normalizedSoftware {
		case minecraftSoftwareVanilla:
			return fetchVanillaReleaseVersions(fetchCtx)
		case minecraftSoftwarePaper:
			return fetchPaperReleaseVersions(fetchCtx)
		case minecraftSoftwarePurpur:
			return fetchPurpurReleaseVersions(fetchCtx)
		default:
			return nil, fmt.Errorf("unsupported minecraft software: %s", normalizedSoftware)
		}
	})
}

func (c *softwareVersionListCache) getOrFetch(
	ctx context.Context,
	key string,
	fetch func(context.Context) ([]string, error),
) ([]string, error) {
	now := time.Now()

	c.mu.Lock()
	entry, exists := c.entries[key]
	if exists && now.Sub(entry.FetchedAt) < minecraftVersionCacheTTL {
		values := append([]string(nil), entry.Values...)
		errText := entry.ErrText
		c.mu.Unlock()
		if len(values) > 0 {
			return values, nil
		}
		if errText != "" {
			return nil, fmt.Errorf(errText)
		}
		return nil, fmt.Errorf("version list is empty")
	}
	c.mu.Unlock()

	values, err := fetch(ctx)
	if err != nil {
		c.mu.Lock()
		oldEntry, hasOld := c.entries[key]
		if hasOld && len(oldEntry.Values) > 0 {
			values = append([]string(nil), oldEntry.Values...)
			c.mu.Unlock()
			return values, nil
		}
		c.entries[key] = softwareVersionListCacheEntry{
			FetchedAt: now,
			ErrText:   err.Error(),
		}
		c.mu.Unlock()
		return nil, err
	}

	normalizedValues := normalizeMinecraftVersionList(values)
	c.mu.Lock()
	c.entries[key] = softwareVersionListCacheEntry{
		Values:    append([]string(nil), normalizedValues...),
		FetchedAt: now,
	}
	c.mu.Unlock()
	return normalizedValues, nil
}

func normalizeMinecraftVersionList(values []string) []string {
	dedup := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		version := strings.TrimSpace(raw)
		if !isStableMinecraftVersion(version) {
			continue
		}
		if _, exists := dedup[version]; exists {
			continue
		}
		dedup[version] = struct{}{}
		out = append(out, version)
	}
	sort.Slice(out, func(i, j int) bool {
		return compareMinecraftVersions(out[i], out[j]) > 0
	})
	return out
}

func isStableMinecraftVersion(value string) bool {
	return stableMinecraftVersionPattern.MatchString(strings.TrimSpace(value))
}

func compareMinecraftVersions(a, b string) int {
	aParts := parseMinecraftVersionParts(a)
	bParts := parseMinecraftVersionParts(b)
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		aPart := 0
		bPart := 0
		if i < len(aParts) {
			aPart = aParts[i]
		}
		if i < len(bParts) {
			bPart = bParts[i]
		}
		if aPart > bPart {
			return 1
		}
		if aPart < bPart {
			return -1
		}
	}
	return 0
}

func parseMinecraftVersionParts(value string) []int {
	rawParts := strings.Split(strings.TrimSpace(value), ".")
	out := make([]int, 0, len(rawParts))
	for _, raw := range rawParts {
		num, err := strconv.Atoi(raw)
		if err != nil {
			return nil
		}
		out = append(out, num)
	}
	return out
}

type mojangVersionManifest struct {
	Latest struct {
		Release string `json:"release"`
	} `json:"latest"`
	Versions []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"versions"`
}

func fetchVanillaReleaseVersions(ctx context.Context) ([]string, error) {
	manifest, err := fetchMojangVersionManifest(ctx)
	if err != nil {
		return nil, err
	}

	versions := make([]string, 0, len(manifest.Versions))
	for _, item := range manifest.Versions {
		if !strings.EqualFold(strings.TrimSpace(item.Type), "release") {
			continue
		}
		versions = append(versions, item.ID)
	}
	return normalizeMinecraftVersionList(versions), nil
}

func fetchMojangVersionManifest(ctx context.Context) (*mojangVersionManifest, error) {
	var payload mojangVersionManifest
	if err := fetchExternalJSON(ctx, mojangVersionManifestURL, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

type paperProjectVersionsResponse struct {
	Versions []string `json:"versions"`
}

func fetchPaperReleaseVersions(ctx context.Context) ([]string, error) {
	var payload paperProjectVersionsResponse
	if err := fetchExternalJSON(ctx, paperVersionsURL, &payload); err != nil {
		return nil, err
	}
	return normalizeMinecraftVersionList(payload.Versions), nil
}

type purpurProjectVersionsResponse struct {
	Versions []string `json:"versions"`
}

func fetchPurpurReleaseVersions(ctx context.Context) ([]string, error) {
	var payload purpurProjectVersionsResponse
	if err := fetchExternalJSON(ctx, purpurVersionsURL, &payload); err != nil {
		return nil, err
	}
	return normalizeMinecraftVersionList(payload.Versions), nil
}

func fetchExternalJSON(ctx context.Context, endpoint string, dst interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vestri-backend/1")
	req.Header.Set("Accept", "application/json")

	resp, err := externalAPIFetchClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("request to %s failed (%d): %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	dec := json.NewDecoder(io.LimitReader(resp.Body, maxExternalAPIResponseBytes))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func resolveMinecraftServerArtifact(
	ctx context.Context,
	softwareVersion,
	requestedGameVersion string,
) (*minecraftServerArtifact, error) {
	software := normalizeMinecraftSoftware(softwareVersion)
	if software == "" {
		return nil, fmt.Errorf("unsupported server software %q", strings.TrimSpace(softwareVersion))
	}

	switch software {
	case minecraftSoftwareVanilla:
		return resolveVanillaServerArtifact(ctx, requestedGameVersion)
	case minecraftSoftwarePaper:
		return resolvePaperServerArtifact(ctx, requestedGameVersion)
	case minecraftSoftwarePurpur:
		return resolvePurpurServerArtifact(ctx, requestedGameVersion)
	default:
		return nil, fmt.Errorf("unsupported server software %q", software)
	}
}

func resolveVanillaServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	manifest, err := fetchMojangVersionManifest(ctx)
	if err != nil {
		return nil, err
	}

	version := strings.TrimSpace(requestedVersion)
	if version == "" || strings.EqualFold(version, "LATEST") {
		version = strings.TrimSpace(manifest.Latest.Release)
	}
	if version == "" {
		return nil, fmt.Errorf("no vanilla release version available")
	}

	var detailsURL string
	for _, entry := range manifest.Versions {
		if !strings.EqualFold(strings.TrimSpace(entry.Type), "release") {
			continue
		}
		if strings.TrimSpace(entry.ID) != version {
			continue
		}
		detailsURL = strings.TrimSpace(entry.URL)
		break
	}
	if detailsURL == "" {
		return nil, fmt.Errorf("vanilla version %s is not available", version)
	}

	var details struct {
		Downloads struct {
			Server struct {
				URL string `json:"url"`
			} `json:"server"`
		} `json:"downloads"`
	}
	if err := fetchExternalJSON(ctx, detailsURL, &details); err != nil {
		return nil, err
	}

	downloadURL := strings.TrimSpace(details.Downloads.Server.URL)
	if downloadURL == "" {
		return nil, fmt.Errorf("vanilla version %s has no server download", version)
	}

	return &minecraftServerArtifact{
		Software:    minecraftSoftwareVanilla,
		Version:     version,
		DownloadURL: downloadURL,
		FileName:    fileNameFromURL(downloadURL, fmt.Sprintf("minecraft-%s.jar", version)),
	}, nil
}

type paperBuildsResponse struct {
	Builds []struct {
		Build     int    `json:"build"`
		Channel   string `json:"channel"`
		Downloads struct {
			Application struct {
				Name string `json:"name"`
			} `json:"application"`
		} `json:"downloads"`
	} `json:"builds"`
}

func resolvePaperServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	version := strings.TrimSpace(requestedVersion)
	if version == "" || strings.EqualFold(version, "LATEST") {
		versions, err := listMinecraftVersionsForSoftware(ctx, minecraftSoftwarePaper)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no paper versions are available")
		}
		version = versions[0]
	}
	if !isStableMinecraftVersion(version) {
		return nil, fmt.Errorf("paper version %q is invalid", version)
	}

	buildURL := fmt.Sprintf(
		"https://api.papermc.io/v2/projects/paper/versions/%s/builds",
		url.PathEscape(version),
	)

	var payload paperBuildsResponse
	if err := fetchExternalJSON(ctx, buildURL, &payload); err != nil {
		return nil, err
	}
	if len(payload.Builds) == 0 {
		return nil, fmt.Errorf("paper version %s has no builds", version)
	}

	selectedBuild := 0
	selectedName := ""
	selectedChannel := ""
	for _, build := range payload.Builds {
		name := strings.TrimSpace(build.Downloads.Application.Name)
		if name == "" {
			continue
		}
		channel := strings.ToLower(strings.TrimSpace(build.Channel))
		if selectedBuild == 0 {
			selectedBuild = build.Build
			selectedName = name
			selectedChannel = channel
			continue
		}

		currentIsDefault := selectedChannel == "default"
		nextIsDefault := channel == "default"
		if currentIsDefault != nextIsDefault {
			if nextIsDefault {
				selectedBuild = build.Build
				selectedName = name
				selectedChannel = channel
			}
			continue
		}

		if build.Build > selectedBuild {
			selectedBuild = build.Build
			selectedName = name
			selectedChannel = channel
		}
	}

	if selectedBuild == 0 || selectedName == "" {
		return nil, fmt.Errorf("paper version %s has no downloadable build", version)
	}

	downloadURL := fmt.Sprintf(
		"https://api.papermc.io/v2/projects/paper/versions/%s/builds/%d/downloads/%s",
		url.PathEscape(version),
		selectedBuild,
		url.PathEscape(selectedName),
	)

	return &minecraftServerArtifact{
		Software:    minecraftSoftwarePaper,
		Version:     version,
		DownloadURL: downloadURL,
		FileName:    selectedName,
	}, nil
}

func resolvePurpurServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	version := strings.TrimSpace(requestedVersion)
	if version == "" || strings.EqualFold(version, "LATEST") {
		versions, err := listMinecraftVersionsForSoftware(ctx, minecraftSoftwarePurpur)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no purpur versions are available")
		}
		version = versions[0]
	}
	if !isStableMinecraftVersion(version) {
		return nil, fmt.Errorf("purpur version %q is invalid", version)
	}

	downloadURL := fmt.Sprintf(
		"https://api.purpurmc.org/v2/purpur/%s/latest/download",
		url.PathEscape(version),
	)
	return &minecraftServerArtifact{
		Software:    minecraftSoftwarePurpur,
		Version:     version,
		DownloadURL: downloadURL,
		FileName:    fmt.Sprintf("purpur-%s.jar", version),
	}, nil
}

func fileNameFromURL(rawURL, fallback string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fallback
	}
	name := strings.TrimSpace(path.Base(parsed.Path))
	if name == "" || name == "." || name == "/" {
		return fallback
	}
	return name
}

func minecraftServerJarFileNameForArtifact(artifact *minecraftServerArtifact) string {
	if artifact == nil {
		return defaultMinecraftServerJarFile
	}
	return normalizeMinecraftJarFileName(artifact.FileName)
}

func minecraftServerJarContainerPath(fileName string) string {
	name := normalizeMinecraftJarFileName(fileName)
	return defaultMinecraftServerJarPrefix + name
}

func minecraftServerJarWorkerPath(rootPath, fileName string) string {
	name := normalizeMinecraftJarFileName(fileName)
	return path.Join(rootPath, minecraftServerDataDir, name)
}

func normalizeMinecraftJarFileName(raw string) string {
	fileName := strings.TrimSpace(raw)
	fileName = strings.ReplaceAll(fileName, "\\", "/")
	fileName = strings.TrimSpace(path.Base(fileName))
	if fileName == "" || fileName == "." || fileName == "/" {
		fileName = defaultMinecraftServerJarFile
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".jar") {
		fileName += ".jar"
	}
	return fileName
}

func (s *Server) provisionMinecraftServerArtifactOnWorker(
	ctx context.Context,
	baseURL *url.URL,
	apiKey,
	rootPath string,
	artifact *minecraftServerArtifact,
) error {
	if artifact == nil {
		return fmt.Errorf("minecraft artifact is required")
	}
	downloadURL := strings.TrimSpace(artifact.DownloadURL)
	if downloadURL == "" {
		return fmt.Errorf("minecraft artifact download URL is empty")
	}
	targetPath := minecraftServerJarWorkerPath(rootPath, artifact.FileName)
	return s.workerFetchRemoteFile(ctx, baseURL, apiKey, downloadURL, targetPath, maxMinecraftJarDownloadBytes)
}

func (s *Server) workerFetchRemoteFile(
	ctx context.Context,
	baseURL *url.URL,
	apiKey,
	sourceURL,
	targetPath string,
	maxBytes int64,
) error {
	payload := map[string]interface{}{
		"url":  sourceURL,
		"path": targetPath,
	}
	if maxBytes > 0 {
		payload["maxBytes"] = maxBytes
	}

	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/fetch", payload)
	if err != nil {
		return err
	}
	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("worker /fs/fetch failed (%d): %s", statusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
