package server

import (
	"context"
	"encoding/json"
	"encoding/xml"
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
	defaultMinecraftRuntimeImage    = "dhernos/vestri-mc:latest"
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
	minecraftSoftwareVanilla  = "VANILLA"
	minecraftSoftwarePaper    = "PAPER"
	minecraftSoftwarePurpur   = "PURPUR"
	minecraftSoftwareSpigot   = "SPIGOT"
	minecraftSoftwareBukkit   = "BUKKIT"
	minecraftSoftwareFabric   = "FABRIC"
	minecraftSoftwareForge    = "FORGE"
	minecraftSoftwareNeoForge = "NEOFORGE"
	minecraftSoftwareSponge   = "SPONGE"
	minecraftSoftwareVelocity = "VELOCITY"
)

const (
	mojangVersionManifestURL  = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
	paperVersionsURL          = "https://api.papermc.io/v2/projects/paper"
	purpurVersionsURL         = "https://api.purpurmc.org/v2/purpur"
	fabricGameVersionsURL     = "https://meta.fabricmc.net/v2/versions/game"
	fabricInstallerURL        = "https://meta.fabricmc.net/v2/versions/installer"
	forgeMavenMetadataURL     = "https://maven.minecraftforge.net/net/minecraftforge/forge/maven-metadata.xml"
	forgeMavenBaseURL         = "https://maven.minecraftforge.net/net/minecraftforge/forge"
	neoForgeMavenMetadataURL  = "https://maven.neoforged.net/releases/net/neoforged/neoforge/maven-metadata.xml"
	neoForgeMavenBaseURL      = "https://maven.neoforged.net/releases/net/neoforged/neoforge"
	spongeArtifactMetadataURL = "https://dl-api.spongepowered.org/v2/groups/org.spongepowered/artifacts/spongevanilla"
	spongeVersionsURL         = "https://dl-api.spongepowered.org/v2/groups/org.spongepowered/artifacts/spongevanilla/versions"
	velocityVersionsURL       = "https://api.papermc.io/v2/projects/velocity"
	spigotDownloadBaseURL     = "https://download.getbukkit.org/spigot"
	bukkitDownloadBaseURL     = "https://download.getbukkit.org/craftbukkit"
)

var (
	stableMinecraftVersionPattern = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)
	looseVersionTokenPattern      = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)
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
	case minecraftSoftwareSpigot:
		return minecraftSoftwareSpigot
	case minecraftSoftwareBukkit:
		return minecraftSoftwareBukkit
	case minecraftSoftwareFabric:
		return minecraftSoftwareFabric
	case minecraftSoftwareForge:
		return minecraftSoftwareForge
	case minecraftSoftwareNeoForge:
		return minecraftSoftwareNeoForge
	case minecraftSoftwareSponge:
		return minecraftSoftwareSponge
	case minecraftSoftwareVelocity:
		return minecraftSoftwareVelocity
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
		case minecraftSoftwareSpigot:
			return fetchSpigotReleaseVersions(fetchCtx)
		case minecraftSoftwareBukkit:
			return fetchBukkitReleaseVersions(fetchCtx)
		case minecraftSoftwareFabric:
			return fetchFabricReleaseVersions(fetchCtx)
		case minecraftSoftwareForge:
			return fetchForgeReleaseVersions(fetchCtx)
		case minecraftSoftwareNeoForge:
			return fetchNeoForgeReleaseVersions(fetchCtx)
		case minecraftSoftwareSponge:
			return fetchSpongeReleaseVersions(fetchCtx)
		case minecraftSoftwareVelocity:
			return fetchVelocityReleaseVersions(fetchCtx)
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

func fetchSpigotReleaseVersions(ctx context.Context) ([]string, error) {
	return fetchPaperReleaseVersions(ctx)
}

func fetchBukkitReleaseVersions(ctx context.Context) ([]string, error) {
	return fetchPaperReleaseVersions(ctx)
}

type fabricGameVersionsResponseItem struct {
	Version string `json:"version"`
	Stable  bool   `json:"stable"`
}

func fetchFabricReleaseVersions(ctx context.Context) ([]string, error) {
	var payload []fabricGameVersionsResponseItem
	if err := fetchExternalJSON(ctx, fabricGameVersionsURL, &payload); err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(payload))
	for _, item := range payload {
		if !item.Stable {
			continue
		}
		versions = append(versions, item.Version)
	}
	return normalizeMinecraftVersionList(versions), nil
}

func fetchVelocityReleaseVersions(ctx context.Context) ([]string, error) {
	var payload paperProjectVersionsResponse
	if err := fetchExternalJSON(ctx, velocityVersionsURL, &payload); err != nil {
		return nil, err
	}
	return normalizeMinecraftVersionList(payload.Versions), nil
}

type mavenMetadata struct {
	Versioning struct {
		Versions struct {
			Values []string `xml:"version"`
		} `xml:"versions"`
	} `xml:"versioning"`
}

type spongeArtifactMetadataResponse struct {
	Tags struct {
		Minecraft []string `json:"minecraft"`
	} `json:"tags"`
}

type spongeVersionListEntry struct {
	TagValues   map[string]string `json:"tagValues"`
	Recommended bool              `json:"recommended"`
}

type spongeVersionsResponse struct {
	Artifacts map[string]spongeVersionListEntry `json:"artifacts"`
}

type spongeVersionAsset struct {
	Classifier  string `json:"classifier"`
	DownloadURL string `json:"downloadUrl"`
	Extension   string `json:"extension"`
}

type spongeVersionDetailsResponse struct {
	Assets []spongeVersionAsset `json:"assets"`
}

func fetchMavenMetadataVersions(ctx context.Context, endpoint string) ([]string, error) {
	var payload mavenMetadata
	if err := fetchExternalXML(ctx, endpoint, &payload); err != nil {
		return nil, err
	}
	return append([]string(nil), payload.Versioning.Versions.Values...), nil
}

func fetchForgeReleaseVersions(ctx context.Context) ([]string, error) {
	fullVersions, err := fetchMavenMetadataVersions(ctx, forgeMavenMetadataURL)
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(fullVersions))
	for _, fullVersion := range fullVersions {
		gameVersion := extractForgeGameVersion(fullVersion)
		if gameVersion == "" {
			continue
		}
		versions = append(versions, gameVersion)
	}
	return normalizeMinecraftVersionList(versions), nil
}

func fetchNeoForgeReleaseVersions(ctx context.Context) ([]string, error) {
	fullVersions, err := fetchMavenMetadataVersions(ctx, neoForgeMavenMetadataURL)
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(fullVersions))
	for _, fullVersion := range fullVersions {
		gameVersion := extractNeoForgeGameVersion(fullVersion)
		if gameVersion == "" {
			continue
		}
		versions = append(versions, gameVersion)
	}
	return normalizeMinecraftVersionList(versions), nil
}

func fetchSpongeReleaseVersions(ctx context.Context) ([]string, error) {
	var payload spongeArtifactMetadataResponse
	if err := fetchExternalJSON(ctx, spongeArtifactMetadataURL, &payload); err != nil {
		return nil, err
	}
	return normalizeMinecraftVersionList(payload.Tags.Minecraft), nil
}

func extractForgeGameVersion(fullVersion string) string {
	value := strings.TrimSpace(fullVersion)
	if value == "" {
		return ""
	}
	idx := strings.Index(value, "-")
	if idx <= 0 {
		return ""
	}
	gameVersion := strings.TrimSpace(value[:idx])
	if !isStableMinecraftVersion(gameVersion) {
		return ""
	}
	return gameVersion
}

func extractNeoForgeGameVersion(fullVersion string) string {
	value := strings.TrimSpace(fullVersion)
	if value == "" {
		return ""
	}
	base := value
	if idx := strings.Index(base, "-"); idx > 0 {
		base = base[:idx]
	}
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		return ""
	}
	if !isNumericVersionPart(parts[0]) || !isNumericVersionPart(parts[1]) {
		return ""
	}
	gameVersion := parts[0] + "." + parts[1]
	if !isStableMinecraftVersion(gameVersion) {
		return ""
	}
	return gameVersion
}

func isNumericVersionPart(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	_, err := strconv.Atoi(value)
	return err == nil
}

func minecraftGameVersionMatches(candidate, requested string) bool {
	candidate = strings.TrimSpace(candidate)
	requested = strings.TrimSpace(requested)
	if candidate == "" || requested == "" {
		return false
	}
	if strings.EqualFold(candidate, requested) {
		return true
	}
	if strings.HasPrefix(candidate, "1.") && strings.EqualFold(strings.TrimPrefix(candidate, "1."), requested) {
		return true
	}
	if strings.HasPrefix(requested, "1.") && strings.EqualFold(candidate, strings.TrimPrefix(requested, "1.")) {
		return true
	}
	return false
}

func latestBuildVersionForMinecraftGame(
	fullVersions []string,
	requestedGameVersion string,
	extractGameVersion func(string) string,
) string {
	candidates := make([]string, 0, len(fullVersions))
	for _, fullVersion := range fullVersions {
		candidate := strings.TrimSpace(fullVersion)
		if candidate == "" {
			continue
		}
		gameVersion := extractGameVersion(candidate)
		if !minecraftGameVersionMatches(gameVersion, requestedGameVersion) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		return compareLooseVersionStrings(candidates[i], candidates[j]) > 0
	})
	return candidates[0]
}

func compareLooseVersionStrings(a, b string) int {
	aTokens := looseVersionTokenPattern.FindAllString(strings.ToLower(strings.TrimSpace(a)), -1)
	bTokens := looseVersionTokenPattern.FindAllString(strings.ToLower(strings.TrimSpace(b)), -1)
	maxLen := len(aTokens)
	if len(bTokens) > maxLen {
		maxLen = len(bTokens)
	}

	for i := 0; i < maxLen; i++ {
		if i >= len(aTokens) {
			return compareMissingLooseVersionTail(bTokens[i:])
		}
		if i >= len(bTokens) {
			return -compareMissingLooseVersionTail(aTokens[i:])
		}

		left := aTokens[i]
		right := bTokens[i]
		leftNum, leftErr := strconv.Atoi(left)
		rightNum, rightErr := strconv.Atoi(right)

		if leftErr == nil && rightErr == nil {
			if leftNum > rightNum {
				return 1
			}
			if leftNum < rightNum {
				return -1
			}
			continue
		}
		if leftErr == nil && rightErr != nil {
			return 1
		}
		if leftErr != nil && rightErr == nil {
			return -1
		}
		if left > right {
			return 1
		}
		if left < right {
			return -1
		}
	}
	return 0
}

func compareMissingLooseVersionTail(tokens []string) int {
	for _, token := range tokens {
		if token == "" {
			continue
		}
		if num, err := strconv.Atoi(token); err == nil {
			if num == 0 {
				continue
			}
			return -1
		}
		return 1
	}
	return 0
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

func fetchExternalXML(ctx context.Context, endpoint string, dst interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vestri-backend/1")
	req.Header.Set("Accept", "application/xml,text/xml")

	resp, err := externalAPIFetchClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("request to %s failed (%d): %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	dec := xml.NewDecoder(io.LimitReader(resp.Body, maxExternalAPIResponseBytes))
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
	case minecraftSoftwareSpigot:
		return resolveSpigotServerArtifact(ctx, requestedGameVersion)
	case minecraftSoftwareBukkit:
		return resolveBukkitServerArtifact(ctx, requestedGameVersion)
	case minecraftSoftwareFabric:
		return resolveFabricServerArtifact(ctx, requestedGameVersion)
	case minecraftSoftwareForge:
		return resolveForgeServerArtifact(ctx, requestedGameVersion)
	case minecraftSoftwareNeoForge:
		return resolveNeoForgeServerArtifact(ctx, requestedGameVersion)
	case minecraftSoftwareSponge:
		return resolveSpongeServerArtifact(ctx, requestedGameVersion)
	case minecraftSoftwareVelocity:
		return resolveVelocityServerArtifact(ctx, requestedGameVersion)
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

func resolveSpigotServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	version := strings.TrimSpace(requestedVersion)
	if version == "" || strings.EqualFold(version, "LATEST") {
		versions, err := listMinecraftVersionsForSoftware(ctx, minecraftSoftwareSpigot)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no spigot versions are available")
		}
		version = versions[0]
	}
	if !isStableMinecraftVersion(version) {
		return nil, fmt.Errorf("spigot version %q is invalid", version)
	}

	downloadURL := fmt.Sprintf("%s/spigot-%s.jar", spigotDownloadBaseURL, url.PathEscape(version))
	return &minecraftServerArtifact{
		Software:    minecraftSoftwareSpigot,
		Version:     version,
		DownloadURL: downloadURL,
		FileName:    fmt.Sprintf("spigot-%s.jar", version),
	}, nil
}

func resolveBukkitServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	version := strings.TrimSpace(requestedVersion)
	if version == "" || strings.EqualFold(version, "LATEST") {
		versions, err := listMinecraftVersionsForSoftware(ctx, minecraftSoftwareBukkit)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no bukkit versions are available")
		}
		version = versions[0]
	}
	if !isStableMinecraftVersion(version) {
		return nil, fmt.Errorf("bukkit version %q is invalid", version)
	}

	downloadURL := fmt.Sprintf("%s/craftbukkit-%s.jar", bukkitDownloadBaseURL, url.PathEscape(version))
	return &minecraftServerArtifact{
		Software:    minecraftSoftwareBukkit,
		Version:     version,
		DownloadURL: downloadURL,
		FileName:    fmt.Sprintf("craftbukkit-%s.jar", version),
	}, nil
}

type fabricLoaderVersionsResponseItem struct {
	Loader struct {
		Version string `json:"version"`
	} `json:"loader"`
}

type fabricInstallerVersionsResponseItem struct {
	Version string `json:"version"`
	Stable  bool   `json:"stable"`
}

func resolveFabricServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	version := strings.TrimSpace(requestedVersion)
	if version == "" || strings.EqualFold(version, "LATEST") {
		versions, err := listMinecraftVersionsForSoftware(ctx, minecraftSoftwareFabric)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no fabric versions are available")
		}
		version = versions[0]
	}
	if !isStableMinecraftVersion(version) {
		return nil, fmt.Errorf("fabric version %q is invalid", version)
	}

	loaderVersion, err := fetchLatestFabricLoaderVersion(ctx, version)
	if err != nil {
		return nil, err
	}
	installerVersion, err := fetchLatestFabricInstallerVersion(ctx)
	if err != nil {
		return nil, err
	}

	downloadURL := fmt.Sprintf(
		"https://meta.fabricmc.net/v2/versions/loader/%s/%s/%s/server/jar",
		url.PathEscape(version),
		url.PathEscape(loaderVersion),
		url.PathEscape(installerVersion),
	)
	return &minecraftServerArtifact{
		Software:    minecraftSoftwareFabric,
		Version:     version,
		DownloadURL: downloadURL,
		FileName:    fmt.Sprintf("fabric-%s-loader-%s.jar", version, loaderVersion),
	}, nil
}

func fetchLatestFabricLoaderVersion(ctx context.Context, gameVersion string) (string, error) {
	endpoint := fmt.Sprintf("https://meta.fabricmc.net/v2/versions/loader/%s", url.PathEscape(gameVersion))
	var payload []fabricLoaderVersionsResponseItem
	if err := fetchExternalJSON(ctx, endpoint, &payload); err != nil {
		return "", err
	}
	for _, item := range payload {
		version := strings.TrimSpace(item.Loader.Version)
		if version == "" {
			continue
		}
		return version, nil
	}
	return "", fmt.Errorf("fabric game version %s has no loader versions", gameVersion)
}

func fetchLatestFabricInstallerVersion(ctx context.Context) (string, error) {
	var payload []fabricInstallerVersionsResponseItem
	if err := fetchExternalJSON(ctx, fabricInstallerURL, &payload); err != nil {
		return "", err
	}
	var fallback string
	for _, item := range payload {
		version := strings.TrimSpace(item.Version)
		if version == "" {
			continue
		}
		if fallback == "" {
			fallback = version
		}
		if item.Stable {
			return version, nil
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("no fabric installer versions are available")
}

func resolveForgeServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	gameVersion := strings.TrimSpace(requestedVersion)
	if gameVersion == "" || strings.EqualFold(gameVersion, "LATEST") {
		versions, err := listMinecraftVersionsForSoftware(ctx, minecraftSoftwareForge)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no forge versions are available")
		}
		gameVersion = versions[0]
	}
	if !isStableMinecraftVersion(gameVersion) {
		return nil, fmt.Errorf("forge version %q is invalid", gameVersion)
	}

	fullVersions, err := fetchMavenMetadataVersions(ctx, forgeMavenMetadataURL)
	if err != nil {
		return nil, err
	}
	selectedBuild := latestBuildVersionForMinecraftGame(fullVersions, gameVersion, extractForgeGameVersion)
	if selectedBuild == "" {
		return nil, fmt.Errorf("forge version %s has no builds", gameVersion)
	}

	fileName := fmt.Sprintf("forge-%s-universal.jar", selectedBuild)
	downloadURL := fmt.Sprintf(
		"%s/%s/%s",
		forgeMavenBaseURL,
		url.PathEscape(selectedBuild),
		url.PathEscape(fileName),
	)
	return &minecraftServerArtifact{
		Software:    minecraftSoftwareForge,
		Version:     gameVersion,
		DownloadURL: downloadURL,
		FileName:    fileName,
	}, nil
}

func resolveNeoForgeServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	gameVersion := strings.TrimSpace(requestedVersion)
	if gameVersion == "" || strings.EqualFold(gameVersion, "LATEST") {
		versions, err := listMinecraftVersionsForSoftware(ctx, minecraftSoftwareNeoForge)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no neoforge versions are available")
		}
		gameVersion = versions[0]
	}
	if !isStableMinecraftVersion(gameVersion) {
		return nil, fmt.Errorf("neoforge version %q is invalid", gameVersion)
	}

	fullVersions, err := fetchMavenMetadataVersions(ctx, neoForgeMavenMetadataURL)
	if err != nil {
		return nil, err
	}
	selectedBuild := latestBuildVersionForMinecraftGame(fullVersions, gameVersion, extractNeoForgeGameVersion)
	if selectedBuild == "" {
		return nil, fmt.Errorf("neoforge version %s has no builds", gameVersion)
	}

	fileName := fmt.Sprintf("neoforge-%s-universal.jar", selectedBuild)
	downloadURL := fmt.Sprintf(
		"%s/%s/%s",
		neoForgeMavenBaseURL,
		url.PathEscape(selectedBuild),
		url.PathEscape(fileName),
	)
	return &minecraftServerArtifact{
		Software:    minecraftSoftwareNeoForge,
		Version:     gameVersion,
		DownloadURL: downloadURL,
		FileName:    fileName,
	}, nil
}

func resolveSpongeServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	gameVersion := strings.TrimSpace(requestedVersion)
	if gameVersion == "" || strings.EqualFold(gameVersion, "LATEST") {
		versions, err := listMinecraftVersionsForSoftware(ctx, minecraftSoftwareSponge)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no sponge versions are available")
		}
		gameVersion = versions[0]
	}
	if !isStableMinecraftVersion(gameVersion) {
		return nil, fmt.Errorf("sponge version %q is invalid", gameVersion)
	}

	selectedBuild, err := fetchLatestSpongeBuildVersionForGame(ctx, gameVersion)
	if err != nil {
		return nil, err
	}

	detailsURL := fmt.Sprintf("%s/%s", spongeVersionsURL, url.PathEscape(selectedBuild))
	var payload spongeVersionDetailsResponse
	if err := fetchExternalJSON(ctx, detailsURL, &payload); err != nil {
		return nil, err
	}

	downloadURL, fileName := selectPreferredSpongeJarAsset(payload.Assets, selectedBuild)
	if downloadURL == "" {
		return nil, fmt.Errorf("sponge version %s has no downloadable jar", gameVersion)
	}

	return &minecraftServerArtifact{
		Software:    minecraftSoftwareSponge,
		Version:     gameVersion,
		DownloadURL: downloadURL,
		FileName:    fileName,
	}, nil
}

func fetchLatestSpongeBuildVersionForGame(ctx context.Context, gameVersion string) (string, error) {
	params := url.Values{}
	params.Set("tags", "minecraft:"+gameVersion)
	params.Set("offset", "0")
	params.Set("limit", "1000")
	endpoint := spongeVersionsURL + "?" + params.Encode()

	var payload spongeVersionsResponse
	if err := fetchExternalJSON(ctx, endpoint, &payload); err != nil {
		return "", err
	}
	if len(payload.Artifacts) == 0 {
		return "", fmt.Errorf("sponge version %s has no builds", gameVersion)
	}

	recommended := make([]string, 0, len(payload.Artifacts))
	all := make([]string, 0, len(payload.Artifacts))
	for buildVersion, build := range payload.Artifacts {
		candidate := strings.TrimSpace(buildVersion)
		if candidate == "" {
			continue
		}
		all = append(all, candidate)
		if build.Recommended {
			recommended = append(recommended, candidate)
		}
	}
	selected := recommended
	if len(selected) == 0 {
		selected = all
	}
	if len(selected) == 0 {
		return "", fmt.Errorf("sponge version %s has no builds", gameVersion)
	}

	sort.Slice(selected, func(i, j int) bool {
		return compareLooseVersionStrings(selected[i], selected[j]) > 0
	})
	return selected[0], nil
}

func selectPreferredSpongeJarAsset(assets []spongeVersionAsset, buildVersion string) (string, string) {
	fallbackURL := ""
	fallbackFileName := ""
	for _, asset := range assets {
		if !strings.EqualFold(strings.TrimSpace(asset.Extension), "jar") {
			continue
		}
		downloadURL := strings.TrimSpace(asset.DownloadURL)
		if downloadURL == "" {
			continue
		}
		classifier := strings.ToLower(strings.TrimSpace(asset.Classifier))
		fileName := fileNameFromURL(downloadURL, "")
		if classifier == "universal" {
			if fileName == "" {
				fileName = fmt.Sprintf("spongevanilla-%s-universal.jar", buildVersion)
			}
			return downloadURL, fileName
		}
		if fallbackURL == "" && classifier == "" {
			fallbackURL = downloadURL
			fallbackFileName = fileName
		}
		if fallbackURL == "" {
			fallbackURL = downloadURL
			fallbackFileName = fileName
		}
	}
	if fallbackURL == "" {
		return "", ""
	}
	if fallbackFileName == "" {
		fallbackFileName = fmt.Sprintf("spongevanilla-%s.jar", buildVersion)
	}
	return fallbackURL, fallbackFileName
}

func resolveVelocityServerArtifact(ctx context.Context, requestedVersion string) (*minecraftServerArtifact, error) {
	version := strings.TrimSpace(requestedVersion)
	if version == "" || strings.EqualFold(version, "LATEST") {
		versions, err := listMinecraftVersionsForSoftware(ctx, minecraftSoftwareVelocity)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("no velocity versions are available")
		}
		version = versions[0]
	}
	if !isStableMinecraftVersion(version) {
		return nil, fmt.Errorf("velocity version %q is invalid", version)
	}

	buildURL := fmt.Sprintf(
		"https://api.papermc.io/v2/projects/velocity/versions/%s/builds",
		url.PathEscape(version),
	)

	var payload paperBuildsResponse
	if err := fetchExternalJSON(ctx, buildURL, &payload); err != nil {
		return nil, err
	}
	if len(payload.Builds) == 0 {
		return nil, fmt.Errorf("velocity version %s has no builds", version)
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
		return nil, fmt.Errorf("velocity version %s has no downloadable build", version)
	}

	downloadURL := fmt.Sprintf(
		"https://api.papermc.io/v2/projects/velocity/versions/%s/builds/%d/downloads/%s",
		url.PathEscape(version),
		selectedBuild,
		url.PathEscape(selectedName),
	)

	return &minecraftServerArtifact{
		Software:    minecraftSoftwareVelocity,
		Version:     version,
		DownloadURL: downloadURL,
		FileName:    selectedName,
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

func minecraftServerJarFileNameForArtifact(artifact *minecraftServerArtifact) (string, error) {
	if artifact == nil {
		return "", fmt.Errorf("minecraft artifact is required")
	}
	return normalizeMinecraftJarFileName(artifact.FileName)
}

func minecraftServerJarContainerPath(fileName string) (string, error) {
	name, err := normalizeMinecraftJarFileName(fileName)
	if err != nil {
		return "", err
	}
	return defaultMinecraftServerJarPrefix + name, nil
}

func minecraftServerJarWorkerPath(rootPath, fileName string) (string, error) {
	name, err := normalizeMinecraftJarFileName(fileName)
	if err != nil {
		return "", err
	}
	return path.Join(rootPath, minecraftServerDataDir, name), nil
}

func normalizeMinecraftJarFileName(raw string) (string, error) {
	fileName := strings.TrimSpace(raw)
	fileName = strings.ReplaceAll(fileName, "\\", "/")
	fileName = strings.TrimSpace(path.Base(fileName))
	if fileName == "" || fileName == "." || fileName == "/" {
		return "", fmt.Errorf("minecraft artifact file name is empty")
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".jar") {
		fileName += ".jar"
	}
	return fileName, nil
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
	targetPath, err := minecraftServerJarWorkerPath(rootPath, artifact.FileName)
	if err != nil {
		return err
	}
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
