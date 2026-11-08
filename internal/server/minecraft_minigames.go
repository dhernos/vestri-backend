package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"yourapp/internal/auth"
)

type minecraftMinigameSpec struct {
	InstanceMode string                     `json:"instanceMode,omitempty"`
	LobbyMode    string                     `json:"lobbyMode,omitempty"`
	Teams        []string                   `json:"teams"`
	TeamSize     int                        `json:"teamSize"`
	MinPlayers   int                        `json:"minPlayers"`
	MaxPlayers   int                        `json:"maxPlayers"`
	JoinTimeout  string                     `json:"joinTimeout"`
	ReadyServers int                        `json:"readyServers"`
	Lifecycle    minecraftMinigameLifecycle `json:"lifecycle"`
}

type minecraftMinigameLifecycle struct {
	Ready struct {
		Trigger string `json:"trigger"`
	} `json:"ready"`
	OnAllJoined []minecraftMinigameCommand `json:"onAllJoined"`
	End         struct {
		LogPattern      string `json:"logPattern,omitempty"`
		WhenEmpty       bool   `json:"whenEmpty"`
		EmptyGrace      string `json:"emptyGrace"`
		ReturnPlayersTo string `json:"returnPlayersTo"`
		DeleteServer    bool   `json:"deleteServer"`
	} `json:"end"`
}

type minecraftMinigameCommand struct {
	Command string `json:"command"`
	ForEach string `json:"forEach"`
}

var minecraftMinigameIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var minecraftMinigamePlaceholder = regexp.MustCompile(`\{([^{}]*)\}`)
var minecraftMinigameRegexFlags = regexp.MustCompile(`\(\?([imsU-]+)[:)]`)
var minecraftMinigameRegexOctal = regexp.MustCompile(`\\[1-7]`)
var minecraftMinigameMaxPlayersProperty = regexp.MustCompile(`(?m)^[\t ]*max-players(?:[\t ]*[=:]|[\t ]+)[^\r\n]*(?:\r?\n|$)`)

func validateMinecraftMinigame(spec *minecraftResourceSpec) error {
	if spec.Mode != "" && spec.Mode != "player" && spec.Mode != "minigames" {
		return fmt.Errorf("mode must be empty, player or minigames")
	}
	if spec.Mode != "minigames" {
		if spec.Minigame != nil {
			return fmt.Errorf("minigame requires mode minigames")
		}
		return nil
	}
	game := spec.Minigame
	if game == nil {
		return fmt.Errorf("minigame is required for mode minigames")
	}
	if game.LobbyMode == "" {
		game.LobbyMode = "vestri"
	}
	if game.LobbyMode != "vestri" && game.LobbyMode != "plugin" {
		return fmt.Errorf("lobbyMode must be vestri or plugin")
	}
	if game.InstanceMode == "" {
		game.InstanceMode = "temporary"
	}
	if game.InstanceMode != "temporary" && game.InstanceMode != "permanent" {
		return fmt.Errorf("instanceMode must be temporary or permanent")
	}
	if game.InstanceMode == "permanent" && game.LobbyMode != "plugin" {
		return fmt.Errorf("permanent instanceMode requires plugin lobbyMode")
	}
	if len(game.Teams) > 100 {
		return fmt.Errorf("teams must contain at most 100 identifiers")
	}
	if game.Teams == nil {
		game.Teams = []string{}
	}
	seen := map[string]bool{}
	for _, team := range game.Teams {
		if !minecraftMinigameIdentifier.MatchString(team) || seen[team] {
			return fmt.Errorf("teams must be unique safe identifiers (1-64 ASCII characters)")
		}
		seen[team] = true
	}
	if game.TeamSize < 0 || game.TeamSize > 100 || (len(game.Teams) > 0 && game.TeamSize == 0) {
		return fmt.Errorf("teamSize must be 1-100 with teams, or 0-100 without teams")
	}
	if game.MinPlayers < 1 || game.MinPlayers > 100 || game.MaxPlayers < 1 || game.MaxPlayers > 100 || game.MinPlayers > game.MaxPlayers {
		return fmt.Errorf("player limits must be 1-100 with minPlayers <= maxPlayers")
	}
	if len(game.Teams) > 0 && game.MaxPlayers > len(game.Teams)*game.TeamSize {
		return fmt.Errorf("maxPlayers must not exceed teams * teamSize")
	}
	if game.ReadyServers < 0 || game.ReadyServers > spec.MaxInstances {
		return fmt.Errorf("readyServers must be between 0 and maxInstances")
	}
	if err := defaultMinecraftMinigameDuration(&game.JoinTimeout, "20s"); err != nil {
		return fmt.Errorf("joinTimeout: %w", err)
	}
	lifecycle := &game.Lifecycle
	if lifecycle.Ready.Trigger != "serverLoad" && lifecycle.Ready.Trigger != "explicit" {
		return fmt.Errorf("ready.trigger must be serverLoad or explicit")
	}
	if len(lifecycle.OnAllJoined) > 100 {
		return fmt.Errorf("onAllJoined is limited to 100 commands")
	}
	if game.LobbyMode == "plugin" && len(lifecycle.OnAllJoined) > 0 {
		return fmt.Errorf("onAllJoined must be empty in plugin lobby mode")
	}
	if lifecycle.OnAllJoined == nil {
		lifecycle.OnAllJoined = []minecraftMinigameCommand{}
	}
	for _, command := range lifecycle.OnAllJoined {
		if len(game.Teams) == 0 && (command.ForEach == "team" || strings.Contains(command.Command, "{team}")) {
			return fmt.Errorf("team repetition and {team} require nonempty teams")
		}
		if err := validateMinecraftMinigameCommand(command); err != nil {
			return err
		}
	}
	if game.InstanceMode == "temporary" && !lifecycle.End.DeleteServer {
		return fmt.Errorf("end.deleteServer must be true for temporary instances")
	}
	if game.InstanceMode == "permanent" && (lifecycle.End.DeleteServer || lifecycle.End.WhenEmpty || lifecycle.End.LogPattern != "") {
		return fmt.Errorf("permanent instances require end.deleteServer false, end.whenEmpty false and empty end.logPattern")
	}
	if err := defaultMinecraftMinigameDuration(&lifecycle.End.EmptyGrace, "10s"); err != nil {
		return fmt.Errorf("end.emptyGrace: %w", err)
	}
	if lifecycle.End.ReturnPlayersTo == "" {
		lifecycle.End.ReturnPlayersTo = "lobby"
	}
	if !minecraftMinigameIdentifier.MatchString(lifecycle.End.ReturnPlayersTo) {
		return fmt.Errorf("end.returnPlayersTo must be a safe server identifier")
	}
	pattern := lifecycle.End.LogPattern
	if len(pattern) > 512 || strings.ContainsAny(pattern, "\r\n") {
		return fmt.Errorf("end.logPattern must be at most 512 bytes without newlines")
	}
	if pattern != "" {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("end.logPattern must compile as a Go regular expression")
		}
		for _, unsupported := range []string{"(?P", "(?<", "(?U", "\\p", "\\P", "\\x{", "\\a", "\\v", "[:", "[.", "[="} {
			if strings.Contains(pattern, unsupported) {
				return fmt.Errorf("end.logPattern uses syntax outside the supported Go/Java subset")
			}
		}
		if minecraftMinigameRegexOctal.MatchString(pattern) {
			return fmt.Errorf("end.logPattern octal escapes are not Java-compatible")
		}
		for _, flags := range minecraftMinigameRegexFlags.FindAllStringSubmatch(pattern, -1) {
			if strings.Contains(flags[1], "U") {
				return fmt.Errorf("end.logPattern ungreedy flags are not Java-compatible")
			}
		}
	}
	return nil
}

func defaultMinecraftMinigameDuration(value *string, fallback string) error {
	if *value == "" {
		*value = fallback
	}
	duration, err := time.ParseDuration(*value)
	if err != nil || duration < time.Second || duration > 10*time.Minute {
		return fmt.Errorf("must be a duration between 1s and 10m")
	}
	if duration%time.Millisecond != 0 {
		return fmt.Errorf("must use whole milliseconds")
	}
	*value = duration.String()
	return nil
}

func minecraftMinigameInstanceProperties(properties string, spec *minecraftResourceSpec) string {
	if spec.Mode == "minigames" && spec.Minigame != nil {
		properties = minecraftMinigameMaxPlayersProperty.ReplaceAllString(properties, "")
		return upsertJavaPropertiesValue(properties, "max-players", fmt.Sprint(spec.Minigame.MaxPlayers))
	}
	return properties
}

func validateMinecraftMinigameCommand(command minecraftMinigameCommand) error {
	text := strings.TrimSpace(command.Command)
	if text == "" || len(command.Command) > 1024 || strings.HasPrefix(text, "/") || strings.IndexFunc(command.Command, unicode.IsControl) >= 0 {
		return fmt.Errorf("commands must be 1-1024 bytes, without slash prefix or control characters")
	}
	if command.ForEach != "" && command.ForEach != "team" && command.ForEach != "player" {
		return fmt.Errorf("command forEach must be empty, team or player")
	}
	for _, placeholder := range minecraftMinigamePlaceholder.FindAllStringSubmatch(text, -1) {
		switch placeholder[1] {
		case "matchId":
		case "team":
			if command.ForEach == "" {
				return fmt.Errorf("{team} requires team or player repetition")
			}
		case "player", "uuid":
			if command.ForEach != "player" {
				return fmt.Errorf("{player} and {uuid} require player repetition")
			}
		default:
			return fmt.Errorf("unknown command placeholder")
		}
	}
	if strings.ContainsAny(minecraftMinigamePlaceholder.ReplaceAllString(text, ""), "{}") {
		return fmt.Errorf("malformed command placeholder")
	}
	return nil
}

const minecraftMinigameConfigRelativePath = "data/plugins/VestriConsoleBridge/minigame.json"
const minecraftMinigameExecutionRelativePath = "data/plugins/VestriConsoleBridge/minigame-execution.json"

type minecraftMinigameManifestSpec struct {
	minecraftMinigameSpec
	MaxInstances int `json:"maxInstances"`
}

type minecraftMinigameConfig struct {
	Slug           string                 `json:"slug"`
	Token          string                 `json:"token"`
	ControlURL     string                 `json:"controlUrl"`
	Spec           *minecraftMinigameSpec `json:"spec"`
	SpawnRequestID string                 `json:"spawnRequestId,omitempty"`
}

var minecraftMinigameToken = regexp.MustCompile(`^[0-9a-f]{64}$`)

type minecraftMinigameFileError struct {
	operation string
	file      string
	cause     error
}

func (failure *minecraftMinigameFileError) Error() string {
	return "failed to " + failure.operation + " " + failure.file
}

func (failure *minecraftMinigameFileError) Unwrap() error {
	return failure.cause
}

func readMinecraftMinigameConfig(ctx context.Context, worker pluginWorker, server *auth.GameServer) (*minecraftMinigameConfig, error) {
	content, missing, err := worker.server.workerReadFileOptional(ctx, worker.baseURL, worker.apiKey, path.Join(server.RootPath, minecraftMinigameConfigRelativePath))
	if err != nil {
		return nil, &minecraftMinigameFileError{"read", minecraftMinigameConfigRelativePath, err}
	}
	if missing {
		return nil, fmt.Errorf("minigame configuration is unavailable")
	}
	var config minecraftMinigameConfig
	if json.Unmarshal([]byte(content), &config) != nil || config.Slug != server.Slug || !minecraftMinigameToken.MatchString(config.Token) || config.Spec == nil {
		return nil, fmt.Errorf("minigame configuration is invalid")
	}
	if err := validateMinecraftMinigame(&minecraftResourceSpec{Mode: "minigames", MaxInstances: 100, Minigame: config.Spec}); err != nil {
		return nil, fmt.Errorf("saved minigame spec is invalid")
	}
	if config.SpawnRequestID != "" {
		if _, err := uuid.Parse(config.SpawnRequestID); err != nil {
			return nil, fmt.Errorf("saved minigame spawn request ID is invalid")
		}
	}
	return &config, nil
}

func provisionMinecraftMinigame(ctx context.Context, worker pluginWorker, server, parent *auth.GameServer, spec *minecraftResourceSpec, retry bool, rawRequestID ...string) error {
	filename := path.Join(server.RootPath, minecraftMinigameConfigRelativePath)
	spawnRequestID := ""
	if len(rawRequestID) > 0 {
		if _, err := uuid.Parse(rawRequestID[0]); err != nil {
			return fmt.Errorf("minigame spawn request ID must be a UUID")
		}
		spawnRequestID = rawRequestID[0]
	}
	if !retry {
		if err := worker.server.workerDeletePath(ctx, worker.baseURL, worker.apiKey, path.Join(server.RootPath, minecraftMinigameExecutionRelativePath), false); err != nil {
			return &minecraftMinigameFileError{"delete", minecraftMinigameExecutionRelativePath, err}
		}
	}
	if spec.Mode != "minigames" {
		if err := worker.server.workerDeletePath(ctx, worker.baseURL, worker.apiKey, filename, false); err != nil {
			return &minecraftMinigameFileError{"delete", minecraftMinigameConfigRelativePath, err}
		}
		return nil
	}
	if parent == nil || spec.Minigame == nil {
		return fmt.Errorf("minigame requires a proxy and spec")
	}
	controlURL := "http://" + velocityBackendHostForSlug(parent.Slug) + ":25580"
	if retry {
		config, err := readMinecraftMinigameConfig(ctx, worker, server)
		if err != nil {
			return err
		}
		if config.ControlURL != controlURL {
			return fmt.Errorf("minigame proxy does not match saved configuration")
		}
		if config.SpawnRequestID == "" && spawnRequestID != "" {
			config.SpawnRequestID = spawnRequestID
			content, err := json.Marshal(config)
			if err != nil {
				return err
			}
			if err := worker.server.workerWriteFile(ctx, worker.baseURL, worker.apiKey, filename, string(content)); err != nil {
				return &minecraftMinigameFileError{"write", minecraftMinigameConfigRelativePath, err}
			}
		}
		return nil
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("failed to generate minigame credentials")
	}
	content, err := json.Marshal(minecraftMinigameConfig{Slug: server.Slug, Token: hex.EncodeToString(random[:]), ControlURL: controlURL, Spec: spec.Minigame, SpawnRequestID: spawnRequestID})
	if err != nil {
		return err
	}
	if err := worker.server.workerWriteFile(ctx, worker.baseURL, worker.apiKey, filename, string(content)); err != nil {
		return &minecraftMinigameFileError{"write", minecraftMinigameConfigRelativePath, err}
	}
	return nil
}

func buildMinecraftProxyManifest(ctx context.Context, worker pluginWorker, parent *auth.GameServer, resources []auth.MinecraftResource, instances []auth.MinecraftInstance, servers []auth.GameServer, excludeID string) ([]byte, error) {
	minigames := map[string]minecraftMinigameManifestSpec{}
	templates := map[string]auth.MinecraftResource{}
	for _, resource := range resources {
		if resource.Kind != "templates" {
			continue
		}
		var spec minecraftResourceSpec
		if json.Unmarshal(resource.Spec, &spec) != nil {
			return nil, fmt.Errorf("invalid Minecraft template metadata")
		}
		if spec.ParentID != parent.ID || spec.Mode != "minigames" {
			continue
		}
		if spec.MaxInstances < 1 || spec.MaxInstances > 100 {
			return nil, fmt.Errorf("invalid minigame template instance limit")
		}
		if err := validateMinecraftMinigame(&spec); err != nil {
			return nil, err
		}
		templates[resource.ID] = resource
		minigames[resource.Name] = minecraftMinigameManifestSpec{minecraftMinigameSpec: *spec.Minigame, MaxInstances: spec.MaxInstances}
	}
	dynamic := map[string]auth.MinecraftInstance{}
	serverIDs := map[string]bool{}
	for _, server := range servers {
		serverIDs[server.ID] = true
	}
	for _, instance := range instances {
		if instance.ServerID != excludeID {
			if !serverIDs[instance.ServerID] {
				return nil, fmt.Errorf("Minecraft instance snapshot is incomplete")
			}
			dynamic[instance.ServerID] = instance
		}
	}
	targets := map[string]interface{}{}
	for _, server := range servers {
		instance, found := dynamic[server.ID]
		if !found {
			continue
		}
		var checkedMetadata gameServerStoredMetadata
		if json.Unmarshal(server.Metadata, &checkedMetadata) != nil || checkedMetadata.ParentServerID == "" {
			return nil, fmt.Errorf("invalid Minecraft instance metadata")
		}
		metadata := parseGameServerMetadata(server.Metadata)
		if metadata.ParentServerID != parent.ID {
			continue
		}
		if _, duplicate := targets[server.Slug]; duplicate {
			return nil, fmt.Errorf("duplicate Minecraft instance slug")
		}
		target := map[string]interface{}{"name": minecraftInstanceProxyName(&server), "host": metadata.ConnectHost, "port": metadata.ConnectPort}
		if template, minigame := templates[instance.TemplateID]; minigame {
			config, err := readMinecraftMinigameConfig(ctx, worker, &server)
			if err != nil {
				return nil, err
			}
			if config.ControlURL != "http://"+velocityBackendHostForSlug(parent.Slug)+":25580" {
				return nil, fmt.Errorf("minigame proxy does not match saved configuration")
			}
			target["serverId"], target["template"], target["token"] = server.ID, template.Name, config.Token
			target["id"], target["requestId"] = server.ID, instance.RequestID
			target["spec"] = minecraftMinigameManifestSpec{minecraftMinigameSpec: *config.Spec, MaxInstances: minigames[template.Name].MaxInstances}
			if config.SpawnRequestID != "" {
				target["spawnRequestId"] = config.SpawnRequestID
			}
		}
		targets[server.Slug] = target
	}
	return json.Marshal(map[string]interface{}{"authoritative": excludeID == "", "servers": targets, "minigames": minigames})
}
