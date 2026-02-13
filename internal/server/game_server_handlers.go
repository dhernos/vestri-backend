package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"yourapp/internal/auth"
)

const (
	maxWorkerResponseBytes = 8 << 20
	maxRemoteComposeBytes  = 2 << 20
)

type createGameServerRequest struct {
	TemplateID        string `json:"templateId"`
	Name              string `json:"name"`
	AgreementAccepted bool   `json:"agreementAccepted"`
	SoftwareVersion   string `json:"softwareVersion"`
	GameVersion       string `json:"gameVersion"`
}

type gameServerTemplateResponse struct {
	ID              string                         `json:"id"`
	Name            string                         `json:"name"`
	Description     string                         `json:"description"`
	Game            string                         `json:"game"`
	TemplateVersion string                         `json:"templateVersion"`
	ConfigFiles     []gameServerConfigFileResponse `json:"configFiles"`
	Agreement       *gameServerTemplateAgreement   `json:"agreement,omitempty"`
	VersionConfig   *gameServerTemplateVersions    `json:"versionConfig,omitempty"`
}

type gameServerPermissions struct {
	CanView        bool `json:"canView"`
	CanCreate      bool `json:"canCreate"`
	CanControl     bool `json:"canControl"`
	CanManageFiles bool `json:"canManageFiles"`
	CanReadConsole bool `json:"canReadConsole"`
	CanManage      bool `json:"canManage"`
}

type gameServerResponse struct {
	ID              string                         `json:"id"`
	NodeID          string                         `json:"nodeId"`
	Slug            string                         `json:"slug"`
	Name            string                         `json:"name"`
	TemplateID      string                         `json:"templateId"`
	TemplateVersion string                         `json:"templateVersion"`
	TemplateName    string                         `json:"templateName"`
	Game            string                         `json:"game"`
	SoftwareVersion string                         `json:"softwareVersion,omitempty"`
	GameVersion     string                         `json:"gameVersion,omitempty"`
	StackName       string                         `json:"stackName"`
	RootPath        string                         `json:"rootPath"`
	ComposePath     string                         `json:"composePath"`
	ConfigFiles     []gameServerConfigFileResponse `json:"configFiles"`
	Status          string                         `json:"status"`
	StatusOutput    string                         `json:"statusOutput,omitempty"`
	StatusError     string                         `json:"statusError,omitempty"`
	Permissions     gameServerPermissions          `json:"permissions"`
	CreatedByUserID string                         `json:"createdByUserId"`
	CreatedAt       time.Time                      `json:"createdAt"`
	UpdatedAt       time.Time                      `json:"updatedAt"`
}

func (s *Server) handleListGameServerTemplates(w http.ResponseWriter, r *http.Request) {
	_, node, ok := s.loadNodeForGameServerRequest(w, r)
	if !ok {
		return
	}

	templates, err := gameServerTemplates()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load game server templates")
		return
	}

	resp := make([]gameServerTemplateResponse, 0, len(templates))
	for _, tpl := range templates {
		resp = append(resp, gameServerTemplateResponse{
			ID:              tpl.ID,
			Name:            tpl.Name,
			Description:     tpl.Description,
			Game:            tpl.Game,
			TemplateVersion: tpl.TemplateVersion,
			ConfigFiles:     configFilesToResponse(tpl.ConfigFiles),
			Agreement:       tpl.Agreement,
			VersionConfig:   tpl.VersionConfig,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"templates":   resp,
		"permissions": buildGameServerPermissions(node.AccessRole, auth.NodeAccessViewer),
	})
}

func (s *Server) handleListGameServers(w http.ResponseWriter, r *http.Request) {
	sess, node, ok := s.loadNodeForGameServerRequest(w, r)
	if !ok {
		return
	}

	servers, err := s.Users.ListAccessibleGameServersForNode(r.Context(), sess.UserID, node)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load accessible game servers")
		return
	}

	includeStatus := includeStatusRequested(r)
	var (
		baseURL *url.URL
		apiKey  string
	)
	if includeStatus {
		baseURL, apiKey, err = s.workerTargetFromNode(node)
		if err != nil {
			includeStatus = false
		}
	}

	responsePermissions := gameServerPermissions{
		CanCreate: canCreateGameServer(node.AccessRole),
	}
	resp := make([]gameServerResponse, 0, len(servers))
	for i := range servers {
		state := "unknown"
		output := ""
		statusErr := ""
		permissions := buildGameServerPermissions(node.AccessRole, servers[i].AccessRole)

		if includeStatus && canReadGameServerConsole(servers[i].AccessRole) {
			resolvedState, resolvedOutput, resolveErr := s.workerStackStatus(r.Context(), baseURL, apiKey, servers[i].StackName)
			state = resolvedState
			output = resolvedOutput
			if resolveErr != nil {
				statusErr = resolveErr.Error()
			}
		}

		responsePermissions.CanView = responsePermissions.CanView || permissions.CanView
		responsePermissions.CanControl = responsePermissions.CanControl || permissions.CanControl
		responsePermissions.CanManageFiles = responsePermissions.CanManageFiles || permissions.CanManageFiles
		responsePermissions.CanReadConsole = responsePermissions.CanReadConsole || permissions.CanReadConsole
		responsePermissions.CanManage = responsePermissions.CanManage || permissions.CanManage

		resp = append(resp, buildGameServerResponse(&servers[i].GameServer, permissions, state, output, statusErr))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"servers":       resp,
		"permissions":   responsePermissions,
		"includeStatus": includeStatus,
	})
}

func (s *Server) handleCreateGameServer(w http.ResponseWriter, r *http.Request) {
	sess, node, ok := s.loadNodeForGameServerRequest(w, r)
	if !ok {
		return
	}
	if !canCreateGameServer(node.AccessRole) {
		writeError(w, http.StatusForbidden, "Only owner/admin can create game servers")
		return
	}

	var req createGameServerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	req.TemplateID = strings.TrimSpace(req.TemplateID)
	if req.TemplateID == "" {
		writeError(w, http.StatusBadRequest, "templateId is required")
		return
	}

	template, err := gameServerTemplateByID(req.TemplateID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load game server template")
		return
	}
	if template == nil {
		writeError(w, http.StatusNotFound, "Game server template not found")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = template.Name
	}

	if template.Agreement != nil && template.Agreement.Required && !req.AgreementAccepted {
		writeError(w, http.StatusBadRequest, "Template agreement must be accepted before creating this server")
		return
	}

	softwareVersion, err := resolveTemplateVersionValue(template.VersionConfig, "software", req.SoftwareVersion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	gameVersion, err := resolveTemplateVersionValue(template.VersionConfig, "game", req.GameVersion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	slugBase := slugify(name)
	if slugBase == "" {
		slugBase = slugify(template.ID)
	}
	if slugBase == "" {
		slugBase = "game-server"
	}

	slug, err := s.uniqueGameServerSlug(r.Context(), node.ID, slugBase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to reserve game server slug")
		return
	}

	stackName := slug
	rootPath := slug
	composePath := path.Join(rootPath, "docker-compose.yml")

	renderValues := map[string]string{
		"SERVER_SLUG":     slug,
		"SERVER_NAME":     name,
		"SERVER_SOFTWARE": softwareVersion,
		"SERVER_TYPE":     softwareVersion,
		"GAME_VERSION":    gameVersion,
	}

	composeContent, err := resolveTemplateCompose(r.Context(), template, renderValues)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to load compose file from template")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	if err := s.workerWriteFile(r.Context(), baseURL, apiKey, composePath, composeContent); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to write compose file on worker")
		return
	}

	configFiles := make([]gameServerTemplateConfigFile, 0, len(template.ConfigFiles))
	for _, cfg := range template.ConfigFiles {
		configFiles = append(configFiles, cfg)

		if strings.TrimSpace(cfg.DefaultContent) == "" {
			continue
		}
		absoluteConfigPath := path.Join(rootPath, cfg.Path)
		renderedContent := normalizeTemplateTextEscapes(renderTemplateText(cfg.DefaultContent, renderValues))
		if err := s.workerWriteFile(r.Context(), baseURL, apiKey, absoluteConfigPath, renderedContent); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to write default config files on worker")
			return
		}
	}

	metadataRaw, _ := json.Marshal(gameServerStoredMetadata{
		TemplateName:    template.Name,
		Game:            template.Game,
		ConfigFiles:     configFiles,
		SoftwareVersion: softwareVersion,
		GameVersion:     gameVersion,
	})

	created, err := s.Users.CreateGameServer(r.Context(), auth.CreateGameServerParams{
		NodeID:          node.ID,
		Slug:            slug,
		Name:            name,
		TemplateID:      template.ID,
		TemplateVersion: template.TemplateVersion,
		StackName:       stackName,
		RootPath:        rootPath,
		ComposePath:     composePath,
		Metadata:        metadataRaw,
		CreatedByUserID: sess.UserID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create game server")
		return
	}

	serverRole := auth.NodeAccessOwner
	if sess.UserID != node.OwnerUserID {
		serverRole = auth.NodeAccessAdmin
		if err := s.Users.UpsertGameServerGuest(r.Context(), created.ID, sess.UserID, serverRole); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to grant creator access to the game server")
			return
		}
	}

	permissions := buildGameServerPermissions(node.AccessRole, serverRole)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"server": buildGameServerResponse(created, permissions, "unknown", "", ""),
	})
}

func (s *Server) handleGetGameServer(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canViewGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for this action")
		return
	}

	state := "unknown"
	output := ""
	statusErr := ""
	if includeStatusRequested(r) && canReadGameServerConsole(serverRole) {
		baseURL, apiKey, err := s.workerTargetFromNode(node)
		if err == nil {
			resolvedState, resolvedOutput, resolveErr := s.workerStackStatus(r.Context(), baseURL, apiKey, server.StackName)
			state = resolvedState
			output = resolvedOutput
			if resolveErr != nil {
				statusErr = resolveErr.Error()
			}
		} else {
			statusErr = err.Error()
		}
	}

	permissions := buildGameServerPermissions(node.AccessRole, serverRole)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"server": buildGameServerResponse(server, permissions, state, output, statusErr),
	})
}

func (s *Server) handleGameServerStatus(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canReadGameServerConsole(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for this action")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	state, output, statusErr := s.workerStackStatus(r.Context(), baseURL, apiKey, server.StackName)
	resp := map[string]interface{}{
		"status": state,
		"output": output,
	}
	if statusErr != nil {
		resp["error"] = statusErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStartGameServer(w http.ResponseWriter, r *http.Request) {
	s.handleGameServerStackAction(w, r, "up")
}

func (s *Server) handleStopGameServer(w http.ResponseWriter, r *http.Request) {
	s.handleGameServerStackAction(w, r, "down")
}

func (s *Server) handleDeleteGameServer(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can delete this game server")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	if err := s.cleanupGameServerOnWorker(r.Context(), baseURL, apiKey, server); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to cleanup game server files on worker")
		return
	}

	deleted, err := s.Users.DeleteGameServerByID(r.Context(), node.ID, server.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete game server")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "Game server not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Game server deleted.",
	})
}

func (s *Server) handleGameServerStackAction(w http.ResponseWriter, r *http.Request, action string) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canControlGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin/operator can start or stop this server")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	output, err := s.workerStackAction(r.Context(), baseURL, apiKey, action, server.StackName)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"message": "Worker stack action failed",
			"action":  action,
			"output":  output,
		})
		return
	}

	state, statusOutput, statusErr := s.workerStackStatus(r.Context(), baseURL, apiKey, server.StackName)
	resp := map[string]interface{}{
		"action": action,
		"status": state,
		"output": output,
	}
	if statusOutput != "" {
		resp["statusOutput"] = statusOutput
	}
	if statusErr != nil {
		resp["statusError"] = statusErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) loadNodeForGameServerRequest(w http.ResponseWriter, r *http.Request) (*auth.Session, *auth.WorkerNode, bool) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return nil, nil, false
	}

	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	if nodeRef == "" {
		writeError(w, http.StatusBadRequest, "nodeRef is required")
		return nil, nil, false
	}

	node, err := s.Users.FindAccessibleWorkerNodeByRef(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node")
		return nil, nil, false
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return nil, nil, false
	}

	return sess, node, true
}

func (s *Server) loadNodeAndGameServerForRequest(w http.ResponseWriter, r *http.Request) (*auth.Session, *auth.WorkerNode, *auth.GameServer, string, bool) {
	sess, node, ok := s.loadNodeForGameServerRequest(w, r)
	if !ok {
		return nil, nil, nil, "", false
	}

	serverRef := strings.TrimSpace(chi.URLParam(r, "serverRef"))
	if serverRef == "" {
		writeError(w, http.StatusBadRequest, "serverRef is required")
		return nil, nil, nil, "", false
	}

	access, err := s.Users.FindAccessibleGameServerByRefForNode(r.Context(), sess.UserID, node, serverRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load game server")
		return nil, nil, nil, "", false
	}
	if access == nil {
		writeError(w, http.StatusNotFound, "Game server not found")
		return nil, nil, nil, "", false
	}

	return sess, node, &access.GameServer, access.AccessRole, true
}

func includeStatusRequested(r *http.Request) bool {
	raw := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("includeStatus")))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func buildGameServerPermissions(nodeRole, serverRole string) gameServerPermissions {
	return gameServerPermissions{
		CanView:        canViewGameServer(serverRole),
		CanCreate:      canCreateGameServer(nodeRole),
		CanControl:     canControlGameServer(serverRole),
		CanManageFiles: canManageGameServerFiles(serverRole),
		CanReadConsole: canReadGameServerConsole(serverRole),
		CanManage:      canManageGameServer(serverRole),
	}
}

func buildGameServerResponse(srv *auth.GameServer, permissions gameServerPermissions, status, statusOutput, statusErr string) gameServerResponse {
	metadata := parseGameServerMetadata(srv.Metadata)

	state := status
	if state == "" {
		state = "unknown"
	}

	return gameServerResponse{
		ID:              srv.ID,
		NodeID:          srv.NodeID,
		Slug:            srv.Slug,
		Name:            srv.Name,
		TemplateID:      srv.TemplateID,
		TemplateVersion: srv.TemplateVersion,
		TemplateName:    metadata.TemplateName,
		Game:            metadata.Game,
		SoftwareVersion: metadata.SoftwareVersion,
		GameVersion:     metadata.GameVersion,
		StackName:       srv.StackName,
		RootPath:        srv.RootPath,
		ComposePath:     srv.ComposePath,
		ConfigFiles:     configFilesToResponse(metadata.ConfigFiles),
		Status:          state,
		StatusOutput:    statusOutput,
		StatusError:     statusErr,
		Permissions:     permissions,
		CreatedByUserID: srv.CreatedByUserID,
		CreatedAt:       srv.CreatedAt,
		UpdatedAt:       srv.UpdatedAt,
	}
}

func resolveTemplateVersionValue(config *gameServerTemplateVersions, field, raw string) (string, error) {
	if config == nil {
		return "", nil
	}

	var cfg *gameServerTemplateVersionField
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "software":
		cfg = config.Software
	case "game":
		cfg = config.Game
	default:
		return "", fmt.Errorf("unsupported version field")
	}

	if cfg == nil {
		return "", nil
	}

	value := strings.TrimSpace(raw)
	if value == "" {
		value = strings.TrimSpace(cfg.Default)
	}
	if value == "" && len(cfg.Options) > 0 {
		value = cfg.Options[0]
	}
	if len(cfg.Options) == 0 {
		return value, nil
	}
	for _, option := range cfg.Options {
		if strings.EqualFold(value, option) {
			return option, nil
		}
	}
	return "", fmt.Errorf("invalid value for %s", cfg.Label)
}

func (s *Server) uniqueGameServerSlug(ctx context.Context, nodeID, base string) (string, error) {
	candidate := base
	for i := 0; i < 20; i++ {
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", base, i+1)
		}

		exists, err := s.Users.GameServerSlugExists(ctx, nodeID, candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}

	for {
		suffix := strings.ReplaceAll(auth.NewSessionID(), "-", "")
		candidate = fmt.Sprintf("%s-%s", base, suffix[:8])
		exists, err := s.Users.GameServerSlugExists(ctx, nodeID, candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
}

func resolveTemplateCompose(ctx context.Context, tpl *gameServerTemplate, values map[string]string) (string, error) {
	if tpl == nil {
		return "", fmt.Errorf("template is required")
	}

	if tpl.ComposeInline != "" {
		return renderTemplateText(tpl.ComposeInline, values), nil
	}
	if tpl.ComposeURL == "" {
		return "", fmt.Errorf("template has no compose source")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tpl.ComposeURL, nil)
	if err != nil {
		return "", err
	}

	client := http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("compose source request failed with status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteComposeBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > maxRemoteComposeBytes {
		return "", fmt.Errorf("compose source exceeds size limit")
	}

	return renderTemplateText(string(raw), values), nil
}

func renderTemplateText(value string, replacements map[string]string) string {
	out := value
	if len(replacements) == 0 {
		return out
	}

	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		placeholder := "{{" + key + "}}"
		out = strings.ReplaceAll(out, placeholder, replacements[key])
	}
	return out
}

func normalizeTemplateTextEscapes(value string) string {
	out := strings.ReplaceAll(value, "\\r\\n", "\n")
	out = strings.ReplaceAll(out, "\\n", "\n")
	out = strings.ReplaceAll(out, "\\r", "\r")
	out = strings.ReplaceAll(out, "\\t", "\t")
	return out
}

func (s *Server) cleanupGameServerOnWorker(ctx context.Context, baseURL *url.URL, apiKey string, server *auth.GameServer) error {
	if server == nil {
		return nil
	}

	_, _ = s.workerStackAction(ctx, baseURL, apiKey, "down", server.StackName)

	paths := uniqueCleanupPaths(server.RootPath, server.StackName)
	for _, targetPath := range paths {
		if err := s.workerDeletePath(ctx, baseURL, apiKey, targetPath, true); err != nil {
			return err
		}
	}
	return nil
}

func uniqueCleanupPaths(paths ...string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(paths))
	for _, item := range paths {
		clean := strings.TrimSpace(item)
		if clean == "" {
			continue
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		result = append(result, clean)
	}
	return result
}

func (s *Server) workerWriteFile(ctx context.Context, baseURL *url.URL, apiKey, filePath, content string) error {
	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/write", map[string]string{
		"path":    filePath,
		"content": content,
	})
	if err != nil {
		return err
	}
	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("worker /fs/write failed (%d): %s", statusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *Server) workerDeletePath(ctx context.Context, baseURL *url.URL, apiKey, targetPath string, recursive bool) error {
	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{
		"path":      targetPath,
		"recursive": recursive,
	})
	if err != nil {
		return err
	}
	if statusCode == http.StatusNotFound {
		return nil
	}
	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("worker /fs/delete failed (%d): %s", statusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *Server) workerStackAction(ctx context.Context, baseURL *url.URL, apiKey, action, stackName string) (string, error) {
	action = strings.TrimSpace(strings.ToLower(action))
	endpoint := ""
	switch action {
	case "up":
		endpoint = "/stack/up"
	case "down":
		endpoint = "/stack/down"
	default:
		return "", fmt.Errorf("unsupported stack action: %s", action)
	}

	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, endpoint, map[string]string{
		"stack": stackName,
	})
	if err != nil {
		return "", err
	}

	output := strings.TrimSpace(string(body))
	if statusCode < 200 || statusCode >= 300 {
		return output, fmt.Errorf("worker stack action failed (%d)", statusCode)
	}
	return output, nil
}

func (s *Server) workerStackStatus(ctx context.Context, baseURL *url.URL, apiKey, stackName string) (string, string, error) {
	statusPath := "/stack/status?stack=" + url.QueryEscape(stackName)
	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodGet, statusPath, nil)
	if err != nil {
		return "unknown", "", err
	}

	output := strings.TrimSpace(string(body))
	if statusCode < 200 || statusCode >= 300 {
		return "unknown", output, fmt.Errorf("worker stack status failed (%d)", statusCode)
	}

	return deriveGameServerState(output), output, nil
}

func deriveGameServerState(output string) string {
	lower := strings.ToLower(strings.TrimSpace(output))
	if lower == "" {
		return "down"
	}
	if strings.Contains(lower, "running") || strings.Contains(lower, "up") {
		return "up"
	}
	if strings.Contains(lower, "exited") || strings.Contains(lower, "dead") || strings.Contains(lower, "created") {
		return "down"
	}
	return "down"
}

func (s *Server) callWorkerJSON(ctx context.Context, baseURL *url.URL, apiKey, method, workerPath string, payload interface{}) (int, []byte, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return 0, nil, fmt.Errorf("method is required")
	}

	parsedPath, err := url.Parse(workerPath)
	if err != nil {
		return 0, nil, err
	}

	pathname := "/" + strings.TrimPrefix(parsedPath.Path, "/")
	signedPath := pathname
	if parsedPath.RawQuery != "" {
		signedPath += "?" + parsedPath.RawQuery
	}

	targetURL := *baseURL
	targetURL.Path = joinWorkerPath(baseURL.Path, pathname)
	targetURL.RawQuery = parsedPath.RawQuery

	var (
		bodyBytes []byte
		body      io.Reader
	)
	if payload != nil {
		bodyBytes, err = json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL.String(), body)
	if err != nil {
		return 0, nil, err
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := strings.ReplaceAll(auth.NewSessionID(), "-", "")
	signature := signWorkerRequest(apiKey, ts, nonce, method, signedPath)

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-Request-Timestamp", ts)
	req.Header.Set("X-Request-Nonce", nonce)
	req.Header.Set("X-Request-Signature", signature)

	resp, err := workerHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxWorkerResponseBytes))
	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, respBody, nil
}
