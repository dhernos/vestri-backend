package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"time"

	"github.com/go-chi/chi/v5"
	"yourapp/internal/auth"
)

const (
	maxWorkerResponseBytes = 8 << 20
	maxRemoteComposeBytes  = 2 << 20
	velocityTemplateID     = "minecraft-velocity"
	vanillaTemplateID      = "minecraft-vanilla"
	defaultVelocityPort    = 25577
	defaultMinecraftPort   = 25565

	gameServerKindStandalone      = "standalone"
	gameServerKindVelocity        = "velocity"
	gameServerKindVelocityBackend = "velocity-backend"

	velocityTomlRelativePath          = "data/velocity.toml"
	velocityForwardingSecretRelPath   = "data/forwarding.secret"
	backendServerPropertiesRelative   = "data/server.properties"
	backendPaperGlobalRelative        = "data/config/paper-global.yml"
	backendSpigotConfigRelative       = "data/spigot.yml"
	velocityPlayerForwardingModeValue = "modern"
)

type createGameServerRequest struct {
	TemplateID        string `json:"templateId"`
	Name              string `json:"name"`
	AgreementAccepted bool   `json:"agreementAccepted"`
	SoftwareVersion   string `json:"softwareVersion"`
	GameVersion       string `json:"gameVersion"`
	ParentServerRef   string `json:"parentServerRef"`
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
	Kind            string                         `json:"kind"`
	ParentServerID  string                         `json:"parentServerId,omitempty"`
	ConnectHost     string                         `json:"connectHost,omitempty"`
	ConnectPort     int                            `json:"connectPort,omitempty"`
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
		enrichedTemplate := tpl
		enrichedTemplate.VersionConfig = cloneTemplateVersions(tpl.VersionConfig)
		s.enrichTemplateVersionConfig(r.Context(), &enrichedTemplate)

		resp = append(resp, gameServerTemplateResponse{
			ID:              enrichedTemplate.ID,
			Name:            enrichedTemplate.Name,
			Description:     enrichedTemplate.Description,
			Game:            enrichedTemplate.Game,
			TemplateVersion: enrichedTemplate.TemplateVersion,
			ConfigFiles:     configFilesToResponse(enrichedTemplate.ConfigFiles),
			Agreement:       enrichedTemplate.Agreement,
			VersionConfig:   enrichedTemplate.VersionConfig,
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

	parentRef := strings.TrimSpace(r.URL.Query().Get("parent"))
	parentServerID := ""
	if parentRef != "" {
		parentAccess, findErr := s.Users.FindAccessibleGameServerByRefForNode(r.Context(), sess.UserID, node, parentRef)
		if findErr != nil {
			writeError(w, http.StatusInternalServerError, "Failed to resolve parent server")
			return
		}
		if parentAccess == nil {
			writeError(w, http.StatusNotFound, "Parent server not found")
			return
		}
		if !isVelocityServer(&parentAccess.GameServer) {
			writeError(w, http.StatusBadRequest, "Parent server must be a velocity server")
			return
		}
		parentServerID = parentAccess.ID
	}

	filteredServers := make([]auth.GameServerWithAccess, 0, len(servers))
	for i := range servers {
		metadata := parseGameServerMetadata(servers[i].Metadata)
		if parentServerID == "" {
			if strings.TrimSpace(metadata.ParentServerID) != "" {
				continue
			}
		} else if strings.TrimSpace(metadata.ParentServerID) != parentServerID {
			continue
		}
		filteredServers = append(filteredServers, servers[i])
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
	resp := make([]gameServerResponse, 0, len(filteredServers))
	for i := range filteredServers {
		state := "unknown"
		output := ""
		statusErr := ""
		permissions := buildGameServerPermissions(node.AccessRole, filteredServers[i].AccessRole)

		if includeStatus && canReadGameServerConsole(filteredServers[i].AccessRole) {
			resolvedState, resolvedOutput, resolveErr := s.workerStackStatus(r.Context(), baseURL, apiKey, filteredServers[i].StackName)
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

		resp = append(resp, buildGameServerResponse(&filteredServers[i].GameServer, permissions, state, output, statusErr))
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
	req.ParentServerRef = strings.TrimSpace(req.ParentServerRef)
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
	template.VersionConfig = cloneTemplateVersions(template.VersionConfig)
	s.enrichTemplateVersionConfig(r.Context(), template)

	if template.Agreement != nil && template.Agreement.Required && !req.AgreementAccepted {
		writeError(w, http.StatusBadRequest, "Template agreement must be accepted before creating this server")
		return
	}

	softwareVersion, err := resolveTemplateVersionValue(template.VersionConfig, "software", req.SoftwareVersion, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	gameVersion, err := resolveTemplateVersionValue(template.VersionConfig, "game", req.GameVersion, softwareVersion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var minecraftArtifact *minecraftServerArtifact
	if shouldProvisionMinecraftServerArtifact(template) {
		minecraftArtifact, err = resolveMinecraftServerArtifact(r.Context(), softwareVersion, gameVersion)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Failed to resolve selected Minecraft build")
			return
		}
		gameVersion = minecraftArtifact.Version
	}

	var parentServer *auth.GameServer
	if req.ParentServerRef != "" {
		parentAccess, findErr := s.Users.FindAccessibleGameServerByRefForNode(r.Context(), sess.UserID, node, req.ParentServerRef)
		if findErr != nil {
			writeError(w, http.StatusInternalServerError, "Failed to resolve parent server")
			return
		}
		if parentAccess == nil {
			writeError(w, http.StatusNotFound, "Parent server not found")
			return
		}
		if !canManageGameServer(parentAccess.AccessRole) {
			writeError(w, http.StatusForbidden, "Only server owner/admin can attach backend servers")
			return
		}
		if !isVelocityServer(&parentAccess.GameServer) {
			writeError(w, http.StatusBadRequest, "Parent server must use the velocity template")
			return
		}
		parentServer = &parentAccess.GameServer
	}

	requestedName := strings.TrimSpace(req.Name)
	if requestedName == "" {
		requestedName = template.Name
	}

	slugBase := slugify(requestedName)
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
	name := slug

	stackName := slug
	rootPath := slug
	composePath := path.Join(rootPath, "docker-compose.yml")
	minecraftServerJarName := defaultMinecraftServerJarFile
	if minecraftArtifact != nil {
		minecraftServerJarName = minecraftServerJarFileNameForArtifact(minecraftArtifact)
	}

	renderValues := map[string]string{
		"SERVER_SLUG":                 slug,
		"SERVER_NAME":                 name,
		"SERVER_SOFTWARE":             softwareVersion,
		"SERVER_TYPE":                 softwareVersion,
		"GAME_VERSION":                gameVersion,
		"MINECRAFT_RUNTIME_IMAGE":     defaultMinecraftRuntimeImage,
		"MINECRAFT_SERVER_JAR_NAME":   minecraftServerJarName,
		"MINECRAFT_JAVA_ARGS":         defaultMinecraftJavaArgs,
		"MINECRAFT_SERVER_START_ARGS": defaultMinecraftServerStartArgs,
	}

	metadata := gameServerStoredMetadata{
		TemplateName:    template.Name,
		Game:            template.Game,
		SoftwareVersion: softwareVersion,
		GameVersion:     gameVersion,
		Kind:            gameServerKindStandalone,
	}
	backendConnectHost := ""
	backendConnectPort := 0

	var composeContent string
	if parentServer != nil {
		if err := validateVelocityBackendTemplate(template); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		parentMetadata := parseGameServerMetadata(parentServer.Metadata)
		velocityNetwork := strings.TrimSpace(parentMetadata.VelocityNetwork)
		if velocityNetwork == "" {
			velocityNetwork = velocityNetworkName(parentServer.Slug)
		}
		connectHost := velocityBackendHostForSlug(slug)

		renderValues["VELOCITY_NETWORK"] = velocityNetwork
		renderValues["VELOCITY_BACKEND_HOST"] = connectHost

		composeContent, err = buildVelocityBackendCompose(template, renderValues)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		metadata.Kind = gameServerKindVelocityBackend
		metadata.ParentServerID = parentServer.ID
		metadata.VelocityNetwork = velocityNetwork
		metadata.ConnectHost = connectHost
		metadata.ConnectPort = defaultMinecraftPort
		backendConnectHost = connectHost
		backendConnectPort = defaultMinecraftPort
	} else {
		if isVelocityTemplateID(template.ID) {
			velocityNetwork := velocityNetworkName(slug)
			renderValues["VELOCITY_NETWORK"] = velocityNetwork
			forwardingSecret, secretErr := generateForwardingSecret()
			if secretErr != nil {
				writeError(w, http.StatusInternalServerError, "Failed to generate velocity forwarding secret")
				return
			}
			renderValues["VELOCITY_FORWARDING_SECRET"] = forwardingSecret
			metadata.Kind = gameServerKindVelocity
			metadata.VelocityNetwork = velocityNetwork
			metadata.ConnectPort = defaultVelocityPort
		}

		composeContent, err = resolveTemplateCompose(r.Context(), template, renderValues)
		if err != nil {
			writeError(w, http.StatusBadGateway, "Failed to load compose file from template")
			return
		}
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

	if minecraftArtifact != nil {
		if err := s.provisionMinecraftServerArtifactOnWorker(r.Context(), baseURL, apiKey, rootPath, minecraftArtifact); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to download Minecraft server jar")
			return
		}
	}

	if parentServer != nil {
		forwardingSecret, registerErr := s.registerVelocityBackendAndResolveForwardingSecret(
			r.Context(),
			baseURL,
			apiKey,
			parentServer,
			slug,
			backendConnectHost,
			backendConnectPort,
		)
		if registerErr != nil {
			writeError(w, http.StatusBadGateway, "Failed to update velocity server configuration")
			return
		}

		if applyErr := s.applyVelocityBackendProxySettings(
			r.Context(),
			baseURL,
			apiKey,
			rootPath,
			softwareVersion,
			forwardingSecret,
		); applyErr != nil {
			writeError(w, http.StatusBadGateway, "Failed to configure backend server for velocity")
			return
		}
	}

	metadata.ConfigFiles = configFiles
	metadataRaw, _ := json.Marshal(metadata)

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

	if isVelocityServer(server) {
		hasBackends, err := s.velocityServerHasBackends(r.Context(), node.ID, server.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to validate velocity backend servers")
			return
		}
		if hasBackends {
			writeError(w, http.StatusBadRequest, "Delete linked backend servers first")
			return
		}
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

	name := strings.TrimSpace(srv.Slug)
	if name == "" {
		name = strings.TrimSpace(srv.Name)
	}
	kind := normalizeGameServerKindValue(metadata.Kind)
	if kind == "" {
		kind = inferGameServerKind(srv, metadata)
	}
	connectPort := metadata.ConnectPort
	if connectPort == 0 {
		switch kind {
		case gameServerKindVelocity:
			connectPort = defaultVelocityPort
		case gameServerKindVelocityBackend:
			connectPort = defaultMinecraftPort
		}
	}

	return gameServerResponse{
		ID:              srv.ID,
		NodeID:          srv.NodeID,
		Slug:            srv.Slug,
		Name:            name,
		TemplateID:      srv.TemplateID,
		TemplateVersion: srv.TemplateVersion,
		TemplateName:    metadata.TemplateName,
		Game:            metadata.Game,
		SoftwareVersion: metadata.SoftwareVersion,
		GameVersion:     metadata.GameVersion,
		StackName:       srv.StackName,
		RootPath:        srv.RootPath,
		ComposePath:     srv.ComposePath,
		Kind:            kind,
		ParentServerID:  strings.TrimSpace(metadata.ParentServerID),
		ConnectHost:     strings.TrimSpace(metadata.ConnectHost),
		ConnectPort:     connectPort,
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

func normalizeGameServerKindValue(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case gameServerKindStandalone:
		return gameServerKindStandalone
	case gameServerKindVelocity:
		return gameServerKindVelocity
	case gameServerKindVelocityBackend:
		return gameServerKindVelocityBackend
	default:
		return ""
	}
}

func inferGameServerKind(srv *auth.GameServer, metadata gameServerStoredMetadata) string {
	if strings.TrimSpace(metadata.ParentServerID) != "" {
		return gameServerKindVelocityBackend
	}
	if srv != nil && isVelocityTemplateID(srv.TemplateID) {
		return gameServerKindVelocity
	}
	return gameServerKindStandalone
}

func isVelocityTemplateID(templateID string) bool {
	return strings.EqualFold(strings.TrimSpace(templateID), velocityTemplateID)
}

func isVelocityServer(server *auth.GameServer) bool {
	if server == nil {
		return false
	}
	metadata := parseGameServerMetadata(server.Metadata)
	kind := normalizeGameServerKindValue(metadata.Kind)
	if kind == "" {
		kind = inferGameServerKind(server, metadata)
	}
	return kind == gameServerKindVelocity
}

func validateVelocityBackendTemplate(template *gameServerTemplate) error {
	if template == nil {
		return fmt.Errorf("template is required")
	}
	if strings.TrimSpace(strings.ToLower(template.Game)) != "minecraft" {
		return fmt.Errorf("velocity backend servers currently support minecraft templates only")
	}
	if isVelocityTemplateID(template.ID) {
		return fmt.Errorf("velocity servers cannot be attached as velocity backend servers")
	}
	if !strings.EqualFold(strings.TrimSpace(template.ID), vanillaTemplateID) {
		return fmt.Errorf("velocity backend servers currently support the minecraft-vanilla template only")
	}
	return nil
}

func velocityNetworkName(slug string) string {
	base := slugify(strings.TrimSpace(slug))
	if base == "" {
		base = "main"
	}
	return "vestri-velocity-" + base
}

func velocityBackendHostForSlug(slug string) string {
	base := slugify(strings.TrimSpace(slug))
	if base == "" {
		base = "backend"
	}
	return "vestri-" + base
}

func buildVelocityBackendCompose(template *gameServerTemplate, values map[string]string) (string, error) {
	if err := validateVelocityBackendTemplate(template); err != nil {
		return "", err
	}
	const composeInline = `services:
  minecraft:
    image: {{MINECRAFT_RUNTIME_IMAGE}}
    container_name: {{VELOCITY_BACKEND_HOST}}
    environment:
      JAVA_ARGS: "{{MINECRAFT_JAVA_ARGS}}"
      SERVER_DIR: "/server"
      SERVER_JAR_NAME: "{{MINECRAFT_SERVER_JAR_NAME}}"
      SERVER_ARGS: "{{MINECRAFT_SERVER_START_ARGS}}"
    volumes:
      - ./data:/server
    stdin_open: true
    tty: true
    restart: unless-stopped
    networks:
      - velocity
networks:
  velocity:
    external: true
    name: "{{VELOCITY_NETWORK}}"
`
	return renderTemplateText(composeInline, values), nil
}

func (s *Server) velocityServerHasBackends(ctx context.Context, nodeID, parentServerID string) (bool, error) {
	parentServerID = strings.TrimSpace(parentServerID)
	if parentServerID == "" {
		return false, nil
	}

	servers, err := s.Users.ListGameServersForNode(ctx, nodeID)
	if err != nil {
		return false, err
	}

	for i := range servers {
		metadata := parseGameServerMetadata(servers[i].Metadata)
		if strings.TrimSpace(metadata.ParentServerID) == parentServerID {
			return true, nil
		}
	}
	return false, nil
}

func generateForwardingSecret() (string, error) {
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(secretBytes), nil
}

func (s *Server) registerVelocityBackendAndResolveForwardingSecret(
	ctx context.Context,
	baseURL *url.URL,
	apiKey string,
	velocityServer *auth.GameServer,
	backendServerName,
	backendHost string,
	backendPort int,
) (string, error) {
	if velocityServer == nil {
		return "", fmt.Errorf("velocity server is required")
	}
	if backendPort <= 0 {
		backendPort = defaultMinecraftPort
	}
	backendServerName = strings.TrimSpace(backendServerName)
	backendHost = strings.TrimSpace(backendHost)
	if backendServerName == "" || backendHost == "" {
		return "", fmt.Errorf("backend server target is invalid")
	}

	velocityTomlPath := path.Join(velocityServer.RootPath, velocityTomlRelativePath)
	velocityTomlContent, missing, err := s.workerReadFileOptional(ctx, baseURL, apiKey, velocityTomlPath)
	if err != nil {
		return "", err
	}
	if missing || strings.TrimSpace(velocityTomlContent) == "" {
		velocityTomlContent = defaultVelocityTomlContent()
	}

	velocityTomlContent = upsertTomlTopLevelStringKey(
		velocityTomlContent,
		"player-info-forwarding-mode",
		velocityPlayerForwardingModeValue,
	)
	velocityTomlContent = upsertVelocityTomlServerEntry(
		velocityTomlContent,
		backendServerName,
		fmt.Sprintf("%s:%d", backendHost, backendPort),
	)
	velocityTomlContent = upsertVelocityTomlTryServer(velocityTomlContent, backendServerName)
	velocityTomlContent = removeTomlTopLevelKey(velocityTomlContent, "forwarding-secret")
	velocityTomlContent = removeTomlTopLevelKey(velocityTomlContent, "forwarding-secret-file")

	if err := s.workerWriteFile(ctx, baseURL, apiKey, velocityTomlPath, velocityTomlContent); err != nil {
		return "", err
	}

	return s.ensureVelocityForwardingSecretFile(ctx, baseURL, apiKey, velocityServer.RootPath)
}

func (s *Server) ensureVelocityForwardingSecretFile(
	ctx context.Context,
	baseURL *url.URL,
	apiKey,
	velocityRootPath string,
) (string, error) {
	secretPath := path.Join(velocityRootPath, velocityForwardingSecretRelPath)
	secretContent, missing, err := s.workerReadFileOptional(ctx, baseURL, apiKey, secretPath)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(secretContent)
	if missing || secret == "" {
		generatedSecret, generateErr := generateForwardingSecret()
		if generateErr != nil {
			return "", generateErr
		}
		secret = generatedSecret
		if err := s.workerWriteFile(ctx, baseURL, apiKey, secretPath, secret+"\n"); err != nil {
			return "", err
		}
	}
	return secret, nil
}

func defaultVelocityTomlContent() string {
	return strings.TrimSpace(`bind = "0.0.0.0:25577"
motd = "A Vestri Velocity Proxy"
show-max-players = 500
online-mode = true
player-info-forwarding-mode = "modern"
servers = {}
try = []`) + "\n"
}

func extractTomlStringKey(content, key string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	keyPrefix := key + " ="
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, keyPrefix) {
			continue
		}
		rawValue := strings.TrimSpace(strings.TrimPrefix(trimmed, keyPrefix))
		if rawValue == "" {
			return ""
		}
		if strings.HasPrefix(rawValue, "\"") {
			for i := 2; i <= len(rawValue); i++ {
				candidate := rawValue[:i]
				unquoted, err := strconv.Unquote(candidate)
				if err == nil {
					return unquoted
				}
			}
		}
		rawValue = strings.SplitN(rawValue, "#", 2)[0]
		return strings.TrimSpace(rawValue)
	}
	return ""
}

func upsertTomlTopLevelStringKey(content, key, value string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	targetLine := fmt.Sprintf(`%s = "%s"`, key, strings.ReplaceAll(value, `"`, `\"`))

	firstSection := len(lines)
	foundLine := -1
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if firstSection == len(lines) {
				firstSection = i
			}
			continue
		}
		if firstSection != len(lines) {
			continue
		}
		if strings.HasPrefix(trimmed, key+" =") {
			foundLine = i
			break
		}
	}

	if foundLine >= 0 {
		lines[foundLine] = targetLine
		return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
	}

	insertAt := firstSection
	if insertAt > len(lines) {
		insertAt = len(lines)
	}
	lines = append(lines[:insertAt], append([]string{targetLine}, lines[insertAt:]...)...)
	return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
}

func removeTomlTopLevelKey(content, key string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	firstSection := len(lines)
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			firstSection = i
			break
		}
	}

	filtered := make([]string, 0, len(lines))
	targetPrefix := key + " ="
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		if i < firstSection && strings.HasPrefix(trimmed, targetPrefix) {
			continue
		}
		filtered = append(filtered, lines[i])
	}
	return ensureTextEndsWithNewline(strings.Join(filtered, "\n"))
}

func upsertVelocityTomlServerEntry(content, serverName, address string) string {
	serverName = strings.TrimSpace(serverName)
	address = strings.TrimSpace(address)
	if serverName == "" || address == "" {
		return ensureTextEndsWithNewline(content)
	}

	entries := make(map[string]string)
	inlineStart, inlineEnd, inlineRaw, inlineFound := findTomlInlineTableAssignment(content, "servers")
	if inlineFound {
		entries = parseTomlInlineServerEntries(inlineRaw)
	} else {
		legacyEntries, legacyFound := parseLegacyVelocityServersTable(content)
		if legacyFound {
			entries = legacyEntries
		}
	}
	entries[serverName] = address
	serversBlock := formatVelocityServersInlineTable(entries)

	if inlineFound {
		content = content[:inlineStart] + serversBlock + content[inlineEnd:]
		return ensureTextEndsWithNewline(content)
	}

	legacyStart, legacyEnd, legacyFound := findLegacyVelocityServersTableBounds(content)
	if legacyFound {
		lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
		replacement := strings.Split(serversBlock, "\n")
		lines = append(lines[:legacyStart], append(replacement, lines[legacyEnd:]...)...)
		return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
	}

	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
		lines = append(lines, "")
	}
	lines = append(lines, strings.Split(serversBlock, "\n")...)
	return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
}

func upsertVelocityTomlTryServer(content, serverName string) string {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return ensureTextEndsWithNewline(content)
	}

	start, end, raw, found := findTomlInlineArrayAssignment(content, "try")
	if !found {
		line := fmt.Sprintf(`try = ["%s"]`, strings.ReplaceAll(serverName, `"`, `\"`))
		lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, line)
		return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
	}

	existing := parseTomlStringList(raw)
	if len(existing) > 0 {
		return ensureTextEndsWithNewline(content)
	}
	line := fmt.Sprintf(`try = ["%s"]`, strings.ReplaceAll(serverName, `"`, `\"`))
	content = content[:start] + line + content[end:]
	return ensureTextEndsWithNewline(content)
}

func findTomlInlineTableAssignment(content, key string) (int, int, string, bool) {
	re := regexp.MustCompile(`(?ms)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=[ \t]*\{.*?\}`)
	loc := re.FindStringIndex(content)
	if loc == nil {
		return 0, 0, "", false
	}
	raw := content[loc[0]:loc[1]]
	return loc[0], loc[1], raw, true
}

func findTomlInlineArrayAssignment(content, key string) (int, int, string, bool) {
	re := regexp.MustCompile(`(?ms)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=[ \t]*\[[^\]]*\]`)
	loc := re.FindStringIndex(content)
	if loc == nil {
		return 0, 0, "", false
	}
	raw := content[loc[0]:loc[1]]
	return loc[0], loc[1], raw, true
}

func parseTomlInlineServerEntries(assignment string) map[string]string {
	entries := make(map[string]string)
	start := strings.Index(assignment, "{")
	end := strings.LastIndex(assignment, "}")
	if start < 0 || end <= start {
		return entries
	}
	body := assignment[start+1 : end]

	entryRe := regexp.MustCompile(`(?m)"?([A-Za-z0-9_-]+)"?\s*=\s*"([^"]*)"`)
	matches := entryRe.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		key := strings.TrimSpace(match[1])
		value := strings.TrimSpace(match[2])
		if key == "" || value == "" {
			continue
		}
		entries[key] = value
	}
	return entries
}

func formatVelocityServersInlineTable(entries map[string]string) string {
	if len(entries) == 0 {
		return "servers = {}"
	}

	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s = %s", key, strconv.Quote(entries[key])))
	}
	return "servers = { " + strings.Join(parts, ", ") + " }"
}

func findLegacyVelocityServersTableBounds(content string) (int, int, bool) {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	serversStart := -1
	serversEnd := len(lines)
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "[servers]" {
			serversStart = i
			continue
		}
		if serversStart >= 0 && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			serversEnd = i
			break
		}
	}
	if serversStart < 0 {
		return 0, 0, false
	}
	return serversStart, serversEnd, true
}

func parseLegacyVelocityServersTable(content string) (map[string]string, bool) {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	serversStart := -1
	serversEnd := len(lines)
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "[servers]" {
			serversStart = i
			continue
		}
		if serversStart >= 0 && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			serversEnd = i
			break
		}
	}
	if serversStart < 0 {
		return nil, false
	}

	entries := make(map[string]string)
	entryRe := regexp.MustCompile(`(?m)"?([A-Za-z0-9_-]+)"?\s*=\s*"([^"]*)"`)
	for i := serversStart + 1; i < serversEnd; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		match := entryRe.FindStringSubmatch(trimmed)
		if len(match) < 3 {
			continue
		}
		key := strings.TrimSpace(match[1])
		value := strings.TrimSpace(match[2])
		if key == "" || value == "" {
			continue
		}
		entries[key] = value
	}
	return entries, true
}

func parseTomlStringList(assignment string) []string {
	start := strings.Index(assignment, "[")
	end := strings.LastIndex(assignment, "]")
	if start < 0 || end <= start {
		return nil
	}
	body := assignment[start+1 : end]
	itemRe := regexp.MustCompile(`"([^"]+)"`)
	matches := itemRe.FindAllStringSubmatch(body, -1)
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		value := strings.TrimSpace(match[1])
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}

func (s *Server) applyVelocityBackendProxySettings(
	ctx context.Context,
	baseURL *url.URL,
	apiKey, rootPath, softwareVersion, forwardingSecret string,
) error {
	backendPropertiesPath := path.Join(rootPath, backendServerPropertiesRelative)
	propertiesContent, _, err := s.workerReadFileOptional(ctx, baseURL, apiKey, backendPropertiesPath)
	if err != nil {
		return err
	}
	propertiesContent = upsertJavaPropertiesValue(propertiesContent, "online-mode", "false")
	if err := s.workerWriteFile(ctx, baseURL, apiKey, backendPropertiesPath, propertiesContent); err != nil {
		return err
	}

	normalizedSoftware := strings.ToUpper(strings.TrimSpace(softwareVersion))
	needsPaperConfig := normalizedSoftware == "PAPER" || normalizedSoftware == "PURPUR"
	needsSpigotConfig := normalizedSoftware == "SPIGOT"

	paperConfigPath := path.Join(rootPath, backendPaperGlobalRelative)
	paperContent, paperMissing, err := s.workerReadFileOptional(ctx, baseURL, apiKey, paperConfigPath)
	if err != nil {
		return err
	}
	if !paperMissing || needsPaperConfig {
		paperContent = upsertPaperGlobalVelocitySettings(paperContent, forwardingSecret)
		if err := s.workerWriteFile(ctx, baseURL, apiKey, paperConfigPath, paperContent); err != nil {
			return err
		}
	}

	spigotConfigPath := path.Join(rootPath, backendSpigotConfigRelative)
	spigotContent, spigotMissing, err := s.workerReadFileOptional(ctx, baseURL, apiKey, spigotConfigPath)
	if err != nil {
		return err
	}
	if !spigotMissing || needsSpigotConfig {
		spigotContent = upsertSpigotVelocitySettings(spigotContent, forwardingSecret)
		if err := s.workerWriteFile(ctx, baseURL, apiKey, spigotConfigPath, spigotContent); err != nil {
			return err
		}
	}

	return nil
}

func upsertJavaPropertiesValue(content, key, value string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	targetPrefix := key + "="
	found := false
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if !strings.Contains(trimmed, "=") {
			continue
		}
		existingKey := strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[0])
		if existingKey != key {
			continue
		}
		lines[i] = targetPrefix + value
		found = true
		break
	}
	if !found {
		if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
			lines[0] = targetPrefix + value
		} else {
			lines = append(lines, targetPrefix+value)
		}
	}
	return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
}

func upsertPaperGlobalVelocitySettings(content, forwardingSecret string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	velocityBlock := []string{
		"  velocity:",
		"    enabled: true",
		"    online-mode: false",
		fmt.Sprintf(`    secret: "%s"`, strings.ReplaceAll(forwardingSecret, `"`, `\"`)),
	}

	proxiesStart, proxiesEnd, proxiesFound := findYAMLSection(lines, "proxies", 0, 0, len(lines))
	if !proxiesFound {
		if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
			lines[0] = "proxies:"
		} else {
			if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
				lines = append(lines, "")
			}
			lines = append(lines, "proxies:")
		}
		lines = append(lines, velocityBlock...)
		return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
	}

	velocityStart, velocityEnd, velocityFound := findYAMLSection(lines, "velocity", 2, proxiesStart+1, proxiesEnd)
	if velocityFound {
		lines = append(lines[:velocityStart], append(velocityBlock, lines[velocityEnd:]...)...)
		return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
	}

	lines = append(lines[:proxiesEnd], append(velocityBlock, lines[proxiesEnd:]...)...)
	return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
}

func upsertSpigotVelocitySettings(content, forwardingSecret string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")

	settingsStart, settingsEnd, settingsFound := findYAMLSection(lines, "settings", 0, 0, len(lines))
	if !settingsFound {
		if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
			lines[0] = "settings:"
		} else {
			if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
				lines = append(lines, "")
			}
			lines = append(lines, "settings:")
		}
		lines = append(lines, "  bungeecord: true")
	} else {
		bungeeStart, _, bungeeFound := findYAMLSection(lines, "bungeecord", 2, settingsStart+1, settingsEnd)
		if bungeeFound {
			lines[bungeeStart] = "  bungeecord: true"
		} else {
			lines = append(lines[:settingsEnd], append([]string{"  bungeecord: true"}, lines[settingsEnd:]...)...)
		}
	}

	velocityBlock := []string{
		"velocity-support:",
		"  enabled: true",
		"  online-mode: false",
		fmt.Sprintf(`  secret: "%s"`, strings.ReplaceAll(forwardingSecret, `"`, `\"`)),
	}
	velocityStart, velocityEnd, velocityFound := findYAMLSection(lines, "velocity-support", 0, 0, len(lines))
	if velocityFound {
		lines = append(lines[:velocityStart], append(velocityBlock, lines[velocityEnd:]...)...)
	} else {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, velocityBlock...)
	}

	return ensureTextEndsWithNewline(strings.Join(lines, "\n"))
}

func findYAMLSection(lines []string, key string, indent, start, end int) (int, int, bool) {
	for i := start; i < end; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if leadingWhitespaceWidth(lines[i]) != indent {
			continue
		}
		if trimmed != key+":" && !strings.HasPrefix(trimmed, key+": ") {
			continue
		}

		sectionEnd := end
		for j := i + 1; j < end; j++ {
			nextTrimmed := strings.TrimSpace(lines[j])
			if nextTrimmed == "" || strings.HasPrefix(nextTrimmed, "#") {
				continue
			}
			if leadingWhitespaceWidth(lines[j]) <= indent {
				sectionEnd = j
				break
			}
		}
		return i, sectionEnd, true
	}
	return -1, -1, false
}

func leadingWhitespaceWidth(value string) int {
	width := 0
	for _, r := range value {
		if r == ' ' {
			width++
			continue
		}
		if r == '\t' {
			width += 2
			continue
		}
		break
	}
	return width
}

func ensureTextEndsWithNewline(value string) string {
	if strings.HasSuffix(value, "\n") {
		return value
	}
	return value + "\n"
}

func resolveTemplateVersionValue(config *gameServerTemplateVersions, field, raw, selectedSoftware string) (string, error) {
	if config == nil {
		return "", nil
	}

	var cfg *gameServerTemplateVersionField
	normalizedField := strings.ToLower(strings.TrimSpace(field))
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

	options := cfg.Options
	if normalizedField == "game" && len(cfg.OptionsBySoftware) > 0 {
		softwareKey := normalizeMinecraftSoftware(selectedSoftware)
		if softwareKey == "" {
			softwareKey = strings.ToUpper(strings.TrimSpace(selectedSoftware))
		}
		if softwareKey != "" {
			if softwareOptions, exists := cfg.OptionsBySoftware[softwareKey]; exists && len(softwareOptions) > 0 {
				options = softwareOptions
			}
		}
	}

	value := strings.TrimSpace(raw)
	if value == "" {
		value = strings.TrimSpace(cfg.Default)
	}
	if value == "" && len(options) > 0 {
		value = options[0]
	}
	if len(options) == 0 {
		return value, nil
	}
	if strings.EqualFold(value, "LATEST") {
		return options[0], nil
	}
	for _, option := range options {
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

func (s *Server) workerReadFileOptional(ctx context.Context, baseURL *url.URL, apiKey, filePath string) (string, bool, error) {
	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodGet, "/fs/read?path="+url.QueryEscape(filePath), nil)
	if err != nil {
		return "", false, err
	}
	if statusCode == http.StatusNotFound {
		return "", true, nil
	}
	if statusCode < 200 || statusCode >= 300 {
		return "", false, fmt.Errorf("worker /fs/read failed (%d): %s", statusCode, strings.TrimSpace(string(body)))
	}
	return string(body), false, nil
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
