package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"yourapp/internal/auth"
)

type minecraftAPIPrincipal struct {
	Key  *auth.MinecraftAPIKey
	Node *auth.WorkerNode
}
type minecraftAPIContextKey struct{}

func minecraftAPIKeyDigest(token string) (string, bool) {
	if len(token) != 68 || !strings.HasPrefix(token, "vmc_") {
		return "", false
	}
	if _, err := hex.DecodeString(token[4:]); err != nil {
		return "", false
	}
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:]), true
}

func (s *Server) requireMinecraftAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		digest, valid := minecraftAPIKeyDigest(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if !valid {
			writeError(w, http.StatusUnauthorized, "A valid Bearer API key is required")
			return
		}
		key, err := s.Users.FindMinecraftAPIKey(r.Context(), digest)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "API key verification is unavailable")
			return
		}
		if key == nil {
			writeError(w, http.StatusUnauthorized, "Invalid or expired API key")
			return
		}
		node, err := s.Users.FindAccessibleWorkerNodeByRef(r.Context(), key.UserID, key.NodeID)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Permission verification is unavailable")
			return
		}
		if node == nil || !canManageNodeMinecraftLibrary(node.AccessRole) {
			writeError(w, http.StatusForbidden, "API key owner no longer has node administration access")
			return
		}
		user, err := s.Users.FindByID(r.Context(), key.UserID)
		if err != nil || user == nil || !roleAllowed([]string{RoleUser, RoleAdmin, RoleEditor}, user.Role) {
			writeError(w, http.StatusForbidden, "API key owner is not permitted")
			return
		}
		if s.Redis == nil {
			writeError(w, http.StatusServiceUnavailable, "API rate limiting is unavailable")
			return
		}
		count, err := s.Redis.Eval(r.Context(), `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],60) end; return n`, []string{"minecraft:rate:" + key.ID}).Int()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "API rate limiting is unavailable")
			return
		}
		if count > 30 {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "API key request limit reached")
			return
		}
		ctx := context.WithValue(r.Context(), minecraftAPIContextKey{}, minecraftAPIPrincipal{Key: key, Node: node})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) handleCreateMinecraftAPIKey(w http.ResponseWriter, r *http.Request) {
	sess, node, ok := s.loadMinecraftAdmin(w, r)
	if !ok {
		return
	}
	var request struct {
		Name       string `json:"name"`
		TemplateID string `json:"templateId"`
		Days       int    `json:"days"`
	}
	if decodeJSON(r, &request) != nil || strings.TrimSpace(request.Name) == "" || len(request.Name) > 64 || request.Days < 1 || request.Days > 365 {
		writeError(w, http.StatusBadRequest, "Provide a key name, template and lifetime between 1 and 365 days")
		return
	}
	if _, err := s.minecraftResource(r.Context(), node.ID, request.TemplateID, "templates"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}
	token := "vmc_" + hex.EncodeToString(random[:])
	digest, _ := minecraftAPIKeyDigest(token)
	key := auth.MinecraftAPIKey{ID: uuid.NewString(), NodeID: node.ID, TemplateID: request.TemplateID, UserID: sess.UserID, Name: strings.TrimSpace(request.Name), ExpiresAt: time.Now().UTC().Add(time.Duration(request.Days) * 24 * time.Hour)}
	if err := s.Users.CreateMinecraftAPIKey(r.Context(), key, digest); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save API key")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]interface{}{"key": key, "token": token})
}

func (s *Server) handleRevokeMinecraftAPIKey(w http.ResponseWriter, r *http.Request) {
	_, node, ok := s.loadMinecraftAdmin(w, r)
	if !ok {
		return
	}
	if err := s.Users.RevokeMinecraftAPIKey(r.Context(), node.ID, chi.URLParam(r, "keyId")); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to revoke key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSpawnMinecraftInstance(w http.ResponseWriter, r *http.Request) {
	principal, api := r.Context().Value(minecraftAPIContextKey{}).(minecraftAPIPrincipal)
	var node *auth.WorkerNode
	var userID, keyID, templateID string
	if api {
		node, userID, keyID, templateID = principal.Node, principal.Key.UserID, principal.Key.ID, principal.Key.TemplateID
	} else {
		sess, adminNode, ok := s.loadMinecraftAdmin(w, r)
		if !ok {
			return
		}
		node, userID, templateID = adminNode, sess.UserID, chi.URLParam(r, "resourceId")
	}
	var request struct {
		RequestID string `json:"requestId"`
	}
	if decodeJSON(r, &request) != nil {
		writeError(w, http.StatusBadRequest, "requestId is required")
		return
	}
	if _, err := uuid.Parse(request.RequestID); err != nil {
		writeError(w, http.StatusBadRequest, "requestId must be a UUID")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	unlock, err := s.lockNodePlugins(ctx, node.ID)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	defer unlock()
	template, err := s.minecraftResource(ctx, node.ID, templateID, "templates")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	var spec minecraftResourceSpec
	if json.Unmarshal(template.Spec, &spec) != nil || spec.MaxInstances < 1 || spec.MaxInstances > 100 || !validPluginFilename(spec.Jar) {
		writeError(w, http.StatusConflict, "Template metadata is invalid")
		return
	}
	requestHash := sha256.Sum256([]byte(keyID + ":" + request.RequestID))
	requestID := hex.EncodeToString(requestHash[:])
	instances, err := s.Users.ListMinecraftInstances(ctx, node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load instances")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Invalid worker configuration")
		return
	}
	active := 0
	for _, instance := range instances {
		if instance.RequestID == requestID {
			if instance.TemplateID != templateID || instance.KeyID != keyID {
				writeError(w, http.StatusConflict, "requestId belongs to another template")
				return
			}
			server, findErr := s.Users.FindGameServerByRefForNode(ctx, node.ID, instance.ServerID)
			if findErr != nil || server == nil {
				writeError(w, http.StatusConflict, "Instance record is incomplete")
				return
			}
			if _, err = s.workerStackAction(ctx, baseURL, apiKey, "up", server.StackName); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Instance could not start; retry with the same requestId or delete it", "serverId": server.ID})
				return
			}
			if err = s.reloadMinecraftInstanceProxy(ctx, pluginWorker{server: s, baseURL: baseURL, apiKey: apiKey}, node.ID, server); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Instance exists, but Velocity could not reload; retry the same requestId", "serverId": server.ID})
				return
			}
			writeJSON(w, http.StatusAccepted, minecraftInstanceResponse(server))
			return
		}
		if instance.TemplateID == templateID {
			active++
		}
	}
	if active >= spec.MaxInstances {
		writeError(w, http.StatusConflict, "Template instance limit reached")
		return
	}
	if len(instances) >= 100 {
		writeError(w, http.StatusConflict, "Node dynamic instance limit (100) reached")
		return
	}
	parent, err := s.Users.FindGameServerByRefForNode(ctx, node.ID, spec.ParentID)
	if err != nil || parent == nil || !isVelocityServer(parent) {
		writeError(w, http.StatusConflict, "The template requires an existing Velocity proxy")
		return
	}
	hasBackends, err := s.velocityServerHasBackends(ctx, node.ID, parent.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check existing velocity backends")
		return
	}
	whitelistEnabled := velocityBackendWhitelistEnabled(hasBackends)
	parentMetadata := parseGameServerMetadata(parent.Metadata)
	if err = s.syncMinecraftProxy(ctx, pluginWorker{server: s, baseURL: baseURL, apiKey: apiKey}, node.ID, parent, ""); err != nil {
		writeError(w, http.StatusBadGateway, "Velocity bridge is unavailable; install Vestri Dynamic Servers and start the proxy")
		return
	}
	network := parentMetadata.VelocityNetwork
	if network == "" {
		network = velocityNetworkName(parent.Slug)
	}
	slug := "mcgame-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	nodeServers, err := s.Users.ListGameServersForNode(ctx, node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to allocate instance name")
		return
	}
	instanceName := nextMinecraftInstanceName(template.Name, nodeServers, parent.ID)
	worker := pluginWorker{server: s, baseURL: baseURL, apiKey: apiKey}
	committed := false
	registered := false
	var created *auth.GameServer
	defer func() {
		if committed {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if registered {
			_ = s.unregisterVelocityBackendFromProxy(cleanupCtx, baseURL, apiKey, parent, instanceName)
		}
		_ = s.workerDeletePath(cleanupCtx, baseURL, apiKey, slug, true)
		if created != nil {
			_, _ = s.Users.DeleteGameServerByID(cleanupCtx, node.ID, created.ID)
		}
	}()
	if err = s.copyMinecraftDirectory(ctx, worker, minecraftResourceDataPath(template), path.Join(slug, "data")); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to copy server template")
		return
	}
	propertiesPath := path.Join(slug, "data/server.properties")
	properties, _, err := s.workerReadFileOptional(ctx, baseURL, apiKey, propertiesPath)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read server properties")
		return
	}
	properties = minecraftInstanceProperties(properties, spec.WorldID == "")
	if spec.WorldID == "" {
		for _, world := range []string{"world", "world_nether", "world_the_end"} {
			if err = s.workerDeletePath(ctx, baseURL, apiKey, path.Join(slug, "data", world), true); err != nil {
				writeError(w, http.StatusBadGateway, "Failed to reset random world")
				return
			}
		}
	} else {
		for _, file := range []string{"uid.dat", "session.lock"} {
			if err = s.workerDeletePath(ctx, baseURL, apiKey, path.Join(slug, "data/world", file), false); err != nil {
				writeError(w, http.StatusBadGateway, "Failed to reset world identity")
				return
			}
		}
	}
	if err = s.workerWriteFile(ctx, baseURL, apiKey, propertiesPath, properties); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to write server properties")
		return
	}
	vanilla, err := gameServerTemplateByID(vanillaTemplateID)
	if err != nil || vanilla == nil {
		writeError(w, http.StatusInternalServerError, "Minecraft runtime template is unavailable")
		return
	}
	values := map[string]string{"SERVER_SLUG": slug, "SERVER_NAME": template.Name, "SERVER_SOFTWARE": spec.Software, "SERVER_TYPE": spec.Software, "GAME_VERSION": spec.Version, "MINECRAFT_RUNTIME_IMAGE": defaultMinecraftRuntimeImage, "MINECRAFT_SERVER_JAR_NAME": spec.Jar, "MINECRAFT_JAVA_ARGS": defaultMinecraftJavaArgs, "MINECRAFT_SERVER_START_ARGS": defaultMinecraftServerStartArgs, "VELOCITY_NETWORK": network, "VELOCITY_BACKEND_HOST": velocityBackendHostForSlug(slug)}
	compose, err := buildVelocityBackendCompose(ctx, vanilla, values)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to build instance configuration")
		return
	}
	if err = s.workerWriteFile(ctx, baseURL, apiKey, path.Join(slug, "docker-compose.yml"), compose); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to write instance configuration")
		return
	}
	secret, err := s.registerVelocityBackendAndResolveForwardingSecret(ctx, baseURL, apiKey, parent, instanceName, velocityBackendHostForSlug(slug), defaultMinecraftPort)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to register instance with Velocity")
		return
	}
	registered = true
	proxyConfigPath := path.Join(parent.RootPath, velocityTomlRelativePath)
	proxyConfig, _, err := s.workerReadFileOptional(ctx, baseURL, apiKey, proxyConfigPath)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read proxy configuration")
		return
	}
	if err = s.workerWriteFile(ctx, baseURL, apiKey, proxyConfigPath, removeVelocityTomlTryServer(proxyConfig, instanceName)); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to preserve Velocity fallback targets")
		return
	}
	if err = s.applyVelocityBackendProxySettings(ctx, baseURL, apiKey, slug, spec.Software, secret, whitelistEnabled); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to configure Velocity forwarding")
		return
	}
	metadata := gameServerStoredMetadata{TemplateName: template.Name, Game: "minecraft", SoftwareVersion: spec.Software, GameVersion: spec.Version, Kind: gameServerKindVelocityBackend, ParentServerID: parent.ID, VelocityNetwork: network, VelocityServerName: instanceName, ConnectHost: velocityBackendHostForSlug(slug), ConnectPort: defaultMinecraftPort, ConfigFiles: vanilla.ConfigFiles}
	metadataRaw, _ := json.Marshal(metadata)
	created, err = s.Users.CreateMinecraftGameInstance(ctx, auth.CreateGameServerParams{NodeID: node.ID, Slug: slug, Name: instanceName, TemplateID: vanillaTemplateID, StackName: slug, RootPath: slug, ComposePath: path.Join(slug, "docker-compose.yml"), Metadata: metadataRaw, CreatedByUserID: userID}, auth.MinecraftInstance{TemplateID: template.ID, KeyID: keyID, RequestID: requestID})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to save instance")
		return
	}
	committed = true
	if _, err = s.workerStackAction(ctx, baseURL, apiKey, "up", slug); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Instance was created but could not start; retry the same requestId or delete it", "serverId": created.ID})
		return
	}
	if err = s.reloadMinecraftInstanceProxy(ctx, worker, node.ID, created); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "Instance exists, but Velocity could not reload; retry the same requestId", "serverId": created.ID})
		return
	}
	writeJSON(w, http.StatusAccepted, minecraftInstanceResponse(created))
}

func (s *Server) reloadMinecraftInstanceProxy(ctx context.Context, worker pluginWorker, nodeID string, server *auth.GameServer) error {
	metadata := parseGameServerMetadata(server.Metadata)
	parent, err := s.Users.FindGameServerByRefForNode(ctx, nodeID, metadata.ParentServerID)
	if err != nil {
		return err
	}
	if parent == nil {
		return fmt.Errorf("Velocity proxy not found")
	}
	return s.syncMinecraftProxy(ctx, worker, nodeID, parent, "")
}

func (s *Server) syncMinecraftProxy(ctx context.Context, worker pluginWorker, nodeID string, parent *auth.GameServer, excludeID string) error {
	instances, err := s.Users.ListMinecraftInstances(ctx, nodeID)
	if err != nil {
		return err
	}
	servers, err := s.Users.ListGameServersForNode(ctx, nodeID)
	if err != nil {
		return err
	}
	dynamic := map[string]bool{}
	for _, instance := range instances {
		if instance.ServerID != excludeID {
			dynamic[instance.ServerID] = true
		}
	}
	targets := map[string]interface{}{}
	for _, server := range servers {
		if !dynamic[server.ID] {
			continue
		}
		metadata := parseGameServerMetadata(server.Metadata)
		if metadata.ParentServerID != parent.ID {
			continue
		}
		targets[server.Slug] = map[string]interface{}{"name": minecraftInstanceProxyName(&server), "host": metadata.ConnectHost, "port": metadata.ConnectPort}
	}
	manifest, err := json.Marshal(map[string]interface{}{"servers": targets})
	if err != nil {
		return err
	}
	if err = s.workerWriteFile(ctx, worker.baseURL, worker.apiKey, path.Join(parent.RootPath, "data/vestri-dynamic-servers.json"), string(manifest)); err != nil {
		return err
	}
	return worker.request(ctx, "/stack/velocity/reload", map[string]string{"stack": parent.StackName})
}

func minecraftInstanceResponse(server *auth.GameServer) map[string]interface{} {
	metadata := parseGameServerMetadata(server.Metadata)
	return map[string]interface{}{"serverId": server.ID, "name": server.Name, "slug": server.Slug, "host": metadata.ConnectHost, "port": metadata.ConnectPort, "parentId": metadata.ParentServerID, "state": "starting"}
}

var minecraftFriendlyName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}-[1-9][0-9]*$`)
var minecraftNameCharacters = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

func nextMinecraftInstanceName(template string, servers []auth.GameServer, parentID string) string {
	prefix := strings.Trim(minecraftNameCharacters.ReplaceAllString(template, ""), "-_")
	if prefix == "" {
		prefix = "Minecraft"
	}
	if len(prefix) > 64 {
		prefix = prefix[:64]
	}
	used := map[string]bool{}
	for _, server := range servers {
		if parseGameServerMetadata(server.Metadata).ParentServerID == parentID {
			used[strings.ToLower(server.Name)] = true
			used[strings.ToLower(server.Slug)] = true
			used[strings.ToLower(minecraftInstanceProxyName(&server))] = true
		}
	}
	for number := 1; ; number++ {
		candidate := fmt.Sprintf("%s-%d", prefix, number)
		if !used[strings.ToLower(candidate)] {
			return candidate
		}
	}
}

func minecraftInstanceProxyName(server *auth.GameServer) string {
	name := parseGameServerMetadata(server.Metadata).VelocityServerName
	if minecraftFriendlyName.MatchString(name) {
		return name
	}
	return server.Slug
}

func minecraftInstanceProperties(properties string, randomWorld bool) string {
	properties = upsertJavaPropertiesValue(properties, "level-name", "world")
	properties = upsertJavaPropertiesValue(properties, "server-port", "25565")
	if randomWorld {
		properties = upsertJavaPropertiesValue(properties, "level-seed", "")
	}
	return properties
}

func minecraftKeyCanAccessInstance(key *auth.MinecraftAPIKey, instance auth.MinecraftInstance) bool {
	return key != nil && key.ID != "" && instance.KeyID == key.ID && instance.TemplateID == key.TemplateID
}

func (s *Server) handleDeleteMinecraftInstance(w http.ResponseWriter, r *http.Request) {
	principal, api := r.Context().Value(minecraftAPIContextKey{}).(minecraftAPIPrincipal)
	var node *auth.WorkerNode
	if api {
		node = principal.Node
	} else {
		_, adminNode, ok := s.loadMinecraftAdmin(w, r)
		if !ok {
			return
		}
		node = adminNode
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	unlock, err := s.lockNodePlugins(ctx, node.ID)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	defer unlock()
	id := chi.URLParam(r, "instanceId")
	instances, err := s.Users.ListMinecraftInstances(ctx, node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load instances")
		return
	}
	found := false
	for _, instance := range instances {
		if instance.ServerID == id && (!api || minecraftKeyCanAccessInstance(principal.Key, instance)) {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	server, err := s.Users.FindGameServerByRefForNode(ctx, node.ID, id)
	if err != nil || server == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Invalid worker configuration")
		return
	}
	if err = s.ensureNoGameServerDatabases(ctx, baseURL, apiKey, server); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if _, err = s.workerStackAction(ctx, baseURL, apiKey, "down", server.StackName); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to stop instance; files were preserved")
		return
	}
	metadata := parseGameServerMetadata(server.Metadata)
	parent, err := s.Users.FindGameServerByRefForNode(ctx, node.ID, metadata.ParentServerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load proxy")
		return
	}
	if parent != nil {
		if err = s.unregisterVelocityBackendFromProxy(ctx, baseURL, apiKey, parent, minecraftInstanceProxyName(server)); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to unregister instance")
			return
		}
		worker := pluginWorker{server: s, baseURL: baseURL, apiKey: apiKey}
		if err = s.syncMinecraftProxy(ctx, worker, node.ID, parent, server.ID); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to synchronize Velocity; instance remains stopped")
			return
		}
	}
	if err = s.workerDeletePath(ctx, baseURL, apiKey, server.RootPath, true); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to delete instance files")
		return
	}
	if _, err = s.Users.DeleteGameServerByID(ctx, node.ID, server.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete instance record")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListMinecraftAPIInstances(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(minecraftAPIContextKey{}).(minecraftAPIPrincipal)
	instances, err := s.Users.ListMinecraftInstances(r.Context(), principal.Node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load instances")
		return
	}
	result := []auth.MinecraftInstance{}
	for _, instance := range instances {
		if minecraftKeyCanAccessInstance(principal.Key, instance) {
			result = append(result, instance)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"instances": result})
}

func (s *Server) registerMinecraftRoutes(r chi.Router) {
	r.Group(func(routes chi.Router) {
		routes.Use(s.requireRoles([]string{RoleUser, RoleAdmin, RoleEditor}))
		root := "/api/nodes/{nodeRef}/minecraft"
		routes.Get(root, s.handleMinecraftLibrary)
		routes.Post(root+"/resources", s.handleCreateMinecraftResource)
		routes.Post(root+"/resources/{resourceId}/shared-plugins", s.handleImportMinecraftSharedPlugins)
		routes.Delete(root+"/resources/{resourceId}", s.handleDeleteMinecraftResource)
		routes.Post(root+"/keys", s.handleCreateMinecraftAPIKey)
		routes.Delete(root+"/keys/{keyId}", s.handleRevokeMinecraftAPIKey)
		routes.Post(root+"/resources/{resourceId}/spawn", s.handleSpawnMinecraftInstance)
		routes.Delete(root+"/instances/{instanceId}", s.handleDeleteMinecraftInstance)
		files := root + "/resources/{resourceId}"
		routes.Get(files+"/files/list", s.withMinecraftResourceFiles(s.handleListGameServerFiles))
		routes.Get(files+"/files/read", s.withMinecraftResourceFiles(s.handleReadGameServerFile))
		routes.Get(files+"/files/download", s.withMinecraftResourceFiles(s.handleDownloadGameServerFile))
		routes.Post(files+"/files/write", s.withMinecraftResourceFiles(s.handleWriteGameServerFile))
		routes.Post(files+"/files/delete", s.withMinecraftResourceFiles(s.handleDeleteGameServerFile))
		routes.Post(files+"/files/upload", s.withMinecraftResourceFiles(s.handleUploadGameServerFile))
		routes.Post(files+"/files/transfer", s.withMinecraftResourceFiles(s.handleTransferGameServerEntry))
		routes.Post(files+"/files/unzip", s.withMinecraftResourceFiles(s.handleUnzipGameServerFile))
		routes.Post(files+"/folders/create", s.withMinecraftResourceFiles(s.handleCreateGroupFolder))
	})
}
