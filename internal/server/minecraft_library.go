package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"yourapp/internal/auth"
)

type minecraftResourceSpec struct {
	Software         string   `json:"software,omitempty"`
	Version          string   `json:"version,omitempty"`
	Jar              string   `json:"jar,omitempty"`
	MandatoryPlugins []string `json:"mandatoryPlugins,omitempty"`
	BaseID           string   `json:"baseId,omitempty"`
	WorldID          string   `json:"worldId,omitempty"`
	PluginIDs        []string `json:"pluginIds,omitempty"`
	ParentID         string   `json:"parentId,omitempty"`
	MaxInstances     int      `json:"maxInstances,omitempty"`
}

type minecraftResourceFilesScopeKey struct{}

func minecraftResourcePath(resource *auth.MinecraftResource) string {
	return path.Join(minecraftLibraryPath(resource.NodeID), resource.Kind, resource.ID)
}

func minecraftResourceDataPath(resource *auth.MinecraftResource) string {
	return path.Join(minecraftResourcePath(resource), "data")
}

func validMinecraftResourceKind(kind string) bool {
	return kind == "bases" || kind == "worlds" || kind == "plugin-packs" || kind == "templates"
}

func (s *Server) loadMinecraftAdmin(w http.ResponseWriter, r *http.Request) (*auth.Session, *auth.WorkerNode, bool) {
	sess, node, ok := s.loadNodeForGameServerRequest(w, r)
	if !ok {
		return nil, nil, false
	}
	if !canManageNodeMinecraftLibrary(node.AccessRole) {
		writeError(w, http.StatusForbidden, "Node owner or admin permission is required")
		return nil, nil, false
	}
	return sess, node, true
}

func (s *Server) withMinecraftResourceFiles(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), minecraftResourceFilesScopeKey{}, true)
		r = r.WithContext(ctx)
		_, node, _, _, ok := s.loadNodeAndGameServerForRequest(w, r)
		if !ok {
			return
		}
		if r.Method != http.MethodGet {
			unlock, err := s.lockNodePlugins(ctx, node.ID)
			if err != nil {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			defer unlock()
		}
		next(w, r)
	}
}

func (s *Server) handleMinecraftLibrary(w http.ResponseWriter, r *http.Request) {
	_, node, ok := s.loadMinecraftAdmin(w, r)
	if !ok {
		return
	}
	resources, err := s.Users.ListMinecraftResources(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load Minecraft resources")
		return
	}
	keys, err := s.Users.ListMinecraftAPIKeys(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load API keys")
		return
	}
	instances, err := s.Users.ListMinecraftInstances(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load instances")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"resources": resources, "keys": keys, "instances": instances})
}

func (s *Server) minecraftResource(ctx context.Context, nodeID, id, kind string) (*auth.MinecraftResource, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid resource reference")
	}
	resource, err := s.Users.FindMinecraftResource(ctx, nodeID, id)
	if err != nil {
		return nil, err
	}
	if resource == nil || resource.Kind != kind {
		return nil, fmt.Errorf("%s resource not found on this node", kind)
	}
	return resource, nil
}

func (s *Server) copyMinecraftDirectory(ctx context.Context, worker pluginWorker, source, dest string) error {
	if err := s.workerMkdirAll(ctx, worker.baseURL, worker.apiKey, path.Dir(dest)); err != nil {
		return err
	}
	return worker.request(ctx, "/fs/transfer", map[string]string{"source": source, "dest": dest, "operation": "copy"})
}

func (s *Server) overlayMinecraftPlugins(ctx context.Context, worker pluginWorker, source, dest string) error {
	var files []string
	if err := s.collectWorkerFiles(ctx, worker.baseURL, worker.apiKey, source, "", 0, &files); err != nil {
		return err
	}
	for _, file := range files {
		if err := s.workerMkdirAll(ctx, worker.baseURL, worker.apiKey, path.Dir(path.Join(dest, file))); err != nil {
			return err
		}
		if err := worker.request(ctx, "/fs/copy", map[string]string{"source": path.Join(source, file), "dest": path.Join(dest, file)}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleCreateMinecraftResource(w http.ResponseWriter, r *http.Request) {
	_, node, ok := s.loadMinecraftAdmin(w, r)
	if !ok {
		return
	}
	var request struct {
		Kind              string                `json:"kind"`
		Name              string                `json:"name"`
		Spec              minecraftResourceSpec `json:"spec"`
		AgreementAccepted bool                  `json:"agreementAccepted"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if !validMinecraftResourceKind(request.Kind) || request.Name == "" || utf8.RuneCountInString(request.Name) > 64 {
		writeError(w, http.StatusBadRequest, "A resource kind and name (1-64 characters) are required")
		return
	}
	if len(request.Spec.MandatoryPlugins) > 100 || len(request.Spec.PluginIDs) > 100 {
		writeError(w, http.StatusBadRequest, "Too many plugins")
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
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Invalid worker configuration")
		return
	}
	worker := pluginWorker{server: s, baseURL: baseURL, apiKey: apiKey, root: minecraftLibraryPath(node.ID)}
	resource := auth.MinecraftResource{ID: uuid.NewString(), NodeID: node.ID, Kind: request.Kind, Name: request.Name}
	spec := request.Spec
	root := minecraftResourcePath(&resource)
	complete := false
	defer func() {
		if !complete {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			_ = s.workerDeletePath(cleanupCtx, baseURL, apiKey, root, true)
		}
	}()
	data := minecraftResourceDataPath(&resource)
	switch resource.Kind {
	case "bases":
		if !request.AgreementAccepted {
			writeError(w, http.StatusBadRequest, "Minecraft EULA acceptance is required")
			return
		}
		spec.Software = strings.ToUpper(strings.TrimSpace(spec.Software))
		if spec.Software != "PAPER" && spec.Software != "PURPUR" {
			writeError(w, http.StatusBadRequest, "Select Paper or Purpur for plugin-based templates")
			return
		}
		if !stableMinecraftVersionPattern.MatchString(spec.Version) {
			writeError(w, http.StatusBadRequest, "An explicit Minecraft release version is required")
			return
		}
		artifact, artifactErr := resolveMinecraftServerArtifact(ctx, spec.Software, spec.Version)
		if artifactErr != nil {
			writeError(w, http.StatusBadGateway, "Failed to resolve Minecraft build")
			return
		}
		spec.Jar, err = minecraftServerJarFileNameForArtifact(artifact)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		spec.Version = artifact.Version
		if err = s.provisionMinecraftServerArtifactOnWorker(ctx, baseURL, apiKey, root, artifact); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to provision Minecraft build")
			return
		}
		if err = s.workerWriteFile(ctx, baseURL, apiKey, path.Join(data, "eula.txt"), "eula=true\n"); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		if err = s.workerWriteFile(ctx, baseURL, apiKey, path.Join(data, "server.properties"), "server-port=25565\nlevel-name=world\nlevel-seed=\nonline-mode=true\nmotd=Minecraft game server\n"); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		for _, name := range spec.MandatoryPlugins {
			if !safeSatisfactoryDirectoryName(name) {
				writeError(w, http.StatusBadRequest, "Invalid mandatory plugin name")
				return
			}
			entries, listErr := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, minecraftPluginLibraryPath(node.ID))
			if listErr != nil {
				writeError(w, http.StatusBadGateway, "Failed to list mandatory plugins")
				return
			}
			found := false
			for _, entry := range entries {
				if entry.Name != name {
					continue
				}
				found = true
				source, dest := path.Join(minecraftPluginLibraryPath(node.ID), name), path.Join(data, "plugins", name)
				if err = s.copyMinecraftDirectory(ctx, worker, source, dest); err != nil {
					writeError(w, http.StatusBadGateway, "Failed to copy mandatory plugin")
					return
				}
			}
			if !found {
				writeError(w, http.StatusBadRequest, "Mandatory plugin not found")
				return
			}
		}
	case "templates":
		if spec.MaxInstances < 1 || spec.MaxInstances > 100 {
			writeError(w, http.StatusBadRequest, "maxInstances must be between 1 and 100")
			return
		}
		if spec.ParentID == "" {
			writeError(w, http.StatusBadRequest, "Select the Velocity proxy for dynamic game instances")
			return
		}
		base, findErr := s.minecraftResource(ctx, node.ID, spec.BaseID, "bases")
		if findErr != nil {
			writeError(w, http.StatusBadRequest, findErr.Error())
			return
		}
		var baseSpec minecraftResourceSpec
		if json.Unmarshal(base.Spec, &baseSpec) != nil {
			writeError(w, http.StatusInternalServerError, "Invalid base metadata")
			return
		}
		spec.Software, spec.Version, spec.Jar = baseSpec.Software, baseSpec.Version, baseSpec.Jar
		if spec.ParentID != "" {
			parent, parentErr := s.Users.FindGameServerByRefForNode(ctx, node.ID, spec.ParentID)
			if parentErr != nil || parent == nil || !isVelocityServer(parent) {
				writeError(w, http.StatusBadRequest, "Select a Velocity proxy on this node")
				return
			}
			spec.ParentID = parent.ID
		}
		if err = s.copyMinecraftDirectory(ctx, worker, minecraftResourceDataPath(base), data); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to copy base server")
			return
		}
		for _, worldName := range []string{"world", "world_nether", "world_the_end"} {
			if err = s.workerDeletePath(ctx, baseURL, apiKey, path.Join(data, worldName), true); err != nil {
				writeError(w, http.StatusBadGateway, "Failed to reset template world")
				return
			}
		}
		if spec.WorldID != "" {
			world, findErr := s.minecraftResource(ctx, node.ID, spec.WorldID, "worlds")
			if findErr != nil {
				writeError(w, http.StatusBadRequest, findErr.Error())
				return
			}
			entries, listErr := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, minecraftResourceDataPath(world))
			if listErr != nil {
				writeError(w, http.StatusBadGateway, "Failed to read selected world")
				return
			}
			validWorld := false
			for _, entry := range entries {
				if entry.Name == "level.dat" && entry.Type == "file" {
					validWorld = true
					break
				}
			}
			if !validWorld {
				writeError(w, http.StatusBadRequest, "Upload the contents of a Minecraft world, including level.dat, before selecting it")
				return
			}
			if err = s.copyMinecraftDirectory(ctx, worker, minecraftResourceDataPath(world), path.Join(data, "world")); err != nil {
				writeError(w, http.StatusBadGateway, "Failed to copy world")
				return
			}
		}
		seen := map[string]bool{}
		for _, id := range spec.PluginIDs {
			if seen[id] {
				writeError(w, http.StatusBadRequest, "Duplicate plugin package")
				return
			}
			seen[id] = true
			pack, findErr := s.minecraftResource(ctx, node.ID, id, "plugin-packs")
			if findErr != nil {
				writeError(w, http.StatusBadRequest, findErr.Error())
				return
			}
			if err = s.overlayMinecraftPlugins(ctx, worker, minecraftResourceDataPath(pack), path.Join(data, "plugins")); err != nil {
				writeError(w, http.StatusBadGateway, "Failed to copy game plugins")
				return
			}
		}
	default:
		spec = minecraftResourceSpec{}
		if err = s.workerMkdirAll(ctx, baseURL, apiKey, data); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	resource.Spec, err = json.Marshal(spec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to encode metadata")
		return
	}
	if err = s.workerWriteFile(ctx, baseURL, apiKey, path.Join(root, "manifest.json"), string(resource.Spec)); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to write template manifest")
		return
	}
	if err = s.Users.CreateMinecraftResource(ctx, resource); err != nil {
		writeError(w, http.StatusConflict, "Resource name already exists or could not be saved")
		return
	}
	complete = true
	writeJSON(w, http.StatusCreated, map[string]interface{}{"resource": resource})
}

func (s *Server) handleDeleteMinecraftResource(w http.ResponseWriter, r *http.Request) {
	_, node, ok := s.loadMinecraftAdmin(w, r)
	if !ok {
		return
	}
	unlock, err := s.lockNodePlugins(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	defer unlock()
	id := chi.URLParam(r, "resourceId")
	resource, err := s.Users.FindMinecraftResource(r.Context(), node.ID, id)
	if err != nil || resource == nil {
		writeError(w, http.StatusNotFound, "Resource not found")
		return
	}
	instances, err := s.Users.ListMinecraftInstances(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load instances")
		return
	}
	for _, instance := range instances {
		if instance.TemplateID == id {
			writeError(w, http.StatusConflict, "Delete template instances first")
			return
		}
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Invalid worker configuration")
		return
	}
	if err = s.workerDeletePath(r.Context(), baseURL, apiKey, minecraftResourcePath(resource), true); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to delete resource files")
		return
	}
	if err = s.Users.DeleteMinecraftResource(r.Context(), node.ID, id); err != nil {
		writeError(w, http.StatusConflict, "Resource is still in use")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
