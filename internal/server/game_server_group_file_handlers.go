package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	velocityPluginStagingRelativePath = "data/vestri-plugin-staging"
	stagingPluginsDirName             = "plugins"
	backendPluginsRelativePath        = "data/plugins"
	maxGroupApplyServers              = 100
	maxGroupApplyDepth                = 16
	maxGroupApplyFiles                = 5000
)

type groupFilesScopeKey struct{}

type applyGroupFilesRequest struct {
	ServerRefs []string `json:"serverRefs"`
	// Items limits the copy to these top-level entries of the staging plugins folder; empty means all.
	Items []string `json:"items"`
}

type createGroupFolderRequest struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

func groupFilesScoped(ctx context.Context) bool {
	scoped, _ := ctx.Value(groupFilesScopeKey{}).(bool)
	return scoped
}

// withGroupFilesScope re-roots the shared file handlers at the Velocity plugin staging folder.
func withGroupFilesScope(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r.WithContext(context.WithValue(r.Context(), groupFilesScopeKey{}, true)))
	}
}

func (s *Server) handleListGroupFiles(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(context.WithValue(r.Context(), groupFilesScopeKey{}, true))
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file listing")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	if err := s.workerMkdirAll(r.Context(), baseURL, apiKey, path.Join(server.RootPath, stagingPluginsDirName)); err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}

	s.handleListGameServerFiles(w, r)
}

func (s *Server) handleCreateGroupFolder(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(context.WithValue(r.Context(), groupFilesScopeKey{}, true))
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file upload")
		return
	}

	var req createGroupFolderRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if !safeSatisfactoryDirectoryName(name) {
		writeError(w, http.StatusBadRequest, "Invalid folder name")
		return
	}
	parentPath, err := resolveServerScopedPath(server.RootPath, req.Path, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/mkdir", map[string]interface{}{
		"path":      path.Join(parentPath, name),
		"exclusive": true,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), statusCode)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleApplyGroupFiles(w http.ResponseWriter, r *http.Request) {
	sess, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file upload")
		return
	}
	if !isVelocityServer(server) {
		writeError(w, http.StatusBadRequest, "Plugin staging is only available for velocity servers")
		return
	}
	unlock, err := s.lockPluginGroup(r.Context(), server.ID)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	defer unlock()

	var req applyGroupFilesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	seen := make(map[string]struct{}, len(req.ServerRefs))
	refs := make([]string, 0, len(req.ServerRefs))
	for _, ref := range req.ServerRefs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if _, dup := seen[ref]; dup {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	if len(refs) == 0 || len(refs) > maxGroupApplyServers {
		writeError(w, http.StatusBadRequest, "Select between 1 and 100 subservers")
		return
	}
	selectedItems := make(map[string]struct{}, len(req.Items))
	for _, item := range req.Items {
		item = strings.TrimSpace(item)
		if !safeSatisfactoryDirectoryName(item) {
			writeError(w, http.StatusBadRequest, "Invalid plugin name")
			return
		}
		selectedItems[item] = struct{}{}
	}

	targetRoots := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref == server.ID {
			targetRoots = append(targetRoots, server.RootPath)
			continue
		}
		access, err := s.Users.FindAccessibleGameServerByRefForNode(r.Context(), sess.UserID, node, ref)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to load game server")
			return
		}
		if access == nil {
			writeError(w, http.StatusNotFound, "Game server not found")
			return
		}
		if !canManageGameServerFiles(access.AccessRole) {
			writeError(w, http.StatusForbidden, "Server permission denied for file upload")
			return
		}
		metadata := parseGameServerMetadata(access.GameServer.Metadata)
		if strings.TrimSpace(metadata.ParentServerID) != server.ID {
			writeError(w, http.StatusBadRequest, "Server does not belong to this velocity group")
			return
		}
		if !supportsVelocityBackendSoftware(metadata.SoftwareVersion) {
			writeError(w, http.StatusBadRequest, "Server software does not support plugins")
			return
		}
		targetRoots = append(targetRoots, access.GameServer.RootPath)
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	stagingPlugins := path.Join(server.RootPath, velocityPluginStagingRelativePath, stagingPluginsDirName)
	worker := pluginWorker{server: s, baseURL: baseURL, apiKey: apiKey, root: server.RootPath}
	manifest, err := worker.load(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	var files []string
	if err := s.collectWorkerFiles(r.Context(), baseURL, apiKey, stagingPlugins, "", 0, &files); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read staged plugins")
		return
	}
	if len(selectedItems) > 0 {
		filtered := files[:0]
		for _, rel := range files {
			top, _, _ := strings.Cut(rel, "/")
			if _, wanted := selectedItems[top]; wanted {
				filtered = append(filtered, rel)
			}
		}
		files = filtered
	}
	if len(files) == 0 {
		writeError(w, http.StatusBadRequest, "No staged plugin files to apply")
		return
	}
	trackedFiles := make(map[string]trackedPlugin)
	for _, plugin := range manifest.Plugins {
		trackedFiles[plugin.Installed.Filename] = plugin
		if plugin.Pending {
			for _, filename := range plugin.Filenames {
				trackedFiles[filename] = plugin
			}
		}
	}
	for _, rel := range files {
		if plugin, tracked := trackedFiles[rel]; tracked && plugin.Pending {
			writeError(w, http.StatusConflict, "Complete the pending plugin update before copying staged plugins")
			return
		}
	}

	for _, root := range targetRoots {
		for _, rel := range files {
			if plugin, tracked := trackedFiles[rel]; tracked {
				if err := worker.replace(r.Context(), path.Join(stagingPlugins, rel), path.Join(root, backendPluginsRelativePath), rel, plugin.Filenames); err != nil {
					writeError(w, http.StatusBadGateway, "Tracked plugin copy failed: "+err.Error())
					return
				}
				continue
			}
			statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/copy", map[string]string{
				"source": path.Join(stagingPlugins, rel),
				"dest":   path.Join(root, backendPluginsRelativePath, rel),
			})
			if err != nil {
				writeError(w, http.StatusBadGateway, "Worker request failed")
				return
			}
			if statusCode < 200 || statusCode >= 300 {
				http.Error(w, strings.TrimSpace(string(body)), statusCode)
				return
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]int{"appliedTo": len(targetRoots)})
}

func (s *Server) workerMkdirAll(ctx context.Context, baseURL *url.URL, apiKey, dir string) error {
	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/mkdir", map[string]interface{}{
		"path":      dir,
		"recursive": true,
	})
	if err != nil {
		return err
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return fmt.Errorf("worker /fs/mkdir failed (%d): %s", statusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// collectWorkerFiles appends regular files below dir as slash-separated paths relative to dir.
func (s *Server) collectWorkerFiles(ctx context.Context, baseURL *url.URL, apiKey, dir, rel string, depth int, out *[]string) error {
	if depth > maxGroupApplyDepth {
		return fmt.Errorf("staging folder is nested too deeply")
	}
	entries, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, path.Join(dir, rel))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !safeSatisfactoryDirectoryName(entry.Name) {
			continue
		}
		entryRel := path.Join(rel, entry.Name)
		switch entry.Type {
		case "dir":
			if err := s.collectWorkerFiles(ctx, baseURL, apiKey, dir, entryRel, depth+1, out); err != nil {
				return err
			}
		case "file":
			if len(*out) >= maxGroupApplyFiles {
				return fmt.Errorf("too many staged files")
			}
			*out = append(*out, entryRel)
		}
	}
	return nil
}
