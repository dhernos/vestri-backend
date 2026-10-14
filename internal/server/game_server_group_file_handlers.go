package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"

	"yourapp/internal/auth"
)

type velocityGroupFileTarget struct {
	server auth.GameServer
}

const velocityGroupStagingRelativePath = "data/vestri-plugin-staging"
const velocityManagedPluginManifestName = ".vestri-managed-plugin-files.json"

type applyVelocityGroupFilesRequest struct {
	ServerRefs []string `json:"serverRefs"`
}

type createVelocityGroupFolderRequest struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

func (s *Server) loadVelocityGroupFileTargets(w http.ResponseWriter, r *http.Request) (*auth.GameServer, []velocityGroupFileTarget, *url.URL, string, bool) {
	_, node, proxy, proxyRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return nil, nil, nil, "", false
	}
	if !isVelocityServer(proxy) {
		writeError(w, http.StatusBadRequest, "Group files are only available for Velocity servers")
		return nil, nil, nil, "", false
	}
	if !canManageGameServerFiles(proxyRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for group files")
		return nil, nil, nil, "", false
	}

	servers, err := s.Users.ListGameServersForNode(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load Velocity backends")
		return nil, nil, nil, "", false
	}
	targets := make([]velocityGroupFileTarget, 0)
	for i := range servers {
		metadata := parseGameServerMetadata(servers[i].Metadata)
		if strings.TrimSpace(metadata.ParentServerID) != proxy.ID {
			continue
		}
		targets = append(targets, velocityGroupFileTarget{server: servers[i]})
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].server.Slug < targets[j].server.Slug
	})
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return nil, nil, nil, "", false
	}
	if err := ensureVelocityGroupStagingDirectory(r.Context(), s, baseURL, apiKey, proxy.RootPath); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to prepare Velocity plugin staging folder")
		return nil, nil, nil, "", false
	}
	for _, target := range targets {
		softwareFolder := velocityPluginSoftwareFolder(parseGameServerMetadata(target.server.Metadata).SoftwareVersion)
		if softwareFolder == "" {
			continue
		}
		if err := ensureVelocityGroupSoftwareDirectory(r.Context(), s, baseURL, apiKey, proxy.RootPath, softwareFolder); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to prepare software-specific plugin folder")
			return nil, nil, nil, "", false
		}
	}
	return proxy, targets, baseURL, apiKey, true
}

func ensureVelocityGroupStagingDirectory(ctx context.Context, s *Server, baseURL *url.URL, apiKey, proxyRoot string) error {
	stagingPath, err := resolveServerScopedPath(proxyRoot, velocityGroupStagingRelativePath, true)
	if err != nil {
		return err
	}
	status, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/mkdir", map[string]interface{}{
		"path":      stagingPath,
		"exclusive": false,
	})
	if err != nil {
		return err
	}
	if status == http.StatusConflict || status >= 200 && status < 300 {
		return nil
	}
	return fmt.Errorf("worker /fs/mkdir failed (%d): %s", status, strings.TrimSpace(string(body)))
}

func velocityPluginSoftwareFolder(software string) string {
	switch strings.ToUpper(strings.TrimSpace(software)) {
	case "PAPER":
		return "paper"
	case "PURPUR":
		return "purpur"
	case "SPIGOT":
		return "spigot"
	case "BUKKIT":
		return "bukkit"
	default:
		return ""
	}
}

func ensureVelocityGroupSoftwareDirectory(ctx context.Context, s *Server, baseURL *url.URL, apiKey, proxyRoot, softwareFolder string) error {
	targetPath := path.Join(proxyRoot, velocityGroupStagingRelativePath, softwareFolder)
	return ensureWorkerDirectory(ctx, s, baseURL, apiKey, targetPath)
}

func resolveVelocityGroupStagingPath(proxyRoot, rawPath string, allowSoftwareRoot bool) (string, string, error) {
	stagingRoot := path.Join(proxyRoot, velocityGroupStagingRelativePath)
	fullPath, err := resolveServerScopedPath(stagingRoot, rawPath, true)
	if err != nil {
		return "", "", err
	}
	cleanPath := path.Clean(strings.TrimLeft(strings.ReplaceAll(strings.TrimSpace(rawPath), "\\", "/"), "/"))
	if cleanPath == "." || cleanPath == "" {
		if allowSoftwareRoot {
			return fullPath, "", nil
		}
		return "", "", fmt.Errorf("choose a software subfolder first")
	}
	parts := strings.Split(cleanPath, "/")
	softwareFolder := parts[0]
	if velocityPluginSoftwareFolder(softwareFolder) != softwareFolder {
		return "", "", fmt.Errorf("path must be inside a supported software folder")
	}
	if len(parts) == 1 && !allowSoftwareRoot {
		return "", "", fmt.Errorf("changes are not allowed at the software folder root")
	}
	return fullPath, softwareFolder, nil
}

func (s *Server) handleListVelocityGroupFiles(w http.ResponseWriter, r *http.Request) {
	proxy, _, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	fullPath, _, err := resolveVelocityGroupStagingPath(proxy.RootPath, r.URL.Query().Get("path"), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query := url.Values{"path": {fullPath}}.Encode()
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/list?"+query, nil)
	writeWorkerJSONResult(w, status, body, err)
}

func (s *Server) handleReadVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	proxy, _, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	fullPath, _, err := resolveVelocityGroupStagingPath(proxy.RootPath, r.URL.Query().Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !isTextFilePath(fullPath) {
		writeError(w, http.StatusUnsupportedMediaType, "Only text file formats can be opened in editor")
		return
	}
	query := url.Values{"path": {fullPath}}.Encode()
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/read?"+query, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if status < 200 || status >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), status)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleWriteVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	proxy, _, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	var req writeGameServerFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	fullPath, _, err := resolveVelocityGroupStagingPath(proxy.RootPath, req.Path, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/write", map[string]string{"path": fullPath, "content": req.Content})
	if err := groupFileWorkerError(status, body, err); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to write plugin staging file")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	proxy, _, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	var req deleteGameServerFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	fullPath, _, err := resolveVelocityGroupStagingPath(proxy.RootPath, req.Path, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{"path": fullPath, "recursive": req.Recursive})
	if err := groupFileWorkerError(status, body, err); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to delete plugin staging path")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleUnzipVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	proxy, _, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	var req unzipGameServerFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	source, _, err := resolveVelocityGroupStagingPath(proxy.RootPath, req.Source, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dest, _, err := resolveVelocityGroupStagingPath(proxy.RootPath, req.Dest, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/unzip", map[string]string{"source": source, "dest": dest})
	if err := groupFileWorkerError(status, body, err); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to extract archive into plugin staging folder")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDownloadVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	proxy, _, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	fullPath, _, err := resolveVelocityGroupStagingPath(proxy.RootPath, r.URL.Query().Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query := url.Values{"path": {fullPath}}.Encode()
	resp, err := s.callWorkerStream(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/download", query, "", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		copyHeaders(w.Header(), resp.Header, []string{"Content-Type", "Content-Disposition", "Content-Length", "Content-Range", "Accept-Ranges"})
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	workerErr := readWorkerErrorText(resp.Body)
	if !isDirectoryDownloadError(resp.StatusCode, workerErr) {
		if workerErr == "" {
			workerErr = "Worker request failed"
		}
		http.Error(w, workerErr, resp.StatusCode)
		return
	}
	name := path.Base(fullPath)
	if name == "" || name == "." || name == "/" {
		name = "group-files"
	}
	tempArchive := buildTempArchiveTarget(proxy.RootPath, name)
	defer s.cleanupWorkerArchive(baseURL, apiKey, tempArchive)
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/zip", map[string]string{"source": fullPath, "dest": tempArchive.ArchivePath})
	if err := groupFileWorkerError(status, body, err); err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	archiveQuery := url.Values{"path": {tempArchive.ArchivePath}}.Encode()
	archiveResp, err := s.callWorkerStream(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/download", archiveQuery, "", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer archiveResp.Body.Close()
	if archiveResp.StatusCode < 200 || archiveResp.StatusCode >= 300 {
		msg := readWorkerErrorText(archiveResp.Body)
		if msg == "" {
			msg = "Worker request failed"
		}
		http.Error(w, msg, archiveResp.StatusCode)
		return
	}
	copyHeaders(w.Header(), archiveResp.Header, []string{"Content-Type", "Content-Encoding", "Content-Length", "Content-Range", "Accept-Ranges"})
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".zip"))
	w.WriteHeader(archiveResp.StatusCode)
	_, _ = io.Copy(w, archiveResp.Body)
}

func (s *Server) handleCreateVelocityGroupFolder(w http.ResponseWriter, r *http.Request) {
	proxy, _, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	var req createVelocityGroupFolderRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	folderName := strings.TrimSpace(strings.ReplaceAll(req.Name, "\\", "/"))
	if folderName == "" || folderName == "." || folderName == ".." || path.Base(folderName) != folderName {
		writeError(w, http.StatusBadRequest, "A single folder name is required")
		return
	}
	fullPath, _, err := resolveVelocityGroupStagingPath(proxy.RootPath, path.Join(req.Path, folderName), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ensureWorkerDirectory(r.Context(), s, baseURL, apiKey, fullPath); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to create plugin staging folder")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleUploadVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	proxy, _, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid multipart form")
		return
	}
	var rawPath, uploadName string
	var uploadTmp *os.File
	defer func() {
		if uploadTmp != nil {
			name := uploadTmp.Name()
			_ = uploadTmp.Close()
			_ = os.Remove(name)
		}
	}()
	for {
		part, partErr := reader.NextPart()
		if errors.Is(partErr, io.EOF) {
			break
		}
		if partErr != nil {
			writeError(w, http.StatusBadRequest, "Invalid multipart form")
			return
		}
		switch part.FormName() {
		case "path":
			value, readErr := io.ReadAll(io.LimitReader(part, maxUploadPathFieldBytes))
			_ = part.Close()
			if readErr != nil {
				writeError(w, http.StatusBadRequest, "Invalid upload path")
				return
			}
			rawPath = strings.TrimSpace(string(value))
		case "file":
			if uploadTmp != nil {
				_ = part.Close()
				writeError(w, http.StatusBadRequest, "Only one file upload is supported")
				return
			}
			uploadTmp, err = os.CreateTemp("", "vestri-group-upload-*")
			if err != nil {
				_ = part.Close()
				writeError(w, http.StatusInternalServerError, "Failed to create temporary upload file")
				return
			}
			if _, err = io.Copy(uploadTmp, part); err != nil {
				_ = part.Close()
				writeError(w, http.StatusBadGateway, "Failed to read uploaded file")
				return
			}
			_ = part.Close()
			uploadName = strings.TrimSpace(part.FileName())
			if uploadName == "" {
				uploadName = "upload.bin"
			}
		default:
			_ = part.Close()
		}
	}
	if strings.TrimSpace(rawPath) == "" || uploadTmp == nil {
		writeError(w, http.StatusBadRequest, "path and file are required")
		return
	}
	fullPath, _, err := resolveVelocityGroupStagingPath(proxy.RootPath, rawPath, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.streamGroupUploadToWorker(r, baseURL, apiKey, uploadTmp, fullPath, uploadName); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to upload into plugin staging folder")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleApplyVelocityGroupFiles(w http.ResponseWriter, r *http.Request) {
	sess, node, proxy, proxyRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !isVelocityServer(proxy) {
		writeError(w, http.StatusBadRequest, "Plugin apply is only available for Velocity servers")
		return
	}
	if !canManageGameServerFiles(proxyRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for plugin apply")
		return
	}
	var req applyVelocityGroupFilesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(req.ServerRefs) == 0 || len(req.ServerRefs) > 100 {
		writeError(w, http.StatusBadRequest, "Select between 1 and 100 backend servers")
		return
	}

	allServers, err := s.Users.ListGameServersForNode(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load Velocity backends")
		return
	}
	groupServerIDs := make(map[string]struct{})
	for i := range allServers {
		if strings.TrimSpace(parseGameServerMetadata(allServers[i].Metadata).ParentServerID) == proxy.ID {
			groupServerIDs[allServers[i].ID] = struct{}{}
		}
	}

	targets := make([]velocityGroupFileTarget, 0, len(req.ServerRefs))
	seen := make(map[string]struct{}, len(req.ServerRefs))
	for _, ref := range req.ServerRefs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			writeError(w, http.StatusBadRequest, "Backend server reference is required")
			return
		}
		access, accessErr := s.Users.FindAccessibleGameServerByRefForNode(r.Context(), sess.UserID, node, ref)
		if accessErr != nil {
			writeError(w, http.StatusInternalServerError, "Failed to validate backend server access")
			return
		}
		if access == nil {
			writeError(w, http.StatusNotFound, "Selected backend server was not found")
			return
		}
		if _, belongsToGroup := groupServerIDs[access.ID]; !belongsToGroup {
			writeError(w, http.StatusBadRequest, "Selected server is not part of this Velocity group")
			return
		}
		if _, duplicate := seen[access.ID]; duplicate {
			continue
		}
		seen[access.ID] = struct{}{}
		if !canManageGameServerFiles(access.AccessRole) {
			writeError(w, http.StatusForbidden, "File management permission is required on every selected backend")
			return
		}
		metadata := parseGameServerMetadata(access.Metadata)
		if !supportsVelocityBackendSoftware(metadata.SoftwareVersion) {
			writeError(w, http.StatusBadRequest, "Selected backend software does not support plugins")
			return
		}
		targets = append(targets, velocityGroupFileTarget{server: access.GameServer})
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	if err := ensureVelocityGroupStagingDirectory(r.Context(), s, baseURL, apiKey, proxy.RootPath); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to prepare Velocity plugin staging folder")
		return
	}
	targetsBySoftware := make(map[string][]velocityGroupFileTarget)
	for _, target := range targets {
		softwareFolder := velocityPluginSoftwareFolder(parseGameServerMetadata(target.server.Metadata).SoftwareVersion)
		targetsBySoftware[softwareFolder] = append(targetsBySoftware[softwareFolder], target)
	}
	for softwareFolder, softwareTargets := range targetsBySoftware {
		stagingPath, err := resolveServerScopedPath(proxy.RootPath, path.Join(velocityGroupStagingRelativePath, softwareFolder), false)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Velocity plugin staging path is invalid")
			return
		}
		archive := buildTempArchiveTarget(proxy.RootPath, "plugin-staging-"+softwareFolder)
		defer s.cleanupWorkerArchive(baseURL, apiKey, archive)
		status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/zip", map[string]string{
			"source": stagingPath,
			"dest":   archive.ArchivePath,
		})
		if err := groupFileWorkerError(status, body, err); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to package plugin staging folder")
			return
		}

		archiveQuery := url.Values{"path": {archive.ArchivePath}}.Encode()
		archiveResp, err := s.callWorkerStream(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/download", archiveQuery, "", nil)
		if err != nil {
			writeError(w, http.StatusBadGateway, "Failed to read plugin staging archive")
			return
		}
		if archiveResp.StatusCode < 200 || archiveResp.StatusCode >= 300 {
			_ = archiveResp.Body.Close()
			writeError(w, http.StatusBadGateway, "Failed to read plugin staging archive")
			return
		}
		archiveFile, err := os.CreateTemp("", "vestri-plugin-staging-*.zip")
		if err != nil {
			_ = archiveResp.Body.Close()
			writeError(w, http.StatusInternalServerError, "Failed to create temporary plugin archive")
			return
		}
		archiveFileName := archiveFile.Name()
		if _, err := io.Copy(archiveFile, archiveResp.Body); err != nil {
			_ = archiveResp.Body.Close()
			_ = archiveFile.Close()
			_ = os.Remove(archiveFileName)
			writeError(w, http.StatusBadGateway, "Failed to receive plugin staging archive")
			return
		}
		_ = archiveResp.Body.Close()
		_ = archiveFile.Close()
		if err := s.applyVelocityStagingArchive(r, baseURL, apiKey, archiveFileName, stagingPath, softwareTargets); err != nil {
			_ = os.Remove(archiveFileName)
			writeError(w, http.StatusBadGateway, "Plugin apply failed; earlier files or selected backends may already have been updated")
			return
		}
		_ = os.Remove(archiveFileName)
	}
	writeJSON(w, http.StatusOK, map[string]int{"appliedTo": len(targets)})
}

func velocityBackendPluginPath(server auth.GameServer) (string, error) {
	metadata := parseGameServerMetadata(server.Metadata)
	if !supportsVelocityBackendSoftware(metadata.SoftwareVersion) {
		return "", fmt.Errorf("backend %s does not support plugins", server.Slug)
	}
	return path.Join(server.RootPath, "data", "plugins"), nil
}

func (s *Server) applyVelocityStagingArchive(r *http.Request, baseURL *url.URL, apiKey, archiveName, stagingPath string, targets []velocityGroupFileTarget) error {
	archive, err := zip.OpenReader(archiveName)
	if err != nil {
		return err
	}
	defer archive.Close()
	managedFiles := make(map[string]struct{})
	for _, entry := range archive.File {
		relativePath, include, err := velocityStagingArchiveRelativePath(entry.Name, stagingPath)
		if err != nil {
			return err
		}
		if !include {
			continue
		}
		if !entry.FileInfo().IsDir() {
			if !entry.Mode().IsRegular() {
				return fmt.Errorf("unsupported archive entry type at %q", entry.Name)
			}
			managedFiles[relativePath] = struct{}{}
		}
	}
	for _, target := range targets {
		pluginPath, err := velocityBackendPluginPath(target.server)
		if err != nil {
			return err
		}
		if err := ensureWorkerDirectory(r.Context(), s, baseURL, apiKey, pluginPath); err != nil {
			return err
		}
	}
	for _, entry := range archive.File {
		relativePath, include, err := velocityStagingArchiveRelativePath(entry.Name, stagingPath)
		if err != nil {
			return err
		}
		if !include {
			continue
		}
		for _, target := range targets {
			pluginPath, err := velocityBackendPluginPath(target.server)
			if err != nil {
				return err
			}
			targetPath := path.Join(pluginPath, relativePath)
			if entry.FileInfo().IsDir() {
				if err := ensureWorkerDirectory(r.Context(), s, baseURL, apiKey, targetPath); err != nil {
					return err
				}
				continue
			}
			parentPath := path.Dir(path.Join(pluginPath, relativePath))
			if err := ensureWorkerDirectory(r.Context(), s, baseURL, apiKey, parentPath); err != nil {
				return err
			}
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		tempFile, err := os.CreateTemp("", "vestri-plugin-entry-*")
		if err != nil {
			return err
		}
		entryReader, err := entry.Open()
		if err != nil {
			_ = tempFile.Close()
			_ = os.Remove(tempFile.Name())
			return err
		}
		_, copyErr := io.Copy(tempFile, entryReader)
		closeEntryErr := entryReader.Close()
		if copyErr != nil || closeEntryErr != nil {
			_ = tempFile.Close()
			_ = os.Remove(tempFile.Name())
			if copyErr != nil {
				return copyErr
			}
			return closeEntryErr
		}
		for _, target := range targets {
			pluginPath, err := velocityBackendPluginPath(target.server)
			if err != nil {
				_ = tempFile.Close()
				_ = os.Remove(tempFile.Name())
				return err
			}
			fullTargetPath := path.Join(pluginPath, relativePath)
			if err := s.streamGroupUploadToWorker(r, baseURL, apiKey, tempFile, fullTargetPath, path.Base(relativePath)); err != nil {
				_ = tempFile.Close()
				_ = os.Remove(tempFile.Name())
				return err
			}
		}
		name := tempFile.Name()
		_ = tempFile.Close()
		_ = os.Remove(name)
	}
	managedFileList := make([]string, 0, len(managedFiles))
	for relativePath := range managedFiles {
		managedFileList = append(managedFileList, relativePath)
	}
	sort.Strings(managedFileList)
	for _, target := range targets {
		previousFiles, err := s.readVelocityManagedPluginFiles(r.Context(), baseURL, apiKey, target.server)
		if err != nil {
			return err
		}
		for _, relativePath := range previousFiles {
			if _, stillManaged := managedFiles[relativePath]; stillManaged {
				continue
			}
			fullPath, err := resolveVelocityManagedPluginFile(target.server, relativePath)
			if err != nil {
				return err
			}
			status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{
				"path":      fullPath,
				"recursive": false,
			})
			if err != nil {
				return err
			}
			if status != http.StatusNotFound {
				if err := groupFileWorkerError(status, body, nil); err != nil {
					return err
				}
			}
		}
		if err := s.writeVelocityManagedPluginFiles(r.Context(), baseURL, apiKey, target.server, managedFileList); err != nil {
			return err
		}
	}
	return nil
}

func velocityStagingArchiveRelativePath(entryName, stagingPath string) (string, bool, error) {
	cleaned := path.Clean(strings.TrimLeft(strings.ReplaceAll(entryName, "\\", "/"), "/"))
	if cleaned == "." || cleaned == "" {
		return "", false, nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false, fmt.Errorf("unsafe plugin archive path %q", entryName)
	}
	prefixes := []string{
		path.Clean(strings.TrimLeft(stagingPath, "/")),
		path.Join(path.Base(velocityGroupStagingRelativePath), path.Base(stagingPath)),
		path.Clean(velocityGroupStagingRelativePath),
		path.Base(stagingPath),
		path.Base(velocityGroupStagingRelativePath),
	}
	for _, prefix := range prefixes {
		if prefix == "." || prefix == "" {
			continue
		}
		if cleaned == prefix {
			return "", false, nil
		}
		if strings.HasPrefix(cleaned, prefix+"/") {
			cleaned = strings.TrimPrefix(cleaned, prefix+"/")
			break
		}
	}
	cleaned = path.Clean(cleaned)
	if cleaned == "." || cleaned == "" {
		return "", false, nil
	}
	if path.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false, fmt.Errorf("unsafe plugin archive path %q", entryName)
	}
	return cleaned, true, nil
}

type velocityManagedPluginFilesManifest struct {
	Files []string `json:"files"`
}

func velocityManagedPluginManifestPath(server auth.GameServer) string {
	return path.Join(server.RootPath, "data", velocityManagedPluginManifestName)
}

func resolveVelocityManagedPluginFile(server auth.GameServer, relativePath string) (string, error) {
	cleaned := path.Clean(strings.TrimLeft(strings.ReplaceAll(strings.TrimSpace(relativePath), "\\", "/"), "/"))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || path.IsAbs(cleaned) {
		return "", fmt.Errorf("unsafe managed plugin path %q", relativePath)
	}
	return resolveServerScopedPath(server.RootPath, path.Join("data", "plugins", cleaned), false)
}

func (s *Server) readVelocityManagedPluginFiles(ctx context.Context, baseURL *url.URL, apiKey string, server auth.GameServer) ([]string, error) {
	query := url.Values{"path": {velocityManagedPluginManifestPath(server)}}.Encode()
	status, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodGet, "/fs/read?"+query, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("failed to read managed plugin manifest (%d): %s", status, strings.TrimSpace(string(body)))
	}
	var manifest velocityManagedPluginFilesManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("invalid managed plugin manifest: %w", err)
	}
	for _, relativePath := range manifest.Files {
		if _, err := resolveVelocityManagedPluginFile(server, relativePath); err != nil {
			return nil, err
		}
	}
	return manifest.Files, nil
}

func (s *Server) writeVelocityManagedPluginFiles(ctx context.Context, baseURL *url.URL, apiKey string, server auth.GameServer, files []string) error {
	content, err := json.Marshal(velocityManagedPluginFilesManifest{Files: files})
	if err != nil {
		return err
	}
	status, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/write", map[string]string{
		"path":    velocityManagedPluginManifestPath(server),
		"content": string(content),
	})
	return groupFileWorkerError(status, body, err)
}

func ensureWorkerDirectory(ctx context.Context, s *Server, baseURL *url.URL, apiKey, targetPath string) error {
	status, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/mkdir", map[string]interface{}{
		"path":      targetPath,
		"exclusive": false,
	})
	if err != nil {
		return err
	}
	if status == http.StatusConflict || status >= 200 && status < 300 {
		return nil
	}
	return fmt.Errorf("worker /fs/mkdir failed (%d): %s", status, strings.TrimSpace(string(body)))
}

func (s *Server) streamGroupUploadToWorker(r *http.Request, baseURL *url.URL, apiKey string, upload *os.File, fullPath, uploadName string) error {
	if _, err := upload.Seek(0, io.SeekStart); err != nil {
		return err
	}
	pipeReader, pipeWriter := io.Pipe()
	formWriter := multipart.NewWriter(pipeWriter)
	writeErrCh := make(chan error, 1)
	go func() {
		writeErrCh <- streamUploadMultipartToWorker(formWriter, pipeWriter, upload, fullPath, uploadName)
	}()
	resp, err := s.callWorkerStream(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/upload", "", formWriter.FormDataContentType(), pipeReader)
	if err != nil {
		_ = pipeWriter.CloseWithError(err)
		<-writeErrCh
		return err
	}
	defer resp.Body.Close()
	writeErr := <-writeErrCh
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("worker returned %d: %s", resp.StatusCode, readWorkerErrorText(resp.Body))
	}
	return writeErr
}

func groupFileWorkerError(status int, body []byte, err error) error {
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("worker returned %d: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

func writeWorkerJSONResult(w http.ResponseWriter, status int, body []byte, err error) {
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if status < 200 || status >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
