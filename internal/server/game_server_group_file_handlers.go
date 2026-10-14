package server

import (
	"context"
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

type applyVelocityGroupFilesRequest struct {
	ServerRefs []string `json:"serverRefs"`
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

func (s *Server) handleListVelocityGroupFiles(w http.ResponseWriter, r *http.Request) {
	proxy, _, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	fullPath, err := resolveServerScopedPath(path.Join(proxy.RootPath, velocityGroupStagingRelativePath), r.URL.Query().Get("path"), true)
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
	fullPath, err := resolveServerScopedPath(path.Join(proxy.RootPath, velocityGroupStagingRelativePath), r.URL.Query().Get("path"), false)
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
	fullPath, err := resolveServerScopedPath(path.Join(proxy.RootPath, velocityGroupStagingRelativePath), req.Path, false)
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
	fullPath, err := resolveServerScopedPath(path.Join(proxy.RootPath, velocityGroupStagingRelativePath), req.Path, false)
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
	source, err := resolveServerScopedPath(path.Join(proxy.RootPath, velocityGroupStagingRelativePath), req.Source, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dest, err := resolveServerScopedPath(path.Join(proxy.RootPath, velocityGroupStagingRelativePath), req.Dest, true)
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
	fullPath, err := resolveServerScopedPath(path.Join(proxy.RootPath, velocityGroupStagingRelativePath), r.URL.Query().Get("path"), false)
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
	fullPath, err := resolveServerScopedPath(path.Join(proxy.RootPath, velocityGroupStagingRelativePath), rawPath, false)
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
	stagingPath, err := resolveServerScopedPath(proxy.RootPath, velocityGroupStagingRelativePath, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Velocity plugin staging path is invalid")
		return
	}
	archive := buildTempArchiveTarget(proxy.RootPath, "plugin-staging")
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
	defer archiveResp.Body.Close()
	if archiveResp.StatusCode < 200 || archiveResp.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "Failed to read plugin staging archive")
		return
	}
	archiveFile, err := os.CreateTemp("", "vestri-plugin-staging-*.zip")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create temporary plugin archive")
		return
	}
	archiveFileName := archiveFile.Name()
	defer func() {
		_ = archiveFile.Close()
		_ = os.Remove(archiveFileName)
	}()
	if _, err := io.Copy(archiveFile, archiveResp.Body); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to receive plugin staging archive")
		return
	}

	for _, target := range targets {
		pluginPath, err := velocityBackendPluginPath(target.server)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.applyPluginArchiveToBackend(r, baseURL, apiKey, archiveFile, target.server, pluginPath); err != nil {
			writeError(w, http.StatusBadGateway, "Plugin apply failed; earlier selected backends may already have been updated")
			return
		}
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

func (s *Server) applyPluginArchiveToBackend(r *http.Request, baseURL *url.URL, apiKey string, archiveFile *os.File, server auth.GameServer, pluginPath string) error {
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/mkdir", map[string]interface{}{
		"path":      pluginPath,
		"exclusive": false,
	})
	if err := groupFileWorkerError(status, body, err); err != nil && status != http.StatusConflict {
		return err
	}
	targetArchive := buildTempArchiveTarget(server.RootPath, "group-plugins")
	defer s.cleanupWorkerArchive(baseURL, apiKey, targetArchive)
	if err := s.streamGroupUploadToWorker(r, baseURL, apiKey, archiveFile, targetArchive.ArchivePath, "plugins.zip"); err != nil {
		return err
	}
	status, body, err = s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/unzip", map[string]string{
		"source": targetArchive.ArchivePath,
		"dest":   pluginPath,
	})
	return groupFileWorkerError(status, body, err)
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