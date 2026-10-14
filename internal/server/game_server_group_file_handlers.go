package server

import (
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

func (s *Server) loadVelocityGroupFileTargets(w http.ResponseWriter, r *http.Request) (*auth.WorkerNode, []velocityGroupFileTarget, *url.URL, string, bool) {
	sess, node, proxy, proxyRole, ok := s.loadNodeAndGameServerForRequest(w, r)
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
		access, accessErr := s.Users.FindAccessibleGameServerByRefForNode(r.Context(), sess.UserID, node, servers[i].ID)
		if accessErr != nil {
			writeError(w, http.StatusInternalServerError, "Failed to validate Velocity backend permissions")
			return nil, nil, nil, "", false
		}
		if access == nil || !canManageGameServerFiles(access.AccessRole) {
			writeError(w, http.StatusForbidden, "Group file access requires file management permission on every backend")
			return nil, nil, nil, "", false
		}
		targets = append(targets, velocityGroupFileTarget{server: access.GameServer})
	}
	if len(targets) == 0 {
		writeError(w, http.StatusNotFound, "This Velocity group has no backend servers")
		return nil, nil, nil, "", false
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].server.Slug < targets[j].server.Slug
	})
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return nil, nil, nil, "", false
	}
	return node, targets, baseURL, apiKey, true
}

func (s *Server) handleListVelocityGroupFiles(w http.ResponseWriter, r *http.Request) {
	_, targets, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	fullPath, err := resolveServerScopedPath(targets[0].server.RootPath, r.URL.Query().Get("path"), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query := url.Values{"path": {fullPath}}.Encode()
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/list?"+query, nil)
	writeWorkerJSONResult(w, status, body, err)
}

func (s *Server) handleReadVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	_, targets, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	fullPath, err := resolveServerScopedPath(targets[0].server.RootPath, r.URL.Query().Get("path"), false)
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
	_, targets, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	var req writeGameServerFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	for _, target := range targets {
		fullPath, err := resolveServerScopedPath(target.server.RootPath, req.Path, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/write", map[string]string{"path": fullPath, "content": req.Content})
		if err := groupFileWorkerError(status, body, err); err != nil {
			writeError(w, http.StatusBadGateway, "Group file write failed; some backends may already have changed")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	_, targets, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	var req deleteGameServerFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	for _, target := range targets {
		fullPath, err := resolveServerScopedPath(target.server.RootPath, req.Path, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{"path": fullPath, "recursive": req.Recursive})
		if err := groupFileWorkerError(status, body, err); err != nil {
			writeError(w, http.StatusBadGateway, "Group file deletion failed; some backends may already have changed")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleUnzipVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	_, targets, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	var req unzipGameServerFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	for _, target := range targets {
		source, err := resolveServerScopedPath(target.server.RootPath, req.Source, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		dest, err := resolveServerScopedPath(target.server.RootPath, req.Dest, true)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/unzip", map[string]string{"source": source, "dest": dest})
		if err := groupFileWorkerError(status, body, err); err != nil {
			writeError(w, http.StatusBadGateway, "Group archive extraction failed; some backends may already have changed")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDownloadVelocityGroupFile(w http.ResponseWriter, r *http.Request) {
	_, targets, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
	if !ok {
		return
	}
	fullPath, err := resolveServerScopedPath(targets[0].server.RootPath, r.URL.Query().Get("path"), false)
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
	tempArchive := buildTempArchiveTarget(targets[0].server.RootPath, name)
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
	_, targets, baseURL, apiKey, ok := s.loadVelocityGroupFileTargets(w, r)
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
	for _, target := range targets {
		fullPath, err := resolveServerScopedPath(target.server.RootPath, rawPath, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.streamGroupUploadToWorker(r, baseURL, apiKey, uploadTmp, fullPath, uploadName); err != nil {
			writeError(w, http.StatusBadGateway, "Group upload failed; some backends may already have changed")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
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