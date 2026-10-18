package server

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type gameServerBackupPolicy struct {
	Enabled         bool   `json:"enabled"`
	EveryDays       int    `json:"everyDays"`
	Time            string `json:"time"`
	KeepDailyDays   int    `json:"keepDailyDays"`
	KeepWeeklyWeeks int    `json:"keepWeeklyWeeks"`
}

const maxGameServerBackupUploadBytes = 1 << 30

func (s *Server) handleGameServerBackups(w http.ResponseWriter, r *http.Request) {
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can manage backups")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	query := url.Values{"root": {gameServer.RootPath}}.Encode()
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/backup?"+query, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if status < 200 || status >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) handleSaveGameServerBackupSettings(w http.ResponseWriter, r *http.Request) {
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can manage backups")
		return
	}
	var req gameServerBackupPolicy
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid backup settings")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/backup/settings", map[string]interface{}{
		"root":   gameServer.RootPath,
		"policy": req,
	})
	s.writeBackupWorkerResponse(w, status, body, err)
}

func (s *Server) handleCreateGameServerBackup(w http.ResponseWriter, r *http.Request) {
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can create backups")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/backup/create", map[string]string{"root": gameServer.RootPath})
	s.writeBackupWorkerResponse(w, status, body, err)
}

func (s *Server) handleDeleteGameServerBackup(w http.ResponseWriter, r *http.Request) {
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can delete backups")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "Backup name is required")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/backup/delete", map[string]string{
		"root": gameServer.RootPath,
		"name": req.Name,
	})
	s.writeBackupWorkerResponse(w, status, body, err)
}

func (s *Server) handleRestoreGameServerBackup(w http.ResponseWriter, r *http.Request) {
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can restore backups")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "Backup name is required")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	output, err := s.workerStackAction(r.Context(), baseURL, apiKey, "down", gameServer.StackName)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"message": "Could not stop server before restore", "output": output})
		return
	}
	status, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/backup/restore", map[string]string{
		"root": gameServer.RootPath,
		"name": req.Name,
	})
	s.writeBackupWorkerResponse(w, status, body, err)
}

func (s *Server) handleDownloadGameServerBackup(w http.ResponseWriter, r *http.Request) {
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can download backups")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "Backup name is required")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	query := url.Values{"root": {gameServer.RootPath}, "name": {name}}.Encode()
	resp, err := s.callWorkerStream(r.Context(), baseURL, apiKey, http.MethodGet, "/backup/download", query, "", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := readWorkerErrorText(resp.Body)
		if message == "" {
			message = "Worker request failed"
		}
		http.Error(w, message, resp.StatusCode)
		return
	}
	copyHeaders(w.Header(), resp.Header, []string{"Content-Type", "Content-Disposition", "Content-Length"})
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) handleUploadGameServerBackup(w http.ResponseWriter, r *http.Request) {
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can upload backups")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxGameServerBackupUploadBytes+(1<<20))
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid multipart form")
		return
	}
	var upload *os.File
	var uploadName string
	defer func() {
		if upload != nil {
			name := upload.Name()
			_ = upload.Close()
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
		if part.FormName() != "file" || upload != nil {
			_ = part.Close()
			continue
		}
		upload, err = os.CreateTemp("", "vestri-backup-upload-*")
		if err != nil {
			_ = part.Close()
			writeError(w, http.StatusInternalServerError, "Failed to prepare uploaded backup")
			return
		}
		uploadBytes, copyErr := io.Copy(upload, io.LimitReader(part, maxGameServerBackupUploadBytes+1))
		if copyErr != nil {
			_ = part.Close()
			writeError(w, http.StatusBadGateway, "Failed to read uploaded backup")
			return
		}
		if uploadBytes > maxGameServerBackupUploadBytes {
			_ = part.Close()
			writeError(w, http.StatusRequestEntityTooLarge, "Backup archive exceeds the 1 GiB upload limit")
			return
		}
		_ = part.Close()
		uploadName = strings.TrimSpace(part.FileName())
		if uploadName == "" {
			uploadName = "backup.zip"
		}
	}
	if upload == nil {
		writeError(w, http.StatusBadRequest, "Backup file is required")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	pipeReader, pipeWriter := io.Pipe()
	formWriter := multipart.NewWriter(pipeWriter)
	writeErrCh := make(chan error, 1)
	go func() {
		writeErrCh <- streamUploadMultipartToWorker(formWriter, pipeWriter, upload, gameServer.RootPath, uploadName)
	}()
	resp, err := s.callWorkerStream(r.Context(), baseURL, apiKey, http.MethodPost, "/backup/upload", "", formWriter.FormDataContentType(), pipeReader)
	if err != nil {
		_ = pipeWriter.CloseWithError(err)
		<-writeErrCh
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()
	writeErr := <-writeErrCh
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := readWorkerErrorText(resp.Body)
		if message == "" {
			message = "Worker request failed"
		}
		http.Error(w, message, resp.StatusCode)
		return
	}
	if writeErr != nil {
		writeError(w, http.StatusBadGateway, "Failed to stream backup to worker")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) writeBackupWorkerResponse(w http.ResponseWriter, status int, body []byte, err error) {
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if status < 200 || status >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
