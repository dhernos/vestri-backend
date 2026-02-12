package server

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

type writeGameServerFileRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func (s *Server) handleListGameServerFiles(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file listing")
		return
	}

	fullPath, err := resolveServerScopedPath(server.RootPath, r.URL.Query().Get("path"), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/list?path="+url.QueryEscape(fullPath), nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), statusCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleReadGameServerFile(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file reading")
		return
	}

	fullPath, err := resolveServerScopedPath(server.RootPath, r.URL.Query().Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/read?path="+url.QueryEscape(fullPath), nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), statusCode)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleWriteGameServerFile(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file writing")
		return
	}

	var req writeGameServerFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	fullPath, err := resolveServerScopedPath(server.RootPath, req.Path, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/write", map[string]string{
		"path":    fullPath,
		"content": req.Content,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), statusCode)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func resolveServerScopedPath(rootPath, rawPath string, allowRoot bool) (string, error) {
	cleanRoot := strings.Trim(strings.TrimSpace(strings.ReplaceAll(rootPath, "\\", "/")), "/")
	if cleanRoot == "" {
		return "", fmt.Errorf("server root path is invalid")
	}

	base := path.Clean("/" + cleanRoot)
	raw := strings.TrimSpace(strings.ReplaceAll(rawPath, "\\", "/"))
	if raw == "" || raw == "." {
		if allowRoot {
			return strings.TrimPrefix(base, "/"), nil
		}
		return "", fmt.Errorf("path is required")
	}

	raw = strings.TrimPrefix(raw, "/")
	if raw == cleanRoot {
		raw = ""
	} else if strings.HasPrefix(raw, cleanRoot+"/") {
		raw = strings.TrimPrefix(raw, cleanRoot+"/")
	}

	joined := path.Clean(path.Join(base, raw))
	if joined != base && !strings.HasPrefix(joined, base+"/") {
		return "", fmt.Errorf("path escape detected")
	}
	if !allowRoot && joined == base {
		return "", fmt.Errorf("path is required")
	}

	return strings.TrimPrefix(joined, "/"), nil
}
