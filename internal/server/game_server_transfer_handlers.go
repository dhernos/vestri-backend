package server

import (
	"net/http"
	"path"
	"strings"
)

func (s *Server) handleTransferGameServerEntry(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file transfer")
		return
	}
	var req struct {
		Source    string `json:"source"`
		Dest      string `json:"dest"`
		Operation string `json:"operation"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Operation != "copy" && req.Operation != "move" && req.Operation != "rename" {
		writeError(w, http.StatusBadRequest, "Invalid file operation")
		return
	}
	source, err := resolveServerScopedPath(server.RootPath, req.Source, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dest, err := resolveServerScopedPath(server.RootPath, req.Dest, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if source == dest || strings.HasPrefix(dest, source+"/") || (req.Operation == "rename" && path.Dir(source) != path.Dir(dest)) {
		writeError(w, http.StatusBadRequest, "Invalid destination")
		return
	}
	if groupFilesScoped(r.Context()) && (path.Clean(req.Source) == stagingPluginsDirName || !strings.HasPrefix(path.Clean(req.Dest), stagingPluginsDirName+"/")) {
		writeError(w, http.StatusBadRequest, "Group file transfers must stay inside the plugins folder")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/transfer", map[string]string{
		"source":    source,
		"dest":      dest,
		"operation": req.Operation,
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
