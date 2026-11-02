package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

const maxDecompressedServerLogBytes int64 = 32 << 20

var errServerLogTooLarge = errors.New("decompressed server log exceeds the maximum size")

type gameServerLogFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func (s *Server) handleListGameServerLogFiles(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canReadGameServerConsole(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for console logs")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	logsPath := path.Join(server.RootPath, "data", "logs")
	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/list?path="+url.QueryEscape(logsPath), nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if statusCode == http.StatusNotFound {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), statusCode)
		return
	}

	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Size int64  `json:"size"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		writeError(w, http.StatusBadGateway, "Invalid worker directory response")
		return
	}
	files := make([]gameServerLogFile, 0, len(entries))
	for _, entry := range entries {
		if entry.Type == "file" && isGameServerLogFileName(entry.Name) {
			files = append(files, gameServerLogFile{Name: entry.Name, Size: entry.Size})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(files); err != nil {
		return
	}
}

func (s *Server) handleReadGameServerLogFile(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canReadGameServerConsole(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for console logs")
		return
	}

	name := r.URL.Query().Get("name")
	if !isGameServerLogFileName(name) {
		writeError(w, http.StatusBadRequest, "Invalid log file name")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	filePath := path.Join(server.RootPath, "data", "logs", name)
	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/read?path="+url.QueryEscape(filePath), nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), statusCode)
		return
	}
	if strings.HasSuffix(strings.ToLower(name), ".log.gz") {
		body, err = decompressServerLog(body)
		if err != nil {
			if errors.Is(err, errServerLogTooLarge) {
				writeError(w, http.StatusRequestEntityTooLarge, "Decompressed log exceeds the maximum size")
				return
			}
			writeError(w, http.StatusUnprocessableEntity, "Invalid compressed log file")
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func isGameServerLogFileName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) || path.Base(name) != name {
		return false
	}
	lowerName := strings.ToLower(name)
	return strings.HasSuffix(lowerName, ".log") || strings.HasSuffix(lowerName, ".log.gz")
}

func isCompressedServerLogPath(serverRoot, filePath string) bool {
	logsRoot := path.Join(serverRoot, "data", "logs")
	return path.Dir(filePath) == logsRoot && strings.HasSuffix(strings.ToLower(filePath), ".log.gz")
}

func decompressServerLog(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(io.LimitReader(reader, maxDecompressedServerLogBytes+1))
	if int64(len(decompressed)) > maxDecompressedServerLogBytes {
		return nil, errServerLogTooLarge
	}
	if err != nil {
		return nil, err
	}
	return decompressed, nil
}
