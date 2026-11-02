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

	"yourapp/internal/auth"
)

const maxDecompressedServerLogBytes int64 = 32 << 20

var errServerLogTooLarge = errors.New("decompressed server log exceeds the maximum size")

type gameServerLogFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

var defaultGameServerLogLocations = []gameServerTemplateLogLocation{
	{Directory: "data/logs", Patterns: []string{"*.log", "*.log.gz"}},
}

// gameServerLogLocations resolves log locations from the server's template; servers
// whose template no longer exists keep the historical Minecraft default.
func gameServerLogLocations(server *auth.GameServer) []gameServerTemplateLogLocation {
	if server == nil {
		return nil
	}
	tpl, err := gameServerTemplateByID(strings.TrimSpace(server.TemplateID))
	if err != nil || tpl == nil {
		return defaultGameServerLogLocations
	}
	return tpl.LogLocations
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

	files := make([]gameServerLogFile, 0)
	for _, location := range gameServerLogLocations(server) {
		logsPath := path.Join(server.RootPath, location.Directory)
		statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/list?path="+url.QueryEscape(logsPath), nil)
		if err != nil {
			writeError(w, http.StatusBadGateway, "Worker request failed")
			return
		}
		if statusCode == http.StatusNotFound {
			continue
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
		for _, entry := range entries {
			if entry.Type == "file" && logLocationMatches(location, entry.Name) {
				files = append(files, gameServerLogFile{
					Name: entry.Name,
					Path: path.Join(location.Directory, entry.Name),
					Size: entry.Size,
				})
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
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

	relativePath, ok := resolveGameServerLogPath(gameServerLogLocations(server), r.URL.Query().Get("path"))
	if !ok {
		writeError(w, http.StatusBadRequest, "Invalid log file path")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	filePath := path.Join(server.RootPath, relativePath)
	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/read?path="+url.QueryEscape(filePath), nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), statusCode)
		return
	}
	if strings.HasSuffix(strings.ToLower(relativePath), ".gz") {
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
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\\`) && path.Base(name) == name
}

func logLocationMatches(location gameServerTemplateLogLocation, name string) bool {
	if !isGameServerLogFileName(name) {
		return false
	}
	lowerName := strings.ToLower(name)
	for _, pattern := range location.Patterns {
		if matched, err := path.Match(strings.ToLower(pattern), lowerName); err == nil && matched {
			return true
		}
	}
	return false
}

// resolveGameServerLogPath validates a server-root-relative log path against the configured locations.
func resolveGameServerLogPath(locations []gameServerTemplateLogLocation, rawPath string) (string, bool) {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" || strings.Contains(rawPath, `\`) {
		return "", false
	}
	cleaned := path.Clean(strings.TrimPrefix(rawPath, "/"))
	directory, name := path.Split(cleaned)
	directory = strings.TrimSuffix(directory, "/")
	for _, location := range locations {
		if location.Directory == directory && logLocationMatches(location, name) {
			return cleaned, true
		}
	}
	return "", false
}

func isCompressedServerLogPath(locations []gameServerTemplateLogLocation, serverRoot, filePath string) bool {
	prefix := strings.Trim(serverRoot, "/") + "/"
	if !strings.HasPrefix(filePath, prefix) || !strings.HasSuffix(strings.ToLower(filePath), ".gz") {
		return false
	}
	_, ok := resolveGameServerLogPath(locations, strings.TrimPrefix(filePath, prefix))
	return ok
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
