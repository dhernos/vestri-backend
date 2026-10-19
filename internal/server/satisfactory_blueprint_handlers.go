package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"

	"yourapp/internal/auth"

	"github.com/go-chi/chi/v5"
)

const (
	satisfactoryBlueprintTargetPath  = "data/saved/blueprints"
	satisfactoryServerSavePath       = "data/saved/server"
	maxSatisfactoryBlueprintBytes    = 64 << 20
)

func satisfactoryBlueprintLibraryPath(nodeID string) string {
	return path.Join("satisfactory-blueprints", nodeID)
}

var (
	satisfactoryBlueprintIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	satisfactoryCalculatorIDPattern = regexp.MustCompile(`^/en/blueprints/index/details/id/([0-9]+)(?:/|$)`)
	satisfactoryCalculatorDirectDownloadPattern = regexp.MustCompile(`^/en/blueprints/index/download(?:-cfg)?/id/([0-9]+)(?:/|$)`)
	satisfactoryCalculatorDownloadPattern = regexp.MustCompile(`href=["'](?:https://(?:www\.)?satisfactory-calculator\.com)?(/en/blueprints/index/download(-cfg)?/id/([0-9]+)(?:/[^"']*)?)["']`)
	satisfactoryAutosaveNamePattern = regexp.MustCompile(`(?i)^(.+)_autosave_[0-9]+\.sav$`)
)

type satisfactoryBlueprintFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type satisfactoryWorkerEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

func newSatisfactoryBlueprintHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 || !isAllowedSatisfactoryBlueprintURL(req.URL) {
				return http.ErrUseLastResponse
			}
			// The calculator redirects to URLs with raw spaces in the query, which Go would send unescaped.
			req.URL.RawQuery = strings.ReplaceAll(req.URL.RawQuery, " ", "%20")
			return nil
		},
	}
}

func (s *Server) loadSatisfactoryBlueprintNodeForRequest(w http.ResponseWriter, r *http.Request) (*auth.WorkerNode, bool) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return nil, false
	}
	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	if nodeRef == "" {
		writeError(w, http.StatusBadRequest, "nodeRef is required")
		return nil, false
	}
	node, err := s.Users.FindAccessibleWorkerNodeByRef(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node")
		return nil, false
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return nil, false
	}
	if !canManageNodeBlueprints(node.AccessRole) {
		writeError(w, http.StatusForbidden, "Node owner or admin permission is required to manage shared blueprints")
		return nil, false
	}
	return node, true
}

func (s *Server) handleListSatisfactoryBlueprintLibrary(w http.ResponseWriter, r *http.Request) {
	node, ok := s.loadSatisfactoryBlueprintNodeForRequest(w, r)
	if !ok {
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	if err := s.ensureSatisfactoryBlueprintDirectory(r.Context(), baseURL, apiKey, node.ID); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to prepare shared blueprint folder")
		return
	}
	files, err := s.listSatisfactoryBlueprintFiles(r.Context(), baseURL, apiKey, satisfactoryBlueprintLibraryPath(node.ID))
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to list shared blueprints")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"blueprints": files})
}

func (s *Server) handleListSatisfactoryBlueprints(w http.ResponseWriter, r *http.Request) {
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canViewGameServer(role) {
		writeError(w, http.StatusForbidden, "Server permission denied for blueprint listing")
		return
	}
	if !isSatisfactoryBlueprintServer(gameServer.TemplateID) {
		writeError(w, http.StatusBadRequest, "Blueprint management is only available for Satisfactory servers")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	if err := s.ensureSatisfactoryBlueprintDirectory(r.Context(), baseURL, apiKey, node.ID); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to prepare shared blueprint folder")
		return
	}
	available, err := s.listSatisfactoryBlueprintFiles(r.Context(), baseURL, apiKey, satisfactoryBlueprintLibraryPath(node.ID))
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to list shared blueprints")
		return
	}
	serverReady, err := s.satisfactoryServerHasCreatedSession(r.Context(), baseURL, apiKey, gameServer)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to check whether a Satisfactory game session has been created")
		return
	}
	installed := []satisfactoryBlueprintFile{}
	if serverReady {
		installedDir, resolved, resolveErr := s.satisfactoryBlueprintServerDirectory(r.Context(), baseURL, apiKey, gameServer)
		if resolveErr != nil {
			writeError(w, http.StatusBadGateway, "Failed to resolve the active Satisfactory game session")
			return
		}
		serverReady = resolved
		if serverReady {
			installed, err = s.listSatisfactoryBlueprintFiles(r.Context(), baseURL, apiKey, installedDir)
			if err != nil {
				writeError(w, http.StatusBadGateway, "Failed to list installed blueprints")
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"available": available,
		"installed": installed,
		"serverReady": serverReady,
	})
}

func (s *Server) handleDownloadSatisfactoryBlueprint(w http.ResponseWriter, r *http.Request) {
	node, ok := s.loadSatisfactoryBlueprintNodeForRequest(w, r)
	if !ok {
		return
	}
	name, ok := safeSatisfactoryBlueprintName(r.URL.Query().Get("name"))
	if !ok {
		writeError(w, http.StatusBadRequest, "Invalid blueprint filename")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	resp, err := s.callWorkerStream(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/download", "path="+url.QueryEscape(path.Join(satisfactoryBlueprintLibraryPath(node.ID), name)), "", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, readWorkerErrorText(resp.Body), resp.StatusCode)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) handleUploadSatisfactoryBlueprint(w http.ResponseWriter, r *http.Request) {
	node, ok := s.loadSatisfactoryBlueprintNodeForRequest(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSatisfactoryBlueprintBytes+(1<<20))
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid multipart form")
		return
	}
	var upload *os.File
	var filename string
	defer func() {
		if upload != nil {
			name := upload.Name()
			_ = upload.Close()
			_ = os.Remove(name)
		}
	}()
	for {
		part, partErr := reader.NextPart()
		if partErr == io.EOF {
			break
		}
		if partErr != nil {
			writeError(w, http.StatusBadRequest, "Invalid multipart form")
			return
		}
		if part.FormName() != "file" {
			_ = part.Close()
			continue
		}
		if upload != nil {
			_ = part.Close()
			writeError(w, http.StatusBadRequest, "Only one blueprint upload is supported")
			return
		}
		filename, ok = safeSatisfactoryBlueprintName(part.FileName())
		if !ok {
			_ = part.Close()
			writeError(w, http.StatusBadRequest, "Only .sbp and .sbpcfg files can be uploaded")
			return
		}
		upload, err = os.CreateTemp("", "vestri-blueprint-upload-*")
		if err != nil {
			_ = part.Close()
			writeError(w, http.StatusInternalServerError, "Failed to stage blueprint upload")
			return
		}
		limited := &io.LimitedReader{R: part, N: maxSatisfactoryBlueprintBytes + 1}
		written, copyErr := io.Copy(upload, limited)
		_ = part.Close()
		if copyErr != nil || written > maxSatisfactoryBlueprintBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "Blueprint exceeds the 64 MiB limit")
			return
		}
	}
	if upload == nil {
		writeError(w, http.StatusBadRequest, "Blueprint file is required")
		return
	}
	if err := s.uploadSatisfactoryBlueprintToWorker(r.Context(), node, upload, filename); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to upload blueprint to worker")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleImportSatisfactoryBlueprint(w http.ResponseWriter, r *http.Request) {
	node, ok := s.loadSatisfactoryBlueprintNodeForRequest(w, r)
	if !ok {
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	blueprintClient := newSatisfactoryBlueprintHTTPClient()
	downloadURL, filename, err := satisfactoryBlueprintDownloadForPage(r.Context(), req.URL, blueprintClient)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	referer := ""
	if parsed, parseErr := url.Parse(strings.TrimSpace(req.URL)); parseErr == nil && isAllowedSatisfactoryBlueprintURL(parsed) {
		referer = parsed.String()
	}

	sources := []satisfactoryBlueprintSource{{url: downloadURL, filename: filename}}
	companionURL, companionName, hasCompanion := satisfactoryBlueprintCompanion(downloadURL, filename)
	if hasCompanion {
		sources = append(sources, satisfactoryBlueprintSource{url: companionURL, filename: companionName, optional: !isSatisfactoryBlueprintPageSource(req.URL)})
	}
	// Blueprint (.sbp) first, then its config (.sbpcfg).
	if strings.EqualFold(path.Ext(filename), ".sbpcfg") && hasCompanion {
		sources[0], sources[1] = sources[1], sources[0]
	}

	for _, source := range sources {
		status, message := s.importSatisfactoryBlueprintFile(r.Context(), blueprintClient, node, source, referer)
		if message == "" {
			continue
		}
		// A bare CDN file link has no guaranteed companion, so that one is best-effort.
		if source.optional {
			continue
		}
		writeError(w, status, message)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

type satisfactoryBlueprintSource struct {
	url      *url.URL
	filename string
	optional bool
}

// isSatisfactoryBlueprintPageSource reports whether the input is a detail page rather than a direct file link.
func isSatisfactoryBlueprintPageSource(raw string) bool {
	page, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	switch strings.ToLower(page.Hostname()) {
	case "static.satisfactory-calculator.com":
		return false
	}
	return true
}

// satisfactoryBlueprintCompanion returns the config URL for a blueprint file, or the blueprint URL for a config file.
func satisfactoryBlueprintCompanion(source *url.URL, filename string) (*url.URL, string, bool) {
	companion := *source
	isConfig := strings.EqualFold(path.Ext(filename), ".sbpcfg")
	companionName := strings.TrimSuffix(filename, path.Ext(filename)) + ".sbpcfg"
	if isConfig {
		companionName = strings.TrimSuffix(filename, path.Ext(filename)) + ".sbp"
	}

	switch strings.ToLower(source.Hostname()) {
	case "satisfactoryblueprints.com", "www.satisfactoryblueprints.com":
		from, to := "/blueprint/download/", "/blueprint/config/"
		if isConfig {
			from, to = to, from
		}
		if !strings.HasPrefix(source.Path, from) {
			return nil, "", false
		}
		companion.Path = to + strings.TrimPrefix(source.Path, from)
		companion.RawPath = ""
	case "satisfactory-calculator.com", "www.satisfactory-calculator.com":
		from, to := "/index/download/id/", "/index/download-cfg/id/"
		if isConfig {
			from, to = to, from
		}
		if !strings.Contains(source.EscapedPath(), from) {
			return nil, "", false
		}
		companion.RawPath = strings.Replace(source.EscapedPath(), from, to, 1)
		companion.Path = strings.Replace(source.Path, from, to, 1)
	case "static.satisfactory-calculator.com":
		ext := ".sbpcfg"
		if isConfig {
			ext = ".sbp"
		}
		companion.Path = strings.TrimSuffix(source.Path, path.Ext(source.Path)) + ext
		companion.RawPath = ""
	default:
		return nil, "", false
	}
	if !isAllowedSatisfactoryBlueprintURL(&companion) {
		return nil, "", false
	}
	return &companion, companionName, true
}

// importSatisfactoryBlueprintFile downloads one file and stores it in the node library; a non-empty message means failure.
func (s *Server) importSatisfactoryBlueprintFile(
	ctx context.Context,
	client *http.Client,
	node *auth.WorkerNode,
	source satisfactoryBlueprintSource,
	referer string,
) (int, string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url.String(), nil)
	if err != nil {
		return http.StatusBadRequest, "Invalid blueprint source"
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	request.Header.Set("Accept", "application/octet-stream, */*")
	if referer != "" {
		request.Header.Set("Referer", referer)
	}
	response, err := client.Do(request)
	if err != nil {
		return http.StatusBadGateway, "Failed to download blueprint from the approved source"
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := fmt.Sprintf("The approved blueprint source returned HTTP %d", response.StatusCode)
		if detail := readWorkerErrorText(response.Body); detail != "" {
			message += ": " + detail
		}
		return http.StatusBadGateway, message
	}
	filename := satisfactoryBlueprintResponseFilename(response, source.filename)
	if response.ContentLength > maxSatisfactoryBlueprintBytes {
		return http.StatusRequestEntityTooLarge, "Blueprint exceeds the 64 MiB limit"
	}
	temp, err := os.CreateTemp("", "vestri-blueprint-import-*")
	if err != nil {
		return http.StatusInternalServerError, "Failed to stage blueprint download"
	}
	defer func() {
		name := temp.Name()
		_ = temp.Close()
		_ = os.Remove(name)
	}()
	limited := &io.LimitedReader{R: response.Body, N: maxSatisfactoryBlueprintBytes + 1}
	written, err := io.Copy(temp, limited)
	if err != nil || written > maxSatisfactoryBlueprintBytes {
		return http.StatusRequestEntityTooLarge, "Blueprint exceeds the 64 MiB limit"
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		return http.StatusInternalServerError, "Failed to prepare blueprint download"
	}
	if err := s.uploadSatisfactoryBlueprintToWorker(ctx, node, temp, filename); err != nil {
		return http.StatusBadGateway, "Failed to save blueprint to worker"
	}
	return 0, ""
}

func (s *Server) handleInstallSatisfactoryBlueprint(w http.ResponseWriter, r *http.Request) {
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(role) {
		writeError(w, http.StatusForbidden, "Server permission denied for blueprint management")
		return
	}
	if !isSatisfactoryBlueprintServer(gameServer.TemplateID) {
		writeError(w, http.StatusBadRequest, "Blueprint management is only available for Satisfactory servers")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	name, ok := safeSatisfactoryBlueprintName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "Invalid blueprint filename")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	serverReady, err := s.satisfactoryServerHasCreatedSession(r.Context(), baseURL, apiKey, gameServer)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to check whether a Satisfactory game session has been created")
		return
	}
	if !serverReady {
		writeError(w, http.StatusConflict, "Create or load a Satisfactory game session in-game before installing blueprints")
		return
	}
	installedDir, resolved, err := s.satisfactoryBlueprintServerDirectory(r.Context(), baseURL, apiKey, gameServer)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to resolve the active Satisfactory game session")
		return
	}
	if !resolved {
		writeError(w, http.StatusConflict, "Create or load a Satisfactory game session and wait for its first autosave before installing blueprints")
		return
	}
	destination := path.Join(installedDir, name)
	installed, err := s.listSatisfactoryBlueprintFiles(r.Context(), baseURL, apiKey, installedDir)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to inspect installed blueprints")
		return
	}
	for _, file := range installed {
		if file.Name == name {
			writeJSON(w, http.StatusOK, map[string]string{"message": "Blueprint is already installed"})
			return
		}
	}
	statusCode, bodyBytes, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/copy", map[string]string{
		"source": path.Join(satisfactoryBlueprintLibraryPath(node.ID), name),
		"dest":   destination,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(bodyBytes)), statusCode)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteSatisfactoryBlueprint(w http.ResponseWriter, r *http.Request) {
	node, ok := s.loadSatisfactoryBlueprintNodeForRequest(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	name, ok := safeSatisfactoryBlueprintName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "Invalid blueprint filename")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{"path": path.Join(satisfactoryBlueprintLibraryPath(node.ID), name)})
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

func (s *Server) ensureSatisfactoryBlueprintDirectory(ctx context.Context, baseURL *url.URL, apiKey, nodeID string) error {
	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/mkdir", map[string]interface{}{
		"path":      satisfactoryBlueprintLibraryPath(nodeID),
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

func (s *Server) listSatisfactoryBlueprintFiles(ctx context.Context, baseURL *url.URL, apiKey, dir string) ([]satisfactoryBlueprintFile, error) {
	entries, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, dir)
	if err != nil {
		return nil, err
	}
	files := make([]satisfactoryBlueprintFile, 0, len(entries))
	for _, entry := range entries {
		name, ok := safeSatisfactoryBlueprintName(entry.Name)
		if entry.Type == "file" && ok {
			files = append(files, satisfactoryBlueprintFile{Name: name, Size: entry.Size})
		}
	}
	return files, nil
}

func (s *Server) listSatisfactoryWorkerEntries(ctx context.Context, baseURL *url.URL, apiKey, dir string) ([]satisfactoryWorkerEntry, error) {
	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodGet, "/fs/list?path="+url.QueryEscape(dir), nil)
	if err != nil {
		return nil, err
	}
	if statusCode == http.StatusNotFound && dir != "" {
		return []satisfactoryWorkerEntry{}, nil
	}
	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("worker /fs/list failed (%d): %s", statusCode, strings.TrimSpace(string(body)))
	}
	var entries []satisfactoryWorkerEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *Server) satisfactoryServerHasCreatedSession(ctx context.Context, baseURL *url.URL, apiKey string, gameServer *auth.GameServer) (bool, error) {
	saveDir := path.Join(gameServer.RootPath, satisfactoryServerSavePath)
	entries, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, saveDir)
	if err != nil {
		return false, err
	}
	return satisfactorySessionSaveExists(entries), nil
}

func satisfactorySessionSaveExists(entries []satisfactoryWorkerEntry) bool {
	for _, entry := range entries {
		if entry.Type == "file" && strings.EqualFold(path.Ext(entry.Name), ".sav") {
			return true
		}
	}
	return false
}

func (s *Server) satisfactoryBlueprintServerDirectory(ctx context.Context, baseURL *url.URL, apiKey string, gameServer *auth.GameServer) (string, bool, error) {
	saveEntries, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, path.Join(gameServer.RootPath, satisfactoryServerSavePath))
	if err != nil {
		return "", false, err
	}
	if !satisfactorySessionSaveExists(saveEntries) {
		return "", false, nil
	}

	sessionName, hasAutosaveSession := satisfactorySessionNameFromAutosaves(saveEntries)
	blueprintRoot := path.Join(gameServer.RootPath, satisfactoryBlueprintTargetPath)
	blueprintEntries, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, blueprintRoot)
	if err != nil {
		return "", false, err
	}
	blueprintSessionName, hasBlueprintSession := satisfactorySingleBlueprintSessionDirectory(blueprintEntries)

	if hasAutosaveSession {
		return path.Join(blueprintRoot, sessionName), true, nil
	}
	if hasBlueprintSession {
		return path.Join(blueprintRoot, blueprintSessionName), true, nil
	}
	return "", false, nil
}

func satisfactorySessionNameFromAutosaves(entries []satisfactoryWorkerEntry) (string, bool) {
	var sessionName string
	for _, entry := range entries {
		if entry.Type != "file" {
			continue
		}
		matches := satisfactoryAutosaveNamePattern.FindStringSubmatch(entry.Name)
		if len(matches) != 2 {
			continue
		}
		candidate := strings.TrimSpace(matches[1])
		if !safeSatisfactoryDirectoryName(candidate) {
			continue
		}
		if sessionName != "" && sessionName != candidate {
			return "", false
		}
		sessionName = candidate
	}
	return sessionName, sessionName != ""
}

func satisfactorySingleBlueprintSessionDirectory(entries []satisfactoryWorkerEntry) (string, bool) {
	var sessionName string
	for _, entry := range entries {
		candidate := strings.TrimSpace(entry.Name)
		if entry.Type != "dir" || !safeSatisfactoryDirectoryName(candidate) {
			continue
		}
		if sessionName != "" && sessionName != candidate {
			return "", false
		}
		sessionName = candidate
	}
	return sessionName, sessionName != ""
}

func safeSatisfactoryDirectoryName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func satisfactoryBlueprintFilename(contentDisposition, fallback string) string {
	name, ok := satisfactoryBlueprintFilenameFromDisposition(contentDisposition, path.Ext(fallback))
	if !ok {
		return fallback
	}
	return name
}

func satisfactoryBlueprintResponseFilename(response *http.Response, fallback string) string {
	for current := response; current != nil; {
		if name, ok := satisfactoryBlueprintFilenameFromDisposition(current.Header.Get("Content-Disposition"), path.Ext(fallback)); ok {
			return name
		}
		if current.Request == nil || current.Request.Response == nil {
			break
		}
		current = current.Request.Response
	}
	return fallback
}

func satisfactoryBlueprintFilenameFromDisposition(contentDisposition, expectedExtension string) (string, bool) {
	_, params, err := mime.ParseMediaType(contentDisposition)
	if err != nil {
		return "", false
	}
	name := strings.TrimSpace(params["filename"])
	if _, ok := safeSatisfactoryBlueprintName(name); !ok || !strings.EqualFold(path.Ext(name), expectedExtension) {
		return "", false
	}
	return name, true
}

func (s *Server) uploadSatisfactoryBlueprintToWorker(ctx context.Context, node *auth.WorkerNode, upload *os.File, filename string) error {
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		return err
	}
	pipeReader, pipeWriter := io.Pipe()
	formWriter := multipart.NewWriter(pipeWriter)
	writeErrCh := make(chan error, 1)
	if err := s.ensureSatisfactoryBlueprintDirectory(ctx, baseURL, apiKey, node.ID); err != nil {
		return err
	}
	targetPath := path.Join(satisfactoryBlueprintLibraryPath(node.ID), filename)
	go func() {
		writeErrCh <- streamUploadMultipartToWorker(formWriter, pipeWriter, upload, targetPath, filename)
	}()
	response, err := s.callWorkerStream(ctx, baseURL, apiKey, http.MethodPost, "/fs/upload", "", formWriter.FormDataContentType(), pipeReader)
	if err != nil {
		_ = pipeWriter.CloseWithError(err)
		<-writeErrCh
		return err
	}
	defer response.Body.Close()
	writeErr := <-writeErrCh
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("worker upload failed (%d): %s", response.StatusCode, readWorkerErrorText(response.Body))
	}
	return writeErr
}

func satisfactoryBlueprintDownloadForPage(ctx context.Context, raw string, client *http.Client) (*url.URL, string, error) {
	page, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !isAllowedSatisfactoryBlueprintURL(page) || page.Fragment != "" {
		return nil, "", fmt.Errorf("URL must be an HTTPS blueprint page from one of the approved sites")
	}
	host := strings.ToLower(page.Hostname())
	var download *url.URL
	var filename string
	switch host {
	case "satisfactoryblueprints.com", "www.satisfactoryblueprints.com":
		if page.Port() != "" {
			return nil, "", fmt.Errorf("URL must use the standard HTTPS port")
		}
		parts := strings.Split(strings.Trim(page.Path, "/"), "/")
		if len(parts) == 2 && parts[0] == "blueprint" && satisfactoryBlueprintIDPattern.MatchString(parts[1]) {
			download, _ = url.Parse("https://satisfactoryblueprints.com/blueprint/download/" + parts[1])
			filename = "blueprint-" + strings.ToLower(parts[1]) + ".sbp"
		} else if len(parts) == 3 && parts[0] == "blueprint" && (parts[1] == "download" || parts[1] == "config") && satisfactoryBlueprintIDPattern.MatchString(parts[2]) {
			ext := ".sbp"
			if parts[1] == "config" {
				ext = ".sbpcfg"
			}
			download, _ = url.Parse("https://satisfactoryblueprints.com/blueprint/" + parts[1] + "/" + parts[2])
			filename = "blueprint-" + strings.ToLower(parts[2]) + ext
		} else {
			return nil, "", fmt.Errorf("URL must identify a Satisfactory Blueprints detail or download page")
		}
	case "satisfactory-calculator.com", "www.satisfactory-calculator.com":
		if page.Port() != "" {
			return nil, "", fmt.Errorf("URL must use the standard HTTPS port")
		}
		if matches := satisfactoryCalculatorDirectDownloadPattern.FindStringSubmatch(page.Path); len(matches) == 2 {
			download = page
			ext := ".sbp"
			if strings.Contains(page.Path, "/download-cfg/") {
				ext = ".sbpcfg"
			}
			filename = "blueprint-" + matches[1] + ext
			break
		}
		matches := satisfactoryCalculatorIDPattern.FindStringSubmatch(page.Path)
		if len(matches) != 2 {
			return nil, "", fmt.Errorf("URL must identify a Satisfactory Calculator blueprint detail or download page")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, page.String(), nil)
		if err != nil {
			return nil, "", fmt.Errorf("invalid blueprint page URL")
		}
		request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
		response, err := client.Do(request)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read the approved blueprint page")
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, "", fmt.Errorf("approved blueprint page returned status %d", response.StatusCode)
		}
		pageBody, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		if err != nil {
			return nil, "", fmt.Errorf("failed to read the approved blueprint page")
		}
		anchor := satisfactoryCalculatorDownloadPattern.FindSubmatch(pageBody)
		if len(anchor) != 4 || string(anchor[3]) != matches[1] {
			return nil, "", fmt.Errorf("blueprint download link was not found on the approved page")
		}
		link := strings.ReplaceAll(string(anchor[1]), "&amp;", "&")
		download, err = page.Parse(link)
		if err != nil || !isAllowedSatisfactoryBlueprintURL(download) || !strings.Contains(download.Path, "/index/download") || !strings.Contains(download.Path, "/id/"+matches[1]+"/") {
			return nil, "", fmt.Errorf("blueprint download URL is not approved")
		}
		ext := ".sbp"
		if strings.Contains(download.Path, "/download-cfg/") {
			ext = ".sbpcfg"
		}
		filename = "blueprint-" + matches[1] + ext
	case "static.satisfactory-calculator.com":
		ext := strings.ToLower(path.Ext(page.Path))
		if page.Port() != "" || !strings.HasPrefix(page.Path, "/data/blueprintsData/") || (ext != ".sbp" && ext != ".sbpcfg") {
			return nil, "", fmt.Errorf("URL must identify a Satisfactory Calculator blueprint file")
		}
		download = page
		filename = path.Base(page.Path)
	default:
		return nil, "", fmt.Errorf("blueprint source host is not approved")
	}
	if !isAllowedSatisfactoryBlueprintURL(download) {
		return nil, "", fmt.Errorf("blueprint download URL is not approved")
	}
	if _, ok := safeSatisfactoryBlueprintName(filename); !ok {
		return nil, "", fmt.Errorf("blueprint download filename is invalid")
	}
	return download, filename, nil
}

func isAllowedSatisfactoryBlueprintURL(value *url.URL) bool {
	if value == nil || !strings.EqualFold(value.Scheme, "https") || value.User != nil || value.Port() != "" {
		return false
	}
	switch strings.ToLower(value.Hostname()) {
	case "satisfactoryblueprints.com", "www.satisfactoryblueprints.com", "satisfactory-calculator.com", "www.satisfactory-calculator.com", "static.satisfactory-calculator.com":
		return true
	default:
		return false
	}
}

func safeSatisfactoryBlueprintName(value string) (string, bool) {
	name := strings.TrimSpace(value)
	if name == "" || path.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return "", false
	}
	ext := strings.ToLower(path.Ext(name))
	if ext != ".sbp" && ext != ".sbpcfg" {
		return "", false
	}
	return name, true
}

func isSatisfactoryBlueprintServer(templateID string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(templateID)), "satisfactory-")
}
