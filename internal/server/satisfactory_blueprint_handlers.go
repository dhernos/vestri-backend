package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"yourapp/internal/auth"
)

const (
	satisfactoryBlueprintLibraryPath = "satisfactory-blueprints"
	satisfactoryBlueprintTargetPath  = "data/Blueprints"
	maxSatisfactoryBlueprintBytes    = 64 << 20
)

var (
	satisfactoryBlueprintPageClient = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 || !isAllowedSatisfactoryBlueprintURL(req.URL) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	satisfactoryBlueprintIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	satisfactoryCalculatorIDPattern = regexp.MustCompile(`^/en/blueprints/index/details/id/([0-9]+)(?:/|$)`)
	satisfactoryCalculatorDownloadPattern = regexp.MustCompile(`href=["'](?:https://satisfactory-calculator\.com)?(/en/blueprints/index/download/id/([0-9]+)(?:/[^"']*)?)["']`)
)

type satisfactoryBlueprintFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func (s *Server) handleListSatisfactoryBlueprints(w http.ResponseWriter, r *http.Request) {
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

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	if err := s.ensureSatisfactoryBlueprintDirectory(r.Context(), baseURL, apiKey); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to prepare shared blueprint folder")
		return
	}
	available, err := s.listSatisfactoryBlueprintFiles(r.Context(), baseURL, apiKey, satisfactoryBlueprintLibraryPath)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to list shared blueprints")
		return
	}
	installed, err := s.listSatisfactoryBlueprintFiles(r.Context(), baseURL, apiKey, path.Join(gameServer.RootPath, satisfactoryBlueprintTargetPath))
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to list installed blueprints")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"available": available,
		"installed": installed,
	})
}

func (s *Server) handleDownloadSatisfactoryBlueprint(w http.ResponseWriter, r *http.Request) {
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
	resp, err := s.callWorkerStream(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/download", "path="+url.QueryEscape(path.Join(satisfactoryBlueprintLibraryPath, name)), "", nil)
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
		URL string `json:"url"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	downloadURL, filename, err := satisfactoryBlueprintDownloadForPage(r.Context(), req.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid blueprint source")
		return
	}
	request.Header.Set("User-Agent", "vestri-blueprint-import/1")
	response, err := satisfactoryBlueprintPageClient.Do(request)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to download blueprint from the approved source")
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "The approved blueprint source did not provide a download")
		return
	}
	if response.ContentLength > maxSatisfactoryBlueprintBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "Blueprint exceeds the 64 MiB limit")
		return
	}
	temp, err := os.CreateTemp("", "vestri-blueprint-import-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to stage blueprint download")
		return
	}
	defer func() {
		name := temp.Name()
		_ = temp.Close()
		_ = os.Remove(name)
	}()
	limited := &io.LimitedReader{R: response.Body, N: maxSatisfactoryBlueprintBytes + 1}
	written, err := io.Copy(temp, limited)
	if err != nil || written > maxSatisfactoryBlueprintBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "Blueprint exceeds the 64 MiB limit")
		return
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to prepare blueprint download")
		return
	}
	if err := s.uploadSatisfactoryBlueprintToWorker(r.Context(), node, temp, filename); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to save blueprint to worker")
		return
	}
	w.WriteHeader(http.StatusCreated)
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
		Name    string `json:"name"`
		Install bool   `json:"install"`
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
	destination := path.Join(gameServer.RootPath, satisfactoryBlueprintTargetPath, name)
	workerPath := "/fs/copy"
	body := map[string]string{
		"source": path.Join(satisfactoryBlueprintLibraryPath, name),
		"dest":   destination,
	}
	if !req.Install {
		workerPath = "/fs/delete"
		body = nil
		statusCode, bodyBytes, callErr := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, workerPath, map[string]interface{}{"path": destination})
		if callErr != nil {
			writeError(w, http.StatusBadGateway, "Worker request failed")
			return
		}
		if statusCode < 200 || statusCode >= 300 {
			http.Error(w, strings.TrimSpace(string(bodyBytes)), statusCode)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	statusCode, bodyBytes, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, workerPath, body)
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
	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{"path": path.Join(satisfactoryBlueprintLibraryPath, name)})
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

func (s *Server) ensureSatisfactoryBlueprintDirectory(ctx context.Context, baseURL *url.URL, apiKey string) error {
	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/mkdir", map[string]interface{}{
		"path":      satisfactoryBlueprintLibraryPath,
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
	statusCode, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodGet, "/fs/list?path="+url.QueryEscape(dir), nil)
	if err != nil {
		return nil, err
	}
	if statusCode == http.StatusNotFound && dir != satisfactoryBlueprintLibraryPath {
		return []satisfactoryBlueprintFile{}, nil
	}
	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("worker /fs/list failed (%d): %s", statusCode, strings.TrimSpace(string(body)))
	}
	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Size int64  `json:"size"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
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

func (s *Server) uploadSatisfactoryBlueprintToWorker(ctx context.Context, node *auth.WorkerNode, upload *os.File, filename string) error {
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		return err
	}
	pipeReader, pipeWriter := io.Pipe()
	formWriter := multipart.NewWriter(pipeWriter)
	writeErrCh := make(chan error, 1)
	targetPath := path.Join(satisfactoryBlueprintLibraryPath, filename)
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

func satisfactoryBlueprintDownloadForPage(ctx context.Context, raw string) (*url.URL, string, error) {
	page, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !isAllowedSatisfactoryBlueprintURL(page) || page.RawQuery != "" || page.Fragment != "" {
		return nil, "", fmt.Errorf("URL must be an HTTPS blueprint page from one of the approved sites")
	}
	host := strings.ToLower(page.Hostname())
	var download *url.URL
	var filename string
	switch host {
	case "satisfactoryblueprints.com":
		if page.Port() != "" || !strings.HasPrefix(page.Path, "/blueprint/") {
			return nil, "", fmt.Errorf("URL must identify a Satisfactory Blueprints detail page")
		}
		id := strings.TrimPrefix(strings.TrimSuffix(page.Path, "/"), "/blueprint/")
		if !satisfactoryBlueprintIDPattern.MatchString(id) {
			return nil, "", fmt.Errorf("URL must identify a valid Satisfactory blueprint")
		}
		download, _ = url.Parse("https://satisfactoryblueprints.com/blueprint/download/" + id)
		filename = "blueprint-" + strings.ToLower(id) + ".sbp"
	case "satisfactory-calculator.com":
		if page.Port() != "" {
			return nil, "", fmt.Errorf("URL must use the standard HTTPS port")
		}
		matches := satisfactoryCalculatorIDPattern.FindStringSubmatch(page.Path)
		if len(matches) != 2 {
			return nil, "", fmt.Errorf("URL must identify a Satisfactory Calculator blueprint detail page")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, page.String(), nil)
		if err != nil {
			return nil, "", fmt.Errorf("invalid blueprint page URL")
		}
		request.Header.Set("User-Agent", "vestri-blueprint-import/1")
		response, err := satisfactoryBlueprintPageClient.Do(request)
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
		if len(anchor) != 3 || string(anchor[2]) != matches[1] {
			return nil, "", fmt.Errorf("blueprint download link was not found on the approved page")
		}
		link := strings.ReplaceAll(string(anchor[1]), "&amp;", "&")
		download, err = page.Parse(link)
		if err != nil || !isAllowedSatisfactoryBlueprintURL(download) || !strings.Contains(download.Path, "/index/download/id/"+matches[1]+"/") {
			return nil, "", fmt.Errorf("blueprint download URL is not approved")
		}
		filename = "blueprint-" + matches[1] + ".sbp"
	default:
		return nil, "", fmt.Errorf("blueprint source host is not approved")
	}
	if !isAllowedSatisfactoryBlueprintURL(download) {
		return nil, "", fmt.Errorf("blueprint download URL is not approved")
	}
	return download, filename, nil
}

func isAllowedSatisfactoryBlueprintURL(value *url.URL) bool {
	if value == nil || !strings.EqualFold(value.Scheme, "https") || value.User != nil || value.Port() != "" {
		return false
	}
	switch strings.ToLower(value.Hostname()) {
	case "satisfactoryblueprints.com", "satisfactory-calculator.com", "static.satisfactory-calculator.com":
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