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
	"strconv"
	"strings"
	"time"

	"yourapp/internal/auth"
)

type writeGameServerFileRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type deleteGameServerFileRequest struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

type unzipGameServerFileRequest struct {
	Source string `json:"source"`
	Dest   string `json:"dest"`
}

const (
	maxUploadPathFieldBytes = 4096
	maxWorkerErrorTextBytes = 16 << 10
	tempArchiveDirName      = ".vestri-tmp-downloads"
)

var readableTextExtensions = map[string]struct{}{
	".asc":        {},
	".bat":        {},
	".c":          {},
	".cfg":        {},
	".conf":       {},
	".cpp":        {},
	".cs":         {},
	".css":        {},
	".csv":        {},
	".env":        {},
	".gitignore":  {},
	".go":         {},
	".h":          {},
	".hpp":        {},
	".htm":        {},
	".html":       {},
	".ini":        {},
	".java":       {},
	".js":         {},
	".json":       {},
	".jsx":        {},
	".kt":         {},
	".kts":        {},
	".log":        {},
	".lua":        {},
	".md":         {},
	".mjs":        {},
	".properties": {},
	".ps1":        {},
	".py":         {},
	".rb":         {},
	".rs":         {},
	".scss":       {},
	".secret":     {},
	".sh":         {},
	".sql":        {},
	".svg":        {},
	".toml":       {},
	".ts":         {},
	".tsx":        {},
	".txt":        {},
	".xml":        {},
	".yaml":       {},
	".yml":        {},
}

var readableTextBaseNames = map[string]struct{}{
	"dockerfile": {},
	"license":    {},
	"makefile":   {},
	"readme":     {},
}

type tempArchiveTarget struct {
	ArchivePath string
	TempDirPath string
	BaseDirPath string
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
	if !isTextFilePath(fullPath) {
		writeError(w, http.StatusUnsupportedMediaType, "Only text file formats can be opened in editor")
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

func (s *Server) handleDeleteGameServerFile(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file deletion")
		return
	}

	var req deleteGameServerFileRequest
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

	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{
		"path":      fullPath,
		"recursive": req.Recursive,
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

func (s *Server) handleUnzipGameServerFile(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for unzip")
		return
	}

	var req unzipGameServerFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	sourcePath, err := resolveServerScopedPath(server.RootPath, req.Source, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	destPath, err := resolveServerScopedPath(server.RootPath, req.Dest, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/unzip", map[string]string{
		"source": sourcePath,
		"dest":   destPath,
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

func (s *Server) handleDownloadGameServerFile(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file download")
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

	query := url.Values{"path": {fullPath}}.Encode()
	resp, err := s.callWorkerStream(r.Context(), baseURL, apiKey, http.MethodGet, "/fs/download", query, "", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		copyHeaders(w.Header(), resp.Header, []string{
			"Content-Type",
			"Content-Encoding",
			"Content-Disposition",
			"Content-Length",
			"Content-Range",
			"Accept-Ranges",
		})
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

	sourceName := path.Base(fullPath)
	if sourceName == "" || sourceName == "." || sourceName == "/" {
		sourceName = "archive"
	}
	tempArchive := buildTempArchiveTarget(server.RootPath, sourceName)
	archivePath := tempArchive.ArchivePath
	defer s.cleanupWorkerArchive(baseURL, apiKey, tempArchive)

	statusCode, body, err := s.callWorkerJSON(r.Context(), baseURL, apiKey, http.MethodPost, "/fs/zip", map[string]string{
		"source": fullPath,
		"dest":   archivePath,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), statusCode)
		return
	}

	archiveQuery := url.Values{"path": {archivePath}}.Encode()
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

	copyHeaders(w.Header(), archiveResp.Header, []string{
		"Content-Type",
		"Content-Encoding",
		"Content-Length",
		"Content-Range",
		"Accept-Ranges",
	})
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", sourceName+".zip"))
	w.WriteHeader(archiveResp.StatusCode)
	_, _ = io.Copy(w, archiveResp.Body)
}

func (s *Server) handleUploadGameServerFile(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerFiles(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for file upload")
		return
	}

	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid multipart form")
		return
	}

	var (
		rawPath    string
		uploadName string
		uploadTmp  *os.File
	)

	defer func() {
		if uploadTmp == nil {
			return
		}
		name := uploadTmp.Name()
		_ = uploadTmp.Close()
		if name != "" {
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
			tmp, tmpErr := os.CreateTemp("", "vestri-server-upload-*")
			if tmpErr != nil {
				_ = part.Close()
				writeError(w, http.StatusInternalServerError, "Failed to create temporary upload file")
				return
			}
			if _, copyErr := io.Copy(tmp, part); copyErr != nil {
				_ = part.Close()
				name := tmp.Name()
				_ = tmp.Close()
				if name != "" {
					_ = os.Remove(name)
				}
				writeError(w, http.StatusBadGateway, "Failed to read uploaded file")
				return
			}
			_ = part.Close()
			if _, seekErr := tmp.Seek(0, io.SeekStart); seekErr != nil {
				name := tmp.Name()
				_ = tmp.Close()
				if name != "" {
					_ = os.Remove(name)
				}
				writeError(w, http.StatusInternalServerError, "Failed to process upload")
				return
			}
			uploadTmp = tmp
			uploadName = strings.TrimSpace(part.FileName())
			if uploadName == "" {
				uploadName = "upload.bin"
			}
		default:
			_ = part.Close()
		}
	}

	if rawPath == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}
	if uploadTmp == nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}

	fullPath, err := resolveServerScopedPath(server.RootPath, rawPath, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
		err := streamUploadMultipartToWorker(formWriter, pipeWriter, uploadTmp, fullPath, uploadName)
		writeErrCh <- err
	}()

	resp, err := s.callWorkerStream(
		r.Context(),
		baseURL,
		apiKey,
		http.MethodPost,
		"/fs/upload",
		"",
		formWriter.FormDataContentType(),
		pipeReader,
	)
	if err != nil {
		_ = pipeWriter.CloseWithError(err)
		<-writeErrCh
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()

	writeErr := <-writeErrCh
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := readWorkerErrorText(resp.Body)
		if msg == "" {
			msg = "Worker request failed"
		}
		http.Error(w, msg, resp.StatusCode)
		return
	}
	if writeErr != nil {
		writeError(w, http.StatusBadGateway, "Failed to stream upload to worker")
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

func (s *Server) callWorkerStream(
	ctx context.Context,
	baseURL *url.URL,
	apiKey,
	method,
	workerPath,
	rawQuery,
	contentType string,
	body io.Reader,
) (*http.Response, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return nil, fmt.Errorf("method is required")
	}

	workerPath = "/" + strings.TrimPrefix(strings.TrimSpace(workerPath), "/")
	if workerPath == "/" {
		return nil, fmt.Errorf("worker path is required")
	}

	signedPath := workerPath
	if rawQuery != "" {
		signedPath += "?" + rawQuery
	}

	targetURL := *baseURL
	targetURL.Path = joinWorkerPath(baseURL.Path, workerPath)
	targetURL.RawQuery = rawQuery

	req, err := http.NewRequestWithContext(ctx, method, targetURL.String(), body)
	if err != nil {
		return nil, err
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := strings.ReplaceAll(auth.NewSessionID(), "-", "")
	signature := signWorkerRequest(apiKey, ts, nonce, method, signedPath)

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-Request-Timestamp", ts)
	req.Header.Set("X-Request-Nonce", nonce)
	req.Header.Set("X-Request-Signature", signature)

	return workerHTTPClient.Do(req)
}

func readWorkerErrorText(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, maxWorkerErrorTextBytes))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func isDirectoryDownloadError(statusCode int, msg string) bool {
	if statusCode != http.StatusBadRequest {
		return false
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(msg)), "directory")
}

func buildTempArchiveTarget(serverRoot, sourceName string) tempArchiveTarget {
	baseName := slugify(strings.TrimSuffix(sourceName, path.Ext(sourceName)))
	if baseName == "" {
		baseName = "archive"
	}
	token := strings.ReplaceAll(auth.NewSessionID(), "-", "")
	if len(token) > 12 {
		token = token[:12]
	}
	baseDir := path.Join(serverRoot, tempArchiveDirName)
	tempDir := path.Join(baseDir, token)
	archiveName := fmt.Sprintf("%s.zip", baseName)
	return tempArchiveTarget{
		ArchivePath: path.Join(tempDir, archiveName),
		TempDirPath: tempDir,
		BaseDirPath: baseDir,
	}
}

func streamUploadMultipartToWorker(
	formWriter *multipart.Writer,
	pipeWriter *io.PipeWriter,
	uploadTmp *os.File,
	targetPath,
	uploadName string,
) error {
	writeErr := func() error {
		if err := formWriter.WriteField("path", targetPath); err != nil {
			return err
		}

		partWriter, err := formWriter.CreateFormFile("file", uploadName)
		if err != nil {
			return err
		}
		if _, err := uploadTmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.Copy(partWriter, uploadTmp); err != nil {
			return err
		}
		if err := formWriter.Close(); err != nil {
			return err
		}
		return nil
	}()

	if writeErr != nil {
		_ = pipeWriter.CloseWithError(writeErr)
		return writeErr
	}
	if err := pipeWriter.Close(); err != nil {
		return err
	}
	return nil
}

func (s *Server) cleanupWorkerArchive(baseURL *url.URL, apiKey string, target tempArchiveTarget) {
	if strings.TrimSpace(target.ArchivePath) == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, _, _ = s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{
		"path":      target.ArchivePath,
		"recursive": false,
	})
	if strings.TrimSpace(target.TempDirPath) != "" {
		_, _, _ = s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{
			"path":      target.TempDirPath,
			"recursive": true,
		})
	}
	if strings.TrimSpace(target.BaseDirPath) != "" {
		_, _, _ = s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodPost, "/fs/delete", map[string]interface{}{
			"path":      target.BaseDirPath,
			"recursive": false,
		})
	}
}

func isTextFilePath(filePath string) bool {
	baseName := strings.ToLower(strings.TrimSpace(path.Base(filePath)))
	if baseName == "" || baseName == "." || baseName == "/" {
		return false
	}
	if _, ok := readableTextBaseNames[baseName]; ok {
		return true
	}

	ext := strings.ToLower(path.Ext(baseName))
	if ext == "" {
		return false
	}
	_, ok := readableTextExtensions[ext]
	return ok
}
