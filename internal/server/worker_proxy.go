package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"yourapp/internal/auth"
)

var workerHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   0,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       0,
		ResponseHeaderTimeout: 10 * time.Minute,
	},
}

func (s *Server) handleWorkerProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	if nodeRef == "" {
		writeError(w, http.StatusBadRequest, "nodeRef is required")
		return
	}

	workerPath := "/" + strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	if workerPath == "/" {
		workerPath = "/"
	}

	node, baseURL, apiKey, err := s.workerTargetForUserNode(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		if errors.Is(err, errWorkerNodeNotFound) {
			writeError(w, http.StatusNotFound, "Node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Node worker configuration is invalid")
		return
	}
	if !canUseWorkerPath(node.AccessRole, r.Method, workerPath) {
		writeError(w, http.StatusForbidden, "Node permission denied for this action")
		return
	}

	isUpload := r.Method == http.MethodPost && workerPath == "/fs/upload"

	signedPath := workerPath
	if r.URL.RawQuery != "" {
		signedPath += "?" + r.URL.RawQuery
	}

	targetURL := *baseURL
	targetURL.Path = joinWorkerPath(baseURL.Path, workerPath)
	targetURL.RawQuery = r.URL.RawQuery

	bodyReader := r.Body
	bodySize := r.ContentLength
	var bodyCounter *countingReadCloser
	var cleanup func()

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := strings.ReplaceAll(auth.NewSessionID(), "-", "")
	signature := signWorkerRequest(apiKey, ts, nonce, r.Method, signedPath)

	proxyCtx := r.Context()
	var cancel context.CancelFunc
	if isUpload {
		tmp, size, err := bufferUploadBody(r.Body)
		if err != nil {
			log.Printf("worker proxy: user=%s method=%s path=%s upload_buffer_error=%v", sess.UserID, r.Method, signedPath, err)
			writeError(w, http.StatusBadGateway, "Failed to read upload body")
			return
		}
		bodyReader = tmp
		bodySize = size
		cleanup = func() {
			name := tmp.Name()
			_ = tmp.Close()
			if name != "" {
				_ = os.Remove(name)
			}
		}

		if bodyReader != nil {
			bodyCounter = &countingReadCloser{r: bodyReader}
			bodyReader = bodyCounter
		}
		// Detach from client connection once body is buffered to avoid upstream timeouts cancelling the worker send.
		proxyCtx, cancel = context.WithTimeout(context.Background(), 15*time.Minute)
	}
	if cancel != nil {
		defer cancel()
	}

	req, err := http.NewRequestWithContext(proxyCtx, r.Method, targetURL.String(), bodyReader)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to create worker request")
		return
	}

	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	if encoding := r.Header.Get("Content-Encoding"); encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	if bodySize >= 0 {
		req.ContentLength = bodySize
	}

	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-Request-Timestamp", ts)
	req.Header.Set("X-Request-Nonce", nonce)
	req.Header.Set("X-Request-Signature", signature)
	if isUpload {
		req.Close = true // avoid reusing connections for large streaming uploads
		if r.ContentLength > 0 && bodySize != r.ContentLength {
			log.Printf("worker proxy: user=%s method=%s path=%s upload_size_mismatch body_size=%d content_length=%d", sess.UserID, r.Method, signedPath, bodySize, r.ContentLength)
		}
	}

	resp, err := workerHTTPClient.Do(req)
	if err != nil {
		if bodyCounter != nil {
			log.Printf("worker proxy: user=%s method=%s path=%s upload_bytes_sent=%d body_size=%d", sess.UserID, r.Method, signedPath, bodyCounter.n, bodySize)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Printf("worker proxy: user=%s method=%s path=%s error=%v ctx_err=%v", sess.UserID, r.Method, signedPath, err, req.Context().Err())
		} else {
			log.Printf("worker proxy: user=%s method=%s path=%s error=%v", sess.UserID, r.Method, signedPath, err)
		}
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()
	if cleanup != nil {
		cleanup()
	}

	copyHeaders(w.Header(), resp.Header, []string{
		"Content-Type",
		"Content-Encoding",
		"Content-Disposition",
		"Content-Length",
		"Content-Range",
		"Accept-Ranges",
	})
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("worker proxy: user=%s method=%s path=%s copy_error=%v", sess.UserID, r.Method, signedPath, err)
	}

	log.Printf("worker proxy: user=%s node=%s method=%s path=%s status=%d", sess.UserID, nodeRef, r.Method, signedPath, resp.StatusCode)
}

var errWorkerNodeNotFound = errors.New("worker node not found")

func (s *Server) workerTargetForUserNode(ctx context.Context, userID, nodeRef string) (*auth.WorkerNode, *url.URL, string, error) {
	node, err := s.Users.FindAccessibleWorkerNodeByRef(ctx, userID, nodeRef)
	if err != nil {
		return nil, nil, "", err
	}
	if node == nil {
		return nil, nil, "", errWorkerNodeNotFound
	}

	baseURL, err := url.Parse(node.BaseURL)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, nil, "", errors.New("worker node base URL is invalid")
	}

	apiKey, err := s.decryptNodeAPIKey(node)
	if err != nil {
		return nil, nil, "", err
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, nil, "", errors.New("worker node api key is missing")
	}

	return node, baseURL, apiKey, nil
}

func signWorkerRequest(apiKey, ts, nonce, method, path string) string {
	payload := fmt.Sprintf("%s\n%s\n%s\n%s", ts, nonce, method, path)
	mac := hmac.New(sha256.New, []byte(apiKey))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func bufferUploadBody(src io.Reader) (*os.File, int64, error) {
	tmp, err := os.CreateTemp("", "vestri-upload-*")
	if err != nil {
		return nil, 0, err
	}

	n, err := io.Copy(tmp, src)
	if err != nil {
		name := tmp.Name()
		_ = tmp.Close()
		if name != "" {
			_ = os.Remove(name)
		}
		return nil, n, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		name := tmp.Name()
		_ = tmp.Close()
		if name != "" {
			_ = os.Remove(name)
		}
		return nil, n, err
	}
	return tmp, n, nil
}

func joinWorkerPath(basePath, workerPath string) string {
	if basePath == "" || basePath == "/" {
		return workerPath
	}
	return strings.TrimRight(basePath, "/") + workerPath
}

func copyHeaders(dst, src http.Header, keys []string) {
	for _, key := range keys {
		if values := src.Values(key); len(values) > 0 {
			for _, v := range values {
				dst.Add(key, v)
			}
		}
	}
}

type countingReadCloser struct {
	r io.ReadCloser
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReadCloser) Close() error {
	return c.r.Close()
}
