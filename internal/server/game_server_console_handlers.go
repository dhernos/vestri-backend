package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"yourapp/internal/auth"
)

const maxConsoleExecWorkerResponseBytes = 16 * 1024

type consoleExecSessionCreateResponse struct {
	SessionID string `json:"sessionId"`
}

type consoleExecInputRequest struct {
	SessionID string `json:"sessionId"`
	Data      string `json:"data"`
}

type consoleExecResizeRequest struct {
	SessionID string `json:"sessionId"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

func (s *Server) handleGameServerConsoleLogsStream(w http.ResponseWriter, r *http.Request) {
	sess, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canReadGameServerConsole(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for this action")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	logOptions, err := parseConsoleLogsQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	workerPath := buildWorkerConsolePath(
		"/stack/logs/stream",
		server.StackName,
		r.URL.Query().Get("service"),
		logOptions,
	)
	log.Printf(
		"game server console logs stream start user=%s node=%s server=%s stack=%s service=%q follow=%q tail=%q",
		sess.UserID,
		node.Slug,
		server.Slug,
		server.StackName,
		strings.TrimSpace(r.URL.Query().Get("service")),
		logOptions.Get("follow"),
		logOptions.Get("tail"),
	)
	s.proxySignedWorkerGET(w, r, baseURL, apiKey, workerPath, false)
}

func (s *Server) handleGameServerConsoleLogsWS(w http.ResponseWriter, r *http.Request) {
	sess, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canReadGameServerConsole(serverRole) {
		writeError(w, http.StatusForbidden, "Server permission denied for this action")
		return
	}
	if !isWebsocketUpgradeRequest(r) {
		writeError(w, http.StatusBadRequest, "WebSocket upgrade required")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	logOptions, err := parseConsoleLogsQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := logOptions["follow"]; !ok {
		logOptions.Set("follow", "true")
	}

	workerPath := buildWorkerConsolePath(
		"/stack/logs/ws",
		server.StackName,
		r.URL.Query().Get("service"),
		logOptions,
	)
	log.Printf(
		"game server console logs ws start user=%s node=%s server=%s stack=%s service=%q follow=%q tail=%q",
		sess.UserID,
		node.Slug,
		server.Slug,
		server.StackName,
		strings.TrimSpace(r.URL.Query().Get("service")),
		logOptions.Get("follow"),
		logOptions.Get("tail"),
	)
	s.proxySignedWorkerGET(w, r, baseURL, apiKey, workerPath, true)
}

func (s *Server) handleGameServerConsoleExecSessionCreate(w http.ResponseWriter, r *http.Request) {
	sess, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can open an interactive console")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	payload, err := json.Marshal(map[string]string{
		"stack": server.StackName,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to build interactive session payload")
		return
	}

	workerQuery := url.Values{}
	if service := strings.TrimSpace(r.URL.Query().Get("service")); service != "" {
		workerQuery.Set("service", service)
	}
	if cols := strings.TrimSpace(r.URL.Query().Get("cols")); cols != "" {
		if _, convErr := strconv.Atoi(cols); convErr == nil {
			workerQuery.Set("cols", cols)
		}
	}
	if rows := strings.TrimSpace(r.URL.Query().Get("rows")); rows != "" {
		if _, convErr := strconv.Atoi(rows); convErr == nil {
			workerQuery.Set("rows", rows)
		}
	}

	resp, err := s.callWorkerStream(
		r.Context(),
		baseURL,
		apiKey,
		http.MethodPost,
		"/stack/exec/session",
		workerQuery.Encode(),
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		log.Printf(
			"game server console exec session create failed user=%s node=%s server=%s stack=%s err=%v",
			sess.UserID,
			node.Slug,
			server.Slug,
			server.StackName,
			err,
		)
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeConsoleWorkerErrorResponse(w, resp)
		return
	}

	var data consoleExecSessionCreateResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxConsoleExecWorkerResponseBytes)).Decode(&data); err != nil {
		writeError(w, http.StatusBadGateway, "Interactive session response is invalid")
		return
	}

	sessionID := normalizeConsoleExecSessionID(data.SessionID)
	if sessionID == "" {
		writeError(w, http.StatusBadGateway, "Interactive session response is invalid")
		return
	}

	log.Printf(
		"game server console exec session create user=%s node=%s server=%s stack=%s session=%s",
		sess.UserID,
		node.Slug,
		server.Slug,
		server.StackName,
		sessionID,
	)
	writeJSON(w, http.StatusOK, map[string]string{
		"sessionId": sessionID,
	})
}

func (s *Server) handleGameServerConsoleExecSessionDelete(w http.ResponseWriter, r *http.Request) {
	sess, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can open an interactive console")
		return
	}

	sessionID := normalizeConsoleExecSessionID(r.URL.Query().Get("session"))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "session is required")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	workerQuery := url.Values{}
	workerQuery.Set("session", sessionID)
	resp, err := s.callWorkerStream(
		r.Context(),
		baseURL,
		apiKey,
		http.MethodDelete,
		"/stack/exec/session",
		workerQuery.Encode(),
		"",
		nil,
	)
	if err != nil {
		log.Printf(
			"game server console exec session delete failed user=%s node=%s server=%s stack=%s session=%s err=%v",
			sess.UserID,
			node.Slug,
			server.Slug,
			server.StackName,
			sessionID,
			err,
		)
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeConsoleWorkerErrorResponse(w, resp)
		return
	}

	log.Printf(
		"game server console exec session delete user=%s node=%s server=%s stack=%s session=%s",
		sess.UserID,
		node.Slug,
		server.Slug,
		server.StackName,
		sessionID,
	)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGameServerConsoleExecStream(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can open an interactive console")
		return
	}

	sessionID := normalizeConsoleExecSessionID(r.URL.Query().Get("session"))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "session is required")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	workerQuery := url.Values{}
	workerQuery.Set("session", sessionID)
	resp, err := s.callWorkerStream(
		r.Context(),
		baseURL,
		apiKey,
		http.MethodGet,
		"/stack/exec/stream",
		workerQuery.Encode(),
		"",
		nil,
	)
	if err != nil {
		log.Printf(
			"game server console exec stream failed node=%s server=%s stack=%s session=%s err=%v",
			node.Slug,
			server.Slug,
			server.StackName,
			sessionID,
			err,
		)
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeConsoleWorkerErrorResponse(w, resp)
		return
	}

	copyHeaders(w.Header(), resp.Header, []string{
		"Content-Type",
		"Cache-Control",
		"X-Accel-Buffering",
	})
	if strings.TrimSpace(w.Header().Get("Content-Type")) == "" {
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	}
	if strings.TrimSpace(w.Header().Get("Cache-Control")) == "" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if strings.TrimSpace(w.Header().Get("X-Accel-Buffering")) == "" {
		w.Header().Set("X-Accel-Buffering", "no")
	}

	w.WriteHeader(http.StatusOK)

	flusher, hasFlusher := w.(http.Flusher)
	if hasFlusher {
		flusher.Flush()
	}

	buffer := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				return
			}
			if hasFlusher {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return
			}
			return
		}
	}
}

func (s *Server) handleGameServerConsoleExecInput(w http.ResponseWriter, r *http.Request) {
	_, node, _, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can open an interactive console")
		return
	}

	var req consoleExecInputRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	req.SessionID = normalizeConsoleExecSessionID(req.SessionID)
	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "sessionId is required")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	payload, err := json.Marshal(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to encode interactive input")
		return
	}

	resp, err := s.callWorkerStream(
		r.Context(),
		baseURL,
		apiKey,
		http.MethodPost,
		"/stack/exec/input",
		"",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeConsoleWorkerErrorResponse(w, resp)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGameServerConsoleExecResize(w http.ResponseWriter, r *http.Request) {
	_, node, _, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can open an interactive console")
		return
	}

	var req consoleExecResizeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	req.SessionID = normalizeConsoleExecSessionID(req.SessionID)
	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "sessionId is required")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	payload, err := json.Marshal(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to encode terminal resize request")
		return
	}

	resp, err := s.callWorkerStream(
		r.Context(),
		baseURL,
		apiKey,
		http.MethodPost,
		"/stack/exec/resize",
		"",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeConsoleWorkerErrorResponse(w, resp)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGameServerConsoleExecWS(w http.ResponseWriter, r *http.Request) {
	sess, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can open an interactive console")
		return
	}
	if !isWebsocketUpgradeRequest(r) {
		writeError(w, http.StatusBadRequest, "WebSocket upgrade required")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	workerPath := buildWorkerConsolePath(
		"/stack/exec/ws",
		server.StackName,
		r.URL.Query().Get("service"),
		nil,
	)
	log.Printf(
		"game server console exec ws start user=%s node=%s server=%s stack=%s service=%q",
		sess.UserID,
		node.Slug,
		server.Slug,
		server.StackName,
		strings.TrimSpace(r.URL.Query().Get("service")),
	)
	s.proxySignedWorkerGET(w, r, baseURL, apiKey, workerPath, true)
}

func buildWorkerConsolePath(pathname, stackName, service string, extraQuery url.Values) string {
	values := url.Values{}
	values.Set("stack", stackName)
	if svc := strings.TrimSpace(service); svc != "" {
		values.Set("service", svc)
	}
	for key, entries := range extraQuery {
		if len(entries) == 0 {
			continue
		}
		values.Set(key, entries[len(entries)-1])
	}
	return pathname + "?" + values.Encode()
}

func parseConsoleLogsQuery(query url.Values) (url.Values, error) {
	values := url.Values{}

	if raw := strings.TrimSpace(query.Get("follow")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid follow value")
		}
		values.Set("follow", strconv.FormatBool(parsed))
	}

	if raw := strings.TrimSpace(query.Get("tail")); raw != "" {
		if strings.EqualFold(raw, "all") {
			values.Set("tail", "all")
			return values, nil
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("invalid tail value")
		}
		values.Set("tail", strconv.Itoa(parsed))
	}

	return values, nil
}

func writeConsoleWorkerErrorResponse(w http.ResponseWriter, resp *http.Response) {
	msg := readWorkerErrorText(resp.Body)
	if msg == "" {
		msg = "Worker request failed"
	}
	writeError(w, resp.StatusCode, msg)
}

func normalizeConsoleExecSessionID(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if len(value) != 32 {
		return ""
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return ""
		}
	}
	return value
}

func (s *Server) proxySignedWorkerGET(w http.ResponseWriter, r *http.Request, baseURL *url.URL, apiKey, workerPath string, requireUpgrade bool) {
	if requireUpgrade && !isWebsocketUpgradeRequest(r) {
		writeError(w, http.StatusBadRequest, "WebSocket upgrade required")
		return
	}

	parsedPath, err := url.Parse(workerPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid worker request path")
		return
	}

	pathname := "/" + strings.TrimPrefix(parsedPath.Path, "/")
	signedPath := pathname
	if parsedPath.RawQuery != "" {
		signedPath += "?" + parsedPath.RawQuery
	}

	proxy := httputil.NewSingleHostReverseProxy(baseURL)
	proxy.Transport = workerHTTPClient.Transport
	if requireUpgrade {
		proxy.FlushInterval = 0
	} else {
		// Force immediate chunk flushes for live console logs.
		proxy.FlushInterval = -1
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		log.Printf("worker console proxy response method=%s path=%s status=%d", resp.Request.Method, signedPath, resp.StatusCode)
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		log.Printf("worker console proxy failed method=%s path=%s err=%v", req.Method, signedPath, proxyErr)
		writeError(rw, http.StatusBadGateway, "Worker request failed")
	}

	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Method = http.MethodGet
		req.URL.Path = joinWorkerPath(baseURL.Path, pathname)
		req.URL.RawQuery = parsedPath.RawQuery
		req.Host = baseURL.Host
		req.Header.Del("Cookie")

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := strings.ReplaceAll(auth.NewSessionID(), "-", "")
		signature := signWorkerRequest(apiKey, ts, nonce, http.MethodGet, signedPath)

		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("X-Request-Timestamp", ts)
		req.Header.Set("X-Request-Nonce", nonce)
		req.Header.Set("X-Request-Signature", signature)
	}

	proxy.ServeHTTP(w, r)
}

func isWebsocketUpgradeRequest(r *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	return headerContainsToken(r.Header, "Connection", "upgrade")
}

func headerContainsToken(header http.Header, key, token string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	for _, value := range header.Values(key) {
		for _, piece := range strings.Split(value, ",") {
			if strings.ToLower(strings.TrimSpace(piece)) == token {
				return true
			}
		}
	}
	return false
}
