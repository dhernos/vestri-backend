package server

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"yourapp/internal/auth"
)

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
	proxy.FlushInterval = 50 * time.Millisecond
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
