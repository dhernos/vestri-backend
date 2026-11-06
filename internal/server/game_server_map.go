package server

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"yourapp/internal/auth"

	"github.com/go-chi/chi/v5"
)

func supportsBlueMap(server *auth.GameServer) bool {
	metadata := parseGameServerMetadata(server.Metadata)
	software := strings.ToUpper(strings.TrimSpace(metadata.SoftwareVersion))
	return strings.EqualFold(metadata.Game, "minecraft") &&
		(software == minecraftSoftwarePaper || software == minecraftSoftwarePurpur) &&
		!isVelocityServer(server)
}

func (s *Server) handleGameServerMap(w http.ResponseWriter, r *http.Request) {
	_, node, server, _, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !supportsBlueMap(server) {
		writeError(w, http.StatusBadRequest, "Maps are only available for Paper/Purpur Minecraft servers")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	asset := chi.URLParam(r, "*")
	if strings.ContainsAny(asset, "\\\x00") || strings.Contains(asset, "//") ||
		path.Clean("/"+asset) != "/"+strings.TrimSuffix(asset, "/") {
		writeError(w, http.StatusBadRequest, "Invalid map path")
		return
	}
	query := r.URL.Query()
	// The browser cannot select a different stack or filesystem root.
	query.Set("stack", server.StackName)
	query.Set("root", server.RootPath)
	workerPath := "/stack/bluemap/view/" + (&url.URL{Path: asset}).EscapedPath()
	if asset == "" && strings.HasSuffix(r.URL.Path, "/map/status") {
		workerPath = "/stack/bluemap/status"
	}
	workerPath += "?" + query.Encode()
	prefix := "/api/nodes/" + url.PathEscape(chi.URLParam(r, "nodeRef")) +
		"/servers/" + url.PathEscape(chi.URLParam(r, "serverRef")) + "/map/view/"
	s.proxySignedWorkerGET(w, r, baseURL, apiKey, workerPath, false, func(resp *http.Response) error {
		if location := resp.Header.Get("Location"); location != "" {
			redirect, err := url.Parse(location)
			if err != nil || redirect.IsAbs() || redirect.Host != "" {
				return fmt.Errorf("invalid BlueMap redirect")
			}
			redirect = (&url.URL{Path: "/" + asset}).ResolveReference(redirect)
			redirect.Path = prefix + strings.TrimPrefix(redirect.Path, "/")
			redirect.RawPath = ""
			resp.Header.Set("Location", redirect.String())
		}
		setBlueMapResponseHeaders(w.Header(), resp.Header)
		resp.Header.Del("Set-Cookie")
		return nil
	})
}

func setBlueMapResponseHeaders(dst, upstream http.Header) {
	// ReverseProxy appends upstream headers to those already set by secureHeaders.
	for name, value := range map[string]string{
		"X-Frame-Options":         "SAMEORIGIN",
		"Content-Security-Policy": blueMapContentSecurityPolicy,
		"Cache-Control":           "private, no-store",
	} {
		dst.Del(name)
		upstream.Set(name, value)
	}
}

const blueMapContentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'; form-action 'none'"
