package server

import (
	"net"
	"net/http"
	"strings"
)

func (s *Server) rejectInsecureAuthTransport(w http.ResponseWriter, r *http.Request) bool {
	if !s.Config.EnforceHTTPSAuth {
		return false
	}
	if s.isSecureTransportRequest(r) {
		return false
	}
	writeError(w, http.StatusUpgradeRequired, "HTTPS_REQUIRED")
	return true
}

func (s *Server) isSecureTransportRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}

	if forwardedProto(r) != "https" {
		return false
	}

	remoteHost := remoteHostFromAddr(r.RemoteAddr)
	if remoteHost == "" {
		return false
	}
	if isTrustedProxy(remoteHost, s.trustedProxies) {
		return true
	}

	ip := net.ParseIP(remoteHost)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func forwardedProto(r *http.Request) string {
	if raw := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); raw != "" {
		first := strings.TrimSpace(strings.Split(raw, ",")[0])
		return strings.ToLower(first)
	}

	forwarded := strings.TrimSpace(r.Header.Get("Forwarded"))
	if forwarded == "" {
		return ""
	}
	for _, entry := range strings.Split(forwarded, ",") {
		for _, part := range strings.Split(entry, ";") {
			token := strings.TrimSpace(part)
			if token == "" {
				continue
			}
			kv := strings.SplitN(token, "=", 2)
			if len(kv) != 2 {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(kv[0]), "proto") {
				continue
			}
			value := strings.TrimSpace(kv[1])
			return strings.ToLower(strings.Trim(value, "\""))
		}
	}
	return ""
}

func remoteHostFromAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}
