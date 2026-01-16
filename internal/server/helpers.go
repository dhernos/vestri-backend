package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"unicode"
)

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"message": message})
}

func decodeJSON(r *http.Request, dst interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func validateEmail(email string) bool {
	if email == "" {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}
	return nil
}

func clientIP(r *http.Request, trusted []net.IPNet) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || remoteHost == "" {
		remoteHost = r.RemoteAddr
	}

	// Only trust forwarded headers when the immediate sender is a trusted proxy.
	if remoteHost != "" && isTrustedProxy(remoteHost, trusted) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			return strings.TrimSpace(xrip)
		}
	}

	return remoteHost
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// deriveLocation looks for proxy-provided geo headers to give the user context about sign-in origin.
func deriveLocation(r *http.Request) string {
	country := firstHeader(r, "CF-IPCountry", "X-Country", "X-Geo-Country")
	city := firstHeader(r, "X-City", "X-Geo-City")
	if country == "" && city == "" {
		return ""
	}
	if country != "" && city != "" {
		return city + ", " + country
	}
	if city != "" {
		return city
	}
	return country
}

func firstHeader(r *http.Request, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(r.Header.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func parseProxyCIDRs(values []string) []net.IPNet {
	var nets []net.IPNet
	for _, v := range values {
		val := strings.TrimSpace(v)
		if val == "" {
			continue
		}
		if ip := net.ParseIP(val); ip != nil {
			mask := net.CIDRMask(128, 128)
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			}
			nets = append(nets, net.IPNet{IP: ip, Mask: mask})
			continue
		}
		if _, cidr, err := net.ParseCIDR(val); err == nil {
			nets = append(nets, *cidr)
		}
	}
	return nets
}

func isTrustedProxy(ipStr string, proxies []net.IPNet) bool {
	if len(proxies) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range proxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
