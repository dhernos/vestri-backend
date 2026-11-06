package server

import (
	"bytes"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

type jsonTestRequest struct {
	Value string `json:"value"`
}

func TestDecodeJSONRejectsBodiesAboveLimit(t *testing.T) {
	body := `{"value":"` + strings.Repeat("x", int(maxJSONBodyBytes)) + `"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	var dst jsonTestRequest

	if err := decodeJSON(req, &dst); err != errJSONBodyTooLarge {
		t.Fatalf("expected oversized body error, got %v", err)
	}
}

func TestDecodeJSONAcceptsBodyAtLimit(t *testing.T) {
	valueLength := int(maxJSONBodyBytes) - len(`{"value":""}`)
	body := `{"value":"` + strings.Repeat("x", valueLength) + `"}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	var dst jsonTestRequest

	if err := decodeJSON(req, &dst); err != nil {
		t.Fatalf("expected body at limit to decode, got %v", err)
	}
	if len(dst.Value) != valueLength {
		t.Fatalf("expected decoded value length %d, got %d", valueLength, len(dst.Value))
	}
}

func TestClientIPWalksForwardedChainFromTrustedProxy(t *testing.T) {
	trusted := parseProxyCIDRs([]string{"10.0.0.0/8"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.3:1234"
	req.Header.Add("X-Forwarded-For", "203.0.113.90, 198.51.100.24")
	req.Header.Add("X-Forwarded-For", "10.0.0.2")

	if got := clientIP(req, trusted); got != "198.51.100.24" {
		t.Fatalf("expected original client address, got %q", got)
	}
}

func TestClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	trusted := parseProxyCIDRs([]string{"10.0.0.0/8"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("X-Forwarded-For", "192.0.2.20")
	req.Header.Set("X-Real-IP", "192.0.2.30")

	if got := clientIP(req, trusted); got != "198.51.100.10" {
		t.Fatalf("expected remote address, got %q", got)
	}
}

func TestClientIPFallsBackForMalformedForwardedChain(t *testing.T) {
	trusted := []net.IPNet{{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(32, 32)}}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "not-an-ip")

	if got := clientIP(req, trusted); got != "10.0.0.1" {
		t.Fatalf("expected trusted peer fallback, got %q", got)
	}
}
