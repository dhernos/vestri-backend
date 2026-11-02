package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var notificationBlockedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

func publicNotificationAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.Zone() != "" {
		return false
	}
	for _, network := range notificationBlockedNetworks {
		if network.Contains(address) {
			return false
		}
	}
	return true
}

func parseNotificationWebhook(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook URL")
	}
	host := strings.ToLower(target.Hostname())
	if len(raw) > 2048 || target.Scheme != "https" || host == "" || target.User != nil || target.Fragment != "" || (target.Port() != "" && target.Port() != "443") || strings.Contains(host, "%") {
		return nil, fmt.Errorf("webhook requires public HTTPS on port 443")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || !strings.Contains(host, ".") && !strings.Contains(host, ":") {
		return nil, fmt.Errorf("local webhook host")
	}
	if address, err := netip.ParseAddr(host); err == nil && !publicNotificationAddress(address) {
		return nil, fmt.Errorf("non-public webhook address")
	}
	return target, nil
}

func dialNotificationWebhook(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, fmt.Errorf("invalid webhook address")
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("webhook host has no addresses")
	}
	for _, resolved := range addresses {
		if !publicNotificationAddress(resolved) {
			return nil, fmt.Errorf("webhook resolves to non-public address")
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	var lastError error
	for _, resolved := range addresses {
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
		if err == nil {
			return connection, nil
		}
		lastError = err
	}
	return nil, lastError
}

var notificationWebhookClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         dialNotificationWebhook,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
	},
}

func sendNotificationWebhook(ctx context.Context, rawURL string, message notificationMessage, text string) error {
	target, err := parseNotificationWebhook(rawURL)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		notificationMessage
		Content         string `json:"content"`
		Text            string `json:"text"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}{notificationMessage: message, Content: text, Text: text, AllowedMentions: struct {
		Parse []string `json:"parse"`
	}{Parse: []string{}}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Vestri-Notifications/1")
	req.Header.Set("X-Vestri-Event", message.Kind)
	req.Header.Set("X-Vestri-Notification-ID", message.ID)
	response, err := notificationWebhookClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", response.StatusCode)
	}
	return nil
}
