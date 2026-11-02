package server

import (
	"net/netip"
	"testing"
)

func TestNotificationWebhookTargets(t *testing.T) {
	for _, raw := range []string{"http://example.com/hook", "https://localhost/hook", "https://127.0.0.1", "https://10.0.0.1", "https://[::1]", "https://[::ffff:127.0.0.1]", "https://100.100.100.200", "https://example.com:8443/hook", "https://user:secret@example.com/hook", "https://worker.internal/hook", "https://example.com/#fragment"} {
		if _, err := parseNotificationWebhook(raw); err == nil {
			t.Errorf("accepted unsafe target %s", raw)
		}
	}
	for _, raw := range []string{"https://example.com/hook?token=value", "https://discord.com/api/webhooks/123/abc", "https://8.8.8.8/hook"} {
		if _, err := parseNotificationWebhook(raw); err != nil {
			t.Errorf("rejected public target: %v", err)
		}
	}
	for _, raw := range []string{"169.254.169.254", "192.168.1.1", "0.1.2.3", "198.18.0.1", "fc00::1", "fe80::1", "64:ff9b::a00:1", "2002:7f00:1::"} {
		if publicNotificationAddress(netip.MustParseAddr(raw)) {
			t.Errorf("accepted unsafe address %s", raw)
		}
	}
}
