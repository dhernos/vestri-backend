package i18n

import (
	"strings"
	"testing"
)

func TestReleaseNotificationTranslations(t *testing.T) {
	for _, locale := range []string{"en", "de"} {
		for _, kind := range []string{"worker_recovered", "server_recovered", "server_invited", "server_access_granted", "server_role_changed", "server_access_removed"} {
			content := NotificationEmail(locale, kind, "Example", "Node", "now", "https://example.com", "Actor <script>", "operator")
			text := NotificationEventText(locale, kind, "Example", "Node", "Actor", "operator")
			if text == "" || strings.Contains(content.Text, "{actor}") || strings.Contains(content.HTML, "<script>") {
				t.Fatalf("invalid %s translation for %s", locale, kind)
			}
			if strings.HasPrefix(kind, "server_") && kind != "server_recovered" {
				if !strings.Contains(content.Text, "Actor") || !strings.Contains(content.Text, "operator") || !strings.Contains(text, "Example") {
					t.Fatalf("missing membership details for %s/%s", locale, kind)
				}
			}
		}
	}
}

func TestNotificationEmailNodeRowHasValidTableMarkup(t *testing.T) {
	content := NotificationEmail("en", "server_down", "Example", "Node", "now", "https://example.com")
	nodeCell := `<td style="padding:8px 10px;width:120px;color:#4e5d86;border-bottom:1px solid #d8e2fb;">Node</td>`
	if !strings.Contains(content.HTML, "<tbody>") || !strings.Contains(content.HTML, nodeCell) {
		t.Fatalf("notification email is missing a well-formed Node table row: %s", content.HTML)
	}
	if strings.Contains(content.HTML, "Node< /td>") {
		t.Fatal("notification email contains a malformed Node table cell")
	}
}
