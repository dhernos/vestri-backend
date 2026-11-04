package i18n

import (
	"strings"
	"testing"
)

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