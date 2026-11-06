package i18n

import (
	"html"
	"strings"
)

type notificationKindCopy struct {
	Subject string
	Message string
	Badge   string
	Color   string
}

type notificationEmailStrings struct {
	Kinds    map[string]notificationKindCopy
	Fallback notificationKindCopy
	Subtitle string
	Server   string
	Node     string
	Time     string
	Button   string
	Settings string
}

var notificationEmailTranslations = map[string]notificationEmailStrings{
	"en": {
		Kinds: map[string]notificationKindCopy{
			"server_created":        {"Server created: {server}", "Server <strong>{server}</strong> was created on node <strong>{node}</strong>.", "Created", "#1f9d55"},
			"server_deleted":        {"Server deleted: {server}", "Server <strong>{server}</strong> was deleted from node <strong>{node}</strong>.", "Deleted", "#5f6f95"},
			"worker_unhealthy":      {"Worker unhealthy: {node}", "Worker node <strong>{node}</strong> has not been healthy for more than one minute.", "Unhealthy", "#d64545"},
			"server_down":           {"Server down: {server}", "Server <strong>{server}</strong> on node <strong>{node}</strong> has been down for more than one minute.", "Down", "#d64545"},
			"worker_recovered":      {"Worker recovered: {node}", "Worker <strong>{node}</strong> is healthy again after a reported outage.", "Recovered", "#1f9d55"},
			"server_recovered":      {"Server recovered: {server}", "Server <strong>{server}</strong> on node <strong>{node}</strong> is running again after a reported outage.", "Recovered", "#1f9d55"},
			"server_invited":        {"Server invitation: {server}", "<strong>{actor}</strong> invited you to server <strong>{server}</strong> with role <strong>{role}</strong>.", "Invited", "#1f9d55"},
			"server_access_granted": {"Server access granted: {server}", "<strong>{actor}</strong> granted you access to server <strong>{server}</strong> with role <strong>{role}</strong>.", "Access granted", "#1f9d55"},
			"server_role_changed":   {"Server role changed: {server}", "<strong>{actor}</strong> changed your role on server <strong>{server}</strong> to <strong>{role}</strong>.", "Role changed", "#5f6f95"},
			"server_access_removed": {"Server access removed: {server}", "<strong>{actor}</strong> removed your access to server <strong>{server}</strong> (previous role: <strong>{role}</strong>).", "Access removed", "#d64545"},
		},
		Fallback: notificationKindCopy{"New notification", "There is a new event on node <strong>{node}</strong>.", "Info", "#4f6cf6"},
		Subtitle: "Server notification from Vestri",
		Server:   "Server",
		Node:     "Node",
		Time:     "Time",
		Button:   "Open notifications",
		Settings: "You receive this email because email delivery is enabled in your notification settings.",
	},
	"de": {
		Kinds: map[string]notificationKindCopy{
			"server_created":        {"Server erstellt: {server}", "Server <strong>{server}</strong> wurde auf der Node <strong>{node}</strong> erstellt.", "Erstellt", "#1f9d55"},
			"server_deleted":        {"Server gel\u00f6scht: {server}", "Server <strong>{server}</strong> wurde von der Node <strong>{node}</strong> gel\u00f6scht.", "Gel\u00f6scht", "#5f6f95"},
			"worker_unhealthy":      {"Worker gest\u00f6rt: {node}", "Die Worker-Node <strong>{node}</strong> ist seit mehr als einer Minute nicht mehr gesund.", "Gest\u00f6rt", "#d64545"},
			"server_down":           {"Server offline: {server}", "Server <strong>{server}</strong> auf der Node <strong>{node}</strong> ist seit mehr als einer Minute offline.", "Offline", "#d64545"},
			"worker_recovered":      {"Worker wieder gesund: {node}", "Worker <strong>{node}</strong> ist nach einer gemeldeten St\u00f6rung wieder gesund.", "Wieder gesund", "#1f9d55"},
			"server_recovered":      {"Server wieder online: {server}", "Server <strong>{server}</strong> auf der Node <strong>{node}</strong> l\u00e4uft nach einem gemeldeten Ausfall wieder.", "Wieder online", "#1f9d55"},
			"server_invited":        {"Servereinladung: {server}", "<strong>{actor}</strong> hat Sie zum Server <strong>{server}</strong> mit der Rolle <strong>{role}</strong> eingeladen.", "Eingeladen", "#1f9d55"},
			"server_access_granted": {"Serverzugriff gew\u00e4hrt: {server}", "<strong>{actor}</strong> hat Ihnen Zugriff auf Server <strong>{server}</strong> mit der Rolle <strong>{role}</strong> gew\u00e4hrt.", "Zugriff gew\u00e4hrt", "#1f9d55"},
			"server_role_changed":   {"Serverrolle ge\u00e4ndert: {server}", "<strong>{actor}</strong> hat Ihre Rolle auf Server <strong>{server}</strong> auf <strong>{role}</strong> ge\u00e4ndert.", "Rolle ge\u00e4ndert", "#5f6f95"},
			"server_access_removed": {"Serverzugriff entfernt: {server}", "<strong>{actor}</strong> hat Ihren Zugriff auf Server <strong>{server}</strong> entfernt (bisherige Rolle: <strong>{role}</strong>).", "Zugriff entfernt", "#d64545"},
		},
		Fallback: notificationKindCopy{"Neue Benachrichtigung", "Es gibt ein neues Ereignis auf der Node <strong>{node}</strong>.", "Info", "#4f6cf6"},
		Subtitle: "Serverbenachrichtigung von Vestri",
		Server:   "Server",
		Node:     "Node",
		Time:     "Zeitpunkt",
		Button:   "Benachrichtigungen \u00f6ffnen",
		Settings: "Sie erhalten diese E-Mail, weil die E-Mail-Zustellung in Ihren Benachrichtigungseinstellungen aktiviert ist.",
	},
}

func NotificationEventText(locale, kind, server, node, actor, role string) string {
	translations := notificationEmailTranslations[NormalizeLocale(locale)]
	copy, ok := translations.Kinds[kind]
	if !ok {
		return ""
	}
	return renderTemplate(strongTags.Replace(copy.Message), map[string]string{"server": server, "node": node, "actor": actor, "role": role})
}

func NotificationEmail(locale, kind, server, node, when, link string, membership ...string) EmailContent {
	t, ok := notificationEmailTranslations[NormalizeLocale(locale)]
	if !ok {
		t = notificationEmailTranslations[DefaultLocale]
	}
	kindCopy, ok := t.Kinds[kind]
	if !ok {
		kindCopy = t.Fallback
	}
	values := map[string]string{"server": server, "node": node}
	if len(membership) > 0 {
		values["actor"] = membership[0]
	}
	if len(membership) > 1 {
		values["role"] = membership[1]
	}
	subject := renderTemplate(kindCopy.Subject, values)
	message := renderTemplateHTML(kindCopy.Message, values)

	cell := "padding:8px 10px;width:120px;color:#4e5d86;"
	row := func(label, value string, last bool) string {
		border := "border-bottom:1px solid #d8e2fb;"
		if last {
			border = ""
		}
		return "<tr><td style=\"" + cell + border + "\">" + html.EscapeString(label) + "</td><td style=\"padding:8px 10px;" + border + "\">" + html.EscapeString(value) + "</td></tr>"
	}
	rows := ""
	if server != "" {
		rows += row(t.Server, server, false)
	}
	rows += row(t.Node, node, false) + row(t.Time, when, true)

	body := "<p style=\"margin:0 0 12px;\"><span style=\"display:inline-block;padding:3px 10px;border-radius:999px;background:" + kindCopy.Color + ";color:#ffffff;font-size:12px;font-weight:600;letter-spacing:0.04em;text-transform:uppercase;\">" + html.EscapeString(kindCopy.Badge) + "</span></p>" +
		"<p style=\"margin:0 0 12px;\">" + message + "</p>" +
		"<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%;border:1px solid #d8e2fb;border-radius:8px;margin:0 0 16px;\"><tbody>" + rows + "</tbody></table>" +
		"<p style=\"margin:0 0 16px;\"><a href=\"" + html.EscapeString(link) + "\" style=\"display:inline-block;background:#4f6cf6;color:#f9fbff;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600;\">" + html.EscapeString(t.Button) + "</a></p>" +
		"<p style=\"margin:0;color:#5f6f95;font-size:13px;\">" + html.EscapeString(t.Settings) + "</p>"

	text := subject + "\n\n" + renderTemplate(strongTags.Replace(kindCopy.Message), values) + "\n\n"
	if server != "" {
		text += t.Server + ": " + server + "\n"
	}
	text += t.Node + ": " + node + "\n" + t.Time + ": " + when + "\n\n" + t.Button + ": " + link

	_, footer := emailLayoutCopy(locale)
	return EmailContent{
		Subject: "Vestri: " + subject,
		Text:    text,
		HTML:    renderEmailLayout(subject, t.Subtitle, footer, body),
	}
}

var strongTags = strings.NewReplacer("<strong>", "", "</strong>", "")
