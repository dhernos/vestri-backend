package server

import (
	"fmt"
	"net/http"
)

const (
	RolePublic = "PUBLIC"
	RoleUser   = "USER"
	RoleAdmin  = "ADMIN"
	RoleEditor = "EDITOR"
)

type AccessRule struct {
	Method string
	Path   string
	Roles  []string
}

var endpointAccess = []AccessRule{
	{Method: http.MethodPost, Path: "/api/register", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/verify-email", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/resend-verification", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/forgot-password", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/reset-password", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/auth/login", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/auth/logout", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/two-factor/send-email-code", Roles: []string{RolePublic}},
	{Method: http.MethodGet, Path: "/api/oauth/{provider}/start", Roles: []string{RolePublic}},
	{Method: http.MethodGet, Path: "/api/oauth/{provider}/callback", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/oauth/{provider}/two-factor", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/passkeys/login/start", Roles: []string{RolePublic}},
	{Method: http.MethodPost, Path: "/api/passkeys/login/finish", Roles: []string{RolePublic}},

	{Method: http.MethodGet, Path: "/api/auth/me", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/sessions", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodDelete, Path: "/api/sessions", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/sessions/current", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/two-factor/setup-start", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/two-factor/setup-finalize", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/two-factor/disable", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/two-factor/step-up", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/profile/update-profile", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/profile/update-email", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/profile/change-password", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/profile/update-image", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodDelete, Path: "/api/profile/delete-account", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/passkeys/register/start", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/passkeys/register/finish", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/passkeys", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodDelete, Path: "/api/passkeys/{id}", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/invites", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/invites/{inviteId}/accept", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodDelete, Path: "/api/nodes/{nodeRef}", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/satisfactory-blueprints", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/satisfactory-blueprints/download", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/satisfactory-blueprints/upload", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/satisfactory-blueprints/import", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/satisfactory-blueprints/delete", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/minecraft/files/list", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/minecraft/files/read", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/minecraft/files/write", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/minecraft/files/delete", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/minecraft/files/upload", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/minecraft/files/download", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/minecraft/files/transfer", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/minecraft/files/unzip", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/minecraft/folders/create", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/templates", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodDelete, Path: "/api/nodes/{nodeRef}/servers/{serverRef}", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/status", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/map/status", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/map/view/*", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/console/logs/stream", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/console/logs/ws", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/ws", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/session", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodDelete, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/session", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/stream", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/input", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/resize", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/start", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/stop", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/images/repull", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/files/list", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/files/read", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/files/write", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/files/delete", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/files/transfer", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/files/unzip", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/files/download", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/files/upload", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/whitelist", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/whitelist", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/list", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/read", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/write", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/delete", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/transfer", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/unzip", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/download", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/upload", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/folders/create", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/apply", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins/update", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins/remove", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/backups", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/databases", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/databases", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/databases/action", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/backups/settings", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/backups/create", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/backups/delete", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/backups/restore", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/backups/download", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/backups/upload", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/blueprints", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/blueprints/install", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/invites", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/invites", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodDelete, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/invites/{inviteId}", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/guests", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodDelete, Path: "/api/nodes/{nodeRef}/servers/{serverRef}/guests/{guestUserId}", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodGet, Path: "/api/nodes/{nodeRef}/worker/*", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/nodes/{nodeRef}/worker/*", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
}

func accessRoles(method, path string) []string {
	for _, rule := range endpointAccess {
		if rule.Method == method && rule.Path == path {
			return rule.Roles
		}
	}
	panic(fmt.Sprintf("missing access roles for %s %s", method, path))
}

func roleAllowed(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func isPublicAccess(roles []string) bool {
	return roleAllowed(roles, RolePublic)
}
