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
	{Method: http.MethodGet, Path: "/api/worker/*", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
	{Method: http.MethodPost, Path: "/api/worker/*", Roles: []string{RoleUser, RoleAdmin, RoleEditor}},
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
