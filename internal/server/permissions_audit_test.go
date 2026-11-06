package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"yourapp/internal/auth"
)

func TestPermissionsAuditRoleMatrix(t *testing.T) {
	roles := []string{"owner", "admin", "operator", "viewer", "", "OWNER", "unknown"}
	for _, test := range []struct {
		name    string
		allowed string
		check   func(string) bool
	}{
		{"node invites", "owner", canManageNodeInvites},
		{"node worker proxy", "owner", canUseNodeWorkerProxy},
		{"node blueprints", "owner admin", canManageNodeBlueprints},
		{"node minecraft library", "owner admin", canManageNodeMinecraftLibrary},
		{"server creation", "owner admin", canCreateGameServer},
		{"server viewing", "owner admin operator viewer", canViewGameServer},
		{"server management", "owner admin", canManageGameServer},
		{"server control", "owner admin operator", canControlGameServer},
		{"server files", "owner admin", canManageGameServerFiles},
		{"console reading", "owner admin operator viewer", canReadGameServerConsole},
		{"server invites", "owner admin", canManageGameServerInvites},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, role := range roles {
				want := false
				for _, allowed := range strings.Fields(test.allowed) {
					if role == allowed {
						want = true
					}
				}
				if got := test.check(role); got != want {
					t.Errorf("role %q: got %t, want %t", role, got, want)
				}
			}
		})
	}
}

func TestPermissionsAuditNotificationRoutesRequireSession(t *testing.T) {
	api := &Server{}
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/notifications"},
		{http.MethodGet, "/api/notifications/unread"},
		{http.MethodDelete, "/api/notifications"},
		{http.MethodDelete, "/api/notifications/id"},
		{http.MethodPost, "/api/notifications/read"},
		{http.MethodPost, "/api/notifications/id/read"},
		{http.MethodGet, "/api/notifications/settings"},
		{http.MethodPost, "/api/notifications/settings"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			api.Router().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401: %s", response.Code, response.Body.String())
			}
		})
	}
}

func runPermissionsAuditDatabase(t *testing.T, api *Server, database *pgxpool.Pool) {
	ctx := context.Background()
	exec := func(t *testing.T, query string, args ...any) {
		t.Helper()
		if _, err := database.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(t *testing.T, query string, args ...any) int {
		t.Helper()
		var result int
		if err := database.QueryRow(ctx, query, args...).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	request := func(t *testing.T, handler http.HandlerFunc, method, path, userID, body string, refs ...string) *httptest.ResponseRecorder {
		t.Helper()
		router := chi.NewRouter()
		router.MethodFunc(method, path, handler)
		ref := "server"
		if len(refs) > 0 {
			ref = refs[0]
		}
		req := httptest.NewRequest(method, strings.NewReplacer("{nodeRef}", "node", "{serverRef}", ref, "{inviteId}", ref, "{notificationId}", ref).Replace(path), strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), sessionContextKey, &auth.Session{UserID: userID, Role: RoleUser}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	exec(t, `DELETE FROM "GameServerGuest"; DELETE FROM "WorkerNodeGuest";
INSERT INTO "GameServer" ("id","nodeId","slug","name","templateId","stackName","rootPath","composePath","createdByUserId") VALUES ('sibling','node','sibling','Sibling','paper','sibling','/sibling','/sibling/compose.yml','owner');`)
	t.Run("resource binding and denied actions", func(t *testing.T) {
		base := "/api/nodes/{nodeRef}/servers/{serverRef}"
		for _, role := range []string{"viewer", "operator", "admin"} {
			exec(t, `INSERT INTO "WorkerNodeGuest" ("id","nodeId","userId","permission") VALUES ('audit-node','node','guest',$1) ON CONFLICT ("nodeId","userId") DO UPDATE SET "permission"=$1`, role)
			if err := api.Users.UpsertGameServerGuest(ctx, "server", "guest", role); err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct{ userID, ref, wantRole string }{
				{"owner", "server", "owner"}, {"owner", "sibling", "owner"},
				{"guest", "server", role}, {"guest", "sibling", ""}, {"other", "server", ""},
			} {
				response := request(t, func(w http.ResponseWriter, req *http.Request) {
					_, _, server, gotRole, ok := api.loadNodeAndGameServerForRequest(w, req)
					if ok && (gotRole != test.wantRole || server.ID != test.ref) {
						t.Errorf("resource binding: got server %s role %s, want %s %s", server.ID, gotRole, test.ref, test.wantRole)
					}
				}, http.MethodGet, base, test.userID, "", test.ref)
				wantStatus := http.StatusOK
				if test.wantRole == "" {
					wantStatus = http.StatusNotFound
				}
				if response.Code != wantStatus {
					t.Fatalf("node role %s user %s server %s: got %d, want %d", role, test.userID, test.ref, response.Code, wantStatus)
				}
			}
			if role == "admin" {
				continue
			}
			for _, action := range []struct {
				name    string
				handler http.HandlerFunc
			}{
				{"delete", api.handleDeleteGameServer},
				{"players", api.handleVelocityPlayers},
				{"files", api.handleWriteGameServerFile},
				{"databases", api.handleGameServerDatabases},
				{"secrets", api.handleListGameServerSecrets},
				{"invites", api.handleCreateGameServerInvite},
				{"exec session", api.handleGameServerConsoleExecSessionCreate},
				{"exec input", api.handleGameServerConsoleExecInput},
			} {
				response := request(t, action.handler, http.MethodPost, base, "guest", `{}`)
				if response.Code != http.StatusForbidden {
					t.Errorf("%s %s: got %d, want 403: %s", role, action.name, response.Code, response.Body.String())
				}
			}
			if role == "viewer" {
				response := request(t, api.handleStartGameServer, http.MethodPost, base, "guest", "")
				if response.Code != http.StatusForbidden {
					t.Errorf("viewer start: got %d, want 403", response.Code)
				}
			}
		}
	})

	t.Run("invite email expiry replay and binding", func(t *testing.T) {
		exec(t, `DELETE FROM "GameServerGuest"; DELETE FROM "WorkerNodeGuest";
INSERT INTO "GameServerInvite" ("id","serverId","inviterUserId","email","permission","expiresAt") VALUES
('audit-valid','server','owner','GUEST@example.com','operator',NOW()+interval '1 day'),
('audit-expired','server','owner','other@example.com','admin',NOW()-interval '1 second'),
('audit-sibling','sibling','owner','guest@example.com','viewer',NOW()+interval '1 day');`)
		for _, test := range []struct {
			inviteID, userID, body string
			status                 int
		}{
			{"audit-valid", "other", `{"email":"guest@example.com","userId":"guest"}`, http.StatusNotFound},
			{"audit-expired", "other", `{}`, http.StatusNotFound},
			{"missing", "guest", `{}`, http.StatusNotFound},
			{"audit-valid", "guest", `{"email":"other@example.com","permission":"owner","serverId":"sibling"}`, http.StatusOK},
			{"audit-valid", "guest", `{}`, http.StatusNotFound},
		} {
			response := request(t, api.handleAcceptNodeInvite, http.MethodPost, "/api/nodes/invites/{inviteId}/accept", test.userID, test.body, test.inviteID)
			if response.Code != test.status {
				t.Fatalf("invite %s user %s: got %d, want %d: %s", test.inviteID, test.userID, response.Code, test.status, response.Body.String())
			}
		}
		if count(t, `SELECT COUNT(*) FROM "GameServerGuest" WHERE "serverId"='server' AND "userId"='guest' AND "permission"='operator'`) != 1 || count(t, `SELECT COUNT(*) FROM "GameServerGuest"`) != 1 {
			t.Fatal("acceptance granted the wrong role, user or server")
		}
		if count(t, `SELECT COUNT(*) FROM "WorkerNodeGuest" WHERE "nodeId"='node' AND "userId"='guest' AND "permission"='viewer'`) != 1 || count(t, `SELECT COUNT(*) FROM "WorkerNodeGuest"`) != 1 {
			t.Fatal("acceptance did not bind minimal node access to the recipient")
		}
		if count(t, `SELECT COUNT(*) FROM "GameServerInvite" WHERE "id" IN ('audit-expired','audit-sibling') AND "acceptedAt" IS NULL`) != 2 {
			t.Fatal("acceptance consumed an expired or unrelated invitation")
		}
		removed, err := api.Users.RevokeGameServerInvite(ctx, "server", "audit-sibling")
		if err != nil || removed {
			t.Fatalf("cross-server revoke succeeded: removed=%t err=%v", removed, err)
		}
	})

	t.Run("notification recipient isolation", func(t *testing.T) {
		exec(t, `DELETE FROM "Notification" WHERE "userId" IN ('guest','other');
INSERT INTO "Notification" ("id","userId","kind","nodeId","nodeName") VALUES
('audit-guest-notice','guest','server_created','node','Node'),
('audit-other-notice','other','server_created','node','Node');`)
		for _, userID := range []string{"guest", "other"} {
			response := request(t, api.handleListNotifications, http.MethodGet, "/api/notifications", userID, "")
			var payload struct {
				Notifications []notificationMessage `json:"notifications"`
				Unread        int                   `json:"unread"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &payload) != nil || len(payload.Notifications) != 1 || payload.Notifications[0].ID != "audit-"+userID+"-notice" || payload.Unread != 1 {
				t.Fatalf("inbox isolation for %s: %d %s", userID, response.Code, response.Body.String())
			}
		}
		for _, action := range []struct {
			method  string
			path    string
			handler http.HandlerFunc
		}{
			{http.MethodPost, "/api/notifications/{notificationId}/read", api.handleReadNotifications},
			{http.MethodDelete, "/api/notifications/{notificationId}", api.handleDeleteNotifications},
			{http.MethodPost, "/api/notifications/read", api.handleReadNotifications},
			{http.MethodDelete, "/api/notifications", api.handleDeleteNotifications},
		} {
			response := request(t, action.handler, action.method, action.path, "guest", `{"userId":"other"}`, "audit-other-notice")
			if response.Code != http.StatusOK || count(t, `SELECT COUNT(*) FROM "Notification" WHERE "id"='audit-other-notice' AND "readAt" IS NULL`) != 1 {
				t.Fatalf("%s %s crossed recipient boundary: %d %s", action.method, action.path, response.Code, response.Body.String())
			}
		}
		if count(t, `SELECT COUNT(*) FROM "Notification" WHERE "userId"='guest'`) != 0 {
			t.Fatal("own inbox was not cleared")
		}
	})
}

func TestPermissionsAuditNotificationDeleteRoles(t *testing.T) {
	for _, path := range []string{"/api/notifications", "/api/notifications/{notificationId}"} {
		roles := accessRoles(http.MethodDelete, path)
		for _, role := range []string{RoleUser, RoleAdmin, RoleEditor, RolePublic, "", "unknown"} {
			want := role == RoleUser || role == RoleAdmin || role == RoleEditor
			if got := roleAllowed(roles, role); got != want {
				t.Errorf("DELETE %s role %q: got %t, want %t", path, role, got, want)
			}
		}
	}
}
