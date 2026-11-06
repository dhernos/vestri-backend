package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"yourapp/internal/auth"
)

func TestNotificationReleaseRoutes(t *testing.T) {
	api := &Server{}
	wanted := map[string]bool{
		"DELETE /api/notifications":                                           false,
		"DELETE /api/notifications/{notificationId}":                          false,
		"POST /api/notifications/read":                                        false,
		"POST /api/notifications/{notificationId}/read":                       false,
		"PATCH /api/nodes/{nodeRef}/servers/{serverRef}/guests/{guestUserId}": false,
	}
	err := chi.Walk(api.Router().(chi.Routes), func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		if _, exists := wanted[key]; exists {
			wanted[key] = true
			if len(accessRoles(method, route)) == 0 {
				t.Errorf("missing access rule for %s", key)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for route, found := range wanted {
		if !found {
			t.Errorf("missing compatible route %s", route)
		}
	}
}

func TestNotificationReleaseDatabase(t *testing.T) {
	databaseURL := os.Getenv("VESTRI_NOTIFICATION_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set VESTRI_NOTIFICATION_TEST_DATABASE_URL to a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "notification_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error(err)
		}
	}()
	configuration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ConnConfig.RuntimeParams["search_path"] = schema
	configuration.MaxConns = 8
	database, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := database.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	applyMigration := func(name string) {
		t.Helper()
		content, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		exec(string(content))
	}
	for _, migration := range []string{"000007_consolidated_schema.up.sql", "000008_minecraft_templates.up.sql", "000009_notifications.up.sql", "000010_notification_inbox_always.up.sql", "000011_notification_release.up.sql"} {
		applyMigration(migration)
	}
	applyMigration("000011_notification_release.down.sql")
	exec(`INSERT INTO "User" ("id", "name", "email") VALUES ('owner','Owner','owner@example.com'),('guest','Guest','guest@example.com'),('other','Other','other@example.com');
INSERT INTO "NotificationSettings" ("userId", "events", "emailEnabled", "webhookEnabled") VALUES ('guest','{"server_down":false,"server_role_changed":false}',true,true);
INSERT INTO "Notification" ("id","userId","kind","nodeId","nodeName","createdAt")
SELECT 'legacy-' || lpad(sequence::text,4,'0'), 'other','server_created','node','Node','2026-01-01'::timestamptz FROM generate_series(1,510) sequence;`)
	applyMigration("000011_notification_release.up.sql")
	count := func(query string, args ...any) int {
		t.Helper()
		var result int
		if err := database.QueryRow(ctx, query, args...).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if count(`SELECT COUNT(*) FROM "Notification" WHERE "userId"='other'`) != 500 || count(`SELECT COUNT(*) FROM "Notification" WHERE "id"='legacy-0010'`) != 0 {
		t.Fatal("migration did not prune oldest legacy notifications deterministically")
	}
	if count(`SELECT COUNT(*) FROM "NotificationSettings" WHERE "userId"='guest' AND "events"->>'server_down'='false' AND "events"->>'server_role_changed'='false' AND "events"->>'server_access_removed'='true'`) != 1 {
		t.Fatal("migration did not preserve preferences or default new kinds")
	}
	exec(`INSERT INTO "WorkerNode" ("id","slug","name","baseUrl","apiKey","ownerUserId") VALUES ('node','node','Node','https://example.com','','owner');
INSERT INTO "GameServer" ("id","nodeId","slug","name","templateId","stackName","rootPath","composePath","createdByUserId") VALUES ('server','node','server','Server','paper','stack','/server','/server/compose.yml','owner');`)
	repository := auth.NewUserRepository(database)
	api := &Server{Users: repository}

	t.Run("membership and preferences", func(t *testing.T) {
		if err := repository.UpsertGameServerGuest(ctx, "server", "guest", "viewer", "owner"); err != nil {
			t.Fatal(err)
		}
		if err := repository.UpsertGameServerGuest(ctx, "server", "guest", "viewer", "owner"); err != nil {
			t.Fatal(err)
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='server_access_granted' AND "userId"='guest' AND "actorName"='Owner' AND "role"='viewer' AND "emailPending" AND "webhookPending"`) != 1 {
			t.Fatal("grant metadata, recipient, preferences or duplicate suppression incorrect")
		}
		if _, err := repository.UpdateGameServerGuestPermission(ctx, "server", "guest", "operator", "owner"); err != nil {
			t.Fatal(err)
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='server_role_changed' AND "userId"='guest' AND "actorName"='Owner' AND "role"='operator' AND NOT "emailPending" AND NOT "webhookPending"`) != 1 {
			t.Fatal("disabled role event must still reach inbox without external delivery")
		}
		removed, err := repository.RemoveGameServerGuest(ctx, "server", "guest", "owner")
		if err != nil || !removed {
			t.Fatalf("remove failed: %v", err)
		}
		if count(`SELECT COUNT(*) FROM "GameServerGuest" WHERE "userId"='guest'`) != 0 || count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='server_access_removed' AND "userId"='guest' AND "actorName"='Owner' AND "role"='operator' AND "emailPending" AND "webhookPending"`) != 1 {
			t.Fatal("removal notice lost after access disappeared")
		}
		exec(`INSERT INTO "GameServerInvite" ("id","serverId","inviterUserId","email","permission","expiresAt") VALUES ('invite','server','owner','GUEST@example.com','viewer',NOW()+interval '1 day')`)
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='server_invited' AND "userId"='guest' AND "actorName"='Owner' AND "role"='viewer'`) != 1 {
			t.Fatal("invitation not delivered to matching registered user")
		}
		invite, err := repository.AcceptGameServerInvite(ctx, "invite", "guest", "guest@example.com")
		if err != nil || invite == nil {
			t.Fatalf("accept failed: %v", err)
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='server_access_granted' AND "userId"='guest' AND "actorName"='Owner'`) != 2 {
			t.Fatal("acceptance did not retain inviter actor")
		}
		router := chi.NewRouter()
		router.Patch("/api/nodes/{nodeRef}/servers/{serverRef}/guests/{guestUserId}", api.handleUpdateGameServerGuest)
		for _, test := range []struct {
			userID     string
			target     string
			permission string
			status     int
		}{
			{"guest", "guest", "admin", http.StatusForbidden},
			{"owner", "owner", "viewer", http.StatusBadRequest},
			{"owner", "guest", "owner", http.StatusBadRequest},
			{"owner", "missing", "viewer", http.StatusNotFound},
			{"owner", "guest", "admin", http.StatusOK},
			{"owner", "guest", "admin", http.StatusOK},
		} {
			request := httptest.NewRequest(http.MethodPatch, "/api/nodes/node/servers/server/guests/"+test.target, strings.NewReader(fmt.Sprintf(`{"permission":%q}`, test.permission)))
			request = request.WithContext(context.WithValue(request.Context(), sessionContextKey, &auth.Session{UserID: test.userID}))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("role update by %s to %s: got %d, want %d: %s", test.userID, test.target, response.Code, test.status, response.Body.String())
			}
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='server_role_changed' AND "role"='admin'`) != 1 {
			t.Fatal("role endpoint emitted duplicate notices or bypassed permissions")
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "userId"='owner' AND "kind" LIKE 'server_access_%'`) != 0 {
			t.Fatal("membership notice leaked to an unrelated recipient")
		}
	})

	t.Run("reported recovery recipients", func(t *testing.T) {
		node := &auth.WorkerNode{ID: "node", Name: "Node"}
		gameServer := &auth.GameServer{ID: "server", Name: "Server"}
		exec(`INSERT INTO "NotificationHealth" ("kind","resourceId","nodeId","serverId","since","wasHealthy") VALUES ('server_down','server','node','server',NOW()-interval '2 minutes',true)`)
		if err := api.recordNotificationHealth(ctx, node, gameServer, "server_down", true, false); err != nil {
			t.Fatal(err)
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='server_down' AND "userId"='guest' AND NOT "emailPending" AND NOT "webhookPending"`) != 1 {
			t.Fatal("reported outage missing from opted-out recipient inbox")
		}
		if err := api.recordNotificationHealth(ctx, node, gameServer, "server_down", false, false); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.RemoveGameServerGuest(ctx, "server", "guest", "owner"); err != nil {
			t.Fatal(err)
		}
		if err := repository.UpsertGameServerGuest(ctx, "server", "other", "viewer", "owner"); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < 2; index++ {
			if err := api.recordNotificationHealth(ctx, node, gameServer, "server_down", false, true); err != nil {
				t.Fatal(err)
			}
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='server_recovered' AND "userId"='owner'`) != 1 || count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='server_recovered' AND "userId"<>'owner'`) != 0 {
			t.Fatal("recovery duplicated, reached a new member, or leaked after access removal")
		}
		if err := api.recordNotificationHealth(ctx, node, nil, "worker_unhealthy", false, true); err != nil {
			t.Fatal(err)
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='worker_recovered'`) != 0 {
			t.Fatal("first healthy worker generated recovery")
		}
		exec(`UPDATE "NotificationHealth" SET "since"=NOW()-interval '2 minutes' WHERE "kind"='worker_unhealthy'`)
		for _, status := range [][2]bool{{true, false}, {false, false}, {false, true}, {false, true}} {
			if err := api.recordNotificationHealth(ctx, node, nil, "worker_unhealthy", status[0], status[1]); err != nil {
				t.Fatal(err)
			}
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "kind"='worker_recovered' AND "userId"='owner'`) != 1 {
			t.Fatal("worker recovery did not survive unknown checks or was duplicated")
		}
	})

	t.Run("concurrent hard bound", func(t *testing.T) {
		var workers sync.WaitGroup
		failures := make(chan error, 40)
		for index := 0; index < 40; index++ {
			workers.Add(1)
			go func(index int) {
				defer workers.Done()
				_, err := database.Exec(ctx, `INSERT INTO "Notification" ("id","userId","kind","nodeId","nodeName","createdAt") VALUES ($1,'other','server_created','node','Node',$2)`, fmt.Sprintf("concurrent-%04d", index), time.Now())
				if err != nil {
					failures <- err
				}
			}(index)
		}
		workers.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "userId"='other'`) != 500 || count(`SELECT COUNT(*) FROM "Notification" WHERE "id" LIKE 'concurrent-%'`) != 40 {
			t.Fatal("concurrent inserts exceeded cap or evicted recent events")
		}
	})

	t.Run("deletion isolation", func(t *testing.T) {
		router := chi.NewRouter()
		router.Delete("/api/notifications", api.handleDeleteNotifications)
		router.Delete("/api/notifications/{notificationId}", api.handleDeleteNotifications)
		var notificationID string
		if err := database.QueryRow(ctx, `SELECT "id" FROM "Notification" WHERE "userId"='guest' LIMIT 1`).Scan(&notificationID); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodDelete, "/api/notifications/"+notificationID, nil)
		request = request.WithContext(context.WithValue(request.Context(), sessionContextKey, &auth.Session{UserID: "guest"}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK || count(`SELECT COUNT(*) FROM "Notification" WHERE "id"=$1`, notificationID) != 0 || count(`SELECT COUNT(*) FROM "Notification" WHERE "userId"='guest'`) == 0 {
			t.Fatal("single-item deletion failed or cleared the whole inbox")
		}
		for _, path := range []string{"/api/notifications/concurrent-0000", "/api/notifications"} {
			request := httptest.NewRequest(http.MethodDelete, path, nil)
			request = request.WithContext(context.WithValue(request.Context(), sessionContextKey, &auth.Session{UserID: "guest"}))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Body.String() != "{\"ok\":true}\n" {
				t.Fatalf("delete returned %d %s", response.Code, response.Body.String())
			}
		}
		if count(`SELECT COUNT(*) FROM "Notification" WHERE "userId"='guest'`) != 0 || count(`SELECT COUNT(*) FROM "Notification" WHERE "userId"='other'`) != 500 {
			t.Fatal("deletion crossed recipient boundary or failed to clear inbox")
		}
	})
	t.Run("permissions audit", func(t *testing.T) {
		runPermissionsAuditDatabase(t, api, database)
	})
}
