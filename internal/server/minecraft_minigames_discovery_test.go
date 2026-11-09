package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"yourapp/internal/auth"
)

func TestMinecraftMinigameDiscoveryDatabase(t *testing.T) {
	databaseURL := os.Getenv("VESTRI_VELOCITY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set VESTRI_VELOCITY_TEST_DATABASE_URL to a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "minigame_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	configuration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ConnConfig.RuntimeParams["search_path"] = schema
	database, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, migration := range []string{"000007_consolidated_schema.up.sql", "000008_minecraft_templates.up.sql", "000009_notifications.up.sql", "000010_notification_inbox_always.up.sql", "000011_notification_release.up.sql"} {
		content, err := os.ReadFile(filepath.Join("..", "..", "migrations", migration))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(ctx, string(content)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(ctx, `INSERT INTO "User" ("id","name","email") VALUES ('owner','Owner','minigame@example.com');
INSERT INTO "WorkerNode" ("id","slug","name","baseUrl","apiKey","ownerUserId") VALUES ('node','node','Node','http://localhost','test-key','owner');
INSERT INTO "GameServer" ("id","nodeId","slug","name","templateId","stackName","rootPath","composePath","createdByUserId","metadata") VALUES
('proxy','node','proxy','Proxy','velocity','proxy','proxy','proxy/docker-compose.yml','owner','{"kind":"velocity"}');`); err != nil {
		t.Fatal(err)
	}
	api := &Server{Users: auth.NewUserRepository(database)}
	manifestPath := "proxy/data/plugins/vestri-dynamic/vestri-dynamic-servers.json"
	files := map[string]string{}
	reloads := 0
	failReload := false
	httpWorker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "GET /fs/list":
			_ = json.NewEncoder(w).Encode([]satisfactoryWorkerEntry{})
		case "POST /fs/write":
			var body struct{ Path, Content string }
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Path != manifestPath {
				t.Errorf("unexpected write: %s", body.Path)
			}
			files[body.Path] = body.Content
		case "POST /stack/velocity/reload":
			reloads++
			if files[manifestPath] == "" {
				t.Error("reload preceded manifest write")
			}
			if failReload {
				w.WriteHeader(http.StatusBadGateway)
			}
		default:
			t.Errorf("unexpected or destructive worker operation: %s %s", request.Method, request.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer httpWorker.Close()
	baseURL, _ := url.Parse(httpWorker.URL)
	worker := pluginWorker{server: api, baseURL: baseURL, apiKey: "test-key"}
	spec := testMinecraftMinigameSpec(t)
	spec.ParentID = "proxy"
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	resource := auth.MinecraftResource{ID: uuid.NewString(), NodeID: "node", Kind: "templates", Name: "Brand New Game", Spec: raw}
	if err := api.Users.CreateMinecraftResource(ctx, resource); err != nil {
		t.Fatal(err)
	}
	failReload = true
	if err := api.syncMinecraftResourceProxy(ctx, worker, &resource); err == nil {
		t.Fatal("reload failure was accepted")
	}
	saved, err := api.Users.FindMinecraftResource(ctx, "node", resource.ID)
	if err != nil || saved == nil {
		t.Fatal("committed resource lost after failed sync", err)
	}
	failReload = false
	canceledCtx, cancelRequest := context.WithCancel(ctx)
	cancelRequest()
	if err := api.syncMinecraftResourceProxy(canceledCtx, worker, saved); err != nil {
		t.Fatal("post-commit sync did not survive request cancellation", err)
	}
	var manifest struct {
		Minigames map[string]struct{ MaxInstances, ReadyServers int }
		Servers   map[string]json.RawMessage
	}
	if err := json.Unmarshal([]byte(files[manifestPath]), &manifest); err != nil {
		t.Fatal(err)
	}
	game, found := manifest.Minigames[resource.Name]
	if !found || len(manifest.Minigames) != 1 || len(manifest.Servers) != 0 || game.MaxInstances != 3 || game.ReadyServers != 1 || reloads != 2 {
		t.Fatal("brand-new template not discoverable before any spawn", files[manifestPath])
	}
	if err := api.Users.DeleteMinecraftResource(ctx, "node", resource.ID); err != nil {
		t.Fatal(err)
	}
	if err := api.syncMinecraftResourceProxy(ctx, worker, saved); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(files[manifestPath]), &manifest); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(files[manifestPath], resource.Name) || reloads != 3 {
		t.Fatal("deleted template remains discoverable", files[manifestPath])
	}
	t.Run("template_updates_and_variants", func(t *testing.T) {
		testMinecraftMinigameTemplateUpdatesDatabase(t, ctx, api, database)
	})
	t.Run("instance_deletion", func(t *testing.T) {
		testMinecraftInstanceDeletionDatabase(t, ctx, api, database)
	})
}
