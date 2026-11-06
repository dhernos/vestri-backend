package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"yourapp/internal/auth"
)

func TestVelocityPluginDataDirectory(t *testing.T) {
	const legacy = "proxy/data"
	const migrated = "proxy/data/plugins/vestri-dynamic"
	for _, test := range []struct {
		name   string
		root   []satisfactoryWorkerEntry
		plugin []satisfactoryWorkerEntry
		want   string
		status int
	}{
		{name: "fresh installation", want: migrated},
		{name: "migrated config", plugin: []satisfactoryWorkerEntry{{Name: "vestri-dynamic-config.json", Type: "file"}}, want: migrated},
		{name: "migrated journal overrides stale root", root: []satisfactoryWorkerEntry{{Name: "vestri-player-policy.json", Type: "file"}}, plugin: []satisfactoryWorkerEntry{{Name: "vestri-players.json", Type: "file"}}, want: migrated},
		{name: "empty new folder must not divert legacy config", root: []satisfactoryWorkerEntry{{Name: "vestri-dynamic-config.json", Type: "file"}}, plugin: []satisfactoryWorkerEntry{}, want: legacy},
		{name: "precreated manifest must not divert legacy policy", root: []satisfactoryWorkerEntry{{Name: "vestri-player-policy.json", Type: "file"}}, plugin: []satisfactoryWorkerEntry{{Name: "vestri-dynamic-servers.json", Type: "file"}}, want: legacy},
		{name: "listing error", status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/fs/list" {
					t.Errorf("unexpected mutation or endpoint: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if test.status != 0 {
					w.WriteHeader(test.status)
					return
				}
				var entries []satisfactoryWorkerEntry
				switch r.URL.Query().Get("path") {
				case legacy:
					entries = test.root
				case migrated:
					entries = test.plugin
				default:
					t.Errorf("unexpected listing: %s", r.URL)
				}
				if entries == nil {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(entries)
			}))
			defer worker.Close()
			baseURL, _ := url.Parse(worker.URL)
			got, err := (&Server{}).velocityPluginDataDirectory(context.Background(), baseURL, "key", "proxy")
			if (err != nil) != (test.status != 0) || got != test.want {
				t.Fatalf("got %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestVelocityPluginDataLegacyArtifacts(t *testing.T) {
	for _, name := range []string{"vestri-dynamic-config.json", "vestri-dynamic-servers.json", "vestri-player-servers.json", "vestri-players.json", "vestri-player-policy.json", "vestri-player-logs"} {
		t.Run(name, func(t *testing.T) {
			worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/fs/list" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				if r.URL.Query().Get("path") == "proxy/data" {
					entryType := "file"
					if name == "vestri-player-logs" {
						entryType = "dir"
					}
					_ = json.NewEncoder(w).Encode([]satisfactoryWorkerEntry{{Name: name, Type: entryType}})
					return
				}
				_ = json.NewEncoder(w).Encode([]satisfactoryWorkerEntry{})
			}))
			defer worker.Close()
			baseURL, _ := url.Parse(worker.URL)
			got, err := (&Server{}).velocityPluginDataDirectory(context.Background(), baseURL, "key", "proxy")
			if err != nil || got != "proxy/data" {
				t.Fatalf("legacy artifact ignored: %q, %v", got, err)
			}
		})
	}
}

func TestVelocityPluginDataEndpoints(t *testing.T) {
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
	schema := "velocity_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	if _, err := database.Exec(ctx, `INSERT INTO "User" ("id","name","email") VALUES ('owner','Owner','velocity@example.com');
INSERT INTO "WorkerNode" ("id","slug","name","baseUrl","apiKey","ownerUserId") VALUES ('node','node','Node','http://localhost','test-key','owner');
INSERT INTO "GameServer" ("id","nodeId","slug","name","templateId","stackName","rootPath","composePath","createdByUserId","metadata") VALUES
('proxy','node','proxy','Proxy','velocity','proxy','proxy','proxy/docker-compose.yml','owner','{"kind":"velocity"}'),
('child','node','child','Child','paper','child','child','child/docker-compose.yml','owner','{"parentServerId":"proxy","connectHost":"child","connectPort":25565}');
INSERT INTO "MinecraftResource" ("id","nodeId","kind","name") VALUES ('template','node','templates','Template');
INSERT INTO "MinecraftInstance" ("serverId","nodeId","templateId","requestId") VALUES ('child','node','template','request');`); err != nil {
		t.Fatal(err)
	}
	api := &Server{Users: auth.NewUserRepository(database)}
	for _, test := range []struct {
		name      string
		directory string
		fresh     bool
		staleRoot bool
		emptyNew  bool
		failList  bool
	}{
		{name: "migrated", directory: "proxy/data/plugins/vestri-dynamic"},
		{name: "legacy", directory: "proxy/data"},
		{name: "fresh", directory: "proxy/data/plugins/vestri-dynamic", fresh: true},
		{name: "legacy with empty new directory", directory: "proxy/data", emptyNew: true},
		{name: "migrated with stale root", directory: "proxy/data/plugins/vestri-dynamic", staleRoot: true},
		{name: "listing failure prevents writes", directory: "proxy/data", failList: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := map[string]string{"proxy/data/velocity.toml": "[servers]\n"}
			policyPath := path.Join(test.directory, "vestri-player-policy.json")
			journalPath := path.Join(test.directory, "vestri-players.json")
			manifestPath := path.Join(test.directory, "vestri-dynamic-servers.json")
			if !test.fresh {
				files[policyPath] = `{"whitelistEnabled":false,"whitelist":[],"bans":[],"ipBans":["127.0.0.2"]}`
				files[journalPath] = `{"players":[{"name":"Present"}],"attempts":[],"policyHealthy":true}`
			}
			if test.staleRoot {
				files["proxy/data/vestri-player-policy.json"] = "invalid stale policy"
			}
			writes, reloads := 0, 0
			reads := map[string]int{}
			worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /fs/list":
					if test.failList {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					directory := r.URL.Query().Get("path")
					entries := []satisfactoryWorkerEntry{}
					for filename := range files {
						if path.Dir(filename) == directory {
							entries = append(entries, satisfactoryWorkerEntry{Name: path.Base(filename), Type: "file"})
						}
					}
					if len(entries) == 0 && !test.emptyNew {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					_ = json.NewEncoder(w).Encode(entries)
				case "GET /fs/read":
					filename := r.URL.Query().Get("path")
					if filename != policyPath && filename != journalPath && filename != "proxy/data/velocity.toml" {
						t.Errorf("unexpected read path: %s", filename)
					}
					reads[filename]++
					if content, found := files[filename]; found {
						_, _ = w.Write([]byte(content))
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				case "POST /fs/write":
					var request struct {
						Path    string
						Content string
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
					}
					if request.Path != policyPath && request.Path != manifestPath {
						t.Errorf("unexpected write path: %s", request.Path)
					}
					files[request.Path] = request.Content
					writes++
				case "POST /stack/velocity/reload":
					var request struct{ Stack string }
					_ = json.NewDecoder(r.Body).Decode(&request)
					if request.Stack != "proxy" || files[manifestPath] == "" {
						t.Error("reload did not follow proxy manifest write")
					}
					reloads++
				default:
					t.Errorf("unexpected endpoint or directory creation: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer worker.Close()
			if _, err := database.Exec(ctx, `UPDATE "WorkerNode" SET "baseUrl"=$1 WHERE "id"='node'`, worker.URL); err != nil {
				t.Fatal(err)
			}
			router := chi.NewRouter()
			router.Get("/nodes/{nodeRef}/servers/{serverRef}/players", api.handleVelocityPlayers)
			router.Post("/nodes/{nodeRef}/servers/{serverRef}/players", api.handleVelocityPlayers)
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				request := httptest.NewRequest(method, "/nodes/node/servers/proxy/players", strings.NewReader(`{"action":"whitelist-enable","enabled":true}`))
				request = request.WithContext(context.WithValue(ctx, sessionContextKey, &auth.Session{UserID: "owner"}))
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if test.failList {
					if response.Code != http.StatusBadGateway {
						t.Fatalf("listing failure: %d %s", response.Code, response.Body)
					}
					continue
				}
				if response.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", method, response.Code, response.Body)
				}
				var result struct {
					Available bool
					Players   []json.RawMessage
					Policy    velocityPlayerPolicy
				}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Available == test.fresh || (!test.fresh && (len(result.Players) != 1 || len(result.Policy.IPBans) != 1)) || result.Policy.WhitelistEnabled != (method == http.MethodPost) {
					t.Fatalf("unexpected player response: %s", response.Body)
				}
			}
			baseURL, _ := url.Parse(worker.URL)
			parent, err := api.Users.FindGameServerByRefForNode(ctx, "node", "proxy")
			if err != nil {
				t.Fatal(err)
			}
			err = api.syncMinecraftProxy(ctx, pluginWorker{server: api, baseURL: baseURL, apiKey: "test-key"}, "node", parent, "")
			if test.failList {
				if err == nil || writes != 0 || reloads != 0 || len(reads) != 0 {
					t.Fatalf("listing failure permitted IO: %v, writes=%d reloads=%d reads=%v", err, writes, reloads, reads)
				}
				return
			}
			if err != nil || writes != 2 || reloads != 1 || reads[policyPath] != 2 || reads[journalPath] != 2 {
				t.Fatalf("unexpected IO: %v, writes=%d reloads=%d reads=%v", err, writes, reloads, reads)
			}
			var manifest struct {
				Servers map[string]struct {
					Host string
					Port int
				}
			}
			if err := json.Unmarshal([]byte(files[manifestPath]), &manifest); err != nil || manifest.Servers["child"].Host != "child" || manifest.Servers["child"].Port != 25565 {
				t.Fatalf("invalid manifest: %s (%v)", files[manifestPath], err)
			}
		})
	}
}
