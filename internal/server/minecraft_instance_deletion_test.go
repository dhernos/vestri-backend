package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"yourapp/internal/auth"
)

func testMinecraftInstanceDeletionDatabase(t *testing.T, ctx context.Context, api *Server, database *pgxpool.Pool) {
	t.Helper()
	redisAddress := os.Getenv("VESTRI_MINECRAFT_TEST_REDIS_ADDR")
	if redisAddress == "" {
		t.Skip("set VESTRI_MINECRAFT_TEST_REDIS_ADDR to a disposable Redis for deletion handler tests")
	}
	api.Redis = redis.NewClient(&redis.Options{Addr: redisAddress})
	t.Cleanup(func() { _ = api.Redis.Close() })
	if err := api.Redis.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	spec := testMinecraftMinigameSpec(t)
	spec.ParentID = "proxy"
	rawSpec, _ := json.Marshal(spec)
	resource := auth.MinecraftResource{ID: "delete-template", NodeID: "node", Kind: "templates", Name: "Delete Game", Spec: rawSpec}
	if err := api.Users.CreateMinecraftResource(ctx, resource); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(ctx, `INSERT INTO "User" ("id","name","email") VALUES ('other-owner','Other','other-minigame@example.com');
INSERT INTO "WorkerNodeGuest" ("id","nodeId","userId","permission") VALUES ('other-admin','node','other-owner','admin');
INSERT INTO "WorkerNode" ("id","slug","name","baseUrl","apiKey","ownerUserId") VALUES ('other-node','other-node','Other','http://localhost','test-key','owner');`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(ctx, `INSERT INTO "MinecraftResource" ("id","nodeId","kind","name","spec") VALUES ('other-template','node','templates','Other',$1), ('other-node-template','other-node','templates','Other node',$1)`, rawSpec); err != nil {
		t.Fatal(err)
	}
	token := "vmc_" + strings.Repeat("a", 64)
	otherToken := "vmc_" + strings.Repeat("b", 64)
	otherUserToken := "vmc_" + strings.Repeat("d", 64)
	otherTemplateToken := "vmc_" + strings.Repeat("e", 64)
	otherNodeToken := "vmc_" + strings.Repeat("f", 64)
	for index, credential := range []string{token, otherToken, otherUserToken, otherTemplateToken, otherNodeToken} {
		keyID := []string{"delete-key", "other-key", "other-user-key", "other-template-key", "other-node-key"}[index]
		digest, _ := minecraftAPIKeyDigest(credential)
		key := auth.MinecraftAPIKey{ID: keyID, NodeID: "node", TemplateID: resource.ID, UserID: "owner", Name: keyID, ExpiresAt: time.Now().Add(time.Hour)}
		if index == 2 {
			key.UserID = "other-owner"
		}
		if index == 3 {
			key.TemplateID = "other-template"
		}
		if index == 4 {
			key.NodeID, key.TemplateID = "other-node", "other-node-template"
		}
		if err := api.Users.CreateMinecraftAPIKey(ctx, key, digest); err != nil {
			t.Fatal(err)
		}
		if err := api.Redis.Del(ctx, "minecraft:rate:"+keyID).Err(); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := "proxy/data/plugins/vestri-dynamic/vestri-dynamic-servers.json"
	for _, scenario := range []string{"reload_failure", "corrupt_survivor", "canceled_postcommit", "stop_failure", "api_delete", "dashboard_minigame", "legacy_dashboard_minigame"} {
		t.Run(scenario, func(t *testing.T) {
			if err := api.Redis.Del(ctx, "minecraft:rate:delete-key", "minecraft:rate:other-key", "minecraft:rate:other-user-key", "minecraft:rate:other-template-key", "minecraft:rate:other-node-key").Err(); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(ctx, `DELETE FROM "GameServer" WHERE "id" IN ('removed','survivor');
INSERT INTO "GameServer" ("id","nodeId","slug","name","templateId","stackName","rootPath","composePath","createdByUserId","metadata") VALUES
('removed','node','removed-slug','Removed-1','paper','removed','removed','removed/docker-compose.yml','owner','{"parentServerId":"proxy","connectHost":"removed","connectPort":25565}'),
('survivor','node','survivor-slug','Survivor-1','paper','survivor','survivor','survivor/docker-compose.yml','owner','{"parentServerId":"proxy","connectHost":"survivor","connectPort":25565}');
INSERT INTO "MinecraftInstance" ("serverId","nodeId","templateId","keyId","requestId") VALUES
('removed','node','delete-template','delete-key','removed-request'),
('survivor','node','delete-template','delete-key','survivor-request');`); err != nil {
				t.Fatal(err)
			}
			requestCtx, cancelRequest := context.WithCancel(ctx)
			defer cancelRequest()
			config, _ := json.Marshal(minecraftMinigameConfig{Slug: "survivor-slug", Token: strings.Repeat("c", 64), ControlURL: "http://" + velocityBackendHostForSlug("proxy") + ":25580", Spec: spec.Minigame})
			files := map[string]string{
				"proxy/data/velocity.toml":                                 "[servers]\nremoved-slug = \"removed:25565\"\nsurvivor-slug = \"survivor:25565\"\ntry = [\"removed-slug\", \"survivor-slug\"]\n",
				path.Join("removed", minecraftMinigameConfigRelativePath):  "corrupt deleted instance config",
				path.Join("survivor", minecraftMinigameConfigRelativePath): string(config),
				manifestPath: `{"authoritative":false,"servers":{"removed-slug":{}}}`,
			}
			delegated := scenario == "dashboard_minigame" || scenario == "legacy_dashboard_minigame"
			if delegated {
				if _, err := database.Exec(ctx, `UPDATE "MinecraftInstance" SET "keyId"=NULL WHERE "serverId"='removed'`); err != nil {
					t.Fatal(err)
				}
				if scenario == "dashboard_minigame" {
					if _, err := database.Exec(ctx, `UPDATE "GameServer" SET "metadata"="metadata" || '{"minecraftMode":"minigames"}'::jsonb WHERE "id"='removed'`); err != nil {
						t.Fatal(err)
					}
				} else {
					legacyConfig, _ := json.Marshal(minecraftMinigameConfig{Slug: "removed-slug", Token: strings.Repeat("c", 64), ControlURL: "http://" + velocityBackendHostForSlug("proxy") + ":25580", Spec: spec.Minigame})
					files[path.Join("removed", minecraftMinigameConfigRelativePath)] = string(legacyConfig)
				}
			}
			failReload, corruptSurvivor := scenario == "reload_failure", scenario == "corrupt_survivor"
			deletedFiles, manifestWrites, reloads := false, 0, 0
			operations := []string{}
			httpWorker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				operations = append(operations, request.Method+" "+request.URL.Path)
				switch request.Method + " " + request.URL.Path {
				case "GET /databases":
					_, _ = w.Write([]byte(`{"databases":[]}`))
				case "POST /stack/down":
					if scenario == "stop_failure" {
						http.Error(w, "private worker body "+token, http.StatusBadGateway)
					}
				case "GET /fs/read":
					filename := request.URL.Query().Get("path")
					if strings.HasPrefix(filename, "removed/") && !delegated {
						t.Error("deletion sync read the removed instance config")
					}
					if strings.HasPrefix(filename, "survivor/") {
						removed, err := api.Users.FindGameServerByRefForNode(ctx, "node", "removed")
						if err != nil || removed != nil || !deletedFiles {
							t.Error("manifest read preceded file/DB deletion")
						}
						if scenario == "canceled_postcommit" {
							cancelRequest()
						}
						if corruptSurvivor {
							_, _ = w.Write([]byte(`{"token":"` + strings.Repeat("c", 64) + `","spec":{}}`))
							return
						}
					}
					if content, found := files[filename]; found {
						_, _ = w.Write([]byte(content))
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				case "GET /fs/list":
					_ = json.NewEncoder(w).Encode([]satisfactoryWorkerEntry{})
				case "POST /fs/write", "POST /fs/delete":
					var body struct {
						Path, Content string
						Recursive     bool
					}
					if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if request.URL.Path == "/fs/delete" {
						if body.Path != "removed" || !body.Recursive {
							t.Errorf("unexpected delete path %q", body.Path)
						}
						deletedFiles = true
						delete(files, path.Join("removed", minecraftMinigameConfigRelativePath))
					} else {
						files[body.Path] = body.Content
						if body.Path == manifestPath {
							manifestWrites++
						}
					}
				case "POST /stack/velocity/reload":
					var committedManifest struct {
						Authoritative bool
						Servers       map[string]json.RawMessage
					}
					if err := json.Unmarshal([]byte(files[manifestPath]), &committedManifest); err != nil || !committedManifest.Authoritative || len(committedManifest.Servers) != 1 || committedManifest.Servers["survivor-slug"] == nil || committedManifest.Servers["removed-slug"] != nil {
						t.Error("first postcommit/retry manifest retained the removed instance or lacked authority")
					}
					reloads++
					if failReload {
						http.Error(w, "private reload body "+token, http.StatusBadGateway)
					}
				default:
					t.Errorf("unexpected worker operation %s %s", request.Method, request.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer httpWorker.Close()
			if _, err := database.Exec(ctx, `UPDATE "WorkerNode" SET "baseUrl"=$1 WHERE "id"='node'`, httpWorker.URL); err != nil {
				t.Fatal(err)
			}
			router := chi.NewRouter()
			router.Delete("/nodes/{nodeRef}/servers/{serverRef}", api.handleDeleteGameServer)
			router.Post("/nodes/{nodeRef}/minecraft/proxies/{proxyRef}/sync", api.handleSyncMinecraftProxy)
			router.With(api.requireMinecraftAPIKey).Delete("/api/minecraft/v1/instances/{instanceId}", api.handleDeleteMinecraftInstance)
			router.With(api.requireMinecraftAPIKey).Post("/api/minecraft/v1/instances/{instanceId}/stop", api.handleStopMinecraftInstance)
			router.With(api.requireMinecraftAPIKey).Post("/api/minecraft/v1/instances/{instanceId}/start", api.handleStartMinecraftInstance)
			router.With(api.requireMinecraftAPIKey).Get("/api/minecraft/v1/instances", api.handleListMinecraftAPIInstances)
			apiRequest := func(method, target, credential string) *httptest.ResponseRecorder {
				request := httptest.NewRequest(method, "/api/minecraft/v1/instances"+target, nil)
				request.Header.Set("Authorization", "Bearer "+credential)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				return response
			}
			apiDelete := func(id, credential string) *httptest.ResponseRecorder {
				request := httptest.NewRequest(http.MethodDelete, "/api/minecraft/v1/instances/"+id, nil)
				request.Header.Set("Authorization", "Bearer "+credential)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				return response
			}
			before := len(operations)
			deniedToken := otherToken
			if delegated {
				deniedToken = otherUserToken
			}
			if response := apiDelete("removed", deniedToken); response.Code != http.StatusForbidden {
				t.Fatalf("foreign-key instance: HTTP %d", response.Code)
			}
			if response := apiDelete("unknown", token); response.Code != http.StatusNotFound {
				t.Fatalf("absent instance: HTTP %d", response.Code)
			}
			if len(operations) != before {
				t.Fatal("denied/absent API delete touched worker")
			}
			if delegated {
				for _, credential := range []string{otherUserToken, otherTemplateToken} {
					for _, action := range []string{"start", "stop"} {
						if response := apiRequest(http.MethodPost, "/removed/"+action, credential); response.Code != http.StatusForbidden {
							t.Fatalf("denied %s: HTTP %d", action, response.Code)
						}
					}
					if response := apiDelete("removed", credential); response.Code != http.StatusForbidden {
						t.Fatalf("denied creator/template delete: HTTP %d", response.Code)
					}
				}
				if response := apiDelete("removed", otherNodeToken); response.Code != http.StatusNotFound {
					t.Fatalf("foreign node delete: HTTP %d", response.Code)
				}
				if len(operations) != before {
					t.Fatal("foreign delegation touched worker")
				}
				if response := apiRequest(http.MethodGet, "", otherToken); response.Code != http.StatusOK || strings.Contains(response.Body.String(), "removed") {
					t.Fatal("list exposed delegated dashboard instance")
				}
				if scenario == "dashboard_minigame" {
					if _, err := database.Exec(ctx, `UPDATE "GameServer" SET "metadata"="metadata" || '{"minecraftMode":"player"}'::jsonb WHERE "id"='removed'`); err != nil {
						t.Fatal(err)
					}
					if response := apiDelete("removed", token); response.Code != http.StatusForbidden || len(operations) != before {
						t.Fatal("ordinary dashboard instance became delegated")
					}
					if _, err := database.Exec(ctx, `UPDATE "GameServer" SET "metadata"="metadata" || '{"minecraftMode":"minigames"}'::jsonb WHERE "id"='removed'`); err != nil {
						t.Fatal(err)
					}
				}
				if response := apiRequest(http.MethodPost, "/removed/stop", otherToken); response.Code != http.StatusOK {
					t.Fatalf("same-creator replacement key stop: HTTP %d", response.Code)
				}
				if _, err := database.Exec(ctx, `UPDATE "GameServer" SET "createdByUserId"='other-owner' WHERE "id"='removed'`); err != nil {
					t.Fatal(err)
				}
				if response := apiRequest(http.MethodPost, "/removed/stop", otherUserToken); response.Code != http.StatusOK {
					t.Fatalf("same-creator node admin stop: HTTP %d", response.Code)
				}
				if _, err := database.Exec(ctx, `UPDATE "WorkerNodeGuest" SET "permission"='viewer' WHERE "id"='other-admin'`); err != nil {
					t.Fatal(err)
				}
				beforeRevoked := len(operations)
				if response := apiDelete("removed", otherUserToken); response.Code != http.StatusForbidden {
					t.Fatalf("revoked admin delete: HTTP %d", response.Code)
				}
				if response := apiRequest(http.MethodPost, "/removed/stop", otherUserToken); response.Code != http.StatusForbidden || len(operations) != beforeRevoked {
					t.Fatal("revoked admin power reached worker")
				}
				if _, err := database.Exec(ctx, `UPDATE "WorkerNodeGuest" SET "permission"='admin' WHERE "id"='other-admin'; UPDATE "GameServer" SET "createdByUserId"='owner' WHERE "id"='removed'`); err != nil {
					t.Fatal(err)
				}
			}
			request := httptest.NewRequest(http.MethodDelete, "/nodes/node/servers/removed-slug", nil)
			request = request.WithContext(context.WithValue(requestCtx, sessionContextKey, &auth.Session{UserID: "owner"}))
			response := httptest.NewRecorder()
			if scenario == "api_delete" || delegated {
				response = apiDelete("removed", token)
			} else {
				router.ServeHTTP(response, request)
			}
			if strings.Contains(response.Body.String(), token) || strings.Contains(response.Body.String(), strings.Repeat("c", 64)) {
				t.Fatal("delete response exposed private credentials")
			}
			var result struct{ Committed bool }
			_ = json.Unmarshal(response.Body.Bytes(), &result)
			removed, err := api.Users.FindGameServerByRefForNode(ctx, "node", "removed")
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "stop_failure" {
				if response.Code != http.StatusBadGateway || result.Committed || removed == nil || deletedFiles || manifestWrites != 0 || reloads != 0 {
					t.Fatal("failed stop claimed a commit or destroyed/synchronized instance")
				}
				return
			}
			wantStatus := http.StatusNoContent
			if failReload || corruptSurvivor {
				wantStatus = http.StatusBadGateway
			}
			if response.Code != wantStatus || result.Committed != (wantStatus == http.StatusBadGateway) || removed != nil || !deletedFiles {
				t.Fatalf("incorrect postcommit delete state: HTTP %d committed=%t removed=%t filesDeleted=%t", response.Code, result.Committed, removed == nil, deletedFiles)
			}
			instances, err := api.Users.ListMinecraftInstances(ctx, "node")
			if err != nil || len(instances) != 1 || instances[0].ServerID != "survivor" {
				t.Fatal("instance row was not cascade-deleted", err)
			}
			if corruptSurvivor && (manifestWrites != 0 || reloads != 0) {
				t.Fatal("corrupt survivor produced a partial authoritative manifest")
			}
			if scenario == "canceled_postcommit" && requestCtx.Err() == nil {
				t.Fatal("test did not cancel the request during postcommit sync")
			}
			before = len(operations)
			if retry := apiDelete("removed", token); retry.Code != http.StatusNotFound || len(operations) != before {
				t.Fatal("committed API delete retry was not a side-effect-free 404")
			}
			failReload, corruptSurvivor = false, false
			recovery := httptest.NewRequest(http.MethodPost, "/nodes/node/minecraft/proxies/proxy/sync", nil)
			recovery = recovery.WithContext(context.WithValue(ctx, sessionContextKey, &auth.Session{UserID: "owner"}))
			recovered := httptest.NewRecorder()
			router.ServeHTTP(recovered, recovery)
			if recovered.Code != http.StatusNoContent {
				t.Fatalf("manual sync recovery: HTTP %d", recovered.Code)
			}
			var manifest struct {
				Authoritative bool
				Servers       map[string]json.RawMessage
			}
			if err := json.Unmarshal([]byte(files[manifestPath]), &manifest); err != nil || !manifest.Authoritative || len(manifest.Servers) != 1 || manifest.Servers["survivor-slug"] == nil || manifest.Servers["removed-slug"] != nil {
				t.Fatal("recovery snapshot was not complete and authoritative", err)
			}
			if strings.Contains(files["proxy/data/velocity.toml"], "removed-slug") {
				t.Fatal("deleted instance remains registered in Velocity TOML")
			}
			oldManifest, oldWrites := files[manifestPath], manifestWrites
			if _, err := database.Exec(ctx, `ALTER TABLE "MinecraftInstance" RENAME TO "MinecraftInstanceUnavailable"`); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := database.Exec(context.Background(), `ALTER TABLE "MinecraftInstanceUnavailable" RENAME TO "MinecraftInstance"`); err != nil {
					t.Error(err)
				}
			}()
			unknown := apiDelete("unknown", token)
			if unknown.Code != http.StatusInternalServerError || strings.Contains(unknown.Body.String(), "committed") {
				t.Fatal("unknown database error was treated as absent or committed")
			}
			recoveryResponse := httptest.NewRecorder()
			router.ServeHTTP(recoveryResponse, recovery)
			if recoveryResponse.Code != http.StatusBadGateway || files[manifestPath] != oldManifest || manifestWrites != oldWrites {
				t.Fatal("failed snapshot query published false authority")
			}
		})
	}
}

func TestMinecraftMinigameIncompleteManifest(t *testing.T) {
	worker, operations := minecraftMinigameTestWorker(t, map[string]string{}, false)
	parent := &auth.GameServer{ID: "proxy", Slug: "proxy"}
	instance := auth.MinecraftInstance{ServerID: "missing"}
	for _, servers := range [][]auth.GameServer{nil, {{ID: "missing", Slug: "missing", Metadata: json.RawMessage(`{}`)}}} {
		manifest, err := buildMinecraftProxyManifest(context.Background(), worker, parent, nil, []auth.MinecraftInstance{instance}, servers, "")
		if err == nil || manifest != nil || len(*operations) != 0 {
			t.Fatal("incomplete snapshot produced an authoritative manifest")
		}
	}
}
