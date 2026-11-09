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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"yourapp/internal/auth"
)

func testMinecraftMinigameTemplateUpdatesDatabase(t *testing.T, ctx context.Context, api *Server, database *pgxpool.Pool) {
	t.Helper()
	address := os.Getenv("VESTRI_MINECRAFT_TEST_REDIS_ADDR")
	if address == "" {
		t.Skip("set VESTRI_MINECRAFT_TEST_REDIS_ADDR for template handler tests")
	}
	api.Redis = redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = api.Redis.Close() })
	if err := api.Redis.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(ctx, `INSERT INTO "User" ("id","name","email") VALUES ('template-admin','Admin','template-admin@example.com'),('template-viewer','Viewer','template-viewer@example.com');
INSERT INTO "WorkerNodeGuest" ("id","nodeId","userId","permission") VALUES ('template-admin','node','template-admin','admin'),('template-viewer','node','template-viewer','viewer');`); err != nil {
		t.Fatal(err)
	}
	defer database.Exec(context.Background(), `DELETE FROM "GameServer" WHERE "id"<>'proxy'; DELETE FROM "MinecraftResource" WHERE "nodeId"='node';`)
	spec := testMinecraftMinigameSpec(t)
	spec.ParentID, spec.Software, spec.Version, spec.Jar = "proxy", "PAPER", "1.21.4", "server.jar"
	maxPlayers := 2
	spec.Minigame.Variants = map[string]minecraftMinigameVariant{"duel": {MaxPlayers: &maxPlayers}}
	if err := json.Unmarshal([]byte(minecraftMinigameSenderLifecycleJSON), &spec.Minigame.Lifecycle); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(spec)
	resource := auth.MinecraftResource{ID: uuid.NewString(), NodeID: "node", Kind: "templates", Name: "Editable Game", Spec: raw}
	if err := api.Users.CreateMinecraftResource(ctx, resource); err != nil {
		t.Fatal(err)
	}
	ordinary := auth.MinecraftResource{ID: uuid.NewString(), NodeID: "node", Kind: "templates", Name: "Ordinary Editable", Spec: json.RawMessage(`{"mode":"player"}`)}
	if err := api.Users.CreateMinecraftResource(ctx, ordinary); err != nil {
		t.Fatal(err)
	}
	manifestPath := "proxy/data/plugins/vestri-dynamic/vestri-dynamic-servers.json"
	resourceManifest := path.Join(minecraftResourcePath(&resource), "manifest.json")
	files := map[string]string{"proxy/data/velocity.toml": "[servers]\n"}
	deleted := map[string]bool{}
	mutations, copies, reloads := 0, 0, 0
	failFile, failReload := false, false
	var cancelAfterCommit context.CancelFunc
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			mutations++
		}
		switch request.Method + " " + request.URL.Path {
		case "GET /fs/read":
			content, found := files[request.URL.Query().Get("path")]
			if !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(content))
		case "GET /fs/list":
			if deleted[request.URL.Query().Get("path")] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode([]satisfactoryWorkerEntry{{Name: vestriPluginFilename, Type: "file"}})
		case "POST /fs/write":
			var body struct{ Path, Content string }
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Path == resourceManifest {
				saved, err := api.Users.FindMinecraftResource(ctx, "node", resource.ID)
				if err != nil || saved == nil || string(saved.Spec) == "" {
					t.Error("worker write preceded DB save", err)
				}
				var expected, actual interface{}
				_ = json.Unmarshal(saved.Spec, &expected)
				_ = json.Unmarshal([]byte(body.Content), &actual)
				expectedJSON, _ := json.Marshal(expected)
				actualJSON, _ := json.Marshal(actual)
				if string(expectedJSON) != string(actualJSON) {
					t.Error("DB is not authoritative before file write")
				}
				if cancelAfterCommit != nil {
					cancelAfterCommit()
					cancelAfterCommit = nil
				}
				if failFile {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
			}
			files[body.Path] = body.Content
		case "POST /fs/delete":
			var body struct{ Path string }
			_ = json.NewDecoder(request.Body).Decode(&body)
			deleted[body.Path] = true
			delete(files, body.Path)
		case "POST /fs/transfer", "POST /fs/copy":
			copies++
			var body struct{ Source, Dest string }
			_ = json.NewDecoder(request.Body).Decode(&body)
			if strings.HasSuffix(body.Dest, "/data") {
				files[path.Join(body.Dest, "server.properties")] = "max-players=99\n"
			} else {
				files[body.Dest] = files[body.Source]
			}
		case "POST /fs/mkdir", "POST /stack/up":
			_, _ = w.Write([]byte(`{"output":"ok"}`))
		case "POST /stack/velocity/reload":
			reloads++
			if failReload {
				w.WriteHeader(http.StatusBadGateway)
			}
		default:
			t.Errorf("unexpected worker operation: %s %s", request.Method, request.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer worker.Close()
	if _, err := database.Exec(ctx, `UPDATE "WorkerNode" SET "baseUrl"=$1 WHERE "id"='node'`, worker.URL); err != nil {
		t.Fatal(err)
	}
	const route = "/nodes/{nodeRef}/minecraft/resources/{resourceId}"
	router := chi.NewRouter()
	router.Patch(route, api.handleUpdateMinecraftResource)
	router.Delete(route, api.handleDeleteMinecraftResource)
	router.Post(route+"/spawn", api.handleSpawnMinecraftInstance)
	router.Post("/nodes/{nodeRef}/minecraft/proxies/{proxyRef}/sync", api.handleSyncMinecraftProxy)
	router.With(api.requireMinecraftAPIKey).Post("/api/minecraft/v1/instances", api.handleSpawnMinecraftInstance)
	requestAs := func(requestCtx context.Context, user, method, target, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, target, strings.NewReader(body))
		request = request.WithContext(context.WithValue(requestCtx, sessionContextKey, &auth.Session{UserID: user, Role: RoleUser}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	target := "/nodes/node/minecraft/resources/" + resource.ID
	patch := func(requestCtx context.Context, user string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]interface{}{"minigame": spec.Minigame, "maxInstances": spec.MaxInstances})
		return requestAs(requestCtx, user, http.MethodPatch, target, string(body))
	}
	assertCode := func(response *httptest.ResponseRecorder, code int) {
		t.Helper()
		if response.Code != code {
			t.Fatalf("status=%d want=%d body=%s", response.Code, code, response.Body.String())
		}
	}
	assertCode(patch(ctx, "template-viewer"), http.StatusForbidden)
	assertCode(requestAs(ctx, "owner", http.MethodPatch, "/nodes/foreign/minecraft/resources/"+resource.ID, `{}`), http.StatusNotFound)
	for _, body := range []string{`{}`, `{"minigame":null}`, `{"minigame":{},"parentId":"other"}`, `{"minigame":{},"maxInstances":0}`} {
		assertCode(requestAs(ctx, "owner", http.MethodPatch, target, body), http.StatusBadRequest)
	}
	assertCode(requestAs(ctx, "owner", http.MethodPatch, "/nodes/node/minecraft/resources/"+ordinary.ID, `{"minigame":{}}`), http.StatusConflict)
	unlock, err := api.lockNodePlugins(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}
	assertCode(patch(ctx, "owner"), http.StatusConflict)
	unlock()
	if mutations != 0 {
		t.Fatal("rejected updates mutated worker")
	}
	for _, list := range []string{"onAllJoined", "teamCommands", "startCommands", "onPlayerJoin"} {
		var invalid map[string]interface{}
		content, _ := json.Marshal(spec.Minigame)
		_ = json.Unmarshal(content, &invalid)
		invalid["lifecycle"].(map[string]interface{})[list] = []interface{}{map[string]interface{}{"command": "say hi", "team": "red", "sender": nil}}
		body, _ := json.Marshal(map[string]interface{}{"minigame": invalid})
		assertCode(requestAs(ctx, "owner", http.MethodPatch, target, string(body)), http.StatusBadRequest)
	}
	assertCode(patch(ctx, "template-admin"), http.StatusOK)
	savedResource, err := api.Users.FindMinecraftResource(ctx, "node", resource.ID)
	if err != nil || savedResource == nil {
		t.Fatal("missing saved PATCH", err)
	}
	for _, content := range []string{string(savedResource.Spec), files[resourceManifest]} {
		var savedSpec minecraftResourceSpec
		if err := json.Unmarshal([]byte(content), &savedSpec); err != nil {
			t.Fatal(err)
		}
		assertMinecraftMinigameSenderLifecycle(t, savedSpec.Minigame.Lifecycle)
	}
	if copies != 0 || reloads != 1 {
		t.Fatal("PATCH copied template files or missed sync")
	}
	var published struct {
		Minigames map[string]minecraftMinigameManifestSpec
	}
	if err := json.Unmarshal([]byte(files[manifestPath]), &published); err != nil {
		t.Fatal(err)
	}
	if published.Minigames[resource.Name].Enabled == nil || !*published.Minigames[resource.Name].Enabled || len(published.Minigames[resource.Name].Variants) != 1 {
		t.Fatal("base and variants not published")
	}
	assertMinecraftMinigameSenderLifecycle(t, published.Minigames[resource.Name].Lifecycle)
	for _, failure := range []string{"file", "reload", "canceled"} {
		spec.Minigame.JoinTimeout = "21s"
		failFile, failReload = failure == "file", failure == "reload"
		requestCtx := ctx
		if failure == "canceled" {
			requestCtx, cancelAfterCommit = context.WithCancel(ctx)
		}
		response := patch(requestCtx, "owner")
		if failure == "canceled" {
			assertCode(response, http.StatusOK)
		} else {
			assertCode(response, http.StatusBadGateway)
			if !strings.Contains(response.Body.String(), `"committed":true`) {
				t.Fatal("missing committed response")
			}
		}
		saved, err := api.Users.FindMinecraftResource(ctx, "node", resource.ID)
		if err != nil || !strings.Contains(string(saved.Spec), "21s") {
			t.Fatal("lost committed update", err)
		}
	}
	failFile, failReload = false, false
	if copies != 0 {
		t.Fatal("PATCH copied files")
	}
	beforeFailure := mutations
	if _, err := database.Exec(ctx, `CREATE FUNCTION reject_template_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test update failure'; END $$;
CREATE TRIGGER reject_template_update BEFORE UPDATE ON "MinecraftResource" FOR EACH ROW EXECUTE FUNCTION reject_template_update();`); err != nil {
		t.Fatal(err)
	}
	response := patch(ctx, "owner")
	assertCode(response, http.StatusInternalServerError)
	if !strings.Contains(response.Body.String(), `"committed":false`) || mutations != beforeFailure {
		t.Fatal("DB failure mutated worker or reported commit")
	}
	if _, err := database.Exec(ctx, `DROP TRIGGER reject_template_update ON "MinecraftResource"; DROP FUNCTION reject_template_update();`); err != nil {
		t.Fatal(err)
	}
	if err := api.Users.UpdateMinecraftResourceSpec(ctx, "other-node", resource.ID, raw); err == nil {
		t.Fatal("repository update escaped node binding")
	}
	spec.MaxInstances = 2
	assertCode(patch(ctx, "owner"), http.StatusOK)
	key := auth.MinecraftAPIKey{ID: uuid.NewString(), NodeID: "node", TemplateID: resource.ID, UserID: "owner", Name: "variant test", ExpiresAt: time.Now().Add(time.Hour)}
	token := "vmc_" + strings.Repeat("d", 64)
	digest, _ := minecraftAPIKeyDigest(token)
	if err := api.Users.CreateMinecraftAPIKey(ctx, key, digest); err != nil {
		t.Fatal(err)
	}
	spawn := func(requestID, variant string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"requestId": requestID, "variant": variant})
		request := httptest.NewRequest(http.MethodPost, "/api/minecraft/v1/instances", strings.NewReader(string(body)))
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request.WithContext(ctx))
		return response
	}
	assertCode(spawn(uuid.NewString(), "unknown"), http.StatusBadRequest)
	assertCode(requestAs(ctx, "owner", http.MethodPost, "/nodes/node/minecraft/resources/"+ordinary.ID+"/spawn", `{"requestId":"`+uuid.NewString()+`","variant":"duel"}`), http.StatusConflict)
	duelID := uuid.NewString()
	response = spawn(duelID, "duel")
	assertCode(response, http.StatusAccepted)
	var duel struct{ ServerID, Slug string }
	if err := json.Unmarshal(response.Body.Bytes(), &duel); err != nil {
		t.Fatal(err)
	}
	configPath := path.Join(duel.Slug, minecraftMinigameConfigRelativePath)
	var config minecraftMinigameConfig
	if err := json.Unmarshal([]byte(files[configPath]), &config); err != nil {
		t.Fatal(err)
	}
	if config.Variant != "duel" || config.Spec.MaxPlayers != 2 || config.Spec.Variants != nil || !strings.Contains(files[path.Join(duel.Slug, "data/server.properties")], "max-players=2\n") {
		t.Fatal("variant not resolved before provisioning")
	}
	assertMinecraftMinigameSenderLifecycle(t, config.Spec.Lifecycle)
	savedConfig := files[configPath]
	before := mutations
	assertCode(spawn(duelID, ""), http.StatusConflict)
	if mutations != before {
		t.Fatal("variant mismatch mutated worker")
	}
	spec.Minigame.Lifecycle.StartCommands = []minecraftMinigameStartCommand{{Command: "changed {matchId}"}}
	spec.Minigame.Variants = nil
	assertCode(patch(ctx, "owner"), http.StatusOK)
	assertCode(spawn(duelID, "duel"), http.StatusAccepted)
	if files[configPath] != savedConfig {
		t.Fatal("retry changed pinned spec or variant after template edit")
	}
	baseID := uuid.NewString()
	response = spawn(baseID, "")
	assertCode(response, http.StatusAccepted)
	var base struct{ Slug string }
	_ = json.Unmarshal(response.Body.Bytes(), &base)
	if !strings.Contains(files[path.Join(base.Slug, "data/server.properties")], "max-players=4\n") {
		t.Fatal("base capacity changed by prior variant")
	}
	baseConfigPath := path.Join(base.Slug, minecraftMinigameConfigRelativePath)
	var legacy map[string]interface{}
	if err := json.Unmarshal([]byte(files[baseConfigPath]), &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "variant")
	legacyContent, _ := json.Marshal(legacy)
	files[baseConfigPath] = string(legacyContent)
	assertCode(spawn(baseID, ""), http.StatusAccepted)
	if files[baseConfigPath] != string(legacyContent) {
		t.Fatal("legacy base retry rewrote configuration")
	}
	assertCode(spawn(uuid.NewString(), ""), http.StatusConflict)
	var manifest struct {
		Minigames map[string]minecraftMinigameManifestSpec
		Servers   map[string]struct {
			Variant string
			Spec    minecraftMinigameManifestSpec
		}
	}
	if err := json.Unmarshal([]byte(files[manifestPath]), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Servers[duel.Slug].Variant != "duel" || manifest.Servers[duel.Slug].Spec.MaxPlayers != 2 || manifest.Servers[base.Slug].Variant != "" || manifest.Servers[base.Slug].Spec.MaxPlayers != 4 {
		t.Fatal("target variants or snapshots not pinned")
	}
	assertMinecraftMinigameSenderLifecycle(t, manifest.Servers[duel.Slug].Spec.Lifecycle)
	beforeCopies := copies
	failReload = true
	response = requestAs(ctx, "owner", http.MethodDelete, target, "")
	assertCode(response, http.StatusBadGateway)
	if !strings.Contains(response.Body.String(), `"committed":true`) {
		t.Fatal("disable sync failure lost commit marker")
	}
	failReload = false
	disabledValue := false
	spec.Minigame.Enabled = &disabledValue
	assertCode(patch(ctx, "owner"), http.StatusOK)
	assertCode(requestAs(ctx, "owner", http.MethodDelete, target, ""), http.StatusConflict)
	if deleted[minecraftResourcePath(&resource)] || copies != beforeCopies {
		t.Fatal("disable deleted or copied template files")
	}
	saved, err := api.Users.FindMinecraftResource(ctx, "node", resource.ID)
	if err != nil || saved == nil {
		t.Fatal("disable deleted DB template", err)
	}
	var disabled minecraftResourceSpec
	if err := json.Unmarshal(saved.Spec, &disabled); err != nil || disabled.Minigame.Enabled == nil || *disabled.Minigame.Enabled {
		t.Fatal("pool not disabled")
	}
	if err := json.Unmarshal([]byte(files[manifestPath]), &manifest); err != nil || *manifest.Minigames[resource.Name].Enabled {
		t.Fatal("disabled pool not published")
	}
	if !*manifest.Servers[duel.Slug].Spec.Enabled {
		t.Fatal("disabling template mutated active instance snapshot")
	}
	before = mutations
	response = spawn(uuid.NewString(), "")
	assertCode(response, http.StatusConflict)
	if !strings.Contains(response.Body.String(), "disabled") || mutations != before {
		t.Fatal("disabled template provisioned")
	}
	response = requestAs(ctx, "owner", http.MethodDelete, target, "")
	assertCode(response, http.StatusConflict)
	if !strings.Contains(response.Body.String(), "Pool disabled; delete instances and retry") {
		t.Fatal("misleading deletion response")
	}
	if _, err := database.Exec(ctx, `DELETE FROM "GameServer" WHERE "id"<>'proxy'`); err != nil {
		t.Fatal(err)
	}
	assertCode(requestAs(ctx, "owner", http.MethodDelete, target, ""), http.StatusNoContent)
	saved, err = api.Users.FindMinecraftResource(ctx, "node", resource.ID)
	if err != nil || saved != nil || !deleted[minecraftResourcePath(&resource)] {
		t.Fatal("final deletion did not remove resource", err)
	}
}
