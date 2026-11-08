package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"yourapp/internal/auth"

	"github.com/go-chi/chi/v5"
)

func TestMinecraftMinigameSyncRoute(t *testing.T) {
	const route = "/api/nodes/{nodeRef}/minecraft/proxies/{proxyRef}/sync"
	api := &Server{}
	found := false
	if err := chi.Walk(api.Router().(chi.Routes), func(method, pattern string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if method == http.MethodPost && pattern == route {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found || len(accessRoles(http.MethodPost, route)) == 0 {
		t.Fatal("missing protected proxy sync route")
	}
	response := httptest.NewRecorder()
	api.Router().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/nodes/node/minecraft/proxies/proxy/sync", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated sync returned %d", response.Code)
	}
}

func testMinecraftMinigameSpec(t *testing.T) minecraftResourceSpec {
	t.Helper()
	var spec minecraftResourceSpec
	if err := json.Unmarshal([]byte(`{"mode":"minigames","maxInstances":3,"minigame":{"teams":["red","blue"],"teamSize":2,"minPlayers":2,"maxPlayers":4,"readyServers":1,"lifecycle":{"ready":{"trigger":"serverLoad"},"onAllJoined":[{"command":"team join {team} {player}","forEach":"player"}],"end":{"deleteServer":true,"whenEmpty":true,"logPattern":"^MATCH_END$"}}}}`), &spec); err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestMinecraftMinigameValidation(t *testing.T) {
	for _, mode := range []string{"", "player"} {
		if err := validateMinecraftMinigame(&minecraftResourceSpec{Mode: mode}); err != nil {
			t.Fatal(err)
		}
	}
	spec := testMinecraftMinigameSpec(t)
	if err := validateMinecraftMinigame(&spec); err != nil {
		t.Fatal(err)
	}
	if spec.Minigame.LobbyMode != "vestri" || spec.Minigame.JoinTimeout != "20s" || spec.Minigame.Lifecycle.End.EmptyGrace != "10s" || spec.Minigame.Lifecycle.End.ReturnPlayersTo != "lobby" {
		t.Fatal("defaults not applied")
	}
	for _, test := range []struct {
		name string
		edit func(*minecraftResourceSpec)
	}{
		{"mode", func(spec *minecraftResourceSpec) { spec.Mode = "other" }},
		{"missing", func(spec *minecraftResourceSpec) { spec.Minigame = nil }},
		{"ordinary with spec", func(spec *minecraftResourceSpec) { spec.Mode = "player" }},
		{"team action without teams", func(spec *minecraftResourceSpec) { spec.Minigame.Teams = nil }},
		{"lobby mode", func(spec *minecraftResourceSpec) { spec.Minigame.LobbyMode = "native" }},
		{"plugin commands", func(spec *minecraftResourceSpec) { spec.Minigame.LobbyMode = "plugin" }},
		{"zero team size", func(spec *minecraftResourceSpec) { spec.Minigame.TeamSize = 0 }},
		{"duplicate", func(spec *minecraftResourceSpec) { spec.Minigame.Teams = []string{"red", "red"} }},
		{"unsafe team", func(spec *minecraftResourceSpec) { spec.Minigame.Teams[0] = "bad team" }},
		{"team size", func(spec *minecraftResourceSpec) { spec.Minigame.TeamSize = 101 }},
		{"capacity", func(spec *minecraftResourceSpec) { spec.Minigame.MaxPlayers = 5 }},
		{"minimum", func(spec *minecraftResourceSpec) { spec.Minigame.MinPlayers = 5 }},
		{"zero players", func(spec *minecraftResourceSpec) { spec.Minigame.MinPlayers = 0 }},
		{"ready count", func(spec *minecraftResourceSpec) { spec.Minigame.ReadyServers = 4 }},
		{"negative ready", func(spec *minecraftResourceSpec) { spec.Minigame.ReadyServers = -1 }},
		{"timeout", func(spec *minecraftResourceSpec) { spec.Minigame.JoinTimeout = "999ms" }},
		{"timeout upper", func(spec *minecraftResourceSpec) { spec.Minigame.JoinTimeout = "11m" }},
		{"timeout invalid", func(spec *minecraftResourceSpec) { spec.Minigame.JoinTimeout = "soon" }},
		{"trigger", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.Ready.Trigger = "load" }},
		{"delete required", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.End.DeleteServer = false }},
		{"grace", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.End.EmptyGrace = "0s" }},
		{"destination", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.End.ReturnPlayersTo = "../lobby" }},
		{"regex", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.End.LogPattern = "[" }},
		{"regex Go only", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.End.LogPattern = "(?P<end>done)" }},
		{"regex POSIX", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.End.LogPattern = "[[:alpha:]]" }},
		{"regex octal", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.End.LogPattern = `\123` }},
		{"regex ungreedy", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.End.LogPattern = "(?iU:done)" }},
		{"regex large", func(spec *minecraftResourceSpec) { spec.Minigame.Lifecycle.End.LogPattern = strings.Repeat("x", 513) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := testMinecraftMinigameSpec(t)
			test.edit(&spec)
			if err := validateMinecraftMinigame(&spec); err == nil {
				t.Fatal("invalid spec accepted")
			}
		})
	}
}

func TestMinecraftMinigameOptionalTeamsAndLobby(t *testing.T) {
	for _, teams := range []string{"", `,"teams":null`, `,"teams":[]`} {
		for _, lobby := range []string{"", "vestri", "plugin"} {
			t.Run(teams+"/"+lobby, func(t *testing.T) {
				var spec minecraftResourceSpec
				if err := json.Unmarshal([]byte(`{"mode":"minigames","maxInstances":3,"minigame":{"lobbyMode":"`+lobby+`","minPlayers":1,"maxPlayers":100`+teams+`,"lifecycle":{"ready":{"trigger":"explicit"},"end":{"deleteServer":true}}}}`), &spec); err != nil {
					t.Fatal(err)
				}
				if err := validateMinecraftMinigame(&spec); err != nil {
					t.Fatal(err)
				}
				if spec.Minigame.Teams == nil || spec.Minigame.TeamSize != 0 || spec.Minigame.Lifecycle.OnAllJoined == nil {
					t.Fatal("optional arrays or team size were not normalized")
				}
				encoded, err := json.Marshal(spec)
				if err != nil || !strings.Contains(string(encoded), `"teams":[]`) || !strings.Contains(string(encoded), `"lobbyMode":"`) {
					t.Fatalf("normalized contract not serialized: %s (%v)", encoded, err)
				}
			})
		}
	}
	for _, test := range []struct {
		name  string
		edit  func(*minecraftMinigameSpec)
		valid bool
	}{
		{"ffa players", func(game *minecraftMinigameSpec) {
			game.Lifecycle.OnAllJoined = []minecraftMinigameCommand{{Command: "tag {player} add {uuid}-{matchId}", ForEach: "player"}}
		}, true},
		{"ffa standalone", func(game *minecraftMinigameSpec) {
			game.Lifecycle.OnAllJoined = []minecraftMinigameCommand{{Command: "say {matchId}"}}
		}, true},
		{"ffa ignored capacity", func(game *minecraftMinigameSpec) { game.TeamSize = 1; game.MaxPlayers = 100 }, true},
		{"ffa negative team size", func(game *minecraftMinigameSpec) { game.TeamSize = -1 }, false},
		{"ffa large team size", func(game *minecraftMinigameSpec) { game.TeamSize = 101 }, false},
		{"ffa zero players", func(game *minecraftMinigameSpec) { game.MinPlayers = 0 }, false},
		{"ffa large players", func(game *minecraftMinigameSpec) { game.MaxPlayers = 101 }, false},
		{"ffa inverted limits", func(game *minecraftMinigameSpec) { game.MinPlayers = 5; game.MaxPlayers = 4 }, false},
		{"ffa team loop", func(game *minecraftMinigameSpec) {
			game.Lifecycle.OnAllJoined = []minecraftMinigameCommand{{Command: "say hi", ForEach: "team"}}
		}, false},
		{"ffa player team", func(game *minecraftMinigameSpec) {
			game.Lifecycle.OnAllJoined = []minecraftMinigameCommand{{Command: "tag {player} add {team}", ForEach: "player"}}
		}, false},
		{"plugin teams", func(game *minecraftMinigameSpec) {
			game.LobbyMode = "plugin"
			game.Teams = []string{"red", "blue"}
			game.TeamSize = 2
		}, true},
		{"plugin empty array", func(game *minecraftMinigameSpec) {
			game.LobbyMode = "plugin"
			game.Lifecycle.OnAllJoined = []minecraftMinigameCommand{}
		}, true},
		{"plugin standalone command", func(game *minecraftMinigameSpec) {
			game.LobbyMode = "plugin"
			game.Lifecycle.OnAllJoined = []minecraftMinigameCommand{{Command: "say hi"}}
		}, false},
		{"plugin still requires ready", func(game *minecraftMinigameSpec) { game.LobbyMode = "plugin"; game.Lifecycle.Ready.Trigger = "" }, false},
		{"plugin still requires deletion", func(game *minecraftMinigameSpec) { game.LobbyMode = "plugin"; game.Lifecycle.End.DeleteServer = false }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := testMinecraftMinigameSpec(t)
			spec.Minigame.Teams = nil
			spec.Minigame.TeamSize = 0
			spec.Minigame.Lifecycle.OnAllJoined = nil
			test.edit(spec.Minigame)
			if err := validateMinecraftMinigame(&spec); (err == nil) != test.valid {
				t.Fatalf("valid=%t error=%v", test.valid, err)
			}
		})
	}
}

func TestMinecraftMinigameDurations(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{"20s", "20s"}, {"1m20s", "1m20s"}, {"10m", "10m0s"},
		{"1500ms", "1.5s"}, {"1.5s", "1.5s"}, {"1s1ms", "1.001s"},
		{"20000000us", "20s"}, {"1500000000ns", "1.5s"},
	} {
		t.Run(test.input, func(t *testing.T) {
			spec := testMinecraftMinigameSpec(t)
			spec.Minigame.JoinTimeout = test.input
			spec.Minigame.Lifecycle.End.EmptyGrace = test.input
			if err := validateMinecraftMinigame(&spec); err != nil {
				t.Fatal(err)
			}
			if spec.Minigame.JoinTimeout != test.want || spec.Minigame.Lifecycle.End.EmptyGrace != test.want {
				t.Fatalf("duration not normalized to %q", test.want)
			}
		})
	}
	for _, input := range []string{"1s1ns", "1s1us", "1.0001s"} {
		if err := defaultMinecraftMinigameDuration(&input, "20s"); err == nil {
			t.Fatalf("sub-millisecond precision accepted: %s", input)
		}
	}
}

func TestMinecraftMinigameInstanceProperties(t *testing.T) {
	for _, input := range []string{"", "max-players=20\nmotd=Keep me\n", "max-players=20\nmax-players=99\n", " max-players : 99\r\nmotd=Keep me\r\n", "max-players 20"} {
		spec := testMinecraftMinigameSpec(t)
		got := minecraftMinigameInstanceProperties(input, &spec)
		if strings.Count(got, "max-players=") != 1 || !strings.Contains(got, "max-players=4\n") {
			t.Fatalf("minigame player cap not enforced: %q", got)
		}
		if strings.Contains(input, "motd=Keep me") && !strings.Contains(got, "motd=Keep me") {
			t.Fatal("unrelated property changed")
		}
		for _, mode := range []string{"", "player"} {
			if got := minecraftMinigameInstanceProperties(input, &minecraftResourceSpec{Mode: mode}); got != input {
				t.Fatalf("ordinary properties changed: %q", got)
			}
		}
	}
}

func TestMinecraftMinigameBoundaries(t *testing.T) {
	spec := testMinecraftMinigameSpec(t)
	spec.MaxInstances = 100
	spec.Minigame.Teams = make([]string, 100)
	for index := range spec.Minigame.Teams {
		spec.Minigame.Teams[index] = strings.Repeat("x", index%63+1) + string(rune('A'+index/63))
	}
	spec.Minigame.TeamSize = 100
	spec.Minigame.MinPlayers, spec.Minigame.MaxPlayers = 100, 100
	spec.Minigame.ReadyServers = 100
	spec.Minigame.JoinTimeout = "10m"
	spec.Minigame.Lifecycle.Ready.Trigger = "explicit"
	spec.Minigame.Lifecycle.End.EmptyGrace = "1s"
	spec.Minigame.Lifecycle.End.LogPattern = "(?im)^MATCH_(?:END|DONE)$"
	spec.Minigame.Lifecycle.OnAllJoined = nil
	if err := validateMinecraftMinigame(&spec); err != nil {
		t.Fatal(err)
	}
	if spec.Minigame.Lifecycle.OnAllJoined == nil {
		t.Fatal("command array should normalize to []")
	}
	spec.Minigame.Teams = append(spec.Minigame.Teams, "extra")
	if err := validateMinecraftMinigame(&spec); err == nil {
		t.Fatal("101 teams accepted")
	}
	spec = testMinecraftMinigameSpec(t)
	spec.Minigame.Lifecycle.OnAllJoined = make([]minecraftMinigameCommand, 101)
	if err := validateMinecraftMinigame(&spec); err == nil {
		t.Fatal("101 commands accepted")
	}
}

func TestMinecraftMinigameCommands(t *testing.T) {
	for _, test := range []struct {
		command string
		repeat  string
		valid   bool
	}{
		{"say {matchId}", "", true}, {"team add {team}", "team", true},
		{"tag {player} add {team}-{uuid}-{matchId}", "player", true},
		{"/say hi", "", false}, {" /say hi", "", false}, {"say hi\nstop", "", false},
		{"say hi\rstop", "", false}, {"say\x00hi", "", false}, {"", "", false},
		{strings.Repeat("x", 1025), "", false}, {"say hi", "all", false},
		{"say {team}", "", false}, {"say {player}", "team", false}, {"say {uuid}", "", false},
		{"say {unknown}", "player", false}, {"say {player", "player", false},
	} {
		t.Run(test.command+test.repeat, func(t *testing.T) {
			err := validateMinecraftMinigameCommand(minecraftMinigameCommand{Command: test.command, ForEach: test.repeat})
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t error=%v", test.valid, err)
			}
		})
	}
}

func minecraftMinigameTestWorker(t *testing.T, files map[string]string, fail bool) (pluginWorker, *[]string) {
	t.Helper()
	operations := []string{}
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		operations = append(operations, request.Method+" "+request.URL.Path)
		if fail {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("sensitive worker response"))
			return
		}
		switch request.Method + " " + request.URL.Path {
		case "GET /fs/read":
			content, found := files[request.URL.Query().Get("path")]
			if !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(content))
		case "POST /fs/write", "POST /fs/delete":
			var body struct {
				Path      string `json:"path"`
				Content   string `json:"content"`
				Recursive bool   `json:"recursive"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if request.URL.Path == "/fs/write" {
				files[body.Path] = body.Content
			} else {
				if body.Recursive || (!strings.HasSuffix(body.Path, minecraftMinigameConfigRelativePath) && !strings.HasSuffix(body.Path, "data/plugins/VestriConsoleBridge/minigame-execution.json")) {
					t.Errorf("unsafe delete: %+v", body)
				}
				if _, found := files[body.Path]; !found {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				delete(files, body.Path)
			}
		default:
			t.Errorf("unexpected worker operation: %s %s", request.Method, request.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(worker.Close)
	baseURL, err := url.Parse(worker.URL)
	if err != nil {
		t.Fatal(err)
	}
	return pluginWorker{server: &Server{}, baseURL: baseURL, apiKey: "worker-key"}, &operations
}

func TestMinecraftMinigameProvision(t *testing.T) {
	ctx := context.Background()
	files := map[string]string{}
	worker, operations := minecraftMinigameTestWorker(t, files, false)
	spec := testMinecraftMinigameSpec(t)
	if err := validateMinecraftMinigame(&spec); err != nil {
		t.Fatal(err)
	}
	parent := &auth.GameServer{ID: "proxy", Slug: "proxy-slug"}
	tokens := map[string]bool{}
	for _, slug := range []string{"first", "second"} {
		server := &auth.GameServer{ID: slug + "-id", Slug: slug, RootPath: "root/" + slug}
		filename := path.Join(server.RootPath, minecraftMinigameConfigRelativePath)
		fence := path.Join(server.RootPath, "data/plugins/VestriConsoleBridge/minigame-execution.json")
		files[filename] = `{"token":"stale copied token"}`
		files[fence] = `{"completed":true}`
		if err := provisionMinecraftMinigame(ctx, worker, server, parent, &spec, false); err != nil {
			t.Fatal(err)
		}
		if _, found := files[fence]; found {
			t.Fatal("fresh minigame spawn retained copied execution fence")
		}
		config, err := readMinecraftMinigameConfig(ctx, worker, server)
		if err != nil {
			t.Fatal(err)
		}
		if config.ControlURL != "http://"+velocityBackendHostForSlug(parent.Slug)+":25580" || tokens[config.Token] || config.Spec.JoinTimeout != "20s" || config.Spec.Lifecycle.End.ReturnPlayersTo != "lobby" {
			t.Fatalf("invalid or reused instance configuration for %s", slug)
		}
		tokens[config.Token] = true
		files[fence] = `{"completed":true}`
		original := files[filename]
		before := len(*operations)
		if err := provisionMinecraftMinigame(ctx, worker, server, parent, &spec, true); err != nil {
			t.Fatal(err)
		}
		if files[filename] != original || len(*operations) != before+1 || (*operations)[before] != "GET /fs/read" {
			t.Fatal("retry changed the existing configuration")
		}
		if files[fence] != `{"completed":true}` {
			t.Fatal("retry reset the existing execution fence")
		}
		response, err := json.Marshal(minecraftInstanceResponse(server))
		if err != nil || strings.Contains(string(response), config.Token) || strings.Contains(string(response), "token") {
			t.Fatal("public instance response exposed minigame credentials")
		}
		if err := provisionMinecraftMinigame(ctx, worker, server, parent, &minecraftResourceSpec{}, false); err != nil {
			t.Fatal(err)
		}
		if _, found := files[filename]; found {
			t.Fatal("ordinary spawn retained copied minigame configuration")
		}
		if _, found := files[fence]; found {
			t.Fatal("ordinary spawn retained copied execution fence")
		}
		files[fence] = `{"completed":true}`
		if err := provisionMinecraftMinigame(ctx, worker, server, nil, &minecraftResourceSpec{Mode: "player"}, true); err != nil {
			t.Fatal("ordinary retry with no stale file failed:", err)
		}
		if files[fence] != `{"completed":true}` {
			t.Fatal("ordinary retry reset the existing execution fence")
		}
	}
}

func TestMinecraftMinigameSpawnRequestID(t *testing.T) {
	ctx := context.Background()
	rawRequestID := "12345678-1234-4567-89ab-123456789abc"
	otherRequestID := "87654321-4321-4567-89ab-123456789abc"
	server := &auth.GameServer{Slug: "instance", RootPath: "instance"}
	parent := &auth.GameServer{Slug: "proxy"}
	for _, legacy := range []bool{false, true} {
		name := "fresh"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			files := map[string]string{}
			worker, operations := minecraftMinigameTestWorker(t, files, false)
			spec := testMinecraftMinigameSpec(t)
			requestIDs := []string{rawRequestID}
			if legacy {
				requestIDs = nil
			}
			if err := provisionMinecraftMinigame(ctx, worker, server, parent, &spec, false, requestIDs...); err != nil {
				t.Fatal(err)
			}
			original, err := readMinecraftMinigameConfig(ctx, worker, server)
			if err != nil {
				t.Fatal(err)
			}
			if (!legacy && original.SpawnRequestID != rawRequestID) || (legacy && original.SpawnRequestID != "") {
				t.Fatal("fresh configuration has wrong correlation")
			}
			originalSpec, _ := json.Marshal(original.Spec)
			fence := path.Join(server.RootPath, minecraftMinigameExecutionRelativePath)
			files[fence] = `{"completed":true}`
			spec.Minigame.TeamSize++
			before := len(*operations)
			if err := provisionMinecraftMinigame(ctx, worker, server, parent, &spec, true, rawRequestID); err != nil {
				t.Fatal(err)
			}
			expectedOperations := 1
			if legacy {
				expectedOperations++
			}
			if len(*operations) != before+expectedOperations || (*operations)[before] != "GET /fs/read" || (legacy && (*operations)[before+1] != "POST /fs/write") {
				t.Fatal("retry did not limit mutations to missing correlation backfill")
			}
			config, err := readMinecraftMinigameConfig(ctx, worker, server)
			if err != nil {
				t.Fatal(err)
			}
			savedSpec, _ := json.Marshal(config.Spec)
			if config.SpawnRequestID != rawRequestID || config.Token != original.Token || config.ControlURL != original.ControlURL || string(savedSpec) != string(originalSpec) || files[fence] != `{"completed":true}` {
				t.Fatal("retry changed saved token, spec, proxy, fence or correlation")
			}
			filename := path.Join(server.RootPath, minecraftMinigameConfigRelativePath)
			saved := files[filename]
			if err := provisionMinecraftMinigame(ctx, worker, server, parent, &spec, true, otherRequestID); err != nil || files[filename] != saved {
				t.Fatal("retry replaced existing correlation")
			}
			response, err := json.Marshal(minecraftInstanceResponse(server))
			if err != nil || strings.Contains(string(response), rawRequestID) || strings.Contains(string(response), "spawnRequestId") {
				t.Fatal("public response exposed private correlation")
			}
		})
	}
	for _, invalid := range []string{"", "invalid", strings.Repeat("a", 64)} {
		for _, retry := range []bool{false, true} {
			worker, operations := minecraftMinigameTestWorker(t, map[string]string{}, false)
			spec := testMinecraftMinigameSpec(t)
			if err := provisionMinecraftMinigame(ctx, worker, server, parent, &spec, retry, invalid); err == nil || len(*operations) != 0 {
				t.Fatal("invalid raw UUID was accepted or mutated worker files")
			}
		}
	}
}

func TestMinecraftMinigameConfigFailures(t *testing.T) {
	spec := testMinecraftMinigameSpec(t)
	server := &auth.GameServer{Slug: "instance", RootPath: "instance"}
	parent := &auth.GameServer{Slug: "proxy"}
	for _, content := range []string{"", "{", `{"slug":"other","token":"` + strings.Repeat("a", 64) + `","spec":{}}`, `{"slug":"instance","token":"invalid","spec":{}}`, `{"slug":"instance","token":"` + strings.Repeat("a", 64) + `"}`, `{"slug":"instance","token":"` + strings.Repeat("a", 64) + `","spec":{},"controlUrl":"http://wrong:25580"}`} {
		t.Run(content, func(t *testing.T) {
			files := map[string]string{}
			filename := path.Join(server.RootPath, minecraftMinigameConfigRelativePath)
			if content != "" {
				files[filename] = content
			}
			worker, operations := minecraftMinigameTestWorker(t, files, false)
			if err := provisionMinecraftMinigame(context.Background(), worker, server, parent, &spec, true); err == nil {
				t.Fatal("invalid retry configuration accepted")
			}
			if len(*operations) != 1 || (*operations)[0] != "GET /fs/read" {
				t.Fatal("failed retry rotated credentials")
			}
		})
	}
	worker, _ := minecraftMinigameTestWorker(t, map[string]string{}, true)
	for _, retry := range []bool{false, true} {
		if err := provisionMinecraftMinigame(context.Background(), worker, server, parent, &spec, retry); err == nil || strings.Contains(err.Error(), "sensitive") {
			t.Fatal("worker failure was accepted or leaked its response")
		}
	}
}

func TestMinecraftMinigameLegacyLobby(t *testing.T) {
	ctx := context.Background()
	files := map[string]string{}
	worker, operations := minecraftMinigameTestWorker(t, files, false)
	instance := &auth.GameServer{Slug: "instance", RootPath: "instance"}
	parent := &auth.GameServer{Slug: "proxy"}
	spec := testMinecraftMinigameSpec(t)
	if err := provisionMinecraftMinigame(ctx, worker, instance, parent, &spec, false); err != nil {
		t.Fatal(err)
	}
	filename := path.Join(instance.RootPath, minecraftMinigameConfigRelativePath)
	var legacy map[string]interface{}
	if err := json.Unmarshal([]byte(files[filename]), &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy["spec"].(map[string]interface{}), "lobbyMode")
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	files[filename] = string(encoded)
	spec.Minigame.LobbyMode = "plugin"
	spec.Minigame.Lifecycle.OnAllJoined = nil
	before := len(*operations)
	if err := provisionMinecraftMinigame(ctx, worker, instance, parent, &spec, true); err != nil {
		t.Fatal(err)
	}
	if files[filename] != string(encoded) || len(*operations) != before+1 {
		t.Fatal("retry rewrote legacy config to the current lobby mode")
	}
	config, err := readMinecraftMinigameConfig(ctx, worker, instance)
	if err != nil || config.Spec.LobbyMode != "vestri" || len(config.Spec.Lifecycle.OnAllJoined) != 1 {
		t.Fatalf("legacy lobby or startup actions lost: %+v (%v)", config, err)
	}
}

func TestMinecraftMinigameFileDiagnostics(t *testing.T) {
	for _, operation := range []string{"read", "write", "delete"} {
		t.Run(operation, func(t *testing.T) {
			worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/fs/delete" && operation == "write" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				http.Error(w, "SECRET worker response", http.StatusForbidden)
			}))
			defer worker.Close()
			baseURL, _ := url.Parse(worker.URL)
			spec := testMinecraftMinigameSpec(t)
			instance := &auth.GameServer{Slug: "instance", RootPath: "instance", StackName: "instance"}
			err := provisionMinecraftMinigame(context.Background(), pluginWorker{server: &Server{}, baseURL: baseURL, apiKey: "SECRET key"}, instance, &auth.GameServer{Slug: "proxy"}, &spec, operation == "read")
			var failure *minecraftMinigameFileError
			if !errors.As(err, &failure) || failure.operation != operation || failure.cause == nil {
				t.Fatalf("lost worker failure context: %v", err)
			}
			wantFile := minecraftMinigameConfigRelativePath
			if operation == "delete" {
				wantFile = minecraftMinigameExecutionRelativePath
			}
			if failure.file != wantFile || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("wrong file or leaked response: %v", err)
			}
			var output bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(previous)
			logMinecraftPreparationFailure(context.Background(), "minigame_config", "node", "caller-uuid", instance, operation == "read", err)
			if strings.Contains(output.String(), "SECRET") || !strings.Contains(output.String(), `operation="`+operation+`"`) || !strings.Contains(output.String(), `file="`+wantFile+`"`) || !strings.Contains(output.String(), `request="caller-uuid"`) {
				t.Fatalf("unsafe or incomplete diagnostic: %s", output.String())
			}
		})
	}
	cause := &minecraftMinigameFileError{"write", minecraftMinigameConfigRelativePath, context.DeadlineExceeded}
	if !errors.Is(cause, context.DeadlineExceeded) || minecraftInstanceErrorClass(cause) != "deadline_exceeded" {
		t.Fatal("wrapped file error lost deadline classification")
	}
}

func TestMinecraftMinigameLobbyManifest(t *testing.T) {
	for _, lobby := range []string{"vestri", "plugin"} {
		for _, teams := range [][]string{nil, {"red", "blue"}} {
			t.Run(lobby+"/"+strings.Join(teams, ","), func(t *testing.T) {
				ctx := context.Background()
				worker, _ := minecraftMinigameTestWorker(t, map[string]string{}, false)
				parent := &auth.GameServer{ID: "proxy", Slug: "proxy"}
				instance := auth.GameServer{ID: "instance-id", Slug: "instance", RootPath: "instance", Name: "FFA-1", Metadata: json.RawMessage(`{"parentServerId":"proxy","connectHost":"instance","connectPort":25565}`)}
				spec := testMinecraftMinigameSpec(t)
				spec.ParentID = parent.ID
				spec.Minigame.LobbyMode = lobby
				spec.Minigame.Teams = teams
				spec.Minigame.Lifecycle.OnAllJoined = nil
				if len(teams) == 0 {
					spec.Minigame.TeamSize = 0
				}
				if err := validateMinecraftMinigame(&spec); err != nil {
					t.Fatal(err)
				}
				if err := provisionMinecraftMinigame(ctx, worker, &instance, parent, &spec, false); err != nil {
					t.Fatal(err)
				}
				for _, changed := range []bool{false, true} {
					if changed {
						spec.Minigame.LobbyMode = "plugin"
						if lobby == "plugin" {
							spec.Minigame.LobbyMode = "vestri"
						}
						if err := provisionMinecraftMinigame(ctx, worker, &instance, parent, &spec, true); err != nil {
							t.Fatal(err)
						}
					}
					raw, _ := json.Marshal(spec)
					manifest, err := buildMinecraftProxyManifest(ctx, worker, parent, []auth.MinecraftResource{{ID: "template", Kind: "templates", Name: "FFA", Spec: raw}}, []auth.MinecraftInstance{{ServerID: instance.ID, TemplateID: "template"}}, []auth.GameServer{instance}, "")
					if err != nil {
						t.Fatal(err)
					}
					var result struct {
						Minigames map[string]minecraftMinigameManifestSpec
						Servers   map[string]struct{ Spec minecraftMinigameManifestSpec }
					}
					if err := json.Unmarshal(manifest, &result); err != nil {
						t.Fatal(err)
					}
					current, pinned := result.Minigames["FFA"], result.Servers[instance.Slug].Spec
					if current.LobbyMode != spec.Minigame.LobbyMode || pinned.LobbyMode != lobby || current.Teams == nil || pinned.Teams == nil || len(current.Teams) != len(teams) || len(pinned.Teams) != len(teams) || pinned.TeamSize != spec.Minigame.TeamSize {
						t.Fatalf("current or pinned lobby contract lost: %s", manifest)
					}
				}
			})
		}
	}
}

func TestMinecraftMinigameManifest(t *testing.T) {
	ctx := context.Background()
	worker, operations := minecraftMinigameTestWorker(t, map[string]string{}, false)
	parent := &auth.GameServer{ID: "proxy", Slug: "proxy"}
	spec := testMinecraftMinigameSpec(t)
	spec.ParentID = parent.ID
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	resources := []auth.MinecraftResource{
		{ID: "game", Kind: "templates", Name: "Team Game", Spec: raw},
		{ID: "unused", Kind: "templates", Name: "No Instances Yet", Spec: raw},
		{ID: "ordinary", Kind: "templates", Name: "Ordinary", Spec: json.RawMessage(`{"parentId":"proxy"}`)},
		{ID: "foreign", Kind: "templates", Name: "Other Proxy", Spec: json.RawMessage(strings.ReplaceAll(string(raw), `"parentId":"proxy"`, `"parentId":"other"`))},
		{ID: "base", Kind: "bases", Name: "Not A Template", Spec: raw},
	}
	servers := []auth.GameServer{
		{ID: "game-id", Slug: "game-slug", Name: "Team Game-1", RootPath: "game-root", Metadata: json.RawMessage(`{"parentServerId":"proxy","velocityServerName":"TeamGame-1","connectHost":"game-host","connectPort":25565}`)},
		{ID: "ordinary-id", Slug: "ordinary-slug", Name: "Ordinary-1", Metadata: json.RawMessage(`{"parentServerId":"proxy","connectHost":"ordinary-host","connectPort":25565}`)},
		{ID: "foreign-id", Slug: "foreign-slug", Metadata: json.RawMessage(`{"parentServerId":"other"}`)},
		{ID: "static-id", Slug: "static-slug", Metadata: json.RawMessage(`{"parentServerId":"proxy"}`)},
	}
	instances := []auth.MinecraftInstance{{ServerID: "game-id", TemplateID: "game", RequestID: strings.Repeat("b", 64)}, {ServerID: "ordinary-id", TemplateID: "ordinary"}, {ServerID: "foreign-id", TemplateID: "foreign"}}
	if err := validateMinecraftMinigame(&spec); err != nil {
		t.Fatal(err)
	}
	if err := provisionMinecraftMinigame(ctx, worker, &servers[0], parent, &spec, false); err != nil {
		t.Fatal(err)
	}
	config, err := readMinecraftMinigameConfig(ctx, worker, &servers[0])
	if err != nil {
		t.Fatal(err)
	}
	spec.MaxInstances = 5
	spec.Minigame.TeamSize = 3
	spec.Minigame.MaxPlayers = 6
	spec.Minigame.JoinTimeout = "30s"
	spec.Minigame.Lifecycle.End.EmptyGrace = "25s"
	resources[0].Spec, err = json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{"", "game-id"} {
		before := len(*operations)
		rawManifest, err := buildMinecraftProxyManifest(ctx, worker, parent, resources, instances, servers, excluded)
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Minigames map[string]map[string]interface{} `json:"minigames"`
			Servers   map[string]map[string]interface{} `json:"servers"`
		}
		if err := json.Unmarshal(rawManifest, &manifest); err != nil {
			t.Fatal(err)
		}
		if len(manifest.Minigames) != 2 || manifest.Minigames["No Instances Yet"] == nil || manifest.Minigames["Team Game"]["maxInstances"] != float64(5) || manifest.Minigames["Team Game"]["joinTimeout"] != "30s" || manifest.Minigames["Team Game"]["maxPlayers"] != float64(6) {
			t.Fatal("wrong template scope or flattened minigame contract")
		}
		ordinary := manifest.Servers["ordinary-slug"]
		if len(ordinary) != 3 || ordinary["host"] != "ordinary-host" || ordinary["port"] != float64(25565) {
			t.Fatal("ordinary server entry changed")
		}
		if excluded == "" {
			game := manifest.Servers["game-slug"]
			if len(manifest.Servers) != 2 || len(game) != 9 || game["token"] != config.Token || game["serverId"] != "game-id" || game["id"] != "game-id" || game["requestId"] != instances[0].RequestID || game["template"] != "Team Game" || game["name"] != "TeamGame-1" || game["host"] != "game-host" || game["port"] != float64(25565) {
				t.Fatal("wrong minigame server manifest entry")
			}
			gotSpec, err := json.Marshal(game["spec"])
			if err != nil {
				t.Fatal(err)
			}
			var savedSpec minecraftMinigameManifestSpec
			if err := json.Unmarshal(gotSpec, &savedSpec); err != nil {
				t.Fatal(err)
			}
			gotSaved, _ := json.Marshal(savedSpec.minecraftMinigameSpec)
			wantSaved, _ := json.Marshal(config.Spec)
			if string(gotSaved) != string(wantSaved) || savedSpec.MaxInstances != 5 || len(game["spec"].(map[string]interface{})) != len(manifest.Minigames["Team Game"]) {
				t.Fatal("instance spec did not preserve spawn-time configuration with current cap and template shape")
			}
		} else if len(manifest.Servers) != 1 || len(*operations) != before {
			t.Fatal("excluded minigame was read or retained")
		}
	}
	missingWorker, _ := minecraftMinigameTestWorker(t, map[string]string{}, false)
	rawRequestID := "12345678-1234-4567-89ab-123456789abc"
	if err := provisionMinecraftMinigame(ctx, worker, &servers[0], parent, &spec, true, rawRequestID); err != nil {
		t.Fatal(err)
	}
	rawManifest, err := buildMinecraftProxyManifest(ctx, worker, parent, resources, instances, servers, "")
	if err != nil {
		t.Fatal(err)
	}
	var correlatedManifest struct {
		Servers map[string]map[string]interface{} `json:"servers"`
	}
	if err := json.Unmarshal(rawManifest, &correlatedManifest); err != nil {
		t.Fatal(err)
	}
	game := correlatedManifest.Servers["game-slug"]
	if len(game) != 10 || game["spawnRequestId"] != rawRequestID || game["requestId"] != instances[0].RequestID || game["token"] != config.Token {
		t.Fatal("manifest lost raw correlation, persisted request hash or saved token")
	}
	if _, present := correlatedManifest.Servers["ordinary-slug"]["spawnRequestId"]; present {
		t.Fatal("ordinary manifest exposed minigame correlation")
	}
	if _, err := buildMinecraftProxyManifest(ctx, missingWorker, parent, resources, instances, servers, ""); err == nil {
		t.Fatal("manifest accepted missing minigame credentials")
	}
}
