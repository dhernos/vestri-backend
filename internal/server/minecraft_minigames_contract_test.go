package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"yourapp/internal/auth"
)

func TestMinecraftMinigameExtendedContract(t *testing.T) {
	spec := testMinecraftMinigameSpec(t)
	if err := validateMinecraftMinigame(&spec); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(spec.Minigame)
	if !strings.Contains(string(encoded), `"enabled":true`) || spec.Minigame.TeamPolicy != "balanced" {
		t.Fatal("defaults missing")
	}
	empty := []string{}
	zero := 0
	spec.Minigame.Lifecycle.OnAllJoined = nil
	spec.Minigame.Variants = map[string]minecraftMinigameVariant{"solo": {Teams: &empty, TeamSize: &zero}}
	if err := validateMinecraftMinigame(&spec); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveMinecraftMinigameVariant(spec.Minigame, "solo")
	if err != nil || len(resolved.Teams) != 0 || resolved.Variants != nil || len(spec.Minigame.Teams) != 2 {
		t.Fatalf("variant not isolated: %+v %v", resolved, err)
	}
	if _, err := resolveMinecraftMinigameVariant(spec.Minigame, "missing"); err == nil {
		t.Fatal("unknown variant accepted")
	}
}

func TestMinecraftMinigameRoleAndLifecycleContract(t *testing.T) {
	for _, test := range []struct {
		name  string
		edit  func(*minecraftMinigameSpec)
		valid bool
	}{
		{"roles", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": 1}
			game.RemainderTeam = "blue"
			game.MaxPlayers = 3
		}, true},
		{"exact roles", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": 1, "blue": 1}
			game.RemainderTeam = "blue"
			game.MaxPlayers = 2
		}, true},
		{"roles without remainder", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": 1, "blue": 1}
			game.MaxPlayers = 2
		}, false},
		{"plugin roles", func(game *minecraftMinigameSpec) {
			game.LobbyMode = "plugin"
			game.Lifecycle.OnAllJoined = nil
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": 1}
			game.RemainderTeam = "blue"
			game.MaxPlayers = 3
		}, false},
		{"single remainder team", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.Teams = []string{"red"}
			game.RemainderTeam = "red"
			game.MaxPlayers = 2
		}, true},
		{"roles without teams", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.Teams = nil
			game.Lifecycle.OnAllJoined = nil
		}, false},
		{"role counts exceed minimum", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": 2, "blue": 1}
			game.RemainderTeam = "blue"
		}, false},
		{"zero role", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": 0}
			game.RemainderTeam = "blue"
			game.MaxPlayers = 2
		}, true},
		{"remainder baseline", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": 1, "blue": 1}
			game.RemainderTeam = "blue"
			game.MaxPlayers = 3
		}, true},
		{"negative role", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": -1}
			game.RemainderTeam = "blue"
		}, false},
		{"unknown role", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"other": 1}
			game.RemainderTeam = "blue"
		}, false},
		{"missing remainder team", func(game *minecraftMinigameSpec) { game.TeamPolicy = "roles"; game.RemainderTeam = "other" }, false},
		{"role overflow", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": 1}
			game.RemainderTeam = "blue"
		}, false},
		{"exact mismatch", func(game *minecraftMinigameSpec) {
			game.TeamPolicy = "roles"
			game.TeamCounts = map[string]int{"red": 1}
		}, false},
		{"balanced counts", func(game *minecraftMinigameSpec) { game.TeamCounts = map[string]int{"red": 1} }, false},
		{"balanced remainder", func(game *minecraftMinigameSpec) { game.RemainderTeam = "red" }, false},
		{"unknown policy", func(game *minecraftMinigameSpec) { game.TeamPolicy = "random" }, false},
		{"team commands", func(game *minecraftMinigameSpec) {
			game.Lifecycle.TeamCommands = []minecraftMinigameTeamCommand{{Team: "red", Command: "role {player} {uuid} {team} {matchId}"}}
		}, true},
		{"wildcard team", func(game *minecraftMinigameSpec) {
			game.Lifecycle.TeamCommands = []minecraftMinigameTeamCommand{{Team: "*", Command: "say hello"}}
		}, false},
		{"missing team", func(game *minecraftMinigameSpec) {
			game.Lifecycle.TeamCommands = []minecraftMinigameTeamCommand{{Command: "say hello"}}
		}, false},
		{"team command invalid", func(game *minecraftMinigameSpec) {
			game.Lifecycle.TeamCommands = []minecraftMinigameTeamCommand{{Team: "red", Command: "/say hi"}}
		}, false},
		{"start", func(game *minecraftMinigameSpec) { game.Lifecycle.StartCommands = []string{"start {matchId}"} }, true},
		{"start player", func(game *minecraftMinigameSpec) { game.Lifecycle.StartCommands = []string{"start {player}"} }, false},
		{"start team", func(game *minecraftMinigameSpec) { game.Lifecycle.StartCommands = []string{"start {team}"} }, false},
		{"combined cap", func(game *minecraftMinigameSpec) {
			for index := 0; index < 100; index++ {
				game.Lifecycle.StartCommands = append(game.Lifecycle.StartCommands, "say hi")
			}
		}, false},
		{"plugin team command", func(game *minecraftMinigameSpec) {
			game.LobbyMode = "plugin"
			game.Lifecycle.OnAllJoined = nil
			game.Lifecycle.TeamCommands = []minecraftMinigameTeamCommand{{Team: "red", Command: "say hello"}}
		}, false},
		{"plugin start command", func(game *minecraftMinigameSpec) {
			game.LobbyMode = "plugin"
			game.Lifecycle.OnAllJoined = nil
			game.Lifecycle.StartCommands = []string{"start"}
		}, false},
		{"logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = "my.Plugin_logger-1" }, true},
		{"colon logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = "my:Plugin_logger-1" }, true},
		{"leading dot logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = ".plugin" }, false},
		{"leading colon logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = ":plugin" }, false},
		{"leading underscore logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = "_plugin" }, false},
		{"leading hyphen logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = "-plugin" }, false},
		{"maximum logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = strings.Repeat("a", 128) }, true},
		{"legacy logger absent", func(game *minecraftMinigameSpec) {}, true},
		{"unsafe logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = "plugin\nINJECT" }, false},
		{"unicode logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = "pl\u00fcgin" }, false},
		{"long logger", func(game *minecraftMinigameSpec) { game.Lifecycle.End.LoggerName = strings.Repeat("a", 129) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := testMinecraftMinigameSpec(t)
			test.edit(spec.Minigame)
			if err := validateMinecraftMinigame(&spec); (err == nil) != test.valid {
				t.Fatalf("valid=%t error=%v", test.valid, err)
			}
		})
	}
}

func TestMinecraftMinigameVariantOverrides(t *testing.T) {
	for _, test := range []struct {
		name, variant string
		valid         bool
	}{
		{"inherit", `{}`, true},
		{"empty teams", `{"teams":[],"teamSize":0}`, true},
		{"null teams inherit", `{"teams":null}`, true},
		{"zero minimum", `{"minPlayers":0}`, false},
		{"zero team size", `{"teamSize":0}`, false},
		{"capacity", `{"maxPlayers":5}`, false},
		{"minimum", `{"minPlayers":5}`, false},
		{"invalid teams", `{"teams":["red","red"]}`, false},
		{"roles", `{"teamPolicy":"roles","teamCounts":{"red":1},"remainderTeam":"blue","maxPlayers":3}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := testMinecraftMinigameSpec(t)
			spec.Minigame.Lifecycle.OnAllJoined = nil
			if err := json.Unmarshal([]byte(`{"one":`+test.variant+`}`), &spec.Minigame.Variants); err != nil {
				t.Fatal(err)
			}
			if err := validateMinecraftMinigame(&spec); (err == nil) != test.valid {
				t.Fatalf("valid=%t error=%v", test.valid, err)
			}
		})
	}
	spec := testMinecraftMinigameSpec(t)
	spec.Minigame.TeamPolicy, spec.Minigame.RemainderTeam = "roles", "blue"
	spec.Minigame.TeamCounts = map[string]int{"red": 1}
	spec.Minigame.MaxPlayers = 3
	if err := json.Unmarshal([]byte(`{"balanced":{"teamPolicy":"balanced","teamCounts":{},"remainderTeam":""}}`), &spec.Minigame.Variants); err != nil {
		t.Fatal(err)
	}
	content, _ := json.Marshal(spec)
	if !strings.Contains(string(content), `"teamCounts":{}`) {
		t.Fatal("explicit empty counts lost")
	}
	if err := json.Unmarshal(content, &spec); err != nil {
		t.Fatal(err)
	}
	if err := validateMinecraftMinigame(&spec); err != nil {
		t.Fatal(err)
	}
	resolved, _ := resolveMinecraftMinigameVariant(spec.Minigame, "balanced")
	resolved.TeamCounts["red"] = 2
	if spec.Minigame.TeamCounts["red"] != 1 || len(*spec.Minigame.Variants["balanced"].TeamCounts) != 0 {
		t.Fatal("variant aliases template")
	}
	spec.Minigame.Variants["../bad"] = minecraftMinigameVariant{}
	if err := validateMinecraftMinigame(&spec); err == nil {
		t.Fatal("unsafe variant accepted")
	}
	delete(spec.Minigame.Variants, "../bad")
	for index := 0; index < 20; index++ {
		spec.Minigame.Variants[strings.Repeat("a", index+1)] = minecraftMinigameVariant{}
	}
	if err := validateMinecraftMinigame(&spec); err == nil {
		t.Fatal("too many variants accepted")
	}
}

func TestMinecraftMinigameVariantInheritedTeamCommands(t *testing.T) {
	for _, test := range []struct {
		name, variant string
		valid         bool
	}{
		{"inherit teams", `{}`, true},
		{"resize existing teams", `{"teamSize":3,"maxPlayers":6}`, true},
		{"remove command team", `{"teams":["blue","green"]}`, false},
		{"remove all teams", `{"teams":[],"teamSize":0}`, false},
		{"roles with existing command team", `{"teamPolicy":"roles","teamCounts":{"red":1},"remainderTeam":"blue","maxPlayers":3}`, true},
		{"roles remove command team", `{"teams":["green","blue"],"teamPolicy":"roles","teamCounts":{"green":1},"remainderTeam":"blue","maxPlayers":3}`, false},
		{"roles without remainder", `{"teamPolicy":"roles","teamCounts":{"red":1,"blue":1},"maxPlayers":2}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := testMinecraftMinigameSpec(t)
			spec.Minigame.Lifecycle.TeamCommands = []minecraftMinigameTeamCommand{{Team: "red", Command: "bedwars join {player} {team}"}}
			if err := json.Unmarshal([]byte(`{"one":`+test.variant+`}`), &spec.Minigame.Variants); err != nil {
				t.Fatal(err)
			}
			resolved, err := resolveMinecraftMinigameVariant(spec.Minigame, "one")
			if err != nil || len(resolved.Lifecycle.OnAllJoined) != 1 || len(resolved.Lifecycle.TeamCommands) != 1 || resolved.Lifecycle.TeamCommands[0].Team != "red" {
				t.Fatalf("variant lost inherited lifecycle: %+v error=%v", resolved, err)
			}
			err = validateMinecraftMinigame(&spec)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t error=%v", test.valid, err)
			}
			if !test.valid && !strings.Contains(err.Error(), "variant one:") {
				t.Fatalf("expected resolved variant validation failure, got %v", err)
			}
		})
	}
}

func TestMinecraftMinigamePatchRoute(t *testing.T) {
	const route = "/api/nodes/{nodeRef}/minecraft/resources/{resourceId}"
	api := &Server{}
	found := false
	if err := chi.Walk(api.Router().(chi.Routes), func(method, pattern string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if method == http.MethodPatch && pattern == route {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found || len(accessRoles(http.MethodPatch, route)) == 0 {
		t.Fatal("missing protected PATCH route")
	}
	response := httptest.NewRecorder()
	api.Router().ServeHTTP(response, httptest.NewRequest(http.MethodPatch, "/api/nodes/node/minecraft/resources/template", strings.NewReader(`{}`)))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PATCH=%d", response.Code)
	}
}

func TestMinecraftMinigameVariantPinnedConfig(t *testing.T) {
	ctx := context.Background()
	worker, _ := minecraftMinigameTestWorker(t, map[string]string{}, false)
	spec := testMinecraftMinigameSpec(t)
	spec.Minigame.Variants = map[string]minecraftMinigameVariant{"ranked": {}}
	spec.Variant = "ranked"
	if err := validateMinecraftMinigame(&spec); err != nil {
		t.Fatal(err)
	}
	instance := &auth.GameServer{Slug: "game", RootPath: "game"}
	parent := &auth.GameServer{Slug: "proxy"}
	if err := provisionMinecraftMinigame(ctx, worker, instance, parent, &spec, false); err != nil {
		t.Fatal(err)
	}
	spec.Minigame.Lifecycle.StartCommands = []string{"changed"}
	if err := provisionMinecraftMinigame(ctx, worker, instance, parent, &spec, true); err != nil {
		t.Fatal(err)
	}
	config, err := readMinecraftMinigameConfig(ctx, worker, instance)
	if err != nil || config.Variant != "ranked" || config.Spec.Variants != nil || len(config.Spec.Lifecycle.StartCommands) != 0 {
		t.Fatalf("not pinned: %+v %v", config, err)
	}
}
