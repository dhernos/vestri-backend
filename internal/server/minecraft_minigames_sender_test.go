package server

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const minecraftMinigameSenderLifecycleJSON = `{"onAllJoined":[{"command":"setup {player} {uuid} {team}","sender":"player"}],"teamCommands":[{"team":"red","command":"team {player} {uuid}","sender":"player"}],"startCommands":["legacy {matchId}",{"command":"start {player} {uuid} {team}","sender":"player"},{"command":"server {matchId}","sender":"server"}],"onPlayerJoin":[{"command":"welcome {player} {uuid} {team}"},{"command":"join {player}","sender":"player"}]}`

func assertMinecraftMinigameSenderLifecycle(t *testing.T, lifecycle minecraftMinigameLifecycle) {
	t.Helper()
	var expected, actual map[string]interface{}
	if err := json.Unmarshal([]byte(minecraftMinigameSenderLifecycleJSON), &expected); err != nil {
		t.Fatal(err)
	}
	delete(expected["startCommands"].([]interface{})[2].(map[string]interface{}), "sender")
	encoded, err := json.Marshal(lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &actual); err != nil {
		t.Fatal(err)
	}
	for field, value := range expected {
		if !reflect.DeepEqual(actual[field], value) {
			t.Fatalf("%s lost lifecycle contract: %s", field, encoded)
		}
	}
}

func TestMinecraftMinigameSenderJSON(t *testing.T) {
	for _, command := range []interface{}{
		minecraftMinigameCommand{Command: "setup", Sender: "server"},
		minecraftMinigameTeamCommand{Team: "red", Command: "team", Sender: "server"},
		minecraftMinigameStartCommand{Command: "start", Sender: "server"},
	} {
		encoded, err := json.Marshal(command)
		if err != nil || strings.Contains(string(encoded), "sender") {
			t.Fatalf("default sender not omitted: %s %v", encoded, err)
		}
	}
	for _, list := range []string{"onAllJoined", "teamCommands", "startCommands", "onPlayerJoin"} {
		for _, sender := range []string{`"console"`, `""`, `null`, `false`, `42`, `{}`, `[]`, `"Player"`} {
			t.Run(list+"/"+sender, func(t *testing.T) {
				var lifecycle minecraftMinigameLifecycle
				if err := json.Unmarshal([]byte(`{"`+list+`":[{"command":"say hi","team":"red","sender":`+sender+`}]}`), &lifecycle); err == nil {
					t.Fatal("invalid sender accepted")
				}
			})
		}
	}
	for _, invalid := range []string{`null`, `42`, `false`, `[]`} {
		var command minecraftMinigameStartCommand
		if err := json.Unmarshal([]byte(invalid), &command); err == nil {
			t.Fatalf("invalid start command accepted: %s", invalid)
		}
	}
	const input = `{"onAllJoined":[{"command":"say setup","sender":"server"}],"teamCommands":[{"team":"red","command":"join {player}","sender":"player"}],"startCommands":["legacy {matchId}",{"command":"start {player} {uuid} {team}","sender":"player"},{"command":"object {matchId}","sender":"server"}],"onPlayerJoin":[{"command":"welcome {player} {uuid} {team}","sender":"server"},{"command":"join","sender":"player"}]}`
	var lifecycle minecraftMinigameLifecycle
	if err := json.Unmarshal([]byte(input), &lifecycle); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`"startCommands":["legacy {matchId}",{"command":"start {player} {uuid} {team}","sender":"player"},{"command":"object {matchId}"}]`,
		`"onPlayerJoin":[{"command":"welcome {player} {uuid} {team}"},{"command":"join","sender":"player"}]`,
		`"teamCommands":[{"team":"red","command":"join {player}","sender":"player"}]`,
	} {
		if !strings.Contains(string(encoded), expected) {
			t.Fatalf("roundtrip lost contract: %s", encoded)
		}
	}
	if strings.Contains(string(encoded), `"sender":"server"`) {
		t.Fatalf("default sender not omitted: %s", encoded)
	}
	var decoded minecraftMinigameLifecycle
	if err := json.Unmarshal(encoded, &decoded); err != nil || !decoded.StartCommands[0].legacy || decoded.StartCommands[2].legacy {
		t.Fatalf("legacy/object distinction lost: %+v %v", decoded.StartCommands, err)
	}
}

func TestMinecraftMinigameSenderScopes(t *testing.T) {
	for _, test := range []struct {
		name, list, command string
		noTeams, valid      bool
	}{
		{"setup once server", "onAllJoined", `{"command":"say {matchId}"}`, false, true},
		{"setup once server player", "onAllJoined", `{"command":"say {player}"}`, false, false},
		{"setup once player", "onAllJoined", `{"command":"start {player} {uuid} {team} {matchId}","sender":"player"}`, false, true},
		{"setup once player ffa", "onAllJoined", `{"command":"start {player} {uuid}","sender":"player"}`, true, true},
		{"setup once player ffa team", "onAllJoined", `{"command":"start {team}","sender":"player"}`, true, false},
		{"setup foreach server", "onAllJoined", `{"command":"set {player} {uuid} {team}","forEach":"player","sender":"server"}`, false, true},
		{"setup foreach player", "onAllJoined", `{"command":"set {player} {uuid} {team}","forEach":"player","sender":"player"}`, false, true},
		{"setup team player", "onAllJoined", `{"command":"set {player} {uuid} {team}","forEach":"team","sender":"player"}`, false, true},
		{"setup team server player", "onAllJoined", `{"command":"set {player}","forEach":"team"}`, false, false},
		{"setup ffa team repetition", "onAllJoined", `{"command":"set","forEach":"team","sender":"player"}`, true, false},
		{"team player", "teamCommands", `{"team":"red","command":"set {player} {uuid} {team} {matchId}","sender":"player"}`, false, true},
		{"team server", "teamCommands", `{"team":"red","command":"set {player} {uuid} {team} {matchId}","sender":"server"}`, false, true},
		{"team unknown", "teamCommands", `{"team":"missing","command":"set","sender":"player"}`, false, false},
		{"legacy start", "startCommands", `"start {matchId}"`, true, true},
		{"legacy start player", "startCommands", `"start {player}"`, false, false},
		{"start server uuid", "startCommands", `{"command":"start {uuid}","sender":"server"}`, false, false},
		{"start server team", "startCommands", `{"command":"start {team}"}`, false, false},
		{"start player", "startCommands", `{"command":"start {player} {uuid} {team} {matchId}","sender":"player"}`, false, true},
		{"start player ffa", "startCommands", `{"command":"start {player} {uuid}","sender":"player"}`, true, true},
		{"start player ffa team", "startCommands", `{"command":"start {team}","sender":"player"}`, true, false},
		{"join server", "onPlayerJoin", `{"command":"set {player} {uuid} {team} {matchId}","sender":"server"}`, false, true},
		{"join player", "onPlayerJoin", `{"command":"set {player} {uuid} {team} {matchId}","sender":"player"}`, false, true},
		{"join ffa", "onPlayerJoin", `{"command":"set {player} {uuid} {matchId}"}`, true, true},
		{"join ffa team", "onPlayerJoin", `{"command":"set {team}"}`, true, false},
		{"join foreach player", "onPlayerJoin", `{"command":"set","forEach":"player"}`, false, false},
		{"join foreach team", "onPlayerJoin", `{"command":"set","forEach":"team"}`, false, false},
		{"join foreach empty", "onPlayerJoin", `{"command":"set","forEach":""}`, false, false},
		{"join foreach null", "onPlayerJoin", `{"command":"set","forEach":null}`, false, false},
		{"join foreach case insensitive", "onPlayerJoin", `{"command":"set","ForEach":""}`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := testMinecraftMinigameSpec(t)
			spec.Minigame.Lifecycle.OnAllJoined = nil
			if test.noTeams {
				spec.Minigame.Teams = nil
			}
			if err := json.Unmarshal([]byte(`{"`+test.list+`":[`+test.command+`]}`), &spec.Minigame.Lifecycle); err != nil {
				t.Fatal(err)
			}
			if err := validateMinecraftMinigame(&spec); (err == nil) != test.valid {
				t.Fatalf("valid=%t error=%v", test.valid, err)
			}
		})
	}
}

func TestMinecraftMinigameJoinModesAndLimits(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		spec := testMinecraftMinigameSpec(t)
		game := spec.Minigame
		game.LobbyMode = "plugin"
		game.Lifecycle.OnAllJoined = nil
		game.Lifecycle.OnPlayerJoin = []minecraftMinigameCommand{{Command: "join {player} {uuid}"}, {Command: "join {player}", Sender: "player"}}
		if permanent {
			game.InstanceMode = "permanent"
			game.Lifecycle.End.DeleteServer, game.Lifecycle.End.WhenEmpty = false, false
			game.Lifecycle.End.LogPattern = ""
		}
		if err := validateMinecraftMinigame(&spec); err != nil {
			t.Fatal(err)
		}
		game.Lifecycle.StartCommands = []minecraftMinigameStartCommand{{Command: "start", Sender: "player"}}
		if err := validateMinecraftMinigame(&spec); err == nil {
			t.Fatal("plugin startup accepted")
		}
	}
	for _, list := range []string{"onAllJoined", "teamCommands", "startCommands", "onPlayerJoin"} {
		for _, text := range []string{"", " ", "/say hi", " /say hi", "say\nhi", "say\x00hi", "say {unknown}", "say {player", strings.Repeat("a", 1025), strings.Repeat("a", 1024), strings.Repeat("\u00e9", 513)} {
			spec := testMinecraftMinigameSpec(t)
			spec.Minigame.Lifecycle.OnAllJoined = nil
			command, _ := json.Marshal(map[string]string{"command": text, "team": "red", "sender": "player"})
			if err := json.Unmarshal([]byte(`{"`+list+`":[`+string(command)+`]}`), &spec.Minigame.Lifecycle); err != nil {
				t.Fatal(err)
			}
			valid := text == strings.Repeat("a", 1024)
			if err := validateMinecraftMinigame(&spec); (err == nil) != valid {
				t.Fatalf("%s text=%q valid=%t error=%v", list, text, valid, err)
			}
		}
	}
	for _, count := range []int{97, 98} {
		spec := testMinecraftMinigameSpec(t)
		for index := 0; index < count; index++ {
			spec.Minigame.Lifecycle.OnPlayerJoin = append(spec.Minigame.Lifecycle.OnPlayerJoin, minecraftMinigameCommand{Command: "join"})
		}
		spec.Minigame.Lifecycle.TeamCommands = []minecraftMinigameTeamCommand{{Team: "red", Command: "team"}}
		spec.Minigame.Lifecycle.StartCommands = []minecraftMinigameStartCommand{{Command: "start"}}
		if err := validateMinecraftMinigame(&spec); (err == nil) != (count == 97) {
			t.Fatalf("combined count=%d error=%v", count+3, err)
		}
	}
}

func TestMinecraftMinigameJoinVariantInheritance(t *testing.T) {
	for _, list := range []string{"onAllJoined", "startCommands", "onPlayerJoin"} {
		for _, variant := range []string{`{}`, `{"teams":["red","green"]}`, `{"teams":[],"teamSize":0}`} {
			spec := testMinecraftMinigameSpec(t)
			spec.Minigame.Lifecycle.OnAllJoined = nil
			if err := json.Unmarshal([]byte(`{"`+list+`":[{"command":"set {player} {uuid} {team}","sender":"player"}]}`), &spec.Minigame.Lifecycle); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(`{"one":`+variant+`}`), &spec.Minigame.Variants); err != nil {
				t.Fatal(err)
			}
			err := validateMinecraftMinigame(&spec)
			if (err == nil) != (variant != `{"teams":[],"teamSize":0}`) {
				t.Fatalf("list=%s variant=%s error=%v", list, variant, err)
			}
			if err != nil && !strings.Contains(err.Error(), "variant one:") {
				t.Fatal(err)
			}
		}
	}
}
