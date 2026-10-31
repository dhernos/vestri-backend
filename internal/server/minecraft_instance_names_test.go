package server

import (
	"encoding/json"
	"testing"

	"yourapp/internal/auth"
)

func TestNextMinecraftInstanceName(t *testing.T) {
	metadata, _ := json.Marshal(gameServerStoredMetadata{ParentServerID: "proxy"})
	servers := []auth.GameServer{{Name: "BedWars-1", Metadata: metadata}, {Name: "bedwars-3", Metadata: metadata}}
	if got := nextMinecraftInstanceName("Bed Wars", servers, "proxy"); got != "BedWars-2" {
		t.Fatalf("expected BedWars-2, got %s", got)
	}
	if got := nextMinecraftInstanceName("Bed Wars", servers, "other"); got != "BedWars-1" {
		t.Fatalf("expected numbering scoped to proxy, got %s", got)
	}
	for _, template := range []string{"!!!", "_ Survival / PvP _"} {
		if got := nextMinecraftInstanceName(template, nil, "proxy"); !minecraftFriendlyName.MatchString(got) {
			t.Fatalf("unsafe name: %s", got)
		}
	}
}

func TestMinecraftInstanceProxyNamePreservesLegacy(t *testing.T) {
	metadata, _ := json.Marshal(gameServerStoredMetadata{VelocityServerName: "BedWars-1"})
	server := &auth.GameServer{Name: "BedWars-1", Slug: "mcgame-legacy", Metadata: metadata}
	if got := minecraftInstanceProxyName(server); got != "BedWars-1" {
		t.Fatalf("unexpected friendly name %s", got)
	}
	server.Name = "Renamed in panel"
	if got := minecraftInstanceProxyName(server); got != "BedWars-1" {
		t.Fatalf("panel rename changed proxy identity: %s", got)
	}
	server.Metadata = nil
	if got := minecraftInstanceProxyName(server); got != server.Slug {
		t.Fatalf("legacy name changed: %s", got)
	}
}
