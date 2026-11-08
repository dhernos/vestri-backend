package server

import (
	"testing"

	"yourapp/internal/auth"
)

func TestMinecraftMinigameDelegationIdentity(t *testing.T) {
	for _, scenario := range []string{"same_creator", "different_creator", "different_template", "different_key", "different_node", "no_admin", "empty_user", "different_server"} {
		t.Run(scenario, func(t *testing.T) {
			principal := minecraftAPIPrincipal{Key: &auth.MinecraftAPIKey{ID: "key", UserID: "creator", NodeID: "node", TemplateID: "template"}, Node: &auth.WorkerNode{ID: "node", AccessRole: "owner"}}
			instance := auth.MinecraftInstance{ServerID: "server", TemplateID: "template"}
			server := &auth.GameServer{ID: "server", NodeID: "node", CreatedByUserID: "creator"}
			switch scenario {
			case "different_creator":
				server.CreatedByUserID = "other"
			case "different_template":
				instance.TemplateID = "other"
			case "different_key":
				instance.KeyID = "other"
			case "different_node":
				server.NodeID = "other"
			case "no_admin":
				principal.Node.AccessRole = "viewer"
			case "empty_user":
				principal.Key.UserID = ""
			case "different_server":
				server.ID = "other"
			}
			if got := minecraftKeyCanDelegateInstance(principal, instance, server); got != (scenario == "same_creator") {
				t.Fatalf("delegation identity = %t", got)
			}
		})
	}
	if minecraftKeyCanDelegateInstance(minecraftAPIPrincipal{}, auth.MinecraftInstance{}, nil) {
		t.Fatal("empty principal delegated")
	}
}
