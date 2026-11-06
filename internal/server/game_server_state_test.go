package server

import "testing"

func TestDeriveGameServerState(t *testing.T) {
	header := "NAME IMAGE COMMAND SERVICE CREATED STATUS PORTS\n"
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"empty", "", "down"},
		{"up", header + "lobby-1-mc-1 itzg/minecraft-server \"/start\" mc 2 minutes ago Up 2 minutes 25565/tcp", "up"},
		{"up with health", header + "lobby-1-mc-1 img \"/start\" mc 1 minute ago Up 1 minute (healthy)", "up"},
		{"exited with up in name", header + "backup-group-1 img \"/start\" mc 2 hours ago Exited (1) 3 minutes ago", "down"},
		{"restarting", header + "lobby-1-mc-1 img \"/start\" mc 2 hours ago Restarting (1) 5 seconds ago", "down"},
		{"header only", header, "down"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveGameServerState(tt.output); got != tt.want {
				t.Fatalf("deriveGameServerState() = %q, want %q", got, tt.want)
			}
		})
	}
}
