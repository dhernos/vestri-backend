package server

import "testing"

func TestParseVelocityPlayerPolicy(t *testing.T) {
	for _, invalid := range []string{
		"null", "{}", `{"whitelist":null}`,
		`{"whitelistEnabled":false,"whitelist":[],"bans":[],"ipBans":["example.com"]}`,
		`{"whitelistEnabled":false,"whitelist":[],"bans":[{"uuid":"invalid","name":"Notch"}],"ipBans":[]}`,
	} {
		if _, err := parseVelocityPlayerPolicy(invalid); err == nil {
			t.Fatalf("accepted invalid policy: %s", invalid)
		}
	}
	if _, err := parseVelocityPlayerPolicy(`{"whitelistEnabled":false,"whitelist":[],"bans":[],"ipBans":["::1"]}`); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyMinecraftWhitelistEnabled(t *testing.T) {
	for _, properties := range []string{"white-list=true\n", "# comment\nwhite-list = true\r\n"} {
		if !legacyMinecraftWhitelistEnabled(properties) {
			t.Fatalf("legacy whitelist not detected: %q", properties)
		}
	}
	for _, properties := range []string{"", "white-list=false", "#white-list=true"} {
		if legacyMinecraftWhitelistEnabled(properties) {
			t.Fatalf("unexpected legacy whitelist: %q", properties)
		}
	}
}

func TestVelocityPlayerPolicy(t *testing.T) {
	policy := emptyVelocityPlayerPolicy()
	player := minecraftWhitelistEntry{UUID: "069a79f4-44e9-4726-a5be-fca90e38aaf5", Name: "Notch"}
	for _, action := range []string{"whitelist-add", "ban", "whitelist-enable"} {
		if err := updateVelocityPlayerPolicy(&policy, action, player, "", true); err != nil {
			t.Fatal(err)
		}
	}
	if !policy.WhitelistEnabled || len(policy.Whitelist) != 1 || len(policy.Bans) != 1 {
		t.Fatalf("unexpected policy: %+v", policy)
	}
	for _, address := range []string{"2001:0db8::1", "2001:db8::1"} {
		if err := updateVelocityPlayerPolicy(&policy, "ip-ban", player, address, false); err != nil {
			t.Fatal(err)
		}
	}
	if len(policy.IPBans) != 1 || policy.IPBans[0] != "2001:db8::1" {
		t.Fatalf("IP bans must be normalized and unique: %v", policy.IPBans)
	}
	for _, action := range []string{"whitelist-remove", "unban", "ip-unban"} {
		if action != "ip-unban" {
			player.Name = ""
		}
		if err := updateVelocityPlayerPolicy(&policy, action, player, "2001:db8::1", false); err != nil {
			t.Fatal(err)
		}
	}
	if len(policy.Whitelist)+len(policy.Bans)+len(policy.IPBans) != 0 {
		t.Fatalf("entries not removed: %+v", policy)
	}
	for _, action := range []string{"ip-ban", "ban", "unknown"} {
		if updateVelocityPlayerPolicy(&policy, action, minecraftWhitelistEntry{}, "not-an-ip", false) == nil {
			t.Fatalf("accepted invalid %s", action)
		}
	}
}
