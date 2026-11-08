package server

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestVelocityPlayerPolicyCountryCompatibility(t *testing.T) {
	legacy := `{"whitelistEnabled":false,"whitelist":[],"bans":[],"ipBans":[]}`
	policy, err := parseVelocityPlayerPolicy(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if policy.CountryWhitelistEnabled || policy.CountryWhitelist == nil || policy.CountryBans == nil || len(policy.CountryWhitelist)+len(policy.CountryBans) != 0 {
		t.Fatalf("unexpected legacy country defaults: %+v", policy)
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]string{"countryWhitelistEnabled": "false", "countryWhitelist": "[]", "countryBans": "[]"} {
		if string(fields[key]) != expected {
			t.Fatalf("%s = %s, want %s", key, fields[key], expected)
		}
	}
	for _, extra := range []string{
		`"countryWhitelistEnabled":null`, `"countryWhitelist":null`, `"countryBans":null`,
		`"countryWhitelistEnabled":"true"`, `"countryWhitelist":false`, `"countryBans":{}`,
		`"countryWhitelist":["ZZ"]`, `"countryBans":["UK"]`,
		`"countryWhitelist":["us"]`, `"countryBans":[" DE "]`,
	} {
		t.Run(extra, func(t *testing.T) {
			content := legacy[:len(legacy)-1] + "," + extra + "}"
			if _, err := parseVelocityPlayerPolicy(content); err == nil {
				t.Fatalf("accepted invalid policy: %s", content)
			}
		})
	}
	if _, err := parseVelocityPlayerPolicy(legacy[:len(legacy)-1] + `,"countryWhitelistEnabled":true,"countryWhitelist":["US","DE","AX"],"countryBans":["GB","BQ","SS"]}`); err != nil {
		t.Fatal(err)
	}
	if len(velocityCountryCodes) != 249 {
		t.Fatalf("expected 249 ISO country codes, got %d", len(velocityCountryCodes))
	}
}

func TestVelocityPlayerPolicyCountryActions(t *testing.T) {
	policy := emptyVelocityPlayerPolicy()
	for _, enabled := range []bool{true, false} {
		if err := updateVelocityCountryPolicy(&policy, "country-whitelist-enable", "", enabled); err != nil {
			t.Fatal(err)
		}
		if policy.CountryWhitelistEnabled != enabled {
			t.Fatalf("country whitelist enabled = %v, want %v", policy.CountryWhitelistEnabled, enabled)
		}
	}
	for _, action := range []string{"country-whitelist-add", "country-ban"} {
		for _, country := range []string{" de ", "DE", "\tus\n", "Us"} {
			if err := updateVelocityCountryPolicy(&policy, action, country, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, countries := range [][]string{policy.CountryWhitelist, policy.CountryBans} {
		if !reflect.DeepEqual(countries, []string{"DE", "US"}) {
			t.Fatalf("countries must be normalized and unique: %v", countries)
		}
	}
	policy.CountryWhitelist = append(policy.CountryWhitelist, "DE", "US")
	policy.CountryBans = append(policy.CountryBans, "DE", "US")
	for _, action := range []string{"country-whitelist-remove", "country-unban"} {
		if err := updateVelocityCountryPolicy(&policy, action, " dE ", false); err != nil {
			t.Fatal(err)
		}
	}
	for _, countries := range [][]string{policy.CountryWhitelist, policy.CountryBans} {
		if !reflect.DeepEqual(countries, []string{"US"}) {
			t.Fatalf("removal must remove all matches and deduplicate: %v", countries)
		}
	}
	for _, action := range []string{"country-whitelist-remove", "country-unban"} {
		for _, country := range []string{"us", "US", "DE"} {
			if err := updateVelocityCountryPolicy(&policy, action, country, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	if policy.CountryWhitelist == nil || policy.CountryBans == nil || len(policy.CountryWhitelist)+len(policy.CountryBans) != 0 {
		t.Fatalf("country entries not removed: %+v", policy)
	}
	for _, action := range []string{"country-whitelist-add", "country-whitelist-remove", "country-ban", "country-unban"} {
		for _, country := range []string{"", "ZZ", "UK", "XK", "USA", "U1", "??"} {
			before, _ := json.Marshal(policy)
			if updateVelocityCountryPolicy(&policy, action, country, true) == nil {
				t.Fatalf("accepted invalid country %q for %s", country, action)
			}
			after, _ := json.Marshal(policy)
			if string(before) != string(after) {
				t.Fatalf("invalid action mutated policy: %s", action)
			}
		}
	}
	if updateVelocityCountryPolicy(&policy, "country-unknown", "US", true) == nil {
		t.Fatal("accepted unknown country action")
	}
}

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
