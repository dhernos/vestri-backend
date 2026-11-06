package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
)

type velocityPlayerPolicy struct {
	WhitelistEnabled bool                      `json:"whitelistEnabled"`
	Whitelist        []minecraftWhitelistEntry `json:"whitelist"`
	Bans             []minecraftWhitelistEntry `json:"bans"`
	IPBans           []string                  `json:"ipBans"`
}

func emptyVelocityPlayerPolicy() velocityPlayerPolicy {
	return velocityPlayerPolicy{Whitelist: []minecraftWhitelistEntry{}, Bans: []minecraftWhitelistEntry{}, IPBans: []string{}}
}

func parseVelocityPlayerPolicy(content string) (velocityPlayerPolicy, error) {
	policy := emptyVelocityPlayerPolicy()
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(content), &fields) != nil {
		return policy, fmt.Errorf("Invalid proxy player policy")
	}
	for _, key := range []string{"whitelistEnabled", "whitelist", "bans", "ipBans"} {
		if value, found := fields[key]; !found || strings.TrimSpace(string(value)) == "null" {
			return policy, fmt.Errorf("Missing player policy field: %s", key)
		}
	}
	if len(content) > 4<<20 || json.Unmarshal([]byte(content), &policy) != nil || strings.TrimSpace(content) == "null" || policy.Whitelist == nil || policy.Bans == nil || policy.IPBans == nil {
		return policy, fmt.Errorf("Invalid proxy player policy; repair it before making changes")
	}
	for _, entries := range [][]minecraftWhitelistEntry{policy.Whitelist, policy.Bans} {
		for _, entry := range entries {
			canonical, err := minecraftProfileUUID(strings.ReplaceAll(entry.UUID, "-", ""))
			if err != nil || canonical != entry.UUID || !minecraftUsernamePattern.MatchString(entry.Name) {
				return policy, fmt.Errorf("Invalid player entry in proxy policy")
			}
		}
	}
	for _, ip := range policy.IPBans {
		if net.ParseIP(ip) == nil {
			return policy, fmt.Errorf("Invalid IP ban in proxy policy")
		}
	}
	return policy, nil
}

func updateVelocityPlayerPolicy(policy *velocityPlayerPolicy, action string, entry minecraftWhitelistEntry, ip string, enabled bool) error {
	switch action {
	case "whitelist-enable":
		policy.WhitelistEnabled = enabled
	case "whitelist-add", "whitelist-remove", "ban", "unban":
		canonical, err := minecraftProfileUUID(strings.ReplaceAll(entry.UUID, "-", ""))
		removing := action == "whitelist-remove" || action == "unban"
		if err != nil || canonical != entry.UUID || (!removing && !minecraftUsernamePattern.MatchString(entry.Name)) {
			return fmt.Errorf("Invalid Minecraft player")
		}
		if strings.HasPrefix(action, "whitelist-") {
			policy.Whitelist = updateMinecraftWhitelist(policy.Whitelist, entry, action == "whitelist-remove")
		} else {
			policy.Bans = updateMinecraftWhitelist(policy.Bans, entry, action == "unban")
		}
	case "ip-ban", "ip-unban":
		address := net.ParseIP(ip)
		if address == nil {
			return fmt.Errorf("Invalid IP address")
		}
		ip = address.String()
		updated := make([]string, 0, len(policy.IPBans)+1)
		for _, existing := range policy.IPBans {
			if parsed := net.ParseIP(existing); parsed == nil || !parsed.Equal(address) {
				updated = append(updated, existing)
			}
		}
		if action == "ip-ban" {
			updated = append(updated, ip)
		}
		policy.IPBans = updated
	default:
		return fmt.Errorf("Invalid player management action")
	}
	return nil
}

func (s *Server) handleVelocityPlayers(w http.ResponseWriter, r *http.Request) {
	sess, node, proxy, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Server permission denied for player management")
		return
	}
	if !isVelocityServer(proxy) {
		writeError(w, http.StatusBadRequest, "Player management requires a Velocity proxy")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	velocityWhitelistMu.Lock()
	defer velocityWhitelistMu.Unlock()
	policyPath := path.Join(proxy.RootPath, "data/vestri-player-policy.json")
	content, missing, err := s.workerReadFileOptional(r.Context(), baseURL, apiKey, policyPath)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read proxy player policy")
		return
	}
	policy := emptyVelocityPlayerPolicy()
	if !missing {
		policy, err = parseVelocityPlayerPolicy(content)
		if err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
	}
	config, _, err := s.workerReadFileOptional(r.Context(), baseURL, apiKey, path.Join(proxy.RootPath, velocityTomlRelativePath))
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read proxy configuration")
		return
	}
	servers, err := s.Users.ListGameServersForNode(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load proxy subservers")
		return
	}
	legacyMain := velocityWhitelistMainServer(proxy.ID, config, servers)
	legacyProperties, legacyPath := "", ""
	legacyEnabled := false
	if legacyMain != nil {
		legacyPath = path.Join(legacyMain.RootPath, "data/server.properties")
		legacyProperties, _, err = s.workerReadFileOptional(r.Context(), baseURL, apiKey, legacyPath)
		if err != nil {
			writeError(w, http.StatusBadGateway, "Failed to read legacy whitelist settings")
			return
		}
		legacyEnabled = legacyMinecraftWhitelistEnabled(legacyProperties)
		if legacyEnabled {
			access, accessErr := s.Users.FindAccessibleGameServerByRefForNode(r.Context(), sess.UserID, node, legacyMain.ID)
			if accessErr != nil || access == nil || !canManageGameServer(access.AccessRole) {
				writeError(w, http.StatusForbidden, "Main subserver management access is required to migrate its whitelist")
				return
			}
			if missing {
				legacy, absent, readErr := s.workerReadFileOptional(r.Context(), baseURL, apiKey, path.Join(legacyMain.RootPath, "data/whitelist.json"))
				if readErr != nil {
					writeError(w, http.StatusBadGateway, "Failed to read legacy whitelist")
					return
				}
				policy.Whitelist, err = parseMinecraftWhitelist(legacy, absent)
				if err != nil {
					writeError(w, http.StatusConflict, err.Error())
					return
				}
				policy.WhitelistEnabled = true
			}
		}
	}
	journal, absent, err := s.workerReadFileOptional(r.Context(), baseURL, apiKey, path.Join(proxy.RootPath, "data/vestri-players.json"))
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read player journal")
		return
	}
	var data struct {
		UpdatedAt     string            `json:"updatedAt"`
		PolicyHealthy *bool             `json:"policyHealthy"`
		PolicyError   string            `json:"policyError"`
		Players       []json.RawMessage `json:"players"`
		Attempts      []json.RawMessage `json:"attempts"`
	}
	data.Players, data.Attempts = []json.RawMessage{}, []json.RawMessage{}
	if !absent && json.Unmarshal([]byte(journal), &data) != nil {
		writeError(w, http.StatusConflict, "Invalid player journal")
		return
	}
	data.Attempts = boundedPlayerEventHistory(data.Attempts)
	if r.Method == http.MethodPost {
		updated, parseErr := time.Parse(time.RFC3339Nano, data.UpdatedAt)
		if legacyEnabled && (absent || parseErr != nil || time.Since(updated) > 30*time.Second || data.PolicyHealthy == nil || !*data.PolicyHealthy) {
			writeError(w, http.StatusConflict, "A running Vestri plugin 1.1.0 or newer with a healthy player journal is required before migrating the backend whitelist")
			return
		}
		var request struct {
			Action   string `json:"action"`
			Username string `json:"username"`
			UUID     string `json:"uuid"`
			IP       string `json:"ip"`
			Enabled  bool   `json:"enabled"`
		}
		if decodeJSON(r, &request) != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/whitelist") {
			switch request.Action {
			case "add":
				request.Action = "whitelist-add"
			case "remove":
				request.Action = "whitelist-remove"
			default:
				writeError(w, http.StatusBadRequest, "Invalid whitelist action")
				return
			}
		}
		entry := minecraftWhitelistEntry{UUID: request.UUID, Name: strings.TrimSpace(request.Username)}
		if entry.UUID == "" && (request.Action == "whitelist-add" || request.Action == "ban") {
			entry, err = resolveMinecraftWhitelistProfile(r.Context(), entry.Name)
			if err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
		}
		if err := updateVelocityPlayerPolicy(&policy, request.Action, entry, strings.TrimSpace(request.IP), request.Enabled); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		encoded, err := json.MarshalIndent(policy, "", "  ")
		if err != nil || len(encoded) > 4<<20 {
			writeError(w, http.StatusInternalServerError, "Failed to encode player policy")
			return
		}
		if err := s.workerWriteFile(r.Context(), baseURL, apiKey, policyPath, string(encoded)+"\n"); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to save player policy")
			return
		}
		if legacyEnabled {
			properties := upsertJavaPropertiesValue(legacyProperties, "white-list", "false")
			properties = upsertJavaPropertiesValue(properties, "enforce-whitelist", "false")
			if err := s.workerWriteFile(r.Context(), baseURL, apiKey, legacyPath, properties); err != nil {
				writeError(w, http.StatusBadGateway, "Proxy policy saved, but legacy whitelist migration failed; retry the operation")
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"policy": policy, "players": data.Players, "attempts": data.Attempts,
		"updatedAt": data.UpdatedAt, "available": !absent,
		"policyHealthy": data.PolicyHealthy, "policyError": data.PolicyError,
		"legacyMigration": legacyEnabled,
		"entries":         policy.Whitelist, "mainServerName": proxy.Name,
	})
}

func legacyMinecraftWhitelistEnabled(properties string) bool {
	for _, line := range strings.Split(properties, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found && strings.TrimSpace(key) == "white-list" {
			return strings.EqualFold(strings.TrimSpace(value), "true")
		}
	}
	return false
}
