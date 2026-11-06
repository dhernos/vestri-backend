package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"yourapp/internal/auth"
)

var minecraftUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)

var velocityWhitelistMu sync.Mutex

var minecraftProfileClient = &http.Client{Timeout: 10 * time.Second}

type minecraftWhitelistEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

func minecraftProfileUUID(value string) (string, error) {
	if len(value) != 32 {
		return "", fmt.Errorf("invalid Minecraft profile UUID")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("invalid Minecraft profile UUID")
	}
	value = strings.ToLower(value)
	return value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:], nil
}

func velocityWhitelistMainServer(parentID, config string, servers []auth.GameServer) *auth.GameServer {
	targets := parseVelocityTomlTryServers(config)
	if len(targets) == 0 {
		return nil
	}
	for i := range servers {
		metadata := parseGameServerMetadata(servers[i].Metadata)
		if metadata.ParentServerID == parentID && servers[i].Slug == targets[0] {
			return &servers[i]
		}
	}
	return nil
}

func resolveMinecraftWhitelistProfile(ctx context.Context, username string) (minecraftWhitelistEntry, error) {
	var entry minecraftWhitelistEntry
	if !minecraftUsernamePattern.MatchString(username) {
		return entry, fmt.Errorf("invalid Minecraft username")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.mojang.com/users/profiles/minecraft/"+username, nil)
	if err != nil {
		return entry, err
	}
	res, err := minecraftProfileClient.Do(req)
	if err != nil {
		return entry, fmt.Errorf("Minecraft profile lookup failed")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusNoContent {
		return entry, fmt.Errorf("Minecraft player not found")
	}
	if res.StatusCode != http.StatusOK {
		return entry, fmt.Errorf("Minecraft profile service is unavailable")
	}
	var profile struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&profile); err != nil {
		return entry, fmt.Errorf("invalid Minecraft profile response")
	}
	if !minecraftUsernamePattern.MatchString(profile.Name) || !strings.EqualFold(profile.Name, username) {
		return entry, fmt.Errorf("invalid Minecraft profile response")
	}
	entry.UUID, err = minecraftProfileUUID(profile.ID)
	entry.Name = profile.Name
	return entry, err
}

func parseMinecraftWhitelist(content string, missing bool) ([]minecraftWhitelistEntry, error) {
	entries := make([]minecraftWhitelistEntry, 0)
	if missing {
		return entries, nil
	}
	if err := json.Unmarshal([]byte(content), &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("existing whitelist.json is invalid; repair it before making changes")
	}
	for _, entry := range entries {
		canonical, err := minecraftProfileUUID(strings.ReplaceAll(entry.UUID, "-", ""))
		if err != nil || !strings.EqualFold(canonical, entry.UUID) || !minecraftUsernamePattern.MatchString(entry.Name) {
			return nil, fmt.Errorf("existing whitelist.json contains an invalid entry")
		}
	}
	return entries, nil
}

func updateMinecraftWhitelist(entries []minecraftWhitelistEntry, entry minecraftWhitelistEntry, remove bool) []minecraftWhitelistEntry {
	updated := make([]minecraftWhitelistEntry, 0, len(entries)+1)
	for _, existing := range entries {
		if !strings.EqualFold(existing.UUID, entry.UUID) && (remove || !strings.EqualFold(existing.Name, entry.Name)) {
			updated = append(updated, existing)
		}
	}
	if !remove {
		updated = append(updated, entry)
	}
	return updated
}

func (s *Server) handleVelocityWhitelist(w http.ResponseWriter, r *http.Request) {
	sess, node, proxy, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Server permission denied for whitelist management")
		return
	}
	if !isVelocityServer(proxy) {
		writeError(w, http.StatusBadRequest, "Whitelist management is only available for velocity servers")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	config, _, err := s.workerReadFileOptional(r.Context(), baseURL, apiKey, path.Join(proxy.RootPath, velocityTomlRelativePath))
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read velocity configuration")
		return
	}
	servers, err := s.Users.ListGameServersForNode(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load subservers")
		return
	}
	main := velocityWhitelistMainServer(proxy.ID, config, servers)
	if main == nil {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]interface{}{"available": false, "entries": []minecraftWhitelistEntry{}})
		} else {
			writeError(w, http.StatusConflict, "Create a main subserver before managing the whitelist")
		}
		return
	}
	access, err := s.Users.FindAccessibleGameServerByRefForNode(r.Context(), sess.UserID, node, main.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load main subserver access")
		return
	}
	if access == nil || !canManageGameServer(access.AccessRole) {
		writeError(w, http.StatusForbidden, "Main subserver permission denied for whitelist management")
		return
	}
	var entry minecraftWhitelistEntry
	var remove bool
	if r.Method == http.MethodPost {
		var req struct {
			Username string `json:"username"`
			UUID     string `json:"uuid"`
			Action   string `json:"action"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		switch req.Action {
		case "add":
			req.Username = strings.TrimSpace(req.Username)
			if !minecraftUsernamePattern.MatchString(req.Username) {
				writeError(w, http.StatusBadRequest, "Invalid Minecraft username")
				return
			}
			entry, err = resolveMinecraftWhitelistProfile(r.Context(), req.Username)
			if err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
		case "remove":
			remove = true
			entry.UUID, err = minecraftProfileUUID(strings.ReplaceAll(req.UUID, "-", ""))
			if err != nil || !strings.EqualFold(entry.UUID, req.UUID) {
				writeError(w, http.StatusBadRequest, "Invalid Minecraft UUID")
				return
			}
		default:
			writeError(w, http.StatusBadRequest, "Invalid whitelist action")
			return
		}
	}
	velocityWhitelistMu.Lock()
	defer velocityWhitelistMu.Unlock()
	filePath := path.Join(main.RootPath, "data/whitelist.json")
	content, missing, err := s.workerReadFileOptional(r.Context(), baseURL, apiKey, filePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read whitelist")
		return
	}
	entries, err := parseMinecraftWhitelist(content, missing)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if r.Method == http.MethodPost {
		entries = updateMinecraftWhitelist(entries, entry, remove)
		encoded, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to encode whitelist")
			return
		}
		if err := s.workerWriteFile(r.Context(), baseURL, apiKey, filePath, string(encoded)+"\n"); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to write whitelist")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"available": true, "mainServerName": main.Name, "entries": entries,
	})
}
