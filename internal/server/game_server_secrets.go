package server

import (
	"fmt"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"

	"yourapp/internal/auth"

	"github.com/go-chi/chi/v5"
)

// Secret env files live outside every server root so the file manager, backups and
// log readers cannot expose them.
const gameServerSecretsDir = ".vestri-secrets"

const maxGameServerSecretValueBytes = 4096

var gameServerSecretKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

type createGameServerSecretRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func gameServerSecretsFilePath(server *auth.GameServer) string {
	return path.Join(gameServerSecretsDir, server.ID+".env")
}

// gameServerSecretsComposeRef returns the secrets file path relative to the compose project directory.
func gameServerSecretsComposeRef(server *auth.GameServer) string {
	composeDir := path.Dir(path.Clean(strings.Trim(server.ComposePath, "/")))
	depth := 0
	if composeDir != "." {
		depth = strings.Count(composeDir, "/") + 1
	}
	return strings.Repeat("../", depth) + gameServerSecretsFilePath(server)
}

func validateGameServerSecret(key, value string) error {
	if !gameServerSecretKeyPattern.MatchString(key) {
		return fmt.Errorf("Secret name must start with a letter or underscore and contain only letters, digits and underscores")
	}
	if value == "" {
		return fmt.Errorf("Secret value is required")
	}
	if len(value) > maxGameServerSecretValueBytes {
		return fmt.Errorf("Secret value is too long")
	}
	// Values are written single-quoted, which disables Compose interpolation but cannot escape these characters.
	if strings.ContainsAny(value, "'\r\n\x00") {
		return fmt.Errorf("Secret value must not contain single quotes or line breaks")
	}
	return nil
}

func parseGameServerSecretKeys(content string) []string {
	keys := make([]string, 0)
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		key, _, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if found && gameServerSecretKeyPattern.MatchString(key) {
			keys = append(keys, key)
		}
	}
	return keys
}

func removeGameServerSecretLine(content, key string) (string, bool) {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	result := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		lineKey, _, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(lineKey) == key {
			removed = true
			continue
		}
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	if len(result) == 0 {
		return "", removed
	}
	return strings.Join(result, "\n") + "\n", removed
}

// ensureComposeAllServicesEnvFile adds envFile to the env_file list of every service.
func ensureComposeAllServicesEnvFile(content, envFile string) string {
	for _, serviceName := range composeServiceNames(content) {
		content = ensureComposeServiceEnvFile(content, serviceName, envFile)
	}
	return content
}

func ensureComposeServiceEnvFile(content, serviceName, envFile string) string {
	lines := splitPreserveTrailingNewline(content)
	serviceStart, serviceEnd, found := findComposeServiceBounds(lines, serviceName)
	if !found {
		return content
	}

	entry := fmt.Sprintf("      - %q", envFile)
	for i := serviceStart + 1; i < serviceEnd; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if leadingWhitespaceWidth(lines[i]) != 4 || !strings.HasPrefix(trimmed, "env_file:") {
			continue
		}

		inlineValue := strings.TrimSpace(strings.TrimPrefix(trimmed, "env_file:"))
		if inlineValue != "" {
			if strings.Trim(inlineValue, `"'`) == envFile {
				return content
			}
			if strings.HasPrefix(inlineValue, "[") {
				// Flow-style lists are left untouched; the user manages them manually.
				return content
			}
			replacement := []string{"    env_file:", "      - " + inlineValue, entry}
			lines = append(lines[:i], append(replacement, lines[i+1:]...)...)
			return strings.Join(lines, "\n")
		}

		listEnd := serviceEnd
		for j := i + 1; j < serviceEnd; j++ {
			nextTrimmed := strings.TrimSpace(lines[j])
			if nextTrimmed == "" || strings.HasPrefix(nextTrimmed, "#") {
				continue
			}
			if leadingWhitespaceWidth(lines[j]) <= 4 {
				listEnd = j
				break
			}
			if strings.Trim(strings.TrimSpace(strings.TrimPrefix(nextTrimmed, "-")), `"'`) == envFile {
				return content
			}
		}
		lines = append(lines[:listEnd], append([]string{entry}, lines[listEnd:]...)...)
		return strings.Join(lines, "\n")
	}

	insertAt := serviceEnd
	for insertAt > serviceStart+1 && strings.TrimSpace(lines[insertAt-1]) == "" {
		insertAt--
	}
	block := []string{"    env_file:", entry}
	lines = append(lines[:insertAt], append(block, lines[insertAt:]...)...)
	return strings.Join(lines, "\n")
}

func (s *Server) handleListGameServerSecrets(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can manage secrets")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	content, _, err := s.workerReadFileOptional(r.Context(), baseURL, apiKey, gameServerSecretsFilePath(server))
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read secrets on worker")
		return
	}
	keys := parseGameServerSecretKeys(content)
	sort.Strings(keys)
	writeJSON(w, http.StatusOK, map[string]interface{}{"secrets": keys})
}

func (s *Server) handleCreateGameServerSecret(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can manage secrets")
		return
	}

	var req createGameServerSecretRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Key = strings.TrimSpace(req.Key)
	if err := validateGameServerSecret(req.Key, req.Value); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	secretsPath := gameServerSecretsFilePath(server)
	content, _, err := s.workerReadFileOptional(r.Context(), baseURL, apiKey, secretsPath)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read secrets on worker")
		return
	}
	for _, existing := range parseGameServerSecretKeys(content) {
		if existing == req.Key {
			writeError(w, http.StatusConflict, "A secret with this name already exists. Delete it first to replace it.")
			return
		}
	}

	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += req.Key + "='" + req.Value + "'\n"
	if err := s.workerWriteFile(r.Context(), baseURL, apiKey, secretsPath, content); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to write secrets on worker")
		return
	}

	composeContent, missing, err := s.workerReadFileOptional(r.Context(), baseURL, apiKey, server.ComposePath)
	if err != nil || missing {
		writeError(w, http.StatusBadGateway, "Failed to read compose file on worker")
		return
	}
	updatedCompose := ensureComposeAllServicesEnvFile(composeContent, gameServerSecretsComposeRef(server))
	if updatedCompose != composeContent {
		if err := s.workerWriteFile(r.Context(), baseURL, apiKey, server.ComposePath, updatedCompose); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to update compose file on worker")
			return
		}
	}

	writeJSON(w, http.StatusCreated, map[string]string{"key": req.Key})
}

func (s *Server) handleDeleteGameServerSecret(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(serverRole) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can manage secrets")
		return
	}
	key := strings.TrimSpace(chi.URLParam(r, "secretKey"))
	if !gameServerSecretKeyPattern.MatchString(key) {
		writeError(w, http.StatusBadRequest, "Invalid secret name")
		return
	}

	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}

	secretsPath := gameServerSecretsFilePath(server)
	content, _, err := s.workerReadFileOptional(r.Context(), baseURL, apiKey, secretsPath)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read secrets on worker")
		return
	}
	updated, removed := removeGameServerSecretLine(content, key)
	if !removed {
		writeError(w, http.StatusNotFound, "Secret not found")
		return
	}
	// The (possibly empty) file is kept because the compose file still references it.
	if err := s.workerWriteFile(r.Context(), baseURL, apiKey, secretsPath, updated); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to write secrets on worker")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Secret deleted."})
}
