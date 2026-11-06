package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"yourapp/internal/auth"
)

func supportsGameServerDatabases(server *auth.GameServer) bool {
	return strings.EqualFold(strings.TrimSpace(parseGameServerMetadata(server.Metadata).Game), "minecraft") || isVelocityServer(server)
}

func (s *Server) handleGameServerDatabases(w http.ResponseWriter, r *http.Request) {
	s.handleGameServerDatabaseRequest(w, r, false)
}

func (s *Server) handleGameServerDatabaseAction(w http.ResponseWriter, r *http.Request) {
	s.handleGameServerDatabaseRequest(w, r, true)
}

func (s *Server) handleGameServerDatabaseRequest(w http.ResponseWriter, r *http.Request, action bool) {
	w.Header().Set("Cache-Control", "no-store")
	_, node, gameServer, role, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServer(role) {
		writeError(w, http.StatusForbidden, "Only server owner/admin can manage databases and view database credentials")
		return
	}
	if !supportsGameServerDatabases(gameServer) {
		writeError(w, http.StatusBadRequest, "Databases are only available for Minecraft and Velocity servers")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Worker node configuration is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	endpoint := "/databases"
	var payload interface{}
	if r.Method == http.MethodGet {
		endpoint += "?" + url.Values{"owner": {gameServer.ID}, "stack": {gameServer.StackName}}.Encode()
	} else {
		var request struct {
			Name    string `json:"name"`
			Engine  string `json:"engine"`
			ID      string `json:"id"`
			Action  string `json:"action"`
			Confirm string `json:"confirm"`
		}
		if decodeJSON(r, &request) != nil {
			writeError(w, http.StatusBadRequest, "Invalid database request")
			return
		}
		if action {
			if request.ID == "" || (request.Action != "start" && request.Action != "stop" && request.Action != "delete") {
				writeError(w, http.StatusBadRequest, "Invalid database action")
				return
			}
			payload = map[string]string{"owner": gameServer.ID, "stack": gameServer.StackName, "id": request.ID, "action": request.Action, "confirm": request.Confirm}
		} else {
			if request.Engine != "mariadb" && request.Engine != "postgres" {
				writeError(w, http.StatusBadRequest, "Unsupported database engine")
				return
			}
			payload = map[string]string{"owner": gameServer.ID, "stack": gameServer.StackName, "name": request.Name, "engine": request.Engine}
		}
	}
	status, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, r.Method, endpoint, payload)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Database worker request failed")
		return
	}
	if status < 200 || status >= 300 {
		writeError(w, status, strings.TrimSpace(string(body)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) ensureNoGameServerDatabases(ctx context.Context, baseURL *url.URL, apiKey string, gameServer *auth.GameServer) error {
	query := url.Values{"owner": {gameServer.ID}, "stack": {gameServer.StackName}}.Encode()
	status, body, err := s.callWorkerJSON(ctx, baseURL, apiKey, http.MethodGet, "/databases?"+query, nil)
	if err != nil {
		return fmt.Errorf("could not check database containers")
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status != http.StatusOK {
		return fmt.Errorf("could not check database containers; check the worker and database storage before deleting this server")
	}
	var state struct {
		Databases []json.RawMessage `json:"databases"`
	}
	if json.Unmarshal(body, &state) != nil {
		return fmt.Errorf("invalid database status response")
	}
	if len(state.Databases) != 0 {
		return fmt.Errorf("delete this server's database containers in the Databases tab first")
	}
	return nil
}
