package server

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

func (s *Server) handleStartMinecraftInstance(w http.ResponseWriter, r *http.Request) {
	s.handleMinecraftInstancePower(w, r, "up")
}

func (s *Server) handleStopMinecraftInstance(w http.ResponseWriter, r *http.Request) {
	s.handleMinecraftInstancePower(w, r, "down")
}

func (s *Server) handleMinecraftInstancePower(w http.ResponseWriter, r *http.Request, action string) {
	principal, ok := r.Context().Value(minecraftAPIContextKey{}).(minecraftAPIPrincipal)
	if !ok || principal.Node == nil || principal.Key == nil {
		writeError(w, http.StatusUnauthorized, "Minecraft API key required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	unlock, err := s.lockNodePlugins(ctx, principal.Node.ID)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	defer unlock()
	id := chi.URLParam(r, "instanceId")
	instances, err := s.Users.ListMinecraftInstances(ctx, principal.Node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load instances")
		return
	}
	found := false
	for _, instance := range instances {
		if instance.ServerID == id && minecraftKeyCanAccessInstance(principal.Key, instance) {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	instance, err := s.Users.FindGameServerByRefForNode(ctx, principal.Node.ID, id)
	if err != nil || instance == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	baseURL, apiKey, err := s.workerTargetFromNode(principal.Node)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Invalid worker configuration")
		return
	}
	if action == "up" {
		metadata := parseGameServerMetadata(instance.Metadata)
		if err = s.ensureVestriPlugin(ctx, baseURL, apiKey, principal.Node.ID, instance.RootPath, metadata.SoftwareVersion, resolvedGameServerKind(instance, metadata)); err != nil {
			writeError(w, http.StatusBadGateway, "Failed to install Vestri plugin: "+err.Error())
			return
		}
	}
	if _, err = s.workerStackAction(ctx, baseURL, apiKey, action, instance.StackName); err != nil {
		writeError(w, http.StatusBadGateway, "Failed to change instance power; files were preserved")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"serverId": id, "action": action})
}
