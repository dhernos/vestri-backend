package server

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"yourapp/internal/auth"
	"yourapp/internal/i18n"
)

type createGameServerInviteRequest struct {
	Email      string `json:"email"`
	Permission string `json:"permission"`
}

func (s *Server) handleCreateGameServerInvite(w http.ResponseWriter, r *http.Request) {
	sess, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerInvites(serverRole) {
		writeError(w, http.StatusForbidden, "You cannot manage invites for this game server")
		return
	}

	var req createGameServerInviteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if !validateEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	permission, ok := normalizeNodePermission(req.Permission)
	if !ok {
		writeError(w, http.StatusBadRequest, "Invalid server permission")
		return
	}

	inviter, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || inviter == nil {
		writeError(w, http.StatusInternalServerError, "Failed to load inviter")
		return
	}

	invite, err := s.Users.CreateGameServerInvite(
		r.Context(),
		server.ID,
		sess.UserID,
		req.Email,
		permission,
		time.Now().Add(nodeInviteTTL),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create game server invite")
		return
	}

	invite.NodeID = node.ID
	invite.NodeName = node.Name
	invite.NodeSlug = node.Slug
	invite.ServerName = server.Name
	invite.ServerSlug = server.Slug

	locale := i18n.LocaleFromRequest(r)
	if err := s.sendGameServerInviteEmail(
		r.Context(),
		locale,
		req.Email,
		inviter.Email,
		node.Name,
		server.Name,
		permission,
		invite.ExpiresAt,
	); err != nil {
		log.Printf("game server invite email send failed: node=%s server=%s invite=%s to=%s err=%v", node.ID, server.ID, invite.ID, req.Email, err)
		_, _ = s.Users.RevokeGameServerInvite(r.Context(), server.ID, invite.ID)
		writeError(w, http.StatusInternalServerError, "Failed to send invite email")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"invite": buildGameServerInviteResponse(invite),
	})
}

func (s *Server) handleListGameServerInvites(w http.ResponseWriter, r *http.Request) {
	_, _, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerInvites(serverRole) {
		writeError(w, http.StatusForbidden, "You cannot view invites for this game server")
		return
	}

	invites, err := s.Users.ListPendingGameServerInvitesForServer(r.Context(), server.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list game server invites")
		return
	}

	resp := make([]map[string]interface{}, 0, len(invites))
	for i := range invites {
		resp = append(resp, buildGameServerInviteResponse(&invites[i]))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"invites": resp,
	})
}

func (s *Server) handleRevokeGameServerInvite(w http.ResponseWriter, r *http.Request) {
	_, _, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerInvites(serverRole) {
		writeError(w, http.StatusForbidden, "You cannot revoke invites for this game server")
		return
	}

	inviteID := strings.TrimSpace(chi.URLParam(r, "inviteId"))
	if inviteID == "" {
		writeError(w, http.StatusBadRequest, "inviteId is required")
		return
	}

	revoked, err := s.Users.RevokeGameServerInvite(r.Context(), server.ID, inviteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to revoke invite")
		return
	}
	if !revoked {
		writeError(w, http.StatusNotFound, "Invite not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Invite revoked.",
	})
}

func (s *Server) handleListGameServerGuests(w http.ResponseWriter, r *http.Request) {
	_, _, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerInvites(serverRole) {
		writeError(w, http.StatusForbidden, "You cannot view guests for this game server")
		return
	}

	guests, err := s.Users.ListGameServerGuests(r.Context(), server.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load game server guests")
		return
	}

	resp := make([]map[string]interface{}, 0, len(guests))
	for i := range guests {
		resp = append(resp, buildGameServerGuestResponse(&guests[i]))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"guests": resp,
	})
}

func (s *Server) handleRemoveGameServerGuest(w http.ResponseWriter, r *http.Request) {
	_, node, server, serverRole, ok := s.loadNodeAndGameServerForRequest(w, r)
	if !ok {
		return
	}
	if !canManageGameServerInvites(serverRole) {
		writeError(w, http.StatusForbidden, "You cannot remove guests for this game server")
		return
	}

	guestUserID := strings.TrimSpace(chi.URLParam(r, "guestUserId"))
	if guestUserID == "" {
		writeError(w, http.StatusBadRequest, "guestUserId is required")
		return
	}
	if guestUserID == node.OwnerUserID {
		writeError(w, http.StatusBadRequest, "Owner access cannot be removed")
		return
	}

	removed, err := s.Users.RemoveGameServerGuest(r.Context(), server.ID, guestUserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to remove guest")
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "Guest not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Guest removed.",
	})
}

func buildGameServerInviteResponse(invite *auth.GameServerInvite) map[string]interface{} {
	return map[string]interface{}{
		"id":          invite.ID,
		"nodeId":      invite.NodeID,
		"nodeName":    invite.NodeName,
		"nodeSlug":    invite.NodeSlug,
		"serverId":    invite.ServerID,
		"serverName":  invite.ServerName,
		"serverSlug":  invite.ServerSlug,
		"inviterUser": invite.InviterUser,
		"inviterMail": invite.InviterMail,
		"email":       invite.Email,
		"permission":  invite.Permission,
		"expiresAt":   invite.ExpiresAt,
		"acceptedAt":  invite.AcceptedAt,
		"createdAt":   invite.CreatedAt,
	}
}

func buildGameServerGuestResponse(guest *auth.GameServerGuest) map[string]interface{} {
	return map[string]interface{}{
		"nodeId":     guest.NodeID,
		"nodeName":   guest.NodeName,
		"nodeSlug":   guest.NodeSlug,
		"serverId":   guest.ServerID,
		"serverName": guest.ServerName,
		"serverSlug": guest.ServerSlug,
		"userId":     guest.UserID,
		"name":       guest.Name,
		"email":      guest.Email,
		"permission": guest.Permission,
		"createdAt":  guest.CreatedAt,
	}
}
