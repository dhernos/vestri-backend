package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"yourapp/internal/auth"
	"yourapp/internal/i18n"
)

const nodeInviteTTL = 7 * 24 * time.Hour

type createNodeRequest struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	BaseURL string `json:"baseUrl"`
	APIKey  string `json:"apiKey"`
}

type createNodeInviteRequest struct {
	Email      string `json:"email"`
	Permission string `json:"permission"`
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req createNodeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	apiKey := strings.TrimSpace(req.APIKey)
	if apiKey == "" {
		writeError(w, http.StatusBadRequest, "apiKey is required")
		return
	}

	encryptedAPIKey, err := s.encryptNodeAPIKey(apiKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Node API key encryption is not configured")
		return
	}

	rawAddress := strings.TrimSpace(req.BaseURL)
	if rawAddress == "" {
		rawAddress = strings.TrimSpace(req.IP)
	}
	if rawAddress == "" {
		writeError(w, http.StatusBadRequest, "ip or baseUrl is required")
		return
	}

	baseURL, host, err := normalizeNodeBaseURL(rawAddress)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = host
	}

	slugBase := slugify(name)
	if slugBase == "" {
		slugBase = "node"
	}

	slug, err := s.uniqueNodeSlug(r.Context(), slugBase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to reserve slug")
		return
	}

	node, err := s.Users.CreateWorkerNode(r.Context(), slug, name, baseURL, encryptedAPIKey, sess.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create node")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"node": buildNodeResponse(node),
	})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	nodes, err := s.Users.ListAccessibleWorkerNodes(r.Context(), sess.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list nodes")
		return
	}

	resp := make([]map[string]interface{}, 0, len(nodes))
	for i := range nodes {
		resp = append(resp, buildNodeResponse(&nodes[i]))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"nodes": resp,
	})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	if nodeRef == "" {
		writeError(w, http.StatusBadRequest, "nodeRef is required")
		return
	}

	node, err := s.Users.FindAccessibleWorkerNodeByRef(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"node": buildNodeResponse(node),
	})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	if nodeRef == "" {
		writeError(w, http.StatusBadRequest, "nodeRef is required")
		return
	}

	node, err := s.Users.FindWorkerNodeForOwnerByRef(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}

	servers, err := s.Users.ListGameServersForNode(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node servers")
		return
	}

	warnings := make([]string, 0)
	baseURL, apiKey, workerErr := s.workerTargetFromNode(node)
	if workerErr != nil {
		warnings = append(warnings, "worker cleanup skipped due invalid node worker configuration")
	} else {
		for i := range servers {
			if err := s.cleanupGameServerOnWorker(r.Context(), baseURL, apiKey, &servers[i]); err != nil {
				warnings = append(warnings, fmt.Sprintf("server %s cleanup failed", servers[i].Slug))
			}
		}

		legacyNodePath := path.Join("nodes", node.Slug)
		if err := s.workerDeletePath(r.Context(), baseURL, apiKey, legacyNodePath, true); err != nil {
			warnings = append(warnings, "legacy node directory cleanup failed")
		}
	}

	deleted, err := s.Users.DeleteWorkerNodeForOwner(r.Context(), node.ID, sess.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete node")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}

	if len(warnings) > 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message":  "Node deleted with cleanup warnings.",
			"warnings": warnings,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Node deleted.",
	})
}

func (s *Server) handleCreateNodeInvite(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	if nodeRef == "" {
		writeError(w, http.StatusBadRequest, "nodeRef is required")
		return
	}

	node, err := s.Users.FindAccessibleWorkerNodeByRef(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}
	if !canManageNodeInvites(node.AccessRole) {
		writeError(w, http.StatusForbidden, "You cannot manage invites for this node")
		return
	}

	var req createNodeInviteRequest
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
		writeError(w, http.StatusBadRequest, "Invalid node permission")
		return
	}

	inviter, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || inviter == nil {
		writeError(w, http.StatusInternalServerError, "Failed to load inviter")
		return
	}

	invite, err := s.Users.CreateWorkerNodeInvite(
		r.Context(),
		node.ID,
		sess.UserID,
		req.Email,
		permission,
		time.Now().Add(nodeInviteTTL),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create invite")
		return
	}

	invite.NodeID = node.ID
	invite.NodeName = node.Name
	invite.NodeSlug = node.Slug

	locale := i18n.LocaleFromRequest(r)
	if err := s.sendNodeInviteEmail(
		r.Context(),
		locale,
		req.Email,
		inviter.Email,
		node.Name,
		permission,
		invite.ExpiresAt,
	); err != nil {
		log.Printf("node invite email send failed: node=%s invite=%s to=%s err=%v", node.ID, invite.ID, req.Email, err)
		_, _ = s.Users.RevokeWorkerNodeInvite(r.Context(), node.ID, invite.ID)
		writeError(w, http.StatusInternalServerError, "Failed to send invite email")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"invite": buildNodeInviteResponse(invite),
	})
}

func (s *Server) handleListNodeInvites(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	if nodeRef == "" {
		writeError(w, http.StatusBadRequest, "nodeRef is required")
		return
	}

	node, err := s.Users.FindAccessibleWorkerNodeByRef(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}
	if !canManageNodeInvites(node.AccessRole) {
		writeError(w, http.StatusForbidden, "You cannot view invites for this node")
		return
	}

	invites, err := s.Users.ListPendingWorkerNodeInvitesForNode(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list node invites")
		return
	}

	resp := make([]map[string]interface{}, 0, len(invites))
	for i := range invites {
		resp = append(resp, buildNodeInviteResponse(&invites[i]))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"invites": resp,
	})
}

func (s *Server) handleRevokeNodeInvite(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	inviteID := strings.TrimSpace(chi.URLParam(r, "inviteId"))
	if nodeRef == "" || inviteID == "" {
		writeError(w, http.StatusBadRequest, "nodeRef and inviteId are required")
		return
	}

	node, err := s.Users.FindAccessibleWorkerNodeByRef(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}
	if !canManageNodeInvites(node.AccessRole) {
		writeError(w, http.StatusForbidden, "You cannot revoke invites for this node")
		return
	}

	revoked, err := s.Users.RevokeWorkerNodeInvite(r.Context(), node.ID, inviteID)
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

func (s *Server) handleListNodeGuests(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	if nodeRef == "" {
		writeError(w, http.StatusBadRequest, "nodeRef is required")
		return
	}

	node, err := s.Users.FindAccessibleWorkerNodeByRef(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}
	if !canManageNodeInvites(node.AccessRole) {
		writeError(w, http.StatusForbidden, "You cannot view guests for this node")
		return
	}

	guests, err := s.Users.ListWorkerNodeGuests(r.Context(), node.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load guests")
		return
	}

	resp := make([]map[string]interface{}, 0, len(guests))
	for i := range guests {
		resp = append(resp, buildNodeGuestResponse(&guests[i]))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"guests": resp,
	})
}

func (s *Server) handleRemoveNodeGuest(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	nodeRef := strings.TrimSpace(chi.URLParam(r, "nodeRef"))
	guestUserID := strings.TrimSpace(chi.URLParam(r, "guestUserId"))
	if nodeRef == "" || guestUserID == "" {
		writeError(w, http.StatusBadRequest, "nodeRef and guestUserId are required")
		return
	}

	node, err := s.Users.FindAccessibleWorkerNodeByRef(r.Context(), sess.UserID, nodeRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load node")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}
	if !canManageNodeInvites(node.AccessRole) {
		writeError(w, http.StatusForbidden, "You cannot remove guests for this node")
		return
	}
	if guestUserID == node.OwnerUserID {
		writeError(w, http.StatusBadRequest, "Owner access cannot be removed")
		return
	}

	removed, err := s.Users.RemoveWorkerNodeGuest(r.Context(), node.ID, guestUserID)
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

func (s *Server) handleListIncomingNodeInvites(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}

	invites, err := s.Users.ListIncomingWorkerNodeInvites(r.Context(), user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load incoming invites")
		return
	}

	resp := make([]map[string]interface{}, 0, len(invites))
	for i := range invites {
		resp = append(resp, buildNodeInviteResponse(&invites[i]))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"invites": resp,
	})
}

func (s *Server) handleAcceptNodeInvite(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	inviteID := strings.TrimSpace(chi.URLParam(r, "inviteId"))
	if inviteID == "" {
		writeError(w, http.StatusBadRequest, "inviteId is required")
		return
	}

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}

	node, err := s.Users.AcceptWorkerNodeInvite(r.Context(), inviteID, sess.UserID, user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to accept invite")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Invite not found or expired")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Invite accepted.",
		"node":    buildNodeResponse(node),
	})
}

func buildNodeResponse(node *auth.WorkerNode) map[string]interface{} {
	role := strings.TrimSpace(node.AccessRole)
	if role == "" {
		role = auth.NodeAccessOwner
	}

	return map[string]interface{}{
		"id":            node.ID,
		"slug":          node.Slug,
		"name":          node.Name,
		"baseUrl":       node.BaseURL,
		"ownerUserId":   node.OwnerUserID,
		"accessRole":    role,
		"isOwner":       role == auth.NodeAccessOwner,
		"apiKeyPreview": previewNodeAPIKey(node.APIKey),
		"createdAt":     node.CreatedAt,
		"updatedAt":     node.UpdatedAt,
	}
}

func buildNodeInviteResponse(invite *auth.WorkerNodeInvite) map[string]interface{} {
	return map[string]interface{}{
		"id":          invite.ID,
		"nodeId":      invite.NodeID,
		"nodeName":    invite.NodeName,
		"nodeSlug":    invite.NodeSlug,
		"inviterUser": invite.InviterUser,
		"inviterMail": invite.InviterMail,
		"email":       invite.Email,
		"permission":  invite.Permission,
		"expiresAt":   invite.ExpiresAt,
		"acceptedAt":  invite.AcceptedAt,
		"createdAt":   invite.CreatedAt,
	}
}

func buildNodeGuestResponse(guest *auth.WorkerNodeGuest) map[string]interface{} {
	return map[string]interface{}{
		"nodeId":     guest.NodeID,
		"nodeName":   guest.NodeName,
		"nodeSlug":   guest.NodeSlug,
		"userId":     guest.UserID,
		"name":       guest.Name,
		"email":      guest.Email,
		"permission": guest.Permission,
		"createdAt":  guest.CreatedAt,
	}
}

func previewNodeAPIKey(stored string) string {
	if stored == "" {
		return ""
	}
	if strings.HasPrefix(stored, encryptedNodeAPIKeyPrefix) {
		return "stored-encrypted"
	}
	return maskAPIKey(stored)
}

func maskAPIKey(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	if len(apiKey) <= 6 {
		return strings.Repeat("*", len(apiKey))
	}
	return apiKey[:4] + strings.Repeat("*", len(apiKey)-6) + apiKey[len(apiKey)-2:]
}

func normalizeNodePermission(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case auth.NodeAccessAdmin:
		return auth.NodeAccessAdmin, true
	case auth.NodeAccessOperator:
		return auth.NodeAccessOperator, true
	case auth.NodeAccessViewer:
		return auth.NodeAccessViewer, true
	default:
		return "", false
	}
}

func normalizeNodeBaseURL(raw string) (string, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", fmt.Errorf("base URL must not be empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("invalid base URL")
	}
	if parsed.Host == "" {
		return "", "", fmt.Errorf("invalid base URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", fmt.Errorf("only http and https are supported")
	}

	parsed.User = nil
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return strings.TrimRight(parsed.String(), "/"), parsed.Host, nil
}

func slugify(value string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.TrimSpace(value) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	return slug
}

func (s *Server) uniqueNodeSlug(ctx context.Context, base string) (string, error) {
	candidate := base
	for i := 0; i < 20; i++ {
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", base, i+1)
		}

		exists, err := s.Users.WorkerNodeSlugExists(ctx, candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}

	for {
		suffix := strings.ReplaceAll(auth.NewSessionID(), "-", "")
		candidate = fmt.Sprintf("%s-%s", base, suffix[:8])
		exists, err := s.Users.WorkerNodeSlugExists(ctx, candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
}

func (s *Server) encryptNodeAPIKey(apiKey string) (string, error) {
	encrypted, err := s.NodeAPIKey.Encrypt(apiKey)
	if err != nil {
		return "", err
	}
	return encrypted, nil
}

func (s *Server) decryptNodeAPIKey(node *auth.WorkerNode) (string, error) {
	plaintext, encrypted, err := s.NodeAPIKey.Decrypt(node.APIKey)
	if err != nil {
		return "", err
	}
	if !encrypted && s.NodeAPIKey != nil {
		// Lazy-migrate old plaintext keys to encrypted storage.
		reEncrypted, err := s.NodeAPIKey.Encrypt(plaintext)
		if err == nil {
			if updateErr := s.Users.UpdateWorkerNodeAPIKey(context.Background(), node.ID, reEncrypted); updateErr == nil {
				node.APIKey = reEncrypted
			}
		}
	}
	return plaintext, nil
}
