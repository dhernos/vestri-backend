package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

type notificationEvents struct {
	ServerCreated       bool `json:"server_created"`
	ServerDeleted       bool `json:"server_deleted"`
	WorkerUnhealthy     bool `json:"worker_unhealthy"`
	ServerDown          bool `json:"server_down"`
	WorkerRecovered     bool `json:"worker_recovered"`
	ServerRecovered     bool `json:"server_recovered"`
	ServerInvited       bool `json:"server_invited"`
	ServerAccessGranted bool `json:"server_access_granted"`
	ServerRoleChanged   bool `json:"server_role_changed"`
	ServerAccessRemoved bool `json:"server_access_removed"`
}

type notificationSettings struct {
	Events         notificationEvents `json:"events"`
	EmailEnabled   bool               `json:"emailEnabled"`
	WebhookEnabled bool               `json:"webhookEnabled"`
	WebhookURL     string             `json:"webhookUrl"`
	Locale         string             `json:"locale"`
}

type notificationMessage struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	NodeID         string     `json:"nodeId"`
	NodeName       string     `json:"nodeName"`
	ServerID       string     `json:"serverId"`
	ServerName     string     `json:"serverName"`
	ActorName      string     `json:"actorName"`
	Role           string     `json:"role"`
	CreatedAt      time.Time  `json:"createdAt"`
	ReadAt         *time.Time `json:"readAt"`
	DeliveryFailed bool       `json:"deliveryFailed"`
}

type notificationSettingsStore interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func defaultNotificationEvents() notificationEvents {
	return notificationEvents{
		ServerCreated: true, ServerDeleted: true, WorkerUnhealthy: true, ServerDown: true,
		WorkerRecovered: true, ServerRecovered: true, ServerInvited: true,
		ServerAccessGranted: true, ServerRoleChanged: true, ServerAccessRemoved: true,
	}
}

func (s *Server) notificationSettingsForUser(ctx context.Context, userID string, store notificationSettingsStore) (notificationSettings, error) {
	settings := notificationSettings{Events: defaultNotificationEvents(), Locale: "en"}
	err := store.QueryRow(ctx, `SELECT "events", "emailEnabled", "webhookEnabled", "webhookUrl", "locale" FROM "NotificationSettings" WHERE "userId"=$1`, userID).Scan(&settings.Events, &settings.EmailEnabled, &settings.WebhookEnabled, &settings.WebhookURL, &settings.Locale)
	if errors.Is(err, pgx.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	settings.WebhookURL, _, err = s.NodeAPIKey.Decrypt(settings.WebhookURL)
	return settings, err
}

func (s *Server) handleNotificationSettings(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if r.Method == http.MethodGet {
		settings, err := s.notificationSettingsForUser(r.Context(), sess.UserID, s.Users.DB)
		if err != nil {
			writeError(w, 500, "Failed to load notification settings")
			return
		}
		writeJSON(w, 200, settings)
		return
	}
	settings := notificationSettings{Events: defaultNotificationEvents()}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		writeError(w, 400, "Invalid notification settings")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, 400, "Invalid notification settings")
		return
	}
	settings.WebhookURL = strings.TrimSpace(settings.WebhookURL)
	if settings.Locale != "de" && settings.Locale != "en" {
		writeError(w, 400, "Invalid locale")
		return
	}
	if settings.EmailEnabled {
		var verified bool
		if err := s.Users.DB.QueryRow(r.Context(), `SELECT "emailVerified" IS NOT NULL FROM "User" WHERE "id"=$1`, sess.UserID).Scan(&verified); err != nil || !verified {
			writeError(w, 400, "A verified email address is required")
			return
		}
	}
	if settings.WebhookEnabled || settings.WebhookURL != "" {
		if _, err := parseNotificationWebhook(settings.WebhookURL); err != nil {
			writeError(w, 400, "Webhook must be a public HTTPS URL on port 443")
			return
		}
	}
	storedURL := ""
	if settings.WebhookURL != "" {
		var err error
		storedURL, err = s.NodeAPIKey.Encrypt(settings.WebhookURL)
		if err != nil {
			writeError(w, 500, "Webhook encryption is not configured")
			return
		}
	}
	events, err := json.Marshal(settings.Events)
	if err != nil {
		writeError(w, 400, "Invalid events")
		return
	}
	_, err = s.Users.DB.Exec(r.Context(), `INSERT INTO "NotificationSettings" ("userId", "events", "emailEnabled", "webhookEnabled", "webhookUrl", "locale") VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT ("userId") DO UPDATE SET "events"=EXCLUDED."events", "emailEnabled"=EXCLUDED."emailEnabled", "webhookEnabled"=EXCLUDED."webhookEnabled", "webhookUrl"=EXCLUDED."webhookUrl", "locale"=EXCLUDED."locale"`, sess.UserID, events, settings.EmailEnabled, settings.WebhookEnabled, storedURL, settings.Locale)
	if err != nil {
		writeError(w, 500, "Failed to save notification settings")
		return
	}
	writeJSON(w, 200, settings)
}

func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, 401, "Unauthorized")
		return
	}
	before := time.Now().Add(time.Second)
	if raw := r.URL.Query().Get("before"); raw != "" {
		var err error
		before, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			writeError(w, 400, "Invalid cursor")
			return
		}
	}
	rows, err := s.Users.DB.Query(r.Context(), `SELECT "id", "kind", "nodeId", "nodeName", "serverId", "serverName", "actorName", "role", "createdAt", "readAt", "deliveryFailed" FROM "Notification" WHERE "userId"=$1 AND ("createdAt", "id") < ($2,$3) ORDER BY "createdAt" DESC, "id" DESC LIMIT 51`, sess.UserID, before, r.URL.Query().Get("beforeId"))
	if err != nil {
		writeError(w, 500, "Failed to load notifications")
		return
	}
	defer rows.Close()
	messages := make([]notificationMessage, 0)
	for rows.Next() {
		var message notificationMessage
		if err := rows.Scan(&message.ID, &message.Kind, &message.NodeID, &message.NodeName, &message.ServerID, &message.ServerName, &message.ActorName, &message.Role, &message.CreatedAt, &message.ReadAt, &message.DeliveryFailed); err != nil {
			writeError(w, 500, "Failed to load notifications")
			return
		}
		messages = append(messages, message)
	}
	if rows.Err() != nil {
		writeError(w, 500, "Failed to load notifications")
		return
	}
	hasMore := len(messages) > 50
	if hasMore {
		messages = messages[:50]
	}
	var unread int
	if err := s.Users.DB.QueryRow(r.Context(), `SELECT COUNT(*) FROM "Notification" WHERE "userId"=$1 AND "readAt" IS NULL`, sess.UserID).Scan(&unread); err != nil {
		writeError(w, 500, "Failed to count notifications")
		return
	}
	writeJSON(w, 200, map[string]any{"notifications": messages, "hasMore": hasMore, "unread": unread})
}

func (s *Server) handleUnreadNotifications(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, 401, "Unauthorized")
		return
	}
	var unread int
	if err := s.Users.DB.QueryRow(r.Context(), `SELECT COUNT(*) FROM "Notification" WHERE "userId"=$1 AND "readAt" IS NULL`, sess.UserID).Scan(&unread); err != nil {
		writeError(w, 500, "Failed to count notifications")
		return
	}
	writeJSON(w, 200, map[string]int{"unread": unread})
}

func (s *Server) handleDeleteNotifications(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, 401, "Unauthorized")
		return
	}
	id := chi.URLParam(r, "notificationId")
	_, err := s.Users.DB.Exec(r.Context(), `DELETE FROM "Notification" WHERE "userId"=$1 AND ($2='' OR "id"=$2)`, sess.UserID, id)
	if err != nil {
		writeError(w, 500, "Failed to delete notifications")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleReadNotifications(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, 401, "Unauthorized")
		return
	}
	id := chi.URLParam(r, "notificationId")
	_, err := s.Users.DB.Exec(r.Context(), `UPDATE "Notification" SET "readAt"=NOW() WHERE "userId"=$1 AND "readAt" IS NULL AND ($2='' OR "id"=$2)`, sess.UserID, id)
	if err != nil {
		writeError(w, 500, "Failed to mark notifications as read")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
