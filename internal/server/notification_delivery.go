package server

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"yourapp/internal/i18n"

	"github.com/jackc/pgx/v5"
)

func (s *Server) notificationsActionURL(locale string) string {
	return strings.TrimRight(s.Config.BaseURL, "/") + "/" + i18n.NormalizeLocale(locale) + "/notifications"
}

func notificationText(message notificationMessage, locale string) string {
	if text := i18n.NotificationEventText(locale, message.Kind, message.ServerName, message.NodeName, message.ActorName, message.Role); text != "" {
		return text
	}
	return "Vestri notification"
}

func notificationEventEnabled(events notificationEvents, kind string) bool {
	switch kind {
	case "server_created":
		return events.ServerCreated
	case "server_deleted":
		return events.ServerDeleted
	case "worker_unhealthy":
		return events.WorkerUnhealthy
	case "server_down":
		return events.ServerDown
	case "worker_recovered":
		return events.WorkerRecovered
	case "server_recovered":
		return events.ServerRecovered
	case "server_invited":
		return events.ServerInvited
	case "server_access_granted":
		return events.ServerAccessGranted
	case "server_role_changed":
		return events.ServerRoleChanged
	case "server_access_removed":
		return events.ServerAccessRemoved
	}
	return false
}

func (s *Server) deliverNotifications(ctx context.Context) error {
	for delivered := 0; delivered < 20; delivered++ {
		found, err := s.deliverNextNotification(ctx)
		if err != nil {
			return err
		}
		if !found {
			break
		}
	}
	return nil
}

func (s *Server) deliverNextNotification(ctx context.Context) (bool, error) {
	tx, err := s.Users.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var message notificationMessage
	var userID string
	var emailPending, webhookPending bool
	var attempts int
	err = tx.QueryRow(ctx, `SELECT "id", "userId", "kind", "nodeId", "nodeName", "serverId", "serverName", "actorName", "role", "createdAt", "emailPending", "webhookPending", "attempts" FROM "Notification" WHERE ("emailPending" OR "webhookPending") AND NOT "deliveryFailed" AND "nextAttemptAt" <= NOW() ORDER BY "nextAttemptAt", "id" LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&message.ID, &userID, &message.Kind, &message.NodeID, &message.NodeName, &message.ServerID, &message.ServerName, &message.ActorName, &message.Role, &message.CreatedAt, &emailPending, &webhookPending, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	settings, err := s.notificationSettingsForUser(ctx, userID, tx)
	if err != nil {
		return true, err
	}
	if !notificationEventEnabled(settings.Events, message.Kind) {
		emailPending, webhookPending = false, false
	}
	emailPending = emailPending && settings.EmailEnabled
	webhookPending = webhookPending && settings.WebhookEnabled
	text := notificationText(message, settings.Locale)
	if emailPending {
		var address string
		var verified bool
		if err := tx.QueryRow(ctx, `SELECT "email", "emailVerified" IS NOT NULL FROM "User" WHERE "id"=$1`, userID).Scan(&address, &verified); err != nil {
			return true, err
		}
		if !verified {
			emailPending = false
		} else if s.Mailer != nil {
			deliveryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			content := i18n.NotificationEmail(settings.Locale, message.Kind, message.ServerName, message.NodeName, message.CreatedAt.UTC().Format(time.RFC1123), s.notificationsActionURL(settings.Locale), message.ActorName, message.Role)
			err := s.Mailer.Send(deliveryCtx, address, content.Subject, content.Text, content.HTML)
			cancel()
			if err == nil {
				emailPending = false
			} else {
				log.Printf("email notification delivery failed: %s", message.ID)
			}
		}
	}
	if webhookPending {
		deliveryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := sendNotificationWebhook(deliveryCtx, settings.WebhookURL, message, text)
		cancel()
		if err == nil {
			webhookPending = false
		} else {
			log.Printf("webhook notification delivery failed: %s", message.ID)
		}
	}
	attempts++
	_, err = tx.Exec(ctx, `UPDATE "Notification" SET "emailPending"=$2, "webhookPending"=$3, "attempts"=$4, "nextAttemptAt"=$5, "deliveryFailed"=$6 WHERE "id"=$1`, message.ID, emailPending, webhookPending, attempts, time.Now().Add(time.Duration(1<<attempts)*15*time.Second), attempts >= 5 && (emailPending || webhookPending))
	if err != nil {
		return true, err
	}
	return true, tx.Commit(ctx)
}
