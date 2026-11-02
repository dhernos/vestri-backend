package server

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

func notificationText(message notificationMessage, locale string) string {
	if locale == "de" {
		switch message.Kind {
		case "server_created":
			return fmt.Sprintf("Server %s wurde auf %s erstellt.", message.ServerName, message.NodeName)
		case "server_deleted":
			return fmt.Sprintf("Server %s wurde auf %s geloescht.", message.ServerName, message.NodeName)
		case "worker_unhealthy":
			return fmt.Sprintf("Worker %s ist seit mehr als einer Minute nicht mehr gruen.", message.NodeName)
		case "server_down":
			return fmt.Sprintf("Server %s auf %s ist seit mehr als einer Minute down.", message.ServerName, message.NodeName)
		}
	}
	switch message.Kind {
	case "server_created":
		return fmt.Sprintf("Server %s was created on %s.", message.ServerName, message.NodeName)
	case "server_deleted":
		return fmt.Sprintf("Server %s was deleted on %s.", message.ServerName, message.NodeName)
	case "worker_unhealthy":
		return fmt.Sprintf("Worker %s has not been healthy for more than one minute.", message.NodeName)
	case "server_down":
		return fmt.Sprintf("Server %s on %s has been down for more than one minute.", message.ServerName, message.NodeName)
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
	err = tx.QueryRow(ctx, `SELECT "id", "userId", "kind", "nodeId", "nodeName", "serverId", "serverName", "createdAt", "emailPending", "webhookPending", "attempts" FROM "Notification" WHERE ("emailPending" OR "webhookPending") AND NOT "deliveryFailed" AND "nextAttemptAt" <= NOW() ORDER BY "nextAttemptAt" LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&message.ID, &userID, &message.Kind, &message.NodeID, &message.NodeName, &message.ServerID, &message.ServerName, &message.CreatedAt, &emailPending, &webhookPending, &attempts)
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
			err := s.Mailer.Send(deliveryCtx, address, "Vestri: "+message.Kind, text, "<p>"+html.EscapeString(text)+"</p>")
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
