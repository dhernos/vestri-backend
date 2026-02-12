package server

import (
	"context"
	"strings"
	"time"

	"yourapp/internal/i18n"
)

func (s *Server) sendNodeInviteEmail(ctx context.Context, locale, toEmail, inviterEmail, nodeName, permission string, expiresAt time.Time) error {
	if s.Mailer == nil {
		return nil
	}

	content := i18n.NodeInviteEmail(
		locale,
		inviterEmail,
		nodeName,
		permission,
		expiresAt.UTC().Format(time.RFC1123),
		s.nodeInviteActionURL(locale),
	)
	return s.Mailer.Send(ctx, toEmail, content.Subject, content.Text, content.HTML)
}

func (s *Server) sendGameServerInviteEmail(ctx context.Context, locale, toEmail, inviterEmail, nodeName, serverName, permission string, expiresAt time.Time) error {
	if s.Mailer == nil {
		return nil
	}

	target := strings.TrimSpace(nodeName)
	if strings.TrimSpace(serverName) != "" {
		target = target + " / " + strings.TrimSpace(serverName)
	}

	content := i18n.NodeInviteEmail(
		locale,
		inviterEmail,
		target,
		permission,
		expiresAt.UTC().Format(time.RFC1123),
		s.nodeInviteActionURL(locale),
	)
	return s.Mailer.Send(ctx, toEmail, content.Subject, content.Text, content.HTML)
}

func (s *Server) nodeInviteActionURL(locale string) string {
	base := strings.TrimRight(s.Config.BaseURL, "/")
	path := "/" + i18n.NormalizeLocale(locale) + "/nodes"
	if base == "" {
		return path
	}
	return base + path
}
