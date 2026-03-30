package server

import (
	"context"
	"time"

	"yourapp/internal/auth"
	"yourapp/internal/i18n"
)

func (s *Server) sendSignInAlert(ctx context.Context, user *auth.User, sess auth.Session, locale string) error {
	if s.Mailer == nil {
		return nil
	}

	content := i18n.SignInAlertEmail(
		locale,
		user.Email,
		sess.LoginTime.UTC().Format(time.RFC1123),
		sess.IP,
		sess.Location,
		sess.UserAgent,
	)

	return s.Mailer.Send(ctx, user.Email, content.Subject, content.Text, content.HTML)
}
