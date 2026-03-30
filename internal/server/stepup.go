package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"yourapp/internal/auth"
	"yourapp/internal/i18n"
)

var allowedStepUpPurposes = map[string]bool{
	"email_change":    true,
	"password_change": true,
	"account_delete":  true,
	"passkey_manage":  true,
	"disable_2fa":     true,
}

func (s *Server) hasValidStepUp(ctx context.Context, sessionID, purpose string) bool {
	if sessionID == "" || purpose == "" {
		return false
	}
	key := fmt.Sprintf("stepup:%s", sessionID)
	pur, err := s.Redis.HGet(ctx, key, "purpose").Result()
	if err != nil || pur == "" {
		return false
	}
	if pur != purpose && pur != "any" {
		return false
	}
	ttl, _ := s.Redis.TTL(ctx, key).Result()
	return ttl > 0
}

func (s *Server) requireStepUp(ctx context.Context, sess *auth.Session, purpose string) bool {
	if sess == nil {
		return false
	}
	return s.hasValidStepUp(ctx, sess.ID, purpose)
}

func (s *Server) recordStepUp(ctx context.Context, sessionID, purpose string, ttl time.Duration) {
	key := fmt.Sprintf("stepup:%s", sessionID)
	data := map[string]interface{}{
		"purpose":    purpose,
		"verifiedAt": time.Now().Unix(),
	}
	s.Redis.HSet(ctx, key, data)
	s.Redis.Expire(ctx, key, ttl)
}

func (s *Server) triggerStepUpChallenge(r *http.Request, user *auth.User) {
	if user == nil {
		return
	}
	if user.TwoFactorMethod != nil && *user.TwoFactorMethod == "app" {
		// App-based 2FA requires an authenticator code; no email fallback.
		return
	}
	locale := i18n.LocaleFromRequest(r)
	_ = s.sendTwoFactorEmail(r.Context(), user, locale)
}
