package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"yourapp/internal/auth"
	"yourapp/internal/i18n"
)

type registerRequest struct {
	Name     *string `json:"name"`
	Email    string  `json:"email"`
	Password string  `json:"password"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if !validateEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	locale := i18n.LocaleFromRequest(r)
	ip := clientIP(r, s.trustedProxies)
	if locked, ttl, err := s.RateLimiter.RegisterRegisterAttempt(ctx, req.Email, ip); err != nil {
		log.Printf("register: rate limit check failed: %v", err)
		writeError(w, http.StatusInternalServerError, "Registration throttled")
		return
	} else if locked {
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"message":  "Too many signup attempts. Try again later.",
			"cooldown": int64(ttl.Seconds()),
		})
		return
	}

	existing, err := s.Users.FindByEmail(ctx, req.Email)
	if err != nil {
		log.Printf("register: lookup by email failed: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to check user")
		return
	}
	if existing != nil {
		if existing.EmailVerified == nil {
			writeError(w, http.StatusConflict, "User already exists. Please verify your email or sign in to resend the code.")
			return
		}
		writeError(w, http.StatusConflict, "A user with this email already exists.")
		return
	}

	hashed, err := s.Hasher.Hash(req.Password)
	if err != nil {
		log.Printf("register: hash failed: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	var verifiedAt *time.Time
	if s.Config.NoEmailVerify {
		now := time.Now()
		verifiedAt = &now
	}

	user, err := s.Users.Create(ctx, req.Name, req.Email, &hashed, verifiedAt)
	if err != nil {
		log.Printf("register: create user failed: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	if !s.Config.NoEmailVerify {
		if err := s.issueVerification(ctx, user, locale); err != nil {
			log.Printf("register: issue verification failed: %v", err)
			writeError(w, http.StatusInternalServerError, "Registration failed: could not send verification code")
			return
		}
	}

	emailVerificationRequired := !s.Config.NoEmailVerify
	message := "Registration successful! Please check your email to verify your account."
	if !emailVerificationRequired {
		message = "Registration successful! You can now sign in."
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message":                   message,
		"emailVerificationRequired": emailVerificationRequired,
		"user": map[string]string{
			"id":    user.ID,
			"email": user.Email,
		},
	})
}

type verifyEmailRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if !validateEmail(req.Email) || len(req.Code) != 6 {
		writeError(w, http.StatusBadRequest, "Invalid request data")
		return
	}

	ctx := r.Context()
	locked, ttl, err := s.RateLimiter.RegisterVerifyAttempt(ctx, req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to verify email")
		return
	}
	if locked {
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"message":  "Too many verification attempts. Try again later.",
			"cooldown": int64(ttl.Seconds()),
		})
		return
	}
	vt, user, err := s.Users.GetVerificationToken(ctx, req.Email, req.Code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to verify email")
		return
	}
	if vt == nil || user == nil {
		writeError(w, http.StatusBadRequest, "Invalid or expired code.")
		return
	}

	if err := s.Users.SetEmailVerified(ctx, vt.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to mark email verified")
		return
	}
	_ = s.Users.DeleteVerificationTokens(ctx, vt.UserID)
	s.RateLimiter.ResetVerify(ctx, req.Email)

	writeJSON(w, http.StatusOK, map[string]string{"message": "Email successfully verified."})
}

type resendVerificationRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	var req resendVerificationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if !validateEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	ctx := r.Context()
	locale := i18n.LocaleFromRequest(r)
	emailKey := strings.ToLower(req.Email)
	cooldownKey := fmt.Sprintf("resend_cooldown:%s", emailKey)
	if ttl := s.RateLimiter.CooldownTTL(ctx, cooldownKey); ttl > 0 {
		writeJSON(w, http.StatusTooManyRequests, map[string]int64{"cooldown": int64(ttl.Seconds())})
		return
	}
	if locked, ttl, err := s.RateLimiter.RegisterRegisterAttempt(ctx, req.Email, clientIP(r, s.trustedProxies)); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to process request")
		return
	} else if locked {
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"cooldown": int64(ttl.Seconds()),
			"message":  "Too many attempts. Try again later.",
		})
		return
	}

	user, err := s.Users.FindByEmail(ctx, req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}

	if user != nil && user.EmailVerified == nil {
		if err := s.issueVerification(ctx, user, locale); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to send verification code")
			return
		}
	}
	s.RateLimiter.SetCooldown(ctx, cooldownKey, auth.EmailCooldown)

	writeJSON(w, http.StatusOK, map[string]string{"message": "If the account exists, a verification code has been sent."})
}

type loginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	Code       string `json:"code,omitempty"`
	RememberMe bool   `json:"rememberMe"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if !validateEmail(req.Email) || req.Password == "" {
		writeError(w, http.StatusBadRequest, "Invalid credentials")
		return
	}

	ctx := r.Context()
	locale := i18n.LocaleFromRequest(r)
	ip := clientIP(r, s.trustedProxies)
	ua := r.UserAgent()
	location := deriveLocation(r)

	if s.RateLimiter.IsIPBanned(ctx, ip) {
		writeError(w, http.StatusForbidden, "IP_BANNED")
		return
	}

	user, err := s.Users.FindByEmail(ctx, req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Login failed")
		return
	}
	if user == nil || user.PasswordHash == nil || !s.Hasher.Compare(*user.PasswordHash, req.Password) {
		_ = s.RateLimiter.RegisterLoginFailure(ctx, ip)
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS")
		return
	}

	if user.EmailVerified == nil {
		writeError(w, http.StatusForbidden, "EMAIL_NOT_VERIFIED")
		return
	}

	if user.TwoFactorEnabled {
		if req.Code == "" {
			if user.TwoFactorMethod != nil && *user.TwoFactorMethod == "email" {
				_ = s.sendTwoFactorEmail(ctx, user, locale)
			}
			writeError(w, http.StatusForbidden, "TWO_FACTOR_REQUIRED")
			return
		}

		if !s.verifyTwoFactor(ctx, user, req.Code) {
			locked, _ := s.RateLimiter.Register2FAFailure(ctx, user.ID)
			if locked {
				writeError(w, http.StatusForbidden, "TWO_FACTOR_LOCKED")
				return
			}
			writeError(w, http.StatusForbidden, "INVALID_2FA_CODE")
			return
		}
		s.RateLimiter.Reset2FA(ctx, user.ID)
	}

	now := time.Now()
	sessionTTL := s.Config.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = 7 * 24 * time.Hour
	}
	if !req.RememberMe {
		limit := 24 * time.Hour
		if sessionTTL > limit {
			sessionTTL = limit
		}
	}
	expiry := now.Add(sessionTTL)

	session := auth.Session{
		ID:                auth.NewSessionID(),
		UserID:            user.ID,
		Role:              user.Role,
		IP:                ip,
		Location:          location,
		UserAgent:         ua,
		LoginTime:         now,
		ExpiresAt:         expiry,
		TwoFactorEnabled:  user.TwoFactorEnabled,
		TwoFactorVerified: !user.TwoFactorEnabled || req.Code != "",
	}
	if session.TwoFactorVerified {
		session.TwoFactorVerifiedAt = &now
	}

	if err := s.Sessions.Create(ctx, session); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_CREATE_FAILED")
		return
	}

	s.RateLimiter.ResetLogin(ctx, ip)
	auth.SetSessionCookie(w, session.ID, session.ExpiresAt)
	_ = s.sendSignInAlert(ctx, user, session, locale)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user": map[string]interface{}{
			"id":                 user.ID,
			"email":              user.Email,
			"name":               user.Name,
			"role":               user.Role,
			"theme":              user.Theme,
			"image":              user.Image,
			"isTwoFactorEnabled": user.TwoFactorEnabled,
			"twoFactorMethod":    user.TwoFactorMethod,
			"hasPassword":        user.PasswordHash != nil,
			"oauthLinked":        false,
		},
		"sessionId": session.ID,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		_ = s.Sessions.Delete(r.Context(), cookie.Value)
	}
	auth.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}
	oauthLinked, _ := s.Users.HasOAuthAccount(r.Context(), sess.UserID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":                  sess.UserID,
		"email":               user.Email,
		"name":                user.Name,
		"role":                sess.Role,
		"theme":               user.Theme,
		"image":               user.Image,
		"twoFactorMethod":     user.TwoFactorMethod,
		"sessionId":           sess.ID,
		"twoFactorEnabled":    user.TwoFactorEnabled,
		"twoFactorVerified":   sess.TwoFactorVerified,
		"twoFactorVerifiedAt": sess.TwoFactorVerifiedAt,
		"hasPassword":         user.PasswordHash != nil,
		"oauthLinked":         oauthLinked,
	})
}

type sendTwoFactorEmailRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleSendTwoFactorEmailCode(w http.ResponseWriter, r *http.Request) {
	var req sendTwoFactorEmailRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if !validateEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	ctx := r.Context()
	locale := i18n.LocaleFromRequest(r)
	emailKey := strings.ToLower(req.Email)
	cooldownKey := fmt.Sprintf("2fa_email_cooldown:%s", emailKey)

	user, err := s.Users.FindByEmail(ctx, req.Email)
	if err == nil && user != nil && user.TwoFactorMethod != nil && *user.TwoFactorMethod == "email" {
		hasActiveCode := user.TwoFactorEmailCode != nil && user.TwoFactorCodeExpires != nil && user.TwoFactorCodeExpires.After(time.Now())
		if ttl := s.RateLimiter.CooldownTTL(ctx, cooldownKey); ttl > 0 && hasActiveCode {
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"cooldown": int64(ttl.Seconds()),
				"message":  "Please wait before requesting another code.",
			})
			return
		}

		if err := s.sendTwoFactorEmail(ctx, user, locale); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to send code")
			return
		}
	}
	s.RateLimiter.SetCooldown(ctx, cooldownKey, auth.EmailCooldown)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "If the account uses email 2FA, a code was sent.",
	})
}

func (s *Server) issueVerification(ctx context.Context, user *auth.User, locale string) error {
	code := randomSixDigitCode()
	expires := time.Now().Add(10 * time.Minute)

	if err := s.Users.DeleteVerificationTokens(ctx, user.ID); err != nil {
		return err
	}
	if _, err := s.Users.CreateVerificationToken(ctx, user.ID, code, expires); err != nil {
		return err
	}

	content := i18n.VerificationEmail(locale, code, 10)
	return s.Mailer.Send(ctx, user.Email, content.Subject, content.Text, content.HTML)
}

func (s *Server) sendTwoFactorEmail(ctx context.Context, user *auth.User, locale string) error {
	now := time.Now()
	cooldownKey := fmt.Sprintf("2fa_email_cooldown:%s", strings.ToLower(user.Email))
	if ttl := s.RateLimiter.CooldownTTL(ctx, cooldownKey); ttl > 0 {
		hasActiveCode := user.TwoFactorEmailCode != nil && user.TwoFactorCodeExpires != nil && user.TwoFactorCodeExpires.After(now)
		if hasActiveCode {
			// Respect cooldown when a valid code already exists to avoid spamming.
			return nil
		}
	}

	code := randomSixDigitCode()
	expires := now.Add(5 * time.Minute)

	if err := s.Users.SaveEmailCode(ctx, user.ID, code, expires); err != nil {
		return err
	}

	content := i18n.TwoFactorEmail(locale, code, 5)
	if err := s.Mailer.Send(ctx, user.Email, content.Subject, content.Text, content.HTML); err != nil {
		log.Printf("two-factor email send failed for user %s: %v", user.Email, err)
		return err
	}
	s.RateLimiter.SetCooldown(ctx, cooldownKey, auth.EmailCooldown)
	return nil
}

func (s *Server) verifyTwoFactor(ctx context.Context, user *auth.User, code string) bool {
	if user.TwoFactorMethod == nil {
		return false
	}

	switch *user.TwoFactorMethod {
	case "app":
		if user.TwoFactorSecret == nil {
			return false
		}
		return s.TOTP.Verify(*user.TwoFactorSecret, code)
	case "email":
		if user.TwoFactorEmailCode == nil || user.TwoFactorCodeExpires == nil {
			return false
		}
		if user.TwoFactorCodeExpires.Before(time.Now()) {
			return false
		}
		if auth.HashString(code) != *user.TwoFactorEmailCode {
			return false
		}
		_ = s.Users.ClearEmailCode(ctx, user.ID) // clear code
		return true
	default:
		return false
	}
}

func randomSixDigitCode() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "000000"
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	code := n % 1000000
	return fmt.Sprintf("%06d", code)
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
