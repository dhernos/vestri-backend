package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"yourapp/internal/auth"
	"yourapp/internal/i18n"
)

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
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
	cooldownKey := fmt.Sprintf("forgot_password_cooldown:%s", emailKey)
	if ttl := s.RateLimiter.CooldownTTL(ctx, cooldownKey); ttl > 0 {
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"cooldown": int64(ttl.Seconds()),
			"message":  fmt.Sprintf("Please wait %d seconds before making another request.", int(ttl.Seconds())),
		})
		return
	}

	ip := clientIP(r, s.trustedProxies)
	if locked, ttl, err := s.RateLimiter.RegisterResetAttempt(ctx, req.Email, ip); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to process request")
		return
	} else if locked {
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"cooldown": int64(ttl.Seconds()),
			"message":  "Too many reset requests. Try again later.",
		})
		return
	}

	user, err := s.Users.FindByEmail(ctx, req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to process request")
		return
	}

	if user != nil {
		if user.PasswordHash == nil {
			content := i18n.OAuthNoticeEmail(locale)
			_ = s.Mailer.Send(ctx, user.Email, content.Subject, content.Text, content.HTML)
		} else {
			token, err := randomToken(32)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to generate token")
				return
			}

			hashed, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to generate token")
				return
			}

			expires := time.Now().Add(1 * time.Hour)
			if err := s.Users.SetPasswordReset(ctx, user.ID, string(hashed), expires); err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to store token")
				return
			}

			resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.Config.BaseURL, token)
			content := i18n.PasswordResetEmail(locale, resetLink, 1)
			_ = s.Mailer.Send(ctx, user.Email, content.Subject, content.Text, content.HTML)
		}
	}

	s.RateLimiter.SetCooldown(ctx, cooldownKey, auth.EmailCooldown)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "If the email address exists, a password reset email has been sent with instructions.",
	})
}

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "Token is required")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	user, err := s.Users.FindUserWithResetToken(ctx, req.Token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to reset password")
		return
	}
	if user == nil || user.PasswordResetExpires == nil || user.PasswordResetExpires.Before(time.Now()) {
		writeError(w, http.StatusBadRequest, "Invalid or expired token.")
		return
	}

	hashed, err := s.Hasher.Hash(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}
	if err := s.Users.UpdatePassword(ctx, user.ID, hashed); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update password")
		return
	}

	_ = s.Sessions.DeleteByUser(ctx, user.ID)

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password has been reset successfully."})
}
