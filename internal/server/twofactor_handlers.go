package server

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"yourapp/internal/auth"
	"yourapp/internal/i18n"
)

type twoFactorSetupRequest struct {
	Method string `json:"method"`
}

func (s *Server) handleTwoFactorSetupStart(w http.ResponseWriter, r *http.Request) {
	var req twoFactorSetupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Method != "app" && req.Method != "email" {
		writeError(w, http.StatusBadRequest, "Invalid 2FA method")
		return
	}

	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "User not found")
		return
	}

	if req.Method == "app" {
		secret, otpauth, qr, err := s.TOTP.Generate(user.Email)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to generate secret")
			return
		}

		if err := s.Users.UpdateTwoFactorSecret(r.Context(), user.ID, "app", &secret); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to store secret")
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"qrCodeUrl":  qr,
			"secret":     secret,
			"otpauthUrl": otpauth,
			"message":    "QR code generated. Please scan it.",
		})
		return
	}

	code := randomSixDigitCode()
	expires := time.Now().Add(5 * time.Minute)

	if err := s.Users.SaveEmailCode(r.Context(), user.ID, code, expires); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to store code")
		return
	}

	locale := i18n.LocaleFromRequest(r)
	content := i18n.TwoFactorEmail(locale, code, 5)
	if err := s.Mailer.Send(r.Context(), user.Email, content.Subject, content.Text, content.HTML); err != nil {
		log.Printf("two-factor setup email send failed for user %s: %v", user.Email, err)
		writeError(w, http.StatusInternalServerError, "Failed to send code")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("A code was sent to your email (%s).", user.Email),
	})
}

type twoFactorFinalizeRequest struct {
	Code   string `json:"code"`
	Method string `json:"method"`
}

func (s *Server) handleTwoFactorSetupFinalize(w http.ResponseWriter, r *http.Request) {
	var req twoFactorFinalizeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(req.Code) != 6 {
		writeError(w, http.StatusBadRequest, "Invalid code")
		return
	}

	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "User not found")
		return
	}

	if user.TwoFactorMethod == nil || *user.TwoFactorMethod != req.Method {
		writeError(w, http.StatusBadRequest, "2FA setup not started or method mismatch")
		return
	}

	valid := false

	if req.Method == "app" && user.TwoFactorSecret != nil {
		valid = s.TOTP.Verify(*user.TwoFactorSecret, req.Code)
	} else if req.Method == "email" && user.TwoFactorEmailCode != nil && user.TwoFactorCodeExpires != nil {
		if user.TwoFactorCodeExpires.After(time.Now()) && auth.HashString(req.Code) == *user.TwoFactorEmailCode {
			valid = true
		}
	}

	if !valid {
		writeError(w, http.StatusForbidden, "The code is invalid or expired.")
		return
	}

	if err := s.Users.EnableTwoFactor(r.Context(), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to enable 2FA")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Two-factor authentication enabled.",
	})
}

func (s *Server) handleTwoFactorDisable(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var req struct {
		TOTPCode string `json:"totpCode"`
	}
	_ = decodeJSON(r, &req) // best-effort; empty is fine

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "User not found")
		return
	}

	verified := s.requireStepUp(r.Context(), sess, "disable_2fa")
	if !verified {
		if req.TOTPCode == "" {
			if user.TwoFactorMethod != nil && *user.TwoFactorMethod == "email" {
				locale := i18n.LocaleFromRequest(r)
				_ = s.sendTwoFactorEmail(r.Context(), user, locale)
			}
			writeError(w, http.StatusForbidden, "STEP_UP_REQUIRED")
			return
		}
		if !s.verifyTwoFactor(r.Context(), user, req.TOTPCode) {
			writeError(w, http.StatusForbidden, "INVALID_2FA_CODE")
			return
		}
		// Mark step-up for a short window so repeated disable attempts don't resend immediately.
		s.recordStepUp(r.Context(), sess.ID, "disable_2fa", 5*time.Minute)
	}

	if err := s.Users.DisableTwoFactor(r.Context(), sess.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to disable 2FA")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Two-factor authentication disabled.",
	})
}

type twoFactorStepUpRequest struct {
	Code    string `json:"code"`
	Purpose string `json:"purpose"`
}

func (s *Server) handleTwoFactorStepUp(w http.ResponseWriter, r *http.Request) {
	var req twoFactorStepUpRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Code == "" || req.Purpose == "" {
		writeError(w, http.StatusBadRequest, "Code and purpose are required.")
		return
	}
	if !allowedStepUpPurposes[req.Purpose] {
		writeError(w, http.StatusBadRequest, "Unsupported step-up purpose.")
		return
	}

	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "User not found")
		return
	}

	if !s.verifyTwoFactor(r.Context(), user, req.Code) {
		writeError(w, http.StatusForbidden, "Invalid or expired 2FA code.")
		return
	}

	ttl := 5 * time.Minute
	if user.TwoFactorEnabled {
		ttl = 10 * time.Minute // slightly longer for authenticated 2FA users
	}
	s.recordStepUp(r.Context(), sess.ID, req.Purpose, ttl)

	writeJSON(w, http.StatusOK, map[string]string{
		"success": "true",
		"purpose": req.Purpose,
	})
}
