package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"yourapp/internal/auth"
	"yourapp/internal/i18n"
)

const (
	passkeyRegPrefix   = "webauthn:reg:"
	passkeyLoginPrefix = "webauthn:login:"
	passkeyTTL         = 10 * time.Minute
)

type passkeyRegisterStartResponse struct {
	SessionID string                       `json:"sessionId"`
	Options   *protocol.CredentialCreation `json:"options"`
}

type passkeyLoginStartRequest struct {
	Email string `json:"email"`
}

type passkeyLoginStartResponse struct {
	SessionID string                        `json:"sessionId"`
	Options   *protocol.CredentialAssertion `json:"options"`
}

func (s *Server) handlePasskeyRegisterStart(w http.ResponseWriter, r *http.Request) {
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

	existing, err := s.Users.ListPasskeys(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load passkeys")
		return
	}

	needStepUp := user.TwoFactorEnabled || len(existing) > 0
	if needStepUp && !s.requireStepUp(r.Context(), sess, "passkey_manage") {
		if user.TwoFactorMethod != nil && *user.TwoFactorMethod == "email" {
			locale := i18n.LocaleFromRequest(r)
			_ = s.sendTwoFactorEmail(r.Context(), user, locale)
		}
		writeError(w, http.StatusForbidden, "STEP_UP_REQUIRED")
		return
	}

	waUser := auth.NewWebAuthnUser(user, toWebAuthnCreds(existing))
	opts, sessionData, err := s.WebAuthn.BeginRegistration(waUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to start registration")
		return
	}

	token := auth.NewSessionID()
	if err := s.WebAuthnStore.Save(r.Context(), passkeyRegPrefix+token, sessionData, passkeyTTL); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to persist session")
		return
	}

	writeJSON(w, http.StatusOK, passkeyRegisterStartResponse{
		SessionID: token,
		Options:   opts,
	})
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "Missing sessionId")
		return
	}

	sd, err := s.WebAuthnStore.Get(r.Context(), passkeyRegPrefix+sessionID)
	if err != nil || sd == nil {
		writeError(w, http.StatusBadRequest, "Registration session expired")
		return
	}
	defer s.WebAuthnStore.Delete(r.Context(), passkeyRegPrefix+sessionID)

	user, err := s.Users.FindByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}
	existing, err := s.Users.ListPasskeys(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load passkeys")
		return
	}
	waUser := auth.NewWebAuthnUser(user, toWebAuthnCreds(existing))

	credential, err := s.WebAuthn.FinishRegistration(waUser, *sd, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Failed to finish registration")
		return
	}

	label := r.URL.Query().Get("label")
	passkey := auth.PasskeyCredential{
		UserID:          user.ID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transports:      auth.ProtocolTransportsToStrings(credential.Transport),
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
	}
	if strings.TrimSpace(label) != "" {
		passkey.Label = &label
	}

	saved, err := s.Users.CreatePasskey(r.Context(), passkey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to store passkey")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":        saved.ID,
		"createdAt": saved.CreatedAt,
		"label":     saved.Label,
	})
}

func (s *Server) handlePasskeyLoginStart(w http.ResponseWriter, r *http.Request) {
	var req passkeyLoginStartRequest
	if err := decodeJSON(r, &req); err != nil || !validateEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	ctx := r.Context()
	ip := clientIP(r, s.trustedProxies)
	if s.RateLimiter.IsIPBanned(ctx, ip) {
		writeError(w, http.StatusForbidden, "IP_BANNED")
		return
	}

	user, err := s.Users.FindByEmail(ctx, req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load user")
		return
	}
	if user == nil || user.EmailVerified == nil {
		_ = s.RateLimiter.RegisterLoginFailure(ctx, ip)
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS")
		return
	}

	passkeys, err := s.Users.ListPasskeys(ctx, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load passkeys")
		return
	}
	if len(passkeys) == 0 {
		writeError(w, http.StatusBadRequest, "No passkeys registered")
		return
	}

	waUser := auth.NewWebAuthnUser(user, toWebAuthnCreds(passkeys))
	opts, sd, err := s.WebAuthn.BeginLogin(waUser, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to start login")
		return
	}

	token := auth.NewSessionID()
	if err := s.WebAuthnStore.Save(ctx, passkeyLoginPrefix+token, sd, passkeyTTL); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to persist session")
		return
	}

	writeJSON(w, http.StatusOK, passkeyLoginStartResponse{
		SessionID: token,
		Options:   opts,
	})
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "Missing sessionId")
		return
	}

	sd, err := s.WebAuthnStore.Get(ctx, passkeyLoginPrefix+sessionID)
	if err != nil || sd == nil {
		writeError(w, http.StatusBadRequest, "Login session expired")
		return
	}
	defer s.WebAuthnStore.Delete(ctx, passkeyLoginPrefix+sessionID)

	userID, err := uuid.FromBytes(sd.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid session")
		return
	}
	user, err := s.Users.FindByID(ctx, userID.String())
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, "User not found")
		return
	}
	passkeys, err := s.Users.ListPasskeys(ctx, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load passkeys")
		return
	}

	waUser := auth.NewWebAuthnUser(user, toWebAuthnCreds(passkeys))
	credential, err := s.WebAuthn.FinishLogin(waUser, *sd, r)
	if err != nil {
		_ = s.RateLimiter.RegisterLoginFailure(ctx, clientIP(r, s.trustedProxies))
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS")
		return
	}

	var matched *auth.PasskeyCredential
	for _, pk := range passkeys {
		if auth.IsCredentialIDMatch(pk.CredentialID, credential.ID) {
			matched = &pk
			break
		}
	}
	if matched != nil {
		_ = s.Users.UpdatePasskeySignCount(ctx, matched.ID, credential.Authenticator.SignCount)
	}

	now := time.Now()
	session := auth.Session{
		ID:                  auth.NewSessionID(),
		UserID:              user.ID,
		Role:                user.Role,
		IP:                  clientIP(r, s.trustedProxies),
		Location:            deriveLocation(r),
		UserAgent:           r.UserAgent(),
		LoginTime:           now,
		ExpiresAt:           now.Add(s.Config.SessionTTL),
		TwoFactorEnabled:    user.TwoFactorEnabled,
		TwoFactorVerified:   true, // passkeys satisfy strong auth
		TwoFactorVerifiedAt: &now,
	}

	if err := s.Sessions.Create(ctx, session); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_CREATE_FAILED")
		return
	}
	s.RateLimiter.ResetLogin(ctx, clientIP(r, s.trustedProxies))
	auth.SetSessionCookie(w, session.ID, session.ExpiresAt)
	locale := i18n.LocaleFromRequest(r)
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

func (s *Server) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	passkeys, err := s.Users.ListPasskeys(r.Context(), sess.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to load passkeys")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"passkeys": passkeys})
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	user, _ := s.Users.FindByID(r.Context(), sess.UserID)
	if !s.requireStepUp(r.Context(), sess, "passkey_manage") {
		if user != nil && user.TwoFactorMethod != nil && *user.TwoFactorMethod == "email" {
			locale := i18n.LocaleFromRequest(r)
			_ = s.sendTwoFactorEmail(r.Context(), user, locale)
		}
		writeError(w, http.StatusForbidden, "STEP_UP_REQUIRED")
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "Missing id")
		return
	}
	if err := s.Users.DeletePasskey(r.Context(), sess.UserID, id); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete passkey")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Passkey removed"})
}

func toWebAuthnCreds(creds []auth.PasskeyCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.ToWebAuthnCredential())
	}
	return out
}
