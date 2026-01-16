package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"yourapp/internal/auth"
	"yourapp/internal/config"
	"yourapp/internal/i18n"
)

const oauthStatePrefix = "oauth_state:"
const oauthStateTTL = 10 * time.Minute
const oauthPendingPrefix = "oauth_pending:"
const oauthPendingTTL = 10 * time.Minute

type oauthState struct {
	Provider string `json:"provider"`
	ReturnTo string `json:"returnTo"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type oauthUser struct {
	ID     string
	Email  string
	Name   string
	Avatar string
}

type oauthPendingLogin struct {
	UserID    string       `json:"userId"`
	Provider  string       `json:"provider"`
	AccountID string       `json:"accountId"`
	ReturnTo  string       `json:"returnTo"`
	Session   auth.Session `json:"session"`
}

func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(chi.URLParam(r, "provider"))
	cfg := s.getProviderConfig(provider)
	state := auth.NewSessionID()
	returnTo := sanitizeReturnTo(r.URL.Query().Get("returnTo"))

	if cfg == nil {
		log.Printf("oauth start: provider %s not configured", provider)
		s.oauthErrorRedirect(w, r, returnTo, "provider_unavailable")
		return
	}

	raw, _ := json.Marshal(oauthState{Provider: provider, ReturnTo: returnTo})
	if err := s.Redis.Set(r.Context(), oauthStatePrefix+state, raw, oauthStateTTL).Err(); err != nil {
		log.Printf("oauth start: failed to persist state for provider %s: %v", provider, err)
		s.oauthErrorRedirect(w, r, returnTo, "state_persist_failed")
		return
	}

	authURL := s.buildAuthURL(provider, *cfg, state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	returnTo := "/"
	provider := strings.ToLower(chi.URLParam(r, "provider"))
	cfg := s.getProviderConfig(provider)
	locale := i18n.LocaleFromRequest(r)
	if cfg == nil {
		log.Printf("oauth callback: unsupported provider %s", provider)
		s.oauthErrorRedirect(w, r, returnTo, "unsupported_provider")
		return
	}

	stateParam := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if stateParam == "" || code == "" {
		log.Printf("oauth callback: missing state/code for provider %s", provider)
		s.oauthErrorRedirect(w, r, returnTo, "missing_state")
		return
	}

	rawState, err := s.Redis.Get(r.Context(), oauthStatePrefix+stateParam).Bytes()
	if err != nil {
		log.Printf("oauth callback: state lookup failed for provider %s: %v", provider, err)
		s.oauthErrorRedirect(w, r, returnTo, "state_invalid")
		return
	}
	_ = s.Redis.Del(r.Context(), oauthStatePrefix+stateParam).Err()

	var st oauthState
	_ = json.Unmarshal(rawState, &st)
	returnTo = sanitizeReturnTo(st.ReturnTo)
	if st.Provider != provider {
		log.Printf("oauth callback: state mismatch expected %s got %s", st.Provider, provider)
		s.oauthErrorRedirect(w, r, returnTo, "state_mismatch")
		return
	}

	token, err := s.exchangeCode(r.Context(), provider, *cfg, code)
	if err != nil {
		log.Printf("oauth callback: token exchange failed for %s: %v", provider, err)
		s.oauthErrorRedirect(w, r, returnTo, "token_exchange_failed")
		return
	}
	userInfo, err := s.fetchOAuthUser(r.Context(), provider, token.AccessToken)
	if err != nil {
		log.Printf("oauth callback: fetch user failed for %s: %v", provider, err)
		s.oauthErrorRedirect(w, r, returnTo, "profile_fetch_failed")
		return
	}
	if userInfo.Email == "" {
		log.Printf("oauth callback: provider %s missing email", provider)
		s.oauthErrorRedirect(w, r, returnTo, "email_required")
		return
	}

	ctx := r.Context()
	ip := clientIP(r, s.trustedProxies)
	ua := r.UserAgent()
	loc := deriveLocation(r)

	user, err := s.Users.FindByOAuth(ctx, provider, userInfo.ID)
	if err != nil {
		log.Printf("oauth callback: lookup by oauth failed for %s: %v", provider, err)
		s.oauthErrorRedirect(w, r, returnTo, "lookup_failed")
		return
	}
	if user == nil {
		user, err = s.Users.FindByEmail(ctx, userInfo.Email)
		if err != nil {
			log.Printf("oauth callback: lookup by email failed for %s: %v", provider, err)
			s.oauthErrorRedirect(w, r, returnTo, "lookup_failed")
			return
		}
	}

	verifiedAt := time.Now()
	if user == nil {
		var name *string
		if strings.TrimSpace(userInfo.Name) != "" {
			name = &userInfo.Name
		}
		user, err = s.Users.Create(ctx, name, userInfo.Email, nil, &verifiedAt)
		if err != nil {
			log.Printf("oauth callback: create user failed for %s: %v", provider, err)
			s.oauthErrorRedirect(w, r, returnTo, "create_failed")
			return
		}
	}

	if _, err := s.Users.LinkOAuthAccount(ctx, user.ID, provider, userInfo.ID); err != nil {
		log.Printf("oauth callback: link account failed for %s: %v", provider, err)
		s.oauthErrorRedirect(w, r, returnTo, "link_failed")
		return
	}

	now := time.Now()

	if user.TwoFactorEnabled {
		if user.TwoFactorMethod != nil && *user.TwoFactorMethod == "email" {
			_ = s.sendTwoFactorEmail(ctx, user, locale)
		}
		log.Printf("oauth callback: two-factor required for user %s", user.ID)

		pendingID := auth.NewSessionID()
		pending := oauthPendingLogin{
			UserID:    user.ID,
			Provider:  provider,
			AccountID: userInfo.ID,
			ReturnTo:  returnTo,
			Session: auth.Session{
				ID:                auth.NewSessionID(),
				UserID:            user.ID,
				Role:              user.Role,
				IP:                ip,
				Location:          loc,
				UserAgent:         ua,
				LoginTime:         now,
				ExpiresAt:         now.Add(s.Config.SessionTTL),
				TwoFactorEnabled:  true,
				TwoFactorVerified: false,
			},
		}
		rawPending, _ := json.Marshal(pending)
		if err := s.Redis.Set(ctx, oauthPendingPrefix+pendingID, rawPending, oauthPendingTTL).Err(); err != nil {
			log.Printf("oauth callback: failed to store pending 2fa login: %v", err)
			s.oauthErrorRedirect(w, r, returnTo, "two_factor_failed")
			return
		}

		loginPath := s.oauthChallengePath(returnTo)
		redirectURL := appendQueryParams(loginPath, map[string]string{
			"oauth_pending":  pendingID,
			"oauth_provider": provider,
			"oauth_return":   returnTo,
		})

		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	session := auth.Session{
		ID:                auth.NewSessionID(),
		UserID:            user.ID,
		Role:              user.Role,
		IP:                ip,
		Location:          loc,
		UserAgent:         ua,
		LoginTime:         now,
		ExpiresAt:         now.Add(s.Config.SessionTTL),
		TwoFactorEnabled:  user.TwoFactorEnabled,
		TwoFactorVerified: true,
	}
	session.TwoFactorVerifiedAt = &now

	if err := s.Sessions.Create(ctx, session); err != nil {
		log.Printf("oauth callback: session create failed for user %s: %v", user.ID, err)
		s.oauthErrorRedirect(w, r, returnTo, "session_failed")
		return
	}
	s.RateLimiter.ResetLogin(ctx, ip)
	auth.SetSessionCookie(w, session.ID, session.ExpiresAt)
	_ = s.sendSignInAlert(ctx, user, session, locale)

	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (s *Server) getProviderConfig(provider string) *config.OAuthProvider {
	switch provider {
	case "github":
		if s.Config.OAuth.GitHub.ClientID == "" || s.Config.OAuth.GitHub.ClientSecret == "" {
			return nil
		}
		return &s.Config.OAuth.GitHub
	case "discord":
		if s.Config.OAuth.Discord.ClientID == "" || s.Config.OAuth.Discord.ClientSecret == "" {
			return nil
		}
		return &s.Config.OAuth.Discord
	default:
		return nil
	}
}

func (s *Server) buildAuthURL(provider string, cfg config.OAuthProvider, state string) string {
	switch provider {
	case "github":
		u, _ := url.Parse("https://github.com/login/oauth/authorize")
		q := u.Query()
		q.Set("client_id", cfg.ClientID)
		q.Set("redirect_uri", cfg.RedirectURL)
		q.Set("scope", "read:user user:email")
		q.Set("state", state)
		u.RawQuery = q.Encode()
		return u.String()
	case "discord":
		u, _ := url.Parse("https://discord.com/api/oauth2/authorize")
		q := u.Query()
		q.Set("client_id", cfg.ClientID)
		q.Set("redirect_uri", cfg.RedirectURL)
		q.Set("response_type", "code")
		q.Set("scope", "identify email")
		q.Set("state", state)
		q.Set("prompt", "none")
		u.RawQuery = q.Encode()
		return u.String()
	default:
		return ""
	}
}

func (s *Server) exchangeCode(ctx context.Context, provider string, cfg config.OAuthProvider, code string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", cfg.RedirectURL)
	form.Set("grant_type", "authorization_code")

	var endpoint string
	var accept string
	switch provider {
	case "github":
		endpoint = "https://github.com/login/oauth/access_token"
		accept = "application/json"
	case "discord":
		endpoint = "https://discord.com/api/oauth2/token"
	default:
		return nil, errors.New("unsupported provider")
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tok tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, errors.New("missing access token")
	}
	return &tok, nil
}

func (s *Server) fetchOAuthUser(ctx context.Context, provider, accessToken string) (*oauthUser, error) {
	switch provider {
	case "github":
		return fetchGitHubUser(ctx, accessToken)
	case "discord":
		return fetchDiscordUser(ctx, accessToken)
	default:
		return nil, errors.New("unsupported provider")
	}
}

func fetchGitHubUser(ctx context.Context, token string) (*oauthUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	email := data.Email
	if email == "" {
		email, _ = fetchGitHubPrimaryEmail(ctx, token)
	}
	return &oauthUser{
		ID:     fmt.Sprintf("%d", data.ID),
		Email:  email,
		Name:   firstNonEmptyLocal(data.Name, data.Login),
		Avatar: data.AvatarURL,
	}, nil
}

func fetchGitHubPrimaryEmail(ctx context.Context, token string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	if len(emails) > 0 {
		return emails[0].Email, nil
	}
	return "", nil
}

func fetchDiscordUser(ctx context.Context, token string) (*oauthUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/users/@me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data struct {
		ID            string `json:"id"`
		Username      string `json:"username"`
		GlobalName    string `json:"global_name"`
		Email         string `json:"email"`
		Avatar        string `json:"avatar"`
		Discriminator string `json:"discriminator"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	name := data.GlobalName
	if name == "" {
		name = data.Username
		if data.Discriminator != "" && data.Discriminator != "0" {
			name = fmt.Sprintf("%s#%s", data.Username, data.Discriminator)
		}
	}
	var avatarURL string
	if data.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", data.ID, data.Avatar)
	}
	return &oauthUser{
		ID:     data.ID,
		Email:  data.Email,
		Name:   name,
		Avatar: avatarURL,
	}, nil
}

func firstNonEmptyLocal(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (s *Server) handleOAuthTwoFactor(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(chi.URLParam(r, "provider"))
	pendingID := r.URL.Query().Get("pending")
	if pendingID == "" {
		writeError(w, http.StatusBadRequest, "Missing pending token")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || len(req.Code) != 6 {
		writeError(w, http.StatusBadRequest, "Invalid code")
		return
	}

	raw, err := s.Redis.Get(r.Context(), oauthPendingPrefix+pendingID).Bytes()
	if err != nil {
		writeError(w, http.StatusBadRequest, "Expired or invalid challenge")
		return
	}

	var pending oauthPendingLogin
	if err := json.Unmarshal(raw, &pending); err != nil {
		writeError(w, http.StatusBadRequest, "Corrupt challenge")
		return
	}
	if pending.Provider != provider {
		writeError(w, http.StatusBadRequest, "Provider mismatch")
		return
	}

	user, err := s.Users.FindByID(r.Context(), pending.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, "User not found")
		return
	}

	if !s.verifyTwoFactor(r.Context(), user, req.Code) {
		writeError(w, http.StatusForbidden, "INVALID_2FA_CODE")
		return
	}
	s.RateLimiter.Reset2FA(r.Context(), user.ID)

	sess := pending.Session
	now := time.Now()
	sess.TwoFactorVerified = true
	sess.TwoFactorVerifiedAt = &now
	sess.LoginTime = now
	sess.ExpiresAt = now.Add(s.Config.SessionTTL)

	if err := s.Sessions.Create(r.Context(), sess); err != nil {
		writeError(w, http.StatusInternalServerError, "SESSION_CREATE_FAILED")
		return
	}
	_ = s.Redis.Del(r.Context(), oauthPendingPrefix+pendingID).Err()

	s.RateLimiter.ResetLogin(r.Context(), sess.IP)
	auth.SetSessionCookie(w, sess.ID, sess.ExpiresAt)
	locale := i18n.LocaleFromRequest(r)
	_ = s.sendSignInAlert(r.Context(), user, sess, locale)

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
			"oauthLinked":        true,
		},
		"sessionId": sess.ID,
		"returnTo":  pending.ReturnTo,
	})
}

func (s *Server) oauthErrorRedirect(w http.ResponseWriter, r *http.Request, returnTo, reason string) {
	target := sanitizeReturnTo(returnTo)
	u, err := url.Parse(target)
	if err != nil || u.IsAbs() {
		u = &url.URL{Path: "/"}
	}
	q := u.Query()
	q.Set("toast", "oauth_error")
	if reason != "" {
		q.Set("reason", reason)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func sanitizeReturnTo(raw string) string {
	if raw == "" {
		return "/"
	}
	if strings.HasPrefix(raw, "//") {
		return "/"
	}
	if strings.HasPrefix(raw, "/") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() {
		return "/"
	}

	path := u.Path
	if path == "" || !strings.HasPrefix(path, "/") {
		path = "/" + strings.TrimPrefix(path, "/")
	}
	if u.RawQuery != "" {
		path = path + "?" + u.RawQuery
	}
	return path
}

func (s *Server) oauthChallengePath(returnTo string) string {
	// Try to preserve locale from the original returnTo path (e.g., /en/dashboard -> /en/login).
	locale := "en"
	segments := strings.Split(strings.TrimPrefix(returnTo, "/"), "/")
	if len(segments) > 0 && len(segments[0]) == 2 {
		locale = segments[0]
	}
	return "/" + locale + "/login"
}

func appendQueryParams(path string, params map[string]string) string {
	u, err := url.Parse(path)
	if err != nil {
		return path
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
