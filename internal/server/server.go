package server

import (
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/go-webauthn/webauthn/webauthn"
	"yourapp/internal/auth"
	"yourapp/internal/config"
	"yourapp/internal/email"
)

type Server struct {
	Users          *auth.UserRepository
	Sessions       *auth.SessionStore
	RateLimiter    *auth.RateLimiter
	Mailer         *email.Sender
	TOTP           *auth.TOTPService
	Redis          *redis.Client
	Config         config.Config
	Hasher         auth.PasswordHasher
	trustedProxies []net.IPNet
	WebAuthn       *webauthn.WebAuthn
	WebAuthnStore  *auth.WebAuthnSessionStore
}

func NewServer(cfg config.Config, users *auth.UserRepository, sessions *auth.SessionStore, rl *auth.RateLimiter, redisClient *redis.Client, mailer *email.Sender, totp *auth.TOTPService, hasher auth.PasswordHasher) (*Server, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.WebAuthn.RPName,
		RPID:          cfg.WebAuthn.RPID,
		RPOrigins:     cfg.WebAuthn.Origins,
	})
	if err != nil {
		return nil, err
	}

	return &Server{
		Users:          users,
		Sessions:       sessions,
		RateLimiter:    rl,
		Redis:          redisClient,
		Mailer:         mailer,
		TOTP:           totp,
		Config:         cfg,
		Hasher:         hasher,
		trustedProxies: parseProxyCIDRs(cfg.TrustedProxies),
		WebAuthn:       wa,
		WebAuthnStore:  &auth.WebAuthnSessionStore{Redis: redisClient},
	}, nil
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	formatter := &middleware.DefaultLogFormatter{
		Logger:  log.New(log.Writer(), "", log.Flags()),
		NoColor: true,
	}
	r.Use(middleware.RequestLogger(formatter))
	r.Use(middleware.Recoverer)
	r.Use(secureHeaders)

	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/register"))).Post("/api/register", s.handleRegister)
	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/verify-email"))).Post("/api/verify-email", s.handleVerifyEmail)
	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/resend-verification"))).Post("/api/resend-verification", s.handleResendVerification)
	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/forgot-password"))).Post("/api/forgot-password", s.handleForgotPassword)
	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/reset-password"))).Post("/api/reset-password", s.handleResetPassword)

	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/auth/login"))).Post("/api/auth/login", s.handleLogin)
	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/auth/logout"))).Post("/api/auth/logout", s.handleLogout)

	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/two-factor/send-email-code"))).Post("/api/two-factor/send-email-code", s.handleSendTwoFactorEmailCode)

	r.With(s.requireRoles(accessRoles(http.MethodGet, "/api/oauth/{provider}/start"))).Get("/api/oauth/{provider}/start", s.handleOAuthStart)
	r.With(s.requireRoles(accessRoles(http.MethodGet, "/api/oauth/{provider}/callback"))).Get("/api/oauth/{provider}/callback", s.handleOAuthCallback)
	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/oauth/{provider}/two-factor"))).Post("/api/oauth/{provider}/two-factor", s.handleOAuthTwoFactor)

	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/passkeys/login/start"))).Post("/api/passkeys/login/start", s.handlePasskeyLoginStart)
	r.With(s.requireRoles(accessRoles(http.MethodPost, "/api/passkeys/login/finish"))).Post("/api/passkeys/login/finish", s.handlePasskeyLoginFinish)

	r.Group(func(pr chi.Router) {
		pr.Use(s.requireSession(true))

		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/auth/me"))).Get("/api/auth/me", s.handleMe)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/sessions"))).Get("/api/sessions", s.handleListSessions)
		pr.With(s.requireRoles(accessRoles(http.MethodDelete, "/api/sessions"))).Delete("/api/sessions", s.handleDeleteSession)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/sessions/current"))).Get("/api/sessions/current", s.handleCurrentSession)

		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/two-factor/setup-start"))).Post("/api/two-factor/setup-start", s.handleTwoFactorSetupStart)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/two-factor/setup-finalize"))).Post("/api/two-factor/setup-finalize", s.handleTwoFactorSetupFinalize)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/two-factor/disable"))).Post("/api/two-factor/disable", s.handleTwoFactorDisable)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/two-factor/step-up"))).Post("/api/two-factor/step-up", s.handleTwoFactorStepUp)

		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/profile/update-profile"))).Post("/api/profile/update-profile", s.handleUpdateProfile)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/profile/update-email"))).Post("/api/profile/update-email", s.handleUpdateEmail)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/profile/change-password"))).Post("/api/profile/change-password", s.handleChangePassword)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/profile/update-image"))).Post("/api/profile/update-image", s.handleUpdateImage)
		pr.With(s.requireRoles(accessRoles(http.MethodDelete, "/api/profile/delete-account"))).Delete("/api/profile/delete-account", s.handleDeleteAccount)

		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/passkeys/register/start"))).Post("/api/passkeys/register/start", s.handlePasskeyRegisterStart)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/passkeys/register/finish"))).Post("/api/passkeys/register/finish", s.handlePasskeyRegisterFinish)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/passkeys"))).Get("/api/passkeys", s.handleListPasskeys)
		pr.With(s.requireRoles(accessRoles(http.MethodDelete, "/api/passkeys/{id}"))).Delete("/api/passkeys/{id}", s.handleDeletePasskey)

		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/worker/*"))).Get("/api/worker/*", s.handleWorkerProxy)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/worker/*"))).Post("/api/worker/*", s.handleWorkerProxy)
	})

	return r
}
