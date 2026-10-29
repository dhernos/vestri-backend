package server

import (
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"

	"yourapp/internal/auth"
	"yourapp/internal/config"
	"yourapp/internal/email"

	"github.com/go-webauthn/webauthn/webauthn"
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
	NodeAPIKey     *nodeAPIKeyCipher
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

	nodeCipher, err := newNodeAPIKeyCipher(cfg.NodeAPIKeyEncryptionKey)
	if err != nil {
		return nil, err
	}
	if err := configureWorkerHTTPClient(cfg.WorkerTLSCACertFile, cfg.WorkerTLSCACertDir); err != nil {
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
		NodeAPIKey:     nodeCipher,
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

		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes"))).Get("/api/nodes", s.handleListNodes)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes"))).Post("/api/nodes", s.handleCreateNode)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/invites"))).Get("/api/nodes/invites", s.handleListIncomingNodeInvites)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/invites/{inviteId}/accept"))).Post("/api/nodes/invites/{inviteId}/accept", s.handleAcceptNodeInvite)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}"))).Get("/api/nodes/{nodeRef}", s.handleGetNode)
		pr.With(s.requireRoles(accessRoles(http.MethodDelete, "/api/nodes/{nodeRef}"))).Delete("/api/nodes/{nodeRef}", s.handleDeleteNode)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/satisfactory-blueprints"))).Get("/api/nodes/{nodeRef}/satisfactory-blueprints", s.handleListSatisfactoryBlueprintLibrary)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/satisfactory-blueprints/download"))).Get("/api/nodes/{nodeRef}/satisfactory-blueprints/download", s.handleDownloadSatisfactoryBlueprint)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/satisfactory-blueprints/upload"))).Post("/api/nodes/{nodeRef}/satisfactory-blueprints/upload", s.handleUploadSatisfactoryBlueprint)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/satisfactory-blueprints/import"))).Post("/api/nodes/{nodeRef}/satisfactory-blueprints/import", s.handleImportSatisfactoryBlueprint)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/satisfactory-blueprints/delete"))).Post("/api/nodes/{nodeRef}/satisfactory-blueprints/delete", s.handleDeleteSatisfactoryBlueprint)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/templates"))).Get("/api/nodes/{nodeRef}/servers/templates", s.handleListGameServerTemplates)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers"))).Get("/api/nodes/{nodeRef}/servers", s.handleListGameServers)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers"))).Post("/api/nodes/{nodeRef}/servers", s.handleCreateGameServer)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}", s.handleGetGameServer)
		pr.With(s.requireRoles(accessRoles(http.MethodDelete, "/api/nodes/{nodeRef}/servers/{serverRef}"))).Delete("/api/nodes/{nodeRef}/servers/{serverRef}", s.handleDeleteGameServer)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/status"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/status", s.handleGameServerStatus)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/map/status"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/map/status", s.handleGameServerMap)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/map/view/*"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/map/view/*", s.handleGameServerMap)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/console/logs/stream"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/console/logs/stream", s.handleGameServerConsoleLogsStream)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/console/logs/ws"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/console/logs/ws", s.handleGameServerConsoleLogsWS)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/ws"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/ws", s.handleGameServerConsoleExecWS)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/session"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/session", s.handleGameServerConsoleExecSessionCreate)
		pr.With(s.requireRoles(accessRoles(http.MethodDelete, "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/session"))).Delete("/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/session", s.handleGameServerConsoleExecSessionDelete)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/stream"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/stream", s.handleGameServerConsoleExecStream)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/input"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/input", s.handleGameServerConsoleExecInput)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/resize"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/console/exec/resize", s.handleGameServerConsoleExecResize)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/start"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/start", s.handleStartGameServer)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/stop"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/stop", s.handleStopGameServer)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/images/repull"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/images/repull", s.handleRepullGameServerImages)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/whitelist"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/whitelist", s.handleVelocityWhitelist)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/whitelist"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/whitelist", s.handleVelocityWhitelist)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/files/list"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/files/list", s.handleListGameServerFiles)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/files/read"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/files/read", s.handleReadGameServerFile)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/files/write"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/files/write", s.handleWriteGameServerFile)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/files/delete"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/files/delete", s.handleDeleteGameServerFile)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/files/transfer"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/files/transfer", s.handleTransferGameServerEntry)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/files/unzip"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/files/unzip", s.handleUnzipGameServerFile)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/files/download"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/files/download", s.handleDownloadGameServerFile)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/files/upload"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/files/upload", s.handleUploadGameServerFile)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/list"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/list", s.handleListGroupFiles)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/read"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/read", withGroupFilesScope(s.handleReadGameServerFile))
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/write"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/write", withGroupFilesScope(s.handleWriteGameServerFile))
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/delete"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/delete", withGroupFilesScope(s.handleDeleteGameServerFile))
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/transfer"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/transfer", withGroupFilesScope(s.handleTransferGameServerEntry))
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/unzip"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/unzip", withGroupFilesScope(s.handleUnzipGameServerFile))
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/download"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/download", withGroupFilesScope(s.handleDownloadGameServerFile))
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/upload"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/files/upload", withGroupFilesScope(s.handleUploadGameServerFile))
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/folders/create"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/folders/create", s.handleCreateGroupFolder)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/apply"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/apply", s.handleApplyGroupFiles)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins", s.handleTrackedPlugins)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins", s.handleImportPlugin)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins/update"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins/update", s.handleUpdatePlugin)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins/remove"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/group-files/plugins/remove", s.handleRemovePluginTracking)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/backups"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/backups", s.handleGameServerBackups)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/databases"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/databases", s.handleGameServerDatabases)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/databases"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/databases", s.handleGameServerDatabases)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/databases/action"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/databases/action", s.handleGameServerDatabaseAction)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/backups/settings"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/backups/settings", s.handleSaveGameServerBackupSettings)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/backups/create"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/backups/create", s.handleCreateGameServerBackup)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/backups/delete"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/backups/delete", s.handleDeleteGameServerBackup)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/backups/restore"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/backups/restore", s.handleRestoreGameServerBackup)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/backups/download"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/backups/download", s.handleDownloadGameServerBackup)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/backups/upload"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/backups/upload", s.handleUploadGameServerBackup)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/blueprints/install"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/blueprints/install", s.handleInstallSatisfactoryBlueprint)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/blueprints"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/blueprints", s.handleListSatisfactoryBlueprints)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/invites"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/invites", s.handleListGameServerInvites)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/servers/{serverRef}/invites"))).Post("/api/nodes/{nodeRef}/servers/{serverRef}/invites", s.handleCreateGameServerInvite)
		pr.With(s.requireRoles(accessRoles(http.MethodDelete, "/api/nodes/{nodeRef}/servers/{serverRef}/invites/{inviteId}"))).Delete("/api/nodes/{nodeRef}/servers/{serverRef}/invites/{inviteId}", s.handleRevokeGameServerInvite)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/servers/{serverRef}/guests"))).Get("/api/nodes/{nodeRef}/servers/{serverRef}/guests", s.handleListGameServerGuests)
		pr.With(s.requireRoles(accessRoles(http.MethodDelete, "/api/nodes/{nodeRef}/servers/{serverRef}/guests/{guestUserId}"))).Delete("/api/nodes/{nodeRef}/servers/{serverRef}/guests/{guestUserId}", s.handleRemoveGameServerGuest)
		pr.With(s.requireRoles(accessRoles(http.MethodGet, "/api/nodes/{nodeRef}/worker/*"))).Get("/api/nodes/{nodeRef}/worker/*", s.handleWorkerProxy)
		pr.With(s.requireRoles(accessRoles(http.MethodPost, "/api/nodes/{nodeRef}/worker/*"))).Post("/api/nodes/{nodeRef}/worker/*", s.handleWorkerProxy)
	})

	return r
}
