package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port                    string
	BaseURL                 string
	DatabaseURL             string
	RedisURL                string
	UploadDir               string
	LogFile                 string
	NoEmailVerify           bool
	SessionTTL              time.Duration
	TOTPIssuer              string
	WorkerAPIURL            string
	WorkerAPIKey            string
	NodeAPIKeyEncryptionKey string
	Email                   EmailConfig
	TrustedProxies          []string
	WebAuthn                WebAuthnConfig
	OAuth                   OAuthConfig
}

type EmailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	Secure   bool
}

func (e EmailConfig) Enabled() bool {
	return e.Host != "" && e.Port != 0 && e.From != ""
}

type WebAuthnConfig struct {
	RPName  string
	RPID    string
	Origins []string
}

type OAuthProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type OAuthConfig struct {
	GitHub  OAuthProvider
	Discord OAuthProvider
}

func Load() (Config, error) {
	clean := func(val string) string {
		return strings.Trim(val, "\"' \t\r\n")
	}

	rawPort := strings.Trim(getenvDefault("EMAIL_SERVER_PORT", "587"), "\"' ")
	emailPort, err := strconv.Atoi(rawPort)
	if err != nil {
		emailPort = 587
	}

	cfg := Config{
		Port:                    getenvDefault("PORT", "8080"),
		BaseURL:                 firstNonEmpty(os.Getenv("APP_BASE_URL"), os.Getenv("NEXTAUTH_URL"), "http://localhost:3000"),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
		RedisURL:                getenvDefault("REDIS_URL", "redis://localhost:6379"),
		UploadDir:               getenvDefault("UPLOAD_DIR", "../auth_template/public/uploads"),
		LogFile:                 getenvDefault("LOG_FILE", "logs/server.log"),
		NoEmailVerify:           parseBool(os.Getenv("NO_EMAIL_VERIFY")),
		SessionTTL:              7 * 24 * time.Hour,
		TOTPIssuer:              getenvDefault("TOTP_ISSUER", "AuthService"),
		WorkerAPIURL:            getenvDefault("WORKER_API_URL", "http://localhost:8031"),
		WorkerAPIKey:            os.Getenv("WORKER_API_KEY"),
		NodeAPIKeyEncryptionKey: os.Getenv("NODE_API_KEY_ENCRYPTION_KEY"),
		TrustedProxies:          parseList(os.Getenv("TRUSTED_PROXIES")),
	}

	cfg.Email = EmailConfig{
		Host:     clean(os.Getenv("EMAIL_SERVER_HOST")),
		Port:     emailPort,
		Username: clean(os.Getenv("EMAIL_SERVER_USER")),
		Password: clean(os.Getenv("EMAIL_SERVER_PASSWORD")),
		From:     clean(os.Getenv("EMAIL_FROM")),
		Secure:   parseBool(os.Getenv("EMAIL_SERVER_SECURE")),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}

	rpOrigin := getenvDefault("WEB_AUTHN_ORIGIN", cfg.BaseURL)
	rpID := getenvDefault("WEB_AUTHN_RP_ID", hostFromURL(rpOrigin))
	cfg.WebAuthn = WebAuthnConfig{
		RPName:  getenvDefault("WEB_AUTHN_RP_NAME", "Auth Service"),
		RPID:    rpID,
		Origins: parseList(getenvDefault("WEB_AUTHN_ORIGINS", rpOrigin)),
	}
	if len(cfg.WebAuthn.Origins) == 0 {
		cfg.WebAuthn.Origins = []string{rpOrigin}
	}

	cfg.OAuth = OAuthConfig{
		GitHub: OAuthProvider{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			RedirectURL:  getenvDefault("GITHUB_REDIRECT_URL", cfg.BaseURL+"/api/oauth/github/callback"),
		},
		Discord: OAuthProvider{
			ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
			ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
			RedirectURL:  getenvDefault("DISCORD_REDIRECT_URL", cfg.BaseURL+"/api/oauth/discord/callback"),
		},
	}

	absUpload, err := filepath.Abs(cfg.UploadDir)
	if err == nil {
		cfg.UploadDir = absUpload
	}

	return cfg, nil
}

func getenvDefault(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseBool(val string) bool {
	if val == "" {
		return false
	}
	val = strings.ToLower(strings.Trim(val, "\"' "))
	return val == "1" || val == "true" || val == "yes"
}

func parseList(val string) []string {
	parts := strings.Split(val, ",")
	var out []string
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Hostname()
}
