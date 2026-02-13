package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"yourapp/internal/auth"
	"yourapp/internal/config"
	"yourapp/internal/database"
	"yourapp/internal/email"
	applog "yourapp/internal/logging"
	redisx "yourapp/internal/redis"
	"yourapp/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	logOutput := io.Writer(os.Stdout)
	var logFileCloser io.Closer
	if cfg.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o755); err != nil {
			log.Fatalf("log setup error: %v", err)
		}

		maxSizeMB := cfg.LogMaxSizeMB
		if maxSizeMB <= 0 {
			maxSizeMB = 20
		}
		maxBackups := cfg.LogMaxBackups
		if maxBackups < 0 {
			maxBackups = 0
		}

		f, err := applog.NewRotatingFileWriter(cfg.LogFile, int64(maxSizeMB)*1024*1024, maxBackups)
		if err != nil {
			log.Fatalf("log file open error: %v", err)
		}
		logFileCloser = f
		logOutput = io.MultiWriter(os.Stdout, f)
	}
	if logFileCloser != nil {
		defer logFileCloser.Close()
	}
	log.SetOutput(logOutput)
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lshortfile)

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database error: %v", err)
	}
	defer db.Close()

	if autoMigrateEnabled() {
		migrationsDir := os.Getenv("MIGRATIONS_DIR")
		if migrationsDir == "" {
			migrationsDir = "./migrations"
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		if err := database.ApplyMigrations(ctx, db, migrationsDir); err != nil {
			log.Fatalf("migration error: %v", err)
		}
		log.Printf("database migrations applied from %s", migrationsDir)
	}

	redisClient, err := redisx.New(cfg.RedisURL)
	if err != nil {
		log.Fatalf("redis error: %v", err)
	}
	defer redisClient.Close()

	users := auth.NewUserRepository(db)
	sessions := &auth.SessionStore{Redis: redisClient}
	rateLimiter := &auth.RateLimiter{Redis: redisClient}
	mailer := email.NewSender(cfg.Email)
	totpSvc := auth.NewTOTPService(cfg.TOTPIssuer)
	hasher := auth.NewBcryptHasher()

	api, err := server.NewServer(cfg, users, sessions, rateLimiter, redisClient, mailer, totpSvc, hasher)
	if err != nil {
		log.Fatalf("server init error: %v", err)
	}

	addr := ":" + cfg.Port
	srv := &http.Server{
		Addr:         addr,
		Handler:      api.Router(),
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
	}

	log.Printf("Listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func autoMigrateEnabled() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("AUTO_MIGRATE")))
	if raw == "" {
		return true
	}
	return raw == "1" || raw == "true" || raw == "yes"
}
