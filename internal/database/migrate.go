package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationLockID int64 = 7029001

func ApplyMigrations(ctx context.Context, db *pgxpool.Pool, migrationsDir string) error {
	if migrationsDir == "" {
		return fmt.Errorf("migrations directory is required")
	}

	if _, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	if _, err := db.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = db.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)
	}()

	files, err := listMigrationFiles(migrationsDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		version := strings.TrimSuffix(file.Name(), ".up.sql")
		path := filepath.Join(migrationsDir, file.Name())

		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file.Name(), err)
		}

		checksum := checksumHex(raw)

		appliedChecksum, alreadyApplied, err := migrationChecksum(ctx, db, version)
		if err != nil {
			return err
		}
		if alreadyApplied {
			if appliedChecksum != checksum {
				return fmt.Errorf("migration %s was changed after being applied", version)
			}
			continue
		}

		tx, err := db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration transaction %s: %w", version, err)
		}

		if _, err := tx.Exec(ctx, string(raw)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", version, err)
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO schema_migrations (version, checksum)
			VALUES ($1, $2)
		`, version, checksum); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
	}

	return nil
}

func listMigrationFiles(migrationsDir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("read migrations directory: %w", err)
	}

	var files []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".up.sql") {
			files = append(files, entry)
		}
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() < files[j].Name()
	})

	return files, nil
}

func migrationChecksum(ctx context.Context, db *pgxpool.Pool, version string) (checksum string, exists bool, err error) {
	row := db.QueryRow(ctx, `
		SELECT checksum
		FROM schema_migrations
		WHERE version=$1
	`, version)

	if err := row.Scan(&checksum); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read migration state %s: %w", version, err)
	}

	return checksum, true, nil
}

func checksumHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
