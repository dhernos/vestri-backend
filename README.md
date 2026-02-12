# Vestri Backend (Go)

This backend uses PostgreSQL and Redis.

## Database schema and migrations

The schema is defined in SQL migrations under `migrations/`.

- `000001_init.up.sql` creates the initial tables and indexes.
- `000001_init.down.sql` rolls the initial schema back.
- Applied versions are tracked in `schema_migrations`.

Current tables:

- `"User"`
- `"VerificationToken"`
- `"OAuthAccount"`
- `"PasskeyCredential"`

## Simple deployment (no extra migration container)

You have two simple options:

1. Auto-migrate on app startup (default)
   - Start your backend normally.
   - The server runs migrations before serving traffic.
   - Disable with `AUTO_MIGRATE=false`.

2. One-time migrate command in your deploy pipeline
   - Run `go run ./cmd/migrate` before rolling out `cmd/server`.
   - Useful if you want strict separation of schema rollout and app start.

Environment variables:

- `DATABASE_URL` (required)
- `AUTO_MIGRATE` (optional, default `true`)
- `MIGRATIONS_DIR` (optional, default `./migrations`)
