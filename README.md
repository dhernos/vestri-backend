# Vestri Backend (Go)

Vestri backend with PostgreSQL + Redis, user/session/auth flows, node management, and signed worker proxy requests.

## Requirements

- Go `1.22+`
- PostgreSQL
- Redis

## Run locally

```bash
go run ./cmd/server
```

For explicit migration step:

```bash
go run ./cmd/migrate
go run ./cmd/server
```

## Migrations

Schema lives in `migrations/` and applied versions are stored in `schema_migrations`.

- Auto-migrate is enabled by default on server startup.
- Disable with `AUTO_MIGRATE=false` if you want strict rollout separation.

## Core environment variables

- `DATABASE_URL` (required)
- `REDIS_URL` (optional, default `redis://localhost:6379`)
- `PORT` (optional, default `8080`)
- `AUTO_MIGRATE` (optional, default `true`)
- `MIGRATIONS_DIR` (optional, default `./migrations`)
- `LOG_FILE` (optional, default `logs/server.log`)
- `LOG_MAX_SIZE_MB` (optional, default `20`)
- `LOG_MAX_BACKUPS` (optional, default `3`)
- `NODE_API_KEY_ENCRYPTION_KEY` (recommended for encrypted node API key storage)

## Worker TLS trust (v1.0 default)

Backend-to-worker should default to HTTPS.

For custom/internal worker CAs:

- `WORKER_TLS_CA_CERT_DIR` (default `./certs/worker-cas`)
- `WORKER_TLS_CA_CERT_FILE` (optional single extra PEM file)

Behavior:

- Backend loads all `.crt`, `.pem`, `.cer` files from `WORKER_TLS_CA_CERT_DIR`.
- This supports multiple worker nodes with different CAs.
- You can keep one CA file per node, for example:
  - `certs/worker-cas/node-eu.crt`
  - `certs/worker-cas/node-us.crt`

## Node base URL behavior

When creating/updating a node:

- If URL has no scheme, backend assumes `https://` by default.
- HTTP is still supported if you explicitly set `http://...`.

## HTTP fallback (explicit opt-in)

Plain HTTP between backend and worker remains possible but must be intentional:

1. Worker:
   - `useTLS=false`
   - `require_tls=false`
2. Node base URL in backend:
   - explicit `http://host:port`

Without explicit `http://`, backend defaults to HTTPS.
