CREATE TABLE IF NOT EXISTS "GameServerGuest" (
  "id" TEXT PRIMARY KEY,
  "serverId" TEXT NOT NULL REFERENCES "GameServer"("id") ON DELETE CASCADE,
  "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "permission" TEXT NOT NULL DEFAULT 'viewer',
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT "GameServerGuest_serverId_userId_key" UNIQUE ("serverId", "userId")
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'GameServerGuest_permission_check'
  ) THEN
    ALTER TABLE "GameServerGuest"
      ADD CONSTRAINT "GameServerGuest_permission_check"
      CHECK ("permission" IN ('admin', 'operator', 'viewer'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS "GameServerGuest_userId_idx" ON "GameServerGuest" ("userId");
CREATE INDEX IF NOT EXISTS "GameServerGuest_serverId_idx" ON "GameServerGuest" ("serverId");

CREATE TABLE IF NOT EXISTS "GameServerInvite" (
  "id" TEXT PRIMARY KEY,
  "serverId" TEXT NOT NULL REFERENCES "GameServer"("id") ON DELETE CASCADE,
  "inviterUserId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "email" TEXT NOT NULL,
  "permission" TEXT NOT NULL,
  "token" TEXT NOT NULL UNIQUE,
  "expiresAt" TIMESTAMPTZ NOT NULL,
  "acceptedAt" TIMESTAMPTZ,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'GameServerInvite_permission_check'
  ) THEN
    ALTER TABLE "GameServerInvite"
      ADD CONSTRAINT "GameServerInvite_permission_check"
      CHECK ("permission" IN ('admin', 'operator', 'viewer'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS "GameServerInvite_serverId_idx" ON "GameServerInvite" ("serverId");
CREATE INDEX IF NOT EXISTS "GameServerInvite_email_idx" ON "GameServerInvite" (LOWER("email"));
CREATE INDEX IF NOT EXISTS "GameServerInvite_expiresAt_idx" ON "GameServerInvite" ("expiresAt");
CREATE UNIQUE INDEX IF NOT EXISTS "GameServerInvite_serverId_email_pending_key"
ON "GameServerInvite" ("serverId", LOWER("email"))
WHERE "acceptedAt" IS NULL;

DROP TRIGGER IF EXISTS "GameServerInvite_set_updatedAt" ON "GameServerInvite";
CREATE TRIGGER "GameServerInvite_set_updatedAt"
BEFORE UPDATE ON "GameServerInvite"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
