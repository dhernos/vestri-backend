CREATE TABLE IF NOT EXISTS "User" (
  "id" TEXT PRIMARY KEY,
  "name" TEXT,
  "email" TEXT NOT NULL UNIQUE,
  "emailVerified" TIMESTAMPTZ,
  "password" TEXT,
  "image" TEXT,
  "theme" TEXT NOT NULL DEFAULT 'system',
  "twoFactorSecret" TEXT,
  "isTwoFactorEnabled" BOOLEAN NOT NULL DEFAULT FALSE,
  "twoFactorMethod" TEXT,
  "twoFactorEmailCode" TEXT,
  "twoFactorCodeExpires" TIMESTAMPTZ,
  "passwordResetToken" TEXT,
  "passwordResetExpires" TIMESTAMPTZ,
  "role" TEXT NOT NULL DEFAULT 'USER',
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "VerificationToken" (
  "id" TEXT PRIMARY KEY,
  "token" TEXT NOT NULL,
  "expires" TIMESTAMPTZ NOT NULL,
  "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "VerificationToken_userId_idx" ON "VerificationToken" ("userId");
CREATE INDEX IF NOT EXISTS "VerificationToken_userId_token_idx" ON "VerificationToken" ("userId", "token");

CREATE TABLE IF NOT EXISTS "OAuthAccount" (
  "id" TEXT PRIMARY KEY,
  "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "provider" TEXT NOT NULL,
  "providerAccountId" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT "OAuthAccount_provider_providerAccountId_key" UNIQUE ("provider", "providerAccountId")
);

CREATE INDEX IF NOT EXISTS "OAuthAccount_userId_idx" ON "OAuthAccount" ("userId");

CREATE TABLE IF NOT EXISTS "PasskeyCredential" (
  "id" TEXT PRIMARY KEY,
  "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "credentialId" BYTEA NOT NULL,
  "publicKey" BYTEA NOT NULL,
  "attestationType" TEXT NOT NULL,
  "aaguid" BYTEA NOT NULL,
  "transports" TEXT,
  "signCount" BIGINT NOT NULL DEFAULT 0,
  "label" TEXT,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT "PasskeyCredential_credentialId_key" UNIQUE ("credentialId")
);

CREATE INDEX IF NOT EXISTS "PasskeyCredential_userId_idx" ON "PasskeyCredential" ("userId");

CREATE TABLE IF NOT EXISTS "WorkerNode" (
  "id" TEXT PRIMARY KEY,
  "slug" TEXT NOT NULL UNIQUE,
  "name" TEXT NOT NULL,
  "baseUrl" TEXT NOT NULL,
  "apiKey" TEXT NOT NULL,
  "ownerUserId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "WorkerNode_ownerUserId_idx" ON "WorkerNode" ("ownerUserId");
CREATE INDEX IF NOT EXISTS "WorkerNode_ownerUserId_slug_idx" ON "WorkerNode" ("ownerUserId", "slug");

CREATE TABLE IF NOT EXISTS "WorkerNodeGuest" (
  "id" TEXT PRIMARY KEY,
  "nodeId" TEXT NOT NULL REFERENCES "WorkerNode"("id") ON DELETE CASCADE,
  "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "permission" TEXT NOT NULL DEFAULT 'viewer',
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT "WorkerNodeGuest_nodeId_userId_key" UNIQUE ("nodeId", "userId"),
  CONSTRAINT "WorkerNodeGuest_permission_check" CHECK ("permission" IN ('admin', 'operator', 'viewer'))
);

CREATE INDEX IF NOT EXISTS "WorkerNodeGuest_userId_idx" ON "WorkerNodeGuest" ("userId");
CREATE INDEX IF NOT EXISTS "WorkerNodeGuest_nodeId_idx" ON "WorkerNodeGuest" ("nodeId");

CREATE TABLE IF NOT EXISTS "WorkerNodeInvite" (
  "id" TEXT PRIMARY KEY,
  "nodeId" TEXT NOT NULL REFERENCES "WorkerNode"("id") ON DELETE CASCADE,
  "inviterUserId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "email" TEXT NOT NULL,
  "permission" TEXT NOT NULL,
  "expiresAt" TIMESTAMPTZ NOT NULL,
  "acceptedAt" TIMESTAMPTZ,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT "WorkerNodeInvite_permission_check" CHECK ("permission" IN ('admin', 'operator', 'viewer'))
);

ALTER TABLE "WorkerNodeInvite" DROP COLUMN IF EXISTS "token";

CREATE INDEX IF NOT EXISTS "WorkerNodeInvite_nodeId_idx" ON "WorkerNodeInvite" ("nodeId");
CREATE INDEX IF NOT EXISTS "WorkerNodeInvite_email_idx" ON "WorkerNodeInvite" (LOWER("email"));
CREATE INDEX IF NOT EXISTS "WorkerNodeInvite_expiresAt_idx" ON "WorkerNodeInvite" ("expiresAt");
CREATE UNIQUE INDEX IF NOT EXISTS "WorkerNodeInvite_nodeId_email_pending_key"
ON "WorkerNodeInvite" ("nodeId", LOWER("email"))
WHERE "acceptedAt" IS NULL;

CREATE TABLE IF NOT EXISTS "GameServer" (
  "id" TEXT PRIMARY KEY,
  "nodeId" TEXT NOT NULL REFERENCES "WorkerNode"("id") ON DELETE CASCADE,
  "slug" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "templateId" TEXT NOT NULL,
  "templateVersion" TEXT NOT NULL DEFAULT '1',
  "stackName" TEXT NOT NULL,
  "rootPath" TEXT NOT NULL,
  "composePath" TEXT NOT NULL,
  "metadata" JSONB NOT NULL DEFAULT '{}'::jsonb,
  "createdByUserId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE RESTRICT,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT "GameServer_nodeId_slug_key" UNIQUE ("nodeId", "slug"),
  CONSTRAINT "GameServer_nodeId_stackName_key" UNIQUE ("nodeId", "stackName")
);

CREATE INDEX IF NOT EXISTS "GameServer_nodeId_idx" ON "GameServer" ("nodeId");
CREATE INDEX IF NOT EXISTS "GameServer_templateId_idx" ON "GameServer" ("templateId");

CREATE TABLE IF NOT EXISTS "GameServerGuest" (
  "id" TEXT PRIMARY KEY,
  "serverId" TEXT NOT NULL REFERENCES "GameServer"("id") ON DELETE CASCADE,
  "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "permission" TEXT NOT NULL DEFAULT 'viewer',
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT "GameServerGuest_serverId_userId_key" UNIQUE ("serverId", "userId"),
  CONSTRAINT "GameServerGuest_permission_check" CHECK ("permission" IN ('admin', 'operator', 'viewer'))
);

CREATE INDEX IF NOT EXISTS "GameServerGuest_userId_idx" ON "GameServerGuest" ("userId");
CREATE INDEX IF NOT EXISTS "GameServerGuest_serverId_idx" ON "GameServerGuest" ("serverId");

CREATE TABLE IF NOT EXISTS "GameServerInvite" (
  "id" TEXT PRIMARY KEY,
  "serverId" TEXT NOT NULL REFERENCES "GameServer"("id") ON DELETE CASCADE,
  "inviterUserId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "email" TEXT NOT NULL,
  "permission" TEXT NOT NULL,
  "expiresAt" TIMESTAMPTZ NOT NULL,
  "acceptedAt" TIMESTAMPTZ,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT "GameServerInvite_permission_check" CHECK ("permission" IN ('admin', 'operator', 'viewer'))
);

ALTER TABLE "GameServerInvite" DROP COLUMN IF EXISTS "token";

CREATE INDEX IF NOT EXISTS "GameServerInvite_serverId_idx" ON "GameServerInvite" ("serverId");
CREATE INDEX IF NOT EXISTS "GameServerInvite_email_idx" ON "GameServerInvite" (LOWER("email"));
CREATE INDEX IF NOT EXISTS "GameServerInvite_expiresAt_idx" ON "GameServerInvite" ("expiresAt");
CREATE UNIQUE INDEX IF NOT EXISTS "GameServerInvite_serverId_email_pending_key"
ON "GameServerInvite" ("serverId", LOWER("email"))
WHERE "acceptedAt" IS NULL;

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW."updatedAt" = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS "User_set_updatedAt" ON "User";
CREATE TRIGGER "User_set_updatedAt"
BEFORE UPDATE ON "User"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS "OAuthAccount_set_updatedAt" ON "OAuthAccount";
CREATE TRIGGER "OAuthAccount_set_updatedAt"
BEFORE UPDATE ON "OAuthAccount"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS "PasskeyCredential_set_updatedAt" ON "PasskeyCredential";
CREATE TRIGGER "PasskeyCredential_set_updatedAt"
BEFORE UPDATE ON "PasskeyCredential"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS "WorkerNode_set_updatedAt" ON "WorkerNode";
CREATE TRIGGER "WorkerNode_set_updatedAt"
BEFORE UPDATE ON "WorkerNode"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS "WorkerNodeInvite_set_updatedAt" ON "WorkerNodeInvite";
CREATE TRIGGER "WorkerNodeInvite_set_updatedAt"
BEFORE UPDATE ON "WorkerNodeInvite"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS "GameServer_set_updatedAt" ON "GameServer";
CREATE TRIGGER "GameServer_set_updatedAt"
BEFORE UPDATE ON "GameServer"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS "GameServerInvite_set_updatedAt" ON "GameServerInvite";
CREATE TRIGGER "GameServerInvite_set_updatedAt"
BEFORE UPDATE ON "GameServerInvite"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
