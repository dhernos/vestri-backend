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
