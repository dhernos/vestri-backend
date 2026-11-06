CREATE TABLE "MinecraftResource" (
  "id" TEXT PRIMARY KEY,
  "nodeId" TEXT NOT NULL REFERENCES "WorkerNode"("id") ON DELETE CASCADE,
  "kind" TEXT NOT NULL CHECK ("kind" IN ('bases', 'worlds', 'plugin-packs', 'templates')),
  "name" TEXT NOT NULL CHECK (length("name") BETWEEN 1 AND 64),
  "spec" JSONB NOT NULL DEFAULT '{}',
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE ("nodeId", "kind", "name")
);
CREATE INDEX "MinecraftResource_nodeId_idx" ON "MinecraftResource" ("nodeId");

CREATE TABLE "MinecraftAPIKey" (
  "id" TEXT PRIMARY KEY,
  "nodeId" TEXT NOT NULL REFERENCES "WorkerNode"("id") ON DELETE CASCADE,
  "templateId" TEXT NOT NULL REFERENCES "MinecraftResource"("id") ON DELETE CASCADE,
  "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "name" TEXT NOT NULL,
  "digest" TEXT NOT NULL UNIQUE,
  "expiresAt" TIMESTAMPTZ NOT NULL,
  "revokedAt" TIMESTAMPTZ,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX "MinecraftAPIKey_nodeId_idx" ON "MinecraftAPIKey" ("nodeId");

CREATE TABLE "MinecraftInstance" (
  "serverId" TEXT PRIMARY KEY REFERENCES "GameServer"("id") ON DELETE CASCADE,
  "nodeId" TEXT NOT NULL REFERENCES "WorkerNode"("id") ON DELETE CASCADE,
  "templateId" TEXT NOT NULL REFERENCES "MinecraftResource"("id") ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
  "keyId" TEXT REFERENCES "MinecraftAPIKey"("id") ON DELETE SET NULL,
  "requestId" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE ("nodeId", "requestId")
);
CREATE INDEX "MinecraftInstance_templateId_idx" ON "MinecraftInstance" ("templateId");