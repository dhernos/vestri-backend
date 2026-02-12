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

DROP TRIGGER IF EXISTS "WorkerNode_set_updatedAt" ON "WorkerNode";
CREATE TRIGGER "WorkerNode_set_updatedAt"
BEFORE UPDATE ON "WorkerNode"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS "WorkerNodeGuest" (
  "id" TEXT PRIMARY KEY,
  "nodeId" TEXT NOT NULL REFERENCES "WorkerNode"("id") ON DELETE CASCADE,
  "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "permission" TEXT NOT NULL DEFAULT 'viewer',
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT "WorkerNodeGuest_nodeId_userId_key" UNIQUE ("nodeId", "userId")
);

CREATE INDEX IF NOT EXISTS "WorkerNodeGuest_userId_idx" ON "WorkerNodeGuest" ("userId");
CREATE INDEX IF NOT EXISTS "WorkerNodeGuest_nodeId_idx" ON "WorkerNodeGuest" ("nodeId");
