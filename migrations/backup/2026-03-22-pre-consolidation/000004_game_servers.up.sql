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

DROP TRIGGER IF EXISTS "GameServer_set_updatedAt" ON "GameServer";
CREATE TRIGGER "GameServer_set_updatedAt"
BEFORE UPDATE ON "GameServer"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
