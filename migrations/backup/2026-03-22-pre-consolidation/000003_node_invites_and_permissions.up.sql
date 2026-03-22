DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'WorkerNodeGuest_permission_check'
  ) THEN
    ALTER TABLE "WorkerNodeGuest"
      ADD CONSTRAINT "WorkerNodeGuest_permission_check"
      CHECK ("permission" IN ('admin', 'operator', 'viewer'));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS "WorkerNodeInvite" (
  "id" TEXT PRIMARY KEY,
  "nodeId" TEXT NOT NULL REFERENCES "WorkerNode"("id") ON DELETE CASCADE,
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
    WHERE conname = 'WorkerNodeInvite_permission_check'
  ) THEN
    ALTER TABLE "WorkerNodeInvite"
      ADD CONSTRAINT "WorkerNodeInvite_permission_check"
      CHECK ("permission" IN ('admin', 'operator', 'viewer'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS "WorkerNodeInvite_nodeId_idx" ON "WorkerNodeInvite" ("nodeId");
CREATE INDEX IF NOT EXISTS "WorkerNodeInvite_email_idx" ON "WorkerNodeInvite" (LOWER("email"));
CREATE INDEX IF NOT EXISTS "WorkerNodeInvite_expiresAt_idx" ON "WorkerNodeInvite" ("expiresAt");
CREATE UNIQUE INDEX IF NOT EXISTS "WorkerNodeInvite_nodeId_email_pending_key"
ON "WorkerNodeInvite" ("nodeId", LOWER("email"))
WHERE "acceptedAt" IS NULL;

DROP TRIGGER IF EXISTS "WorkerNodeInvite_set_updatedAt" ON "WorkerNodeInvite";
CREATE TRIGGER "WorkerNodeInvite_set_updatedAt"
BEFORE UPDATE ON "WorkerNodeInvite"
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
