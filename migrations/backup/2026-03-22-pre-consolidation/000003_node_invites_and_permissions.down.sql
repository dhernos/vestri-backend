DROP TRIGGER IF EXISTS "WorkerNodeInvite_set_updatedAt" ON "WorkerNodeInvite";
DROP TABLE IF EXISTS "WorkerNodeInvite";

ALTER TABLE "WorkerNodeGuest"
DROP CONSTRAINT IF EXISTS "WorkerNodeGuest_permission_check";
