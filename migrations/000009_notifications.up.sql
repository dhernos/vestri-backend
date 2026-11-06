CREATE TABLE "NotificationSettings" (
  "userId" TEXT PRIMARY KEY REFERENCES "User"("id") ON DELETE CASCADE,
  "events" JSONB NOT NULL DEFAULT '{"server_created":true,"server_deleted":true,"worker_unhealthy":true,"server_down":true}',
  "emailEnabled" BOOLEAN NOT NULL DEFAULT FALSE,
  "webhookEnabled" BOOLEAN NOT NULL DEFAULT FALSE,
  "webhookUrl" TEXT NOT NULL DEFAULT '',
  "locale" TEXT NOT NULL DEFAULT 'en'
);

CREATE TABLE "Notification" (
  "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
  "kind" TEXT NOT NULL,
  "nodeId" TEXT NOT NULL,
  "nodeName" TEXT NOT NULL,
  "serverId" TEXT NOT NULL DEFAULT '',
  "serverName" TEXT NOT NULL DEFAULT '',
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "readAt" TIMESTAMPTZ,
  "emailPending" BOOLEAN NOT NULL DEFAULT FALSE,
  "webhookPending" BOOLEAN NOT NULL DEFAULT FALSE,
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "nextAttemptAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "deliveryFailed" BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX "Notification_user_created_idx" ON "Notification" ("userId", "createdAt" DESC, "id" DESC);
CREATE INDEX "Notification_delivery_idx" ON "Notification" ("nextAttemptAt") WHERE ("emailPending" OR "webhookPending") AND NOT "deliveryFailed";

CREATE TABLE "NotificationHealth" (
  "kind" TEXT NOT NULL,
  "resourceId" TEXT NOT NULL,
  "nodeId" TEXT NOT NULL REFERENCES "WorkerNode"("id") ON DELETE CASCADE,
  "serverId" TEXT REFERENCES "GameServer"("id") ON DELETE CASCADE,
  "since" TIMESTAMPTZ,
  "sent" BOOLEAN NOT NULL DEFAULT FALSE,
  "wasHealthy" BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY ("kind", "resourceId")
);

CREATE FUNCTION vestri_notify(event_kind TEXT, node_id TEXT, node_name TEXT, server_id TEXT DEFAULT '', server_name TEXT DEFAULT '', creator_id TEXT DEFAULT '') RETURNS VOID AS $$
BEGIN
  INSERT INTO "Notification" ("userId", "kind", "nodeId", "nodeName", "serverId", "serverName", "emailPending", "webhookPending")
  SELECT recipients.id, event_kind, node_id, node_name, server_id, server_name,
         COALESCE(settings."emailEnabled", FALSE), COALESCE(settings."webhookEnabled", FALSE)
  FROM (
    SELECT "ownerUserId" AS id FROM "WorkerNode" WHERE "id" = node_id
    UNION
    SELECT "userId" FROM "WorkerNodeGuest" WHERE "nodeId" = node_id AND server_id = ''
    UNION
    SELECT "userId" FROM "GameServerGuest" WHERE "serverId" = server_id
    UNION
    SELECT creator_id WHERE creator_id <> '' AND event_kind = 'server_created'
  ) recipients
  LEFT JOIN "NotificationSettings" settings ON settings."userId" = recipients.id
  WHERE COALESCE((settings."events" ->> event_kind)::boolean, TRUE);
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION vestri_notify_server_lifecycle() RETURNS TRIGGER AS $$
DECLARE node_name TEXT;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT "name" INTO node_name FROM "WorkerNode" WHERE "id" = NEW."nodeId";
    PERFORM vestri_notify('server_created', NEW."nodeId", node_name, NEW."id", NEW."name", NEW."createdByUserId");
    RETURN NEW;
  END IF;
  SELECT "name" INTO node_name FROM "WorkerNode" WHERE "id" = OLD."nodeId";
  IF node_name IS NOT NULL THEN
    PERFORM vestri_notify('server_deleted', OLD."nodeId", node_name, OLD."id", OLD."name");
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "GameServer_notification_insert" AFTER INSERT ON "GameServer" FOR EACH ROW EXECUTE FUNCTION vestri_notify_server_lifecycle();
CREATE TRIGGER "GameServer_notification_delete" BEFORE DELETE ON "GameServer" FOR EACH ROW EXECUTE FUNCTION vestri_notify_server_lifecycle();

CREATE FUNCTION vestri_notify_node_deleted() RETURNS TRIGGER AS $$
DECLARE game_server RECORD;
BEGIN
  FOR game_server IN SELECT "id", "name" FROM "GameServer" WHERE "nodeId" = OLD."id" LOOP
    PERFORM vestri_notify('server_deleted', OLD."id", OLD."name", game_server."id", game_server."name");
  END LOOP;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "WorkerNode_notification_delete" BEFORE DELETE ON "WorkerNode" FOR EACH ROW EXECUTE FUNCTION vestri_notify_node_deleted();