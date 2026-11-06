ALTER TABLE "Notification" ADD COLUMN "actorName" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Notification" ADD COLUMN "role" TEXT NOT NULL DEFAULT '';
ALTER TABLE "NotificationHealth" ADD COLUMN "reportedUserIds" TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE "NotificationSettings" ALTER COLUMN "events" SET DEFAULT '{"server_created":true,"server_deleted":true,"worker_unhealthy":true,"server_down":true,"worker_recovered":true,"server_recovered":true,"server_invited":true,"server_access_granted":true,"server_role_changed":true,"server_access_removed":true}';
UPDATE "NotificationSettings" SET "events" = '{"worker_recovered":true,"server_recovered":true,"server_invited":true,"server_access_granted":true,"server_role_changed":true,"server_access_removed":true}'::jsonb || "events";

CREATE FUNCTION vestri_notification_lock_user() RETURNS TRIGGER AS $$
BEGIN
  PERFORM 1 FROM "User" WHERE "id" = NEW."userId" FOR UPDATE;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "Notification_lock_user" BEFORE INSERT ON "Notification" FOR EACH ROW EXECUTE FUNCTION vestri_notification_lock_user();

CREATE FUNCTION vestri_notification_prune() RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM "Notification" WHERE "userId" = NEW."userId" AND "id" IN (
    SELECT "id" FROM "Notification" WHERE "userId" = NEW."userId"
    ORDER BY "createdAt" DESC, "id" DESC OFFSET 500
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "Notification_prune" AFTER INSERT ON "Notification" FOR EACH ROW EXECUTE FUNCTION vestri_notification_prune();
DELETE FROM "Notification" WHERE "id" IN (
  SELECT "id" FROM (
    SELECT "id", row_number() OVER (PARTITION BY "userId" ORDER BY "createdAt" DESC, "id" DESC) AS position
    FROM "Notification"
  ) ranked WHERE position > 500
);

CREATE FUNCTION vestri_notification_recipients(node_id TEXT, server_id TEXT) RETURNS TABLE(id TEXT) AS $$
  SELECT "ownerUserId" FROM "WorkerNode" WHERE "id" = node_id
  UNION SELECT "userId" FROM "WorkerNodeGuest" WHERE "nodeId" = node_id AND server_id = ''
  UNION SELECT "userId" FROM "GameServerGuest" WHERE "serverId" = server_id;
$$ LANGUAGE sql;

CREATE FUNCTION vestri_notify_user(event_kind TEXT, recipient_id TEXT, node_id TEXT, node_name TEXT, server_id TEXT, server_name TEXT, actor_name TEXT DEFAULT '', access_role TEXT DEFAULT '') RETURNS VOID AS $$
BEGIN
  INSERT INTO "Notification" ("userId", "kind", "nodeId", "nodeName", "serverId", "serverName", "actorName", "role", "emailPending", "webhookPending")
  SELECT recipient."id", event_kind, node_id, node_name, server_id, server_name, actor_name, access_role,
    COALESCE(settings."emailEnabled", FALSE) AND COALESCE((settings."events" ->> event_kind)::boolean, TRUE),
    COALESCE(settings."webhookEnabled", FALSE) AND COALESCE((settings."events" ->> event_kind)::boolean, TRUE)
  FROM "User" recipient LEFT JOIN "NotificationSettings" settings ON settings."userId" = recipient."id"
  WHERE recipient."id" = recipient_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION vestri_notify(event_kind TEXT, node_id TEXT, node_name TEXT, server_id TEXT DEFAULT '', server_name TEXT DEFAULT '', creator_id TEXT DEFAULT '') RETURNS VOID AS $$
DECLARE recipient RECORD;
BEGIN
  FOR recipient IN
    SELECT id FROM vestri_notification_recipients(node_id, server_id)
    UNION SELECT creator_id WHERE creator_id <> '' AND event_kind = 'server_created'
    ORDER BY id
  LOOP
    PERFORM vestri_notify_user(event_kind, recipient.id, node_id, node_name, server_id, server_name);
  END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION vestri_notify_health(event_kind TEXT, node_id TEXT, node_name TEXT, server_id TEXT, server_name TEXT) RETURNS VOID AS $$
DECLARE recipient RECORD; reported TEXT[] := '{}';
BEGIN
  FOR recipient IN SELECT id FROM vestri_notification_recipients(node_id, server_id) ORDER BY id LOOP
    PERFORM vestri_notify_user(event_kind, recipient.id, node_id, node_name, server_id, server_name);
    reported := array_append(reported, recipient.id);
  END LOOP;
  UPDATE "NotificationHealth" SET "reportedUserIds" = reported
  WHERE "kind" = event_kind AND "resourceId" = CASE WHEN server_id = '' THEN node_id ELSE server_id END;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION vestri_notify_recovery(event_kind TEXT, node_id TEXT, node_name TEXT, server_id TEXT, server_name TEXT) RETURNS VOID AS $$
DECLARE recipient RECORD; recovery_kind TEXT;
BEGIN
  recovery_kind := CASE event_kind WHEN 'server_down' THEN 'server_recovered' WHEN 'worker_unhealthy' THEN 'worker_recovered' END;
  IF recovery_kind IS NULL THEN RETURN; END IF;
  FOR recipient IN
    SELECT id FROM vestri_notification_recipients(node_id, server_id)
    WHERE id = ANY(COALESCE((SELECT "reportedUserIds" FROM "NotificationHealth"
      WHERE "kind" = event_kind AND "resourceId" = CASE WHEN server_id = '' THEN node_id ELSE server_id END), '{}'::text[]))
    ORDER BY id
  LOOP
    PERFORM vestri_notify_user(recovery_kind, recipient.id, node_id, node_name, server_id, server_name);
  END LOOP;
  UPDATE "NotificationHealth" SET "reportedUserIds" = '{}'
  WHERE "kind" = event_kind AND "resourceId" = CASE WHEN server_id = '' THEN node_id ELSE server_id END;
END;
$$ LANGUAGE plpgsql;

UPDATE "NotificationHealth" health SET "reportedUserIds" = ARRAY(
  SELECT DISTINCT notification."userId" FROM "Notification" notification
  WHERE notification."kind" = health."kind" AND notification."createdAt" >= health."since"
    AND notification."nodeId" = health."nodeId" AND notification."serverId" = COALESCE(health."serverId", '')
) WHERE health."sent";

CREATE FUNCTION vestri_notify_server_membership() RETURNS TRIGGER AS $$
DECLARE resource RECORD; recipient_id TEXT; server_id TEXT; event_kind TEXT; access_role TEXT; actor_name TEXT;
BEGIN
  IF TG_OP = 'DELETE' THEN
    recipient_id := OLD."userId"; server_id := OLD."serverId"; access_role := OLD."permission";
    event_kind := 'server_access_removed';
  ELSE
    IF TG_OP = 'UPDATE' AND NEW."permission" = OLD."permission" THEN RETURN NEW; END IF;
    recipient_id := NEW."userId"; server_id := NEW."serverId"; access_role := NEW."permission";
    event_kind := CASE WHEN TG_OP = 'INSERT' THEN 'server_access_granted' ELSE 'server_role_changed' END;
  END IF;
  SELECT s."name" AS server_name, n."id" AS node_id, n."name" AS node_name INTO resource
  FROM "GameServer" s JOIN "WorkerNode" n ON n."id" = s."nodeId" WHERE s."id" = server_id;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT COALESCE(NULLIF("name", ''), "email") INTO actor_name FROM "User"
  WHERE "id" = current_setting('vestri.notification_actor', TRUE);
  PERFORM vestri_notify_user(event_kind, recipient_id, resource.node_id, resource.node_name, server_id, resource.server_name, COALESCE(actor_name, 'System'), access_role);
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "GameServerGuest_notification" AFTER INSERT OR UPDATE OR DELETE ON "GameServerGuest" FOR EACH ROW EXECUTE FUNCTION vestri_notify_server_membership();

CREATE FUNCTION vestri_notify_server_invitation() RETURNS TRIGGER AS $$
DECLARE resource RECORD; recipient RECORD; actor_name TEXT;
BEGIN
  IF NEW."acceptedAt" IS NOT NULL OR NEW."expiresAt" <= NOW() THEN RETURN NEW; END IF;
  IF TG_OP = 'UPDATE' AND NEW."permission" = OLD."permission" AND NEW."expiresAt" = OLD."expiresAt" THEN RETURN NEW; END IF;
  SELECT s."name" AS server_name, n."id" AS node_id, n."name" AS node_name INTO resource
  FROM "GameServer" s JOIN "WorkerNode" n ON n."id" = s."nodeId" WHERE s."id" = NEW."serverId";
  SELECT COALESCE(NULLIF("name", ''), "email") INTO actor_name FROM "User" WHERE "id" = NEW."inviterUserId";
  FOR recipient IN SELECT "id" FROM "User" WHERE LOWER("email") = LOWER(NEW."email") ORDER BY "id" LOOP
    PERFORM vestri_notify_user('server_invited', recipient."id", resource.node_id, resource.node_name, NEW."serverId", resource.server_name, COALESCE(actor_name, 'System'), NEW."permission");
  END LOOP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER "GameServerInvite_notification" AFTER INSERT OR UPDATE ON "GameServerInvite" FOR EACH ROW EXECUTE FUNCTION vestri_notify_server_invitation();