DROP TRIGGER "GameServerInvite_notification" ON "GameServerInvite";
DROP FUNCTION vestri_notify_server_invitation();
DROP TRIGGER "GameServerGuest_notification" ON "GameServerGuest";
DROP FUNCTION vestri_notify_server_membership();
DROP FUNCTION vestri_notify_recovery(TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION vestri_notify_health(TEXT, TEXT, TEXT, TEXT, TEXT);
CREATE OR REPLACE FUNCTION vestri_notify(event_kind TEXT, node_id TEXT, node_name TEXT, server_id TEXT DEFAULT '', server_name TEXT DEFAULT '', creator_id TEXT DEFAULT '') RETURNS VOID AS $$
BEGIN
  INSERT INTO "Notification" ("userId", "kind", "nodeId", "nodeName", "serverId", "serverName", "emailPending", "webhookPending")
  SELECT recipients.id, event_kind, node_id, node_name, server_id, server_name,
    COALESCE(settings."emailEnabled", FALSE) AND COALESCE((settings."events" ->> event_kind)::boolean, TRUE),
    COALESCE(settings."webhookEnabled", FALSE) AND COALESCE((settings."events" ->> event_kind)::boolean, TRUE)
  FROM (
    SELECT "ownerUserId" AS id FROM "WorkerNode" WHERE "id" = node_id
    UNION SELECT "userId" FROM "WorkerNodeGuest" WHERE "nodeId" = node_id AND server_id = ''
    UNION SELECT "userId" FROM "GameServerGuest" WHERE "serverId" = server_id
    UNION SELECT creator_id WHERE creator_id <> '' AND event_kind = 'server_created'
  ) recipients LEFT JOIN "NotificationSettings" settings ON settings."userId" = recipients.id;
END;
$$ LANGUAGE plpgsql;
DROP FUNCTION vestri_notify_user(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION vestri_notification_recipients(TEXT, TEXT);
DROP TRIGGER "Notification_prune" ON "Notification";
DROP FUNCTION vestri_notification_prune();
DROP TRIGGER "Notification_lock_user" ON "Notification";
DROP FUNCTION vestri_notification_lock_user();
ALTER TABLE "NotificationHealth" DROP COLUMN "reportedUserIds";
ALTER TABLE "Notification" DROP COLUMN "actorName", DROP COLUMN "role";
ALTER TABLE "NotificationSettings" ALTER COLUMN "events" SET DEFAULT '{"server_created":true,"server_deleted":true,"worker_unhealthy":true,"server_down":true}';
UPDATE "NotificationSettings" SET "events" = "events" - ARRAY['worker_recovered','server_recovered','server_invited','server_access_granted','server_role_changed','server_access_removed'];