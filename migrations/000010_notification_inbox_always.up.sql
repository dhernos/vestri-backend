CREATE OR REPLACE FUNCTION vestri_notify(event_kind TEXT, node_id TEXT, node_name TEXT, server_id TEXT DEFAULT '', server_name TEXT DEFAULT '', creator_id TEXT DEFAULT '') RETURNS VOID AS $$
BEGIN
  INSERT INTO "Notification" ("userId", "kind", "nodeId", "nodeName", "serverId", "serverName", "emailPending", "webhookPending")
  SELECT recipients.id, event_kind, node_id, node_name, server_id, server_name,
         COALESCE(settings."emailEnabled", FALSE) AND COALESCE((settings."events" ->> event_kind)::boolean, TRUE),
         COALESCE(settings."webhookEnabled", FALSE) AND COALESCE((settings."events" ->> event_kind)::boolean, TRUE)
  FROM (
    SELECT "ownerUserId" AS id FROM "WorkerNode" WHERE "id" = node_id
    UNION
    SELECT "userId" FROM "WorkerNodeGuest" WHERE "nodeId" = node_id AND server_id = ''
    UNION
    SELECT "userId" FROM "GameServerGuest" WHERE "serverId" = server_id
    UNION
    SELECT creator_id WHERE creator_id <> '' AND event_kind = 'server_created'
  ) recipients
  LEFT JOIN "NotificationSettings" settings ON settings."userId" = recipients.id;
END;
$$ LANGUAGE plpgsql;
