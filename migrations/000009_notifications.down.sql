DROP TRIGGER IF EXISTS "WorkerNode_notification_delete" ON "WorkerNode";
DROP TRIGGER IF EXISTS "GameServer_notification_delete" ON "GameServer";
DROP TRIGGER IF EXISTS "GameServer_notification_insert" ON "GameServer";
DROP FUNCTION IF EXISTS vestri_notify_node_deleted();
DROP FUNCTION IF EXISTS vestri_notify_server_lifecycle();
DROP FUNCTION IF EXISTS vestri_notify(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP TABLE IF EXISTS "NotificationHealth", "Notification", "NotificationSettings";