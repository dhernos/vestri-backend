# Vestri Backend

Backend documentation lives in the main repository:

- https://github.com/dhernos/vestri

## Notifications

Migrations `000009_notifications`, `000010_notification_inbox_always`, and
`000011_notification_release` add the persistent inbox, per-user preferences,
health tracking, membership notices, recovery pairing, retention and delivery
queue. They run automatically at backend startup
unless `AUTO_MIGRATE` is disabled. Apply the migration manually before starting
the new backend when automatic migrations are disabled. No worker update is
required.

Settings support server creation/deletion, unhealthy/down and recovered
workers/servers, invitations, access grants, role changes and access removal.
Events are enabled by default; email
and webhook delivery are opt-in. Server events go to the node owner and explicit
server guests, following existing server access rules. Creation also notifies
the creator. Worker alerts go to the node owner and node guests.

Membership events go only to the affected user, not to the actor or all server
members. `server_invited` matches the invite email to an existing account;
`server_access_granted` is generated on membership creation (including invite
acceptance), `server_role_changed` only when the permission actually changes,
and `server_access_removed` on removal. These notices include `actorName`,
`serverName` and `role` (the previous role for removal). HTTP mutations use the
authenticated actor; acceptance attributes the grant to the inviter. Database
mutations without actor context are explicitly attributed to `System`.
Membership notices are persisted in the same transaction as the mutation and
address the affected user directly, so removal still reaches their inbox and
opt-in delivery queue after access is gone. Cascading server deletion uses the
existing server-deleted notification rather than a misleading membership notice.
Invitations for addresses without an account retain the existing invitation
email workflow; transactional invitation emails are separate from opt-in
notification emails.

Every kind always goes to the inbox even when its event switch is off. Event
switches control only opt-in email/webhook delivery and are checked again at
delivery time. Existing settings and older payloads default missing new switches
to enabled without resetting explicitly disabled switches. English and German
email and webhook text cover all supported kinds.

The backend polls workers every 15 seconds, independently of open browsers. A
worker is healthy only when both `/health` fields `status` and
`external_service` are `OK`. Failures must persist for more than 60 seconds.
Only one down notification is generated per outage. Explicitly healthy status
after a reported outage emits `worker_recovered` or `server_recovered` once and
resets the timer. Unknown status preserves an already reported outage and never
emits recovery; it resets an unreported failure timer. First-ever healthy status
and unreported short failures never emit recovery. Recovery goes only to users
who received the paired outage and still have resource access, not newly added
members. Pairing survives inbox deletion and backend restarts. Migration backfill
uses retained outage notices; recipients whose old notices were already deleted
cannot be reconstructed. PostgreSQL advisory locks
coordinate multiple backend processes. Unknown server status or an unreachable
worker does not generate additional server-down alerts. A server must have been
observed running before its first down alert. Intentional stops also qualify.

Email uses the existing `EMAIL_SERVER_*` and `EMAIL_FROM` configuration and the
user's current verified account address. Webhooks require a public HTTPS URL
on port 443. Private, loopback and link-local destinations, redirects and proxy
environment settings are not allowed. The URL is encrypted using the existing
`NODE_API_KEY_ENCRYPTION_KEY`. Event switches are checked again before delivery.

Webhook POSTs contain `id`, `kind`, node/server identifiers and names,
`actorName`, `role`, `createdAt`, and localized `content`/`text`. Discord mentions are disabled. Headers
`X-Vestri-Event` and `X-Vestri-Notification-ID` identify the event. Delivery is
at least once; receivers should deduplicate using the notification ID. Failed
channels are retried up to five times with exponential backoff; successful
channels are not intentionally retried. Exhausted delivery appears in the inbox.

Inbox endpoints are session-protected: `GET /api/notifications` (50 events per
page; `before` and `beforeId` cursors), `GET/POST /api/notifications/settings`,
`POST /api/notifications/read`, and
`POST /api/notifications/{notificationId}/read`. New deletion APIs are
`DELETE /api/notifications/{notificationId}` (one item) and
`DELETE /api/notifications` (clear all). Both return HTTP 200 `{"ok":true}` and
only affect the authenticated user's inbox. Missing or foreign IDs are
idempotent no-ops, without revealing another user's notification existence.
Existing GET and POST routes remain compatible.

`PATCH /api/nodes/{nodeRef}/servers/{serverRef}/guests/{guestUserId}` accepts
`{"permission":"admin"}`, `operator`, or `viewer` and returns HTTP 200
`{"ok":true}`. Only server owners/admins can update roles; owner access cannot
be changed, missing guests return 404, and unchanged roles do not create notices.

### Retention Limits

The inbox has a hard limit of **500 notifications per user**. Migration prunes
existing excess records; a per-user row lock and insert trigger enforce the
limit transactionally even across concurrent backend processes. Oldest records
are removed first, ordered by `createdAt`, then `id` (retaining descending order).
Read/unread and pending/failed delivery records count equally. Eviction and
explicit deletion also remove queued delivery work; a delivery already in flight
may still finish. Rolling back the migration cannot restore evicted records.

Minecraft/Velocity interactive player event history (`attempts` on the player
and legacy whitelist endpoints) has a hard response limit of **1000 events per
server**, matching the existing plugin journal limit `MAX_ATTEMPTS=1000`.
Oversized legacy journals retain the newest events by `completedAt`, falling
back to `time`, with descending `id` tie-breaking and stable source order for
identical keys. Invalid/missing timestamps sort oldest. The backend does not
rewrite live plugin journals or trim the separate JSONL audit archives; those
files remain owned and retained by the plugin. Player profiles and policies are
not event history and are not trimmed by this limit. No plugin/worker change is
required for the current producer's bounded journal.

### Regression Tests

Run `go test ./...`. Database-backed release regressions are opt-in:
`VESTRI_NOTIFICATION_TEST_DATABASE_URL=<disposable PostgreSQL URL> go test ./internal/server -run TestNotificationRelease -count=1`.
They create an isolated schema, apply and roll back/reapply actual migrations,
exercise concurrent retention, recipient/actor/preferences correctness, recovery
pairing, role authorization and deletion isolation, then drop the test schema.

Velocity plugin data-path and worker HTTP regressions run with
`go test ./internal/server -run TestVelocityPluginData -count=1`.
To include real player GET/POST and dynamic manifest synchronization checks,
set `VESTRI_VELOCITY_TEST_DATABASE_URL` to a disposable PostgreSQL URL. These
checks apply migrations in an isolated schema and drop it after the test.

Velocity dynamic-server plugin setup and console commands:
https://github.com/dhernos/vestri-plugin

## Velocity Plugin Data Directory

The backend writes the dynamic-server manifest and player policy, and reads
the player journal, under `<proxy root>/data/plugins/vestri-dynamic/`, matching
Velocity's official plugin data directory. The plugin owns startup migration;
the backend does not move or delete plugin data.

Path selection uses read-only worker directory listings on each operation:

- A config (`vestri-dynamic-config.json`) or journal (`vestri-players.json`)
  in the official directory selects that directory, even if stale root files
  remain.
- Otherwise, any legacy config, manifest, owned-server registry, journal,
  policy, or `vestri-player-logs` entry directly under `<proxy root>/data/`
  keeps reads and writes there for compatibility with older plugins. An empty
  or manifest-only official directory does not override legacy evidence.
- With no legacy evidence, the official directory is used, including before
  the plugin's first startup. Worker writes create missing parent directories.
- Listing failures abort the operation rather than guessing a write target.

This avoids precreating the official data directory while legacy data still
awaits migration. Manifest synchronization and player management resolve the
directory independently on each operation, so later plugin migration is picked
up without restarting the backend.

## Automatic Paper and Velocity Plugin Installation

Vestri automatically installs the universal Vestri plugin JAR from
https://github.com/dhernos/vestri-plugin/releases/tag/latest into
`<server root>/data/plugins/vestri-dynamic-servers.jar`:

- When creating a Paper server or Velocity proxy.
- When spawning a Paper instance from a saved Minecraft template.
- Before starting existing Paper/Velocity servers through Vestri, including
  saved-request spawn retries and paused-instance wake-up.

The backend discovers the versioned JAR asset from the fixed `latest` tag,
verifies its GitHub SHA256 digest, and requires both Paper and Velocity plugin
descriptors before uploading it to the worker. The stable installed filename
prevents duplicate versioned copies; older `vestri-dynamic-servers-*.jar` files
are removed only after a verified replacement is installed. Other plugins and
plugin configuration files are not changed.

Automatic installation also registers `github:dhernos/vestri-plugin` in the
node-wide tracked plugin manifest at
`.vestri-minecraft/<node ID>/tracked-plugins.json` and stores the JAR in
`.vestri-minecraft/<node ID>/plugins/vestri-dynamic-servers.jar`. It appears in
the existing Velocity plugin staging area's tracked-plugin list. New servers
reuse that staged version without repeatedly downloading from GitHub. Other
tracked entries and staged plugins are preserved, and the entry is registered
only once per node.

Use the tracked plugin's **Update** button to download a newer release into
staging and deploy it to the selected Velocity proxy and its accessible linked
Paper/Purpur servers **only where that plugin is already installed**, using the
existing plugin manager's permissions and compatibility scope. Installation is
identified by an exact tracked JAR filename (the installed filename or its saved
filename history) in each server's `data/plugins` directory. Missing plugins,
missing directories, and unrelated JARs are left alone; directory listing errors
abort the update before any files change. Staging is still updated when no
server currently has the plugin. Retry updates use the same presence check, so
removing a plugin excludes that server from future updates. Manually renamed,
untracked JARs are not recognized. Restart affected servers to load the new JAR. Release
identity includes the asset's SHA256 digest, so replacing the asset under the
mutable `latest` tag is detected even when its filename does not change. Normal
tracked checks retain the existing six-hour interval. There is no background
automatic deployment of new releases.

An installed stable server JAR is left in place on subsequent starts. Existing
untracked installations are copied to staging and adopted on their next
Vestri-managed start without downloading from GitHub; their installed version
is marked `unknown` until explicitly updated, not guessed to be the latest.
Removing a server's JAR reinstalls the staged copy rather than fetching a newer
release. A pending tracked update or missing staged copy must be repaired with
the staging area's update/retry controls before automatic installation can
continue. Vanilla, Fabric, Forge, and other software selections are unchanged.

The backend needs outbound HTTPS access to `api.github.com`, `github.com`, and
`release-assets.githubusercontent.com`. Missing releases, rate limits,
checksum failures, or worker upload errors prevent creation/start when a new
installation is required and return an error instead of starting without the
plugin. Already-tracked staged copies and adoption of existing installations do
not require GitHub availability.

Installation does not enable or configure the console bridge or player-owned
spawning automatically. Configure the plugin's template API keys, bridge
secret/allowlist, and player permissions separately. Redeploy the updated
backend to enable this provisioning behavior; no worker update is required.

Offline installer regressions run with `go test ./internal/server`. To also
verify the current published JAR over HTTPS:

```sh
VESTRI_PLUGIN_RELEASE_TEST=1 go test ./internal/server -run TestLiveVestriPluginRelease -v
```
