# Vestri Backend

Backend documentation lives in the main repository:

- https://github.com/dhernos/vestri

## Minecraft Minigame Templates

Minecraft template `spec` accepts optional `mode` (`""`, `"player"`, or
`"minigames"`) and optional `minigame`. Existing ordinary templates without
either field remain compatible. `minigame` is required only for `minigames`
mode and rejected in other modes. Creation and spawn both validate the spec,
including saved metadata on request-ID retries. No database migration is needed.

Example template spec (use existing base/proxy resource IDs):

```json
{
  "baseId": "<base UUID>",
  "parentId": "<Velocity server ID>",
  "maxInstances": 3,
  "mode": "minigames",
  "minigame": {
    "teams": ["red", "blue"],
    "teamSize": 2,
    "minPlayers": 2,
    "maxPlayers": 4,
    "joinTimeout": "20s",
    "readyServers": 1,
    "lifecycle": {
      "ready": { "trigger": "serverLoad" },
      "onAllJoined": [
        { "command": "team add {team}", "forEach": "team" },
        { "command": "team join {team} {player}", "forEach": "player" }
      ],
      "end": {
        "logPattern": "^MATCH_END$",
        "whenEmpty": true,
        "emptyGrace": "10s",
        "returnPlayersTo": "lobby",
        "deleteServer": true
      }
    }
  }
}
```

- `teams`: 1-100 unique, case-sensitive identifiers matching
  `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`. `returnPlayersTo` uses the same identifier
  rule. The backend does not check Minecraft team or fallback-server existence.
- `teamSize`, `minPlayers`, and `maxPlayers`: integers 1-100, with
  `minPlayers <= maxPlayers <= len(teams) * teamSize`.
- `readyServers`: integer 0 through template `maxInstances` (itself 1-100);
  omitted means 0. `joinTimeout` defaults to `20s`; `emptyGrace` defaults to
  `10s`. Both use Go duration strings and must be between `1s` and `10m`
  inclusive, with whole-millisecond precision. Validated values normalize to
  canonical Go duration strings (`20s`, `1m20s`, `1.5s`, `1.001s`), compatible
  with the Java parser for concatenated ms/s/m/h components; sub-millisecond precision is rejected rather
  than rounded. `returnPlayersTo` defaults to `lobby`.
- `ready.trigger`: required, `serverLoad` or `explicit`. `onAllJoined` is
  an array of at most 100 commands (omitted/null becomes `[]`). Each command is
  1-1024 bytes, nonblank, without a leading slash (including after whitespace)
  or control characters/newlines. `forEach` is empty/omitted, `team`, or `player`.
  Only `{team}`, `{player}`, `{uuid}`, and `{matchId}` placeholders are accepted;
  unmatched braces are rejected. `{team}` requires team or player repetition;
  `{player}` and `{uuid}` require player repetition; `{matchId}` works anywhere.
- `end.logPattern` is optional, at most 512 bytes, and has no CR/LF. It must
  compile with Go's regexp engine; named groups, lookarounds/backreferences,
  ungreedy flags, POSIX classes, octal escapes without leading zero, and
  divergent Unicode/escape forms are rejected for practical Java compatibility.
  This is not a complete Java regex verifier or a Java execution-time bound;
  avoid pathological nested repetition and test patterns in the plugin runtime.
- `end.whenEmpty` is boolean (omitted means false); `end.deleteServer` must
  explicitly be `true`. The backend validates and transports lifecycle rules;
  executing commands, readiness, transfers, end detection, and deletion remains
  the plugin's responsibility.

Before instance startup, the backend writes
`<instance root>/data/plugins/VestriConsoleBridge/minigame.json` containing
`{slug, token, controlUrl, spec, spawnRequestId?}`. Optional `spawnRequestId` is
the validated raw caller request UUID, preserved exactly for private correlation.
`token` is a fresh cryptographically random
64-character lowercase hex credential per instance, replacing any copied config.
`controlUrl` is exactly `http://<velocityBackendHostForSlug(parent.Slug)>:25580`.
The proxy bridge must listen on that port on the shared Velocity Docker network.
Saved-request retries preserve the saved token, spec, and existing correlation;
if `spawnRequestId` is absent, they backfill it from the caller UUID without
rotating the token. Missing/corrupt/wrong-proxy files fail closed; restore the saved file or
delete and respawn the instance. Ordinary spawns/retries remove stale copied
`minigame.json` and do not receive minigame credentials.
All fresh spawns also remove copied `minigame-execution.json` from the same
directory before any fresh token is written. Retries never remove that durable
execution fence from an existing instance.
Fresh minigame spawns always replace copied `server.properties` player limits
with `max-players=spec.minigame.maxPlayers`. Ordinary player limits are unchanged;
saved-request retries do not rewrite server properties.

Proxy synchronization writes top-level `minigames` alongside `servers` in
`vestri-dynamic-servers.json`. `minigames` maps the exact template **name** to
the flattened minigame spec plus `maxInstances`, includes templates with no
instances, and only includes minigame templates for that parent proxy. Server
entries remain keyed by slug with existing `name`, `host`, `port`; minigame
instances additionally include `serverId` and `id` (both the database server ID),
`requestId`, `template` (exact template name), `spec`, and `token` read from their instance
file. `requestId` is the exact persisted `auth.MinecraftInstance.RequestID`,
currently the lowercase SHA-256 hex digest of `key.ID + ":" + request UUID`.
It is not the server slug, server ID, or raw caller request UUID and remains
unchanged. When present in the instance config, `spawnRequestId` is also included
in the private minigame server entry so the proxy can correlate its local caller
UUID before the spawn response arrives. Legacy configs omit this field until
backfilled by a saved-request retry. Neither tokens nor `spawnRequestId` are
added to public spawn responses. Excluded/deleting instances are omitted.
The top-level `maxInstances` value within each minigame entry remains the template
cap, and `readyServers` remains the desired ready-pool count within that cap.
Each private `servers[slug].spec` has the same flattened shape as
`minigames[templateName]`: inline minigame fields plus `maxInstances`, with no
extra `minigame` wrapper, hash, or version. Its minigame fields come from the saved
spawn-time instance `config.Spec`; only `maxInstances` uses the current template
cap. The top-level template entry continues to contain the current template spec.
The proxy can persist `target.spec` in its per-instance ledger and compare raw
specs to drain mismatched ready instances, while active instances retain their
original lifecycle. Ordinary server entries omit `spec`. This is a transport
contract only; the backend does not perform draining or change plugin behavior.

Template creation synchronizes the parent proxy after database persistence,
before returning success, so ready-pool discovery includes brand-new templates
before any spawn. Template deletion synchronizes after database deletion to remove
discovery entries. Both syncs have a separate 30-second timeout and continue if
the original request is canceled. A sync failure returns HTTP 502 with
`committed: true` and the created `resource` or deleted `resourceId`: the database
change is already committed. Created files are retained, with no destructive
rollback. Fix proxy/worker availability and manually retry with session-authenticated
`POST /api/nodes/{nodeRef}/minecraft/proxies/{proxyRef}/sync` (node owner/admin;
proxy ID or slug). This regenerates the manifest and reloads the proxy, returning
HTTP 204 on success; it does not spawn instances or change API keys.
Do not repeat creation or deletion. Until sync succeeds, discovery may
be stale. There is no automatic retry queue.

The plugin's existing `vestri-dynamic-config.json` **`templates` map from names
to template-scoped API keys remains manual user configuration**. Automatic
manifest generation does not mint API keys or modify that config. Configure the
matching exact template names and keys on the proxy, including capitalization
and spaces: a manifest key and server `template` of `Team Game` must map to the
config key `Team Game`, not `team game` or a slug. Deploy a compatible plugin
before using minigame mode; this backend change alone does not add plugin runtime
behavior. Credentials appear only in worker-side instance/proxy files, not
template metadata or instance API responses; authorized file administrators can
still read them. Protect worker access and do not publish these files.

Focused regressions: `go test ./internal/server -run TestMinecraftMinigame -count=1`.
They cover validation/defaults, worker provisioning/retry/cleanup/failures,
exact request-ID and name transport, duration normalization, parent-scoped
manifests, the protected manual sync route, and token-free public instance responses.
Set `VESTRI_VELOCITY_TEST_DATABASE_URL` to a disposable PostgreSQL URL to also run
the isolated-schema discovery regression: brand-new templates with zero instances,
deleted template removal, cancellation-independent post-commit sync, and retained
resources/retry after a proxy reload failure.

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
staging and deploy it to explicitly selected servers from the Velocity proxy and
its accessible linked Paper/Purpur servers **only where that plugin is already installed**, using the
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

Tracked-plugin list responses include `servers: [{id, name, platform, version}]`
and `templates: [{id, name, platform, version}]` alongside `plugins`. Server
choices are only the current Velocity proxy and its accessible linked Paper/Purpur
children with file-management permission, not arbitrary servers on the node.
Platforms are `VELOCITY` or `PAPER` (including Purpur). Each plugin's `targetRefs`
identifies the targets compatible with its resolved latest release.
Template choices are node-wide Paper/Purpur templates, with platform
`PAPER` and software/version resolved from their base when `baseId` is present.
They are response-only metadata, not persisted in the tracking manifest.
The plugin update POST accepts `{ "id": "<tracked plugin ID>", "serverIds":
["<server ID>"], "templateIds": ["<template UUID>"] }`. Both selections are opt-in:
omitted or empty `serverIds` deploys to no servers, and omitted or empty
`templateIds` deploys to no templates. Staging still updates with neither selected.
Nonempty selections are accepted only for updates, with at most 101 distinct
server IDs and 100 distinct template IDs. Server IDs must exactly match the
accessible candidates; template IDs must resolve to compatible templates on the
same node. Empty, duplicate, unknown, or out-of-scope IDs are rejected. The
resolved release must support every selected server and template; incompatible
selections fail with an explicit error before downloads or writes. Release
resolution retains all accessible server compatibility targets, regardless of
deployment selection, and adds selected templates. Only selected targets are
inspected for existing installations; unselected server directories are not listed.

Template selection is a node-library owner/admin operation and is deliberately
not restricted by the template's `parentId`: templates belonging to other proxies
on the same node may be selected. Selected templates use the same exact tracked
filename preflight as servers, under
`.vestri-minecraft/<node ID>/templates/<template ID>/data/plugins`. Missing JARs
are not installed; listing failures abort the entire update before writes.
Unselected templates, bases, worlds, and plugin packs are unchanged. Updating a
template affects future instances copied from it; existing instance files are
updated only when explicitly selected from the accessible linked-server scope. Imports retain
their staging-only behavior.

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
