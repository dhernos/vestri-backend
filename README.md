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
    "enabled": true,
    "teamPolicy": "balanced",
    "instanceMode": "temporary",
    "lobbyMode": "vestri",
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
        "loggerName": "my.minigame.Plugin",
        "whenEmpty": true,
        "emptyGrace": "10s",
        "returnPlayersTo": "lobby",
        "deleteServer": true
      }
    }
  }
}
```

- `enabled`: optional boolean, defaults to and serializes as `true` after
  validation. Disabled templates stay in discovery with `enabled: false` but
  spawn requests return HTTP 409, including saved-request retries. Compatible
  coordinators must stop queue admissions and replenishment for disabled pools.
  Disabling does not change any existing instance's pinned spec or lifecycle;
  coordinators must ignore `enabled` when comparing instance compatibility.
- `teamPolicy`: optional `balanced` (default) or `roles`. Balanced mode rejects
  nonempty `teamCounts` and `remainderTeam`. Roles assign individual players,
  intentionally allowing party splits, and require `lobbyMode: "vestri"` and
  at least one declared team. Optional `teamCounts` maps existing,
  case-sensitive team identifiers to exact nonnegative counts, each no greater
  than `teamSize`. Required `remainderTeam` must name an existing team and gets
  players remaining after the exact counts (in addition to any explicit count
  for that team). Exact counts must fit `minPlayers`, and the remainder must fit
  that team's `teamSize` at `maxPlayers`. Unspecified exact counts are zero.
  The backend validates/transports
  assignment settings; assignment itself belongs to the coordinator. For example,
  `teams: ["speedrunner", "hunter"]`, `teamPolicy: "roles"`,
  `teamCounts: {"speedrunner": 2}`, and `remainderTeam: "hunter"` assign exactly
  two speedrunners and the rest hunters. Set `minPlayers >= 2`, a total
  `maxPlayers`, and a `teamSize` large enough for each team's maximum occupancy.
  At `minPlayers: 2` the roster may contain only speedrunners. Compatible
  coordinators randomly select individuals, intentionally splitting parties;
  this is not a security-grade randomness guarantee.
- `variants`: optional map of up to 20 safe identifiers (same syntax as team
  names) to overrides for `teams`, `teamSize`, `minPlayers`, `maxPlayers`,
  `teamPolicy`, `teamCounts`, and `remainderTeam` only. Unspecified fields inherit
  the base. Explicit `teams: []`, `teamCounts: {}`, numeric zero, and
  `remainderTeam: ""` are retained as overrides, not treated as missing. Every
  resolved variant passes the same validation as the base, including lifecycle
  command compatibility with its teams. `readyServers` warms the base pool only;
  variant pools are on demand. All variants and the base share `maxInstances`.
- `instanceMode`: optional string, defaults to `temporary`; only `temporary`
  and `permanent` are accepted. Missing fields in legacy templates and saved
  instance configs normalize to `temporary`. Permanent instances require
  `lobbyMode: "plugin"`, `end.deleteServer: false`, `end.whenEmpty: false`,
  and an empty/omitted `end.logPattern`. Invalid combinations are rejected,
  not silently normalized. They persist across game ends and empty periods;
  compatible coordinators and Paper agents must ignore explicit end signals
  for permanent instances. The backend transports this contract but does not
  implement agent or coordinator execution.
- `lobbyMode`: optional string, defaults to `vestri`; only `vestri` and
  `plugin` are accepted. `vestri` uses Vestri's minimum-player wait and
  `onAllJoined` startup actions. `plugin` delegates the lobby/start decision to
  the game plugin: Vestri does not wait for `minPlayers` or execute `onAllJoined`.
  Nonempty `onAllJoined`, `teamCommands`, or `startCommands` is therefore
  rejected in plugin mode, not silently ignored; send empty arrays.
  `onPlayerJoin` actions are allowed in both lobby modes, including permanent
  plugin-lobby instances; they are not startup actions.
  Readiness still applies; ending applies to temporary
  instances only.
- `teams`: optional, omitted/null/`[]` all normalize to `[]` for free-for-all
  games. Nonempty arrays contain at most 100 unique, case-sensitive identifiers matching
  `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`. `returnPlayersTo` uses the same identifier
  rule. The backend does not check Minecraft team or fallback-server existence.
- `minPlayers` and `maxPlayers`: integers 1-100, with `minPlayers <= maxPlayers`
  in both lobby modes. Plugin-lobby callers can send `minPlayers: 1`, but the
  backend does not relax player-limit validation.
- `teamSize`: integers 1-100 when teams are nonempty; then
  `maxPlayers <= len(teams) * teamSize` is also required. Without teams, omitted
  or zero is allowed, positive defaults up to 100 are ignored for capacity, and
  negative or greater-than-100 values are rejected. Native lobbies may still
  declare teams; identifier, size, and capacity validation is unchanged.
- `readyServers`: integer 0 through template `maxInstances` (itself 1-100);
  omitted means 0. For temporary instances it is the desired spare ready-pool
  count, not the total active count. For permanent instances it is the minimum
  persistent instance count, including active instances, within the same cap;
  zero enables on-demand creation without a prewarmed minimum. These are
  coordinator semantics, not a backend provisioning loop.
  `joinTimeout` defaults to `20s`; `emptyGrace` defaults to
  `10s`. Both use Go duration strings and must be between `1s` and `10m`
  inclusive, with whole-millisecond precision. Validated values normalize to
  canonical Go duration strings (`20s`, `1m20s`, `1.5s`, `1.001s`), compatible
  with the Java parser for concatenated ms/s/m/h components; sub-millisecond precision is rejected rather
  than rounded. `returnPlayersTo` defaults to `lobby`.
- `ready.trigger`: required, `serverLoad` or `explicit`. `onAllJoined` is
  an array of commands (omitted/null becomes `[]`). Each command is
  1-1024 bytes, nonblank, without a leading slash (including after whitespace)
  or control characters/newlines. `forEach` is empty/omitted, `team`, or `player`.
  Commands optionally accept `sender: "server"` (the default) or
  `sender: "player"`. Other values, including explicit null, empty strings, and
  non-strings, are rejected. Default server senders are omitted on serialization.
  Only `{team}`, `{player}`, `{uuid}`, and `{matchId}` placeholders are accepted;
  unmatched braces are rejected. For server commands, `{team}` requires team or
  player repetition; `{player}` and `{uuid}` require player repetition.
  Player-sender commands have selected-player context even without repetition;
  `{player}`, `{uuid}`, and `{team}` refer to that selected player.
  `{matchId}` works anywhere.
  Without teams, both `forEach: "team"` (even without a placeholder) and
  `{team}` are rejected. Once-only commands and per-player `{player}`/`{uuid}`
  actions remain valid for team-free Vestri lobbies.
- `lifecycle.teamCommands`: optional array of `{team, command, sender?}`. `team` is
  required and must exactly match a declared team; `*` is not accepted. The
  command runs per player assigned to that team and accepts `{player}`, `{uuid}`,
  `{team}`, and `{matchId}` using the same validation as `forEach: "player"`.
- `lifecycle.startCommands`: optional array of final once-only commands. Each
  entry is either a legacy string (server sender) or
  `{"command":"...","sender":"player"}` with optional `sender` defaulting to
  server. Legacy strings remain strings when saved, patched, resolved into
  variants, or pinned to instance configs; object entries remain objects.
  Server starts accept only `{matchId}`. Player starts accept `{player}`,
  `{uuid}`, `{team}`, and `{matchId}` using one selected roster player.
- `lifecycle.onPlayerJoin`: optional array of `{command, sender?}` actions for
  each admitted player join, including later joins/rejoins on permanent servers.
  `forEach` must be absent, even an empty or null value is rejected. Both senders
  use the joining player's `{player}`, `{uuid}`, and optional `{team}` context,
  not a random roster member; `{matchId}` is also accepted. `{team}` always
  requires declared teams, including in inherited variant actions.
  `onAllJoined`, `teamCommands`, `startCommands`, and `onPlayerJoin` together are
  limited to 100 commands, with the same 1024-byte/placeholder/control-character
  limits for every entry.

Compatible agents must execute setup, team commands, and final starts in order.
Setup `forEach: "player"` supports either sender for each assigned player.
Setup `forEach: "team"` with a player sender selects an online member of that
team, with `{player}`/`{uuid}` from that member. Once-only setup and start actions
with a player sender select one random eligible online match-roster player per
action, not every player. Team commands still run once per assigned player for
either sender. Player commands run as the actual selected player with normal
permissions: no OP elevation, sudo, or console fallback. No eligible online player
means a player-sender action is skipped (NOOP). These are agent execution
requirements; the backend validates, persists, and transports them and does not
dispatch Minecraft commands. Deploy sender/join-capable agents before using the
new fields. Existing broadcast and end behavior, including strict trusted-plugin
logger matching, is unchanged.

A managed lifecycle can mix legacy starts and sender-aware actions:

```json
{
  "ready": { "trigger": "serverLoad" },
  "onAllJoined": [
    { "command": "team join {team} {player}", "forEach": "player" },
    { "command": "arena select {team}", "forEach": "team", "sender": "player" }
  ],
  "teamCommands": [
    { "team": "red", "command": "arena ready {player}", "sender": "player" }
  ],
  "startCommands": [
    "say Match {matchId} ready",
    { "command": "arena start", "sender": "player" }
  ],
  "onPlayerJoin": [
    { "command": "tag {player} add participant" },
    { "command": "arena join", "sender": "player" }
  ],
  "end": { "whenEmpty": true, "deleteServer": true }
}
```

The end rules below are unchanged:

- `end.logPattern` is optional, at most 512 bytes, and has no CR/LF. It must
  compile with Go's regexp engine; named groups, lookarounds/backreferences,
  ungreedy flags, POSIX classes, octal escapes without leading zero, and
  divergent Unicode/escape forms are rejected for practical Java compatibility.
  This is not a complete Java regex verifier or a Java execution-time bound;
  avoid pathological nested repetition and test patterns in the plugin runtime.
  `end.loggerName`, when supplied, must match `[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`.
  It remains
  optional in backend validation for legacy saved specs and retries. Editors
  must require an explicit logger for new/edited nonempty patterns; compatible
  Paper agents disable log matching and warn when the logger is absent or
  unverified. It must exactly, case-sensitively match an installed gameplay
  plugin's `getLogger().getName()`; verify it against that plugin's source or
  runtime logger. Root/global, server/chat sources, and Vestri's own logger are
  not trusted end sources. The backend validates logger syntax, not installed
  plugin identity; that check belongs to Paper.
  The current Paper matcher uses Java regex `find()` on the raw JUL
  `LogRecord.getMessage()`, not formatted console output: `^xy$` matches `xy`
  without a timestamp or prefix, while unanchored patterns match substrings.
  It does not scrape stdout, Log4j, or SLF4J. Logger identity cannot distinguish
  a real end signal from malicious player text logged by the gameplay plugin
  itself through its trusted logger. An adapter issuing the console-only
  `vestridynamic end` from actual game state provides a stronger integration;
  explicit and empty-server end remain available when log matching is disabled.
- `end.whenEmpty` is boolean (omitted means false); `end.deleteServer` must
  explicitly be `true` for temporary instances and must be `false` for permanent
  instances. Permanent instances also require `whenEmpty: false` and an empty
  `logPattern`, since game ends are ignored. The backend validates and transports lifecycle rules;
  executing commands, readiness, transfers, end detection, and deletion remains
  the plugin's responsibility.

A native plugin-lobby FFA minigame block can use:

```json
{
  "lobbyMode": "plugin",
  "teams": [],
  "minPlayers": 1,
  "maxPlayers": 20,
  "readyServers": 1,
  "lifecycle": {
    "ready": { "trigger": "serverLoad" },
    "onAllJoined": [],
    "end": {
      "whenEmpty": true,
      "deleteServer": true
    }
  }
}
```

Use `explicit` readiness instead when the game plugin must finish initialization
before accepting players. `plugin` mode does not remove the readiness signal,
join timeout, maximum-player limit, ready pool, or configured end lifecycle.

For a permanent plugin-lobby server, use the same native block with
`"instanceMode": "permanent"`, `"end": {"whenEmpty": false,
"deleteServer": false}` and no `logPattern`. Set `readyServers` to the desired
minimum persistent instance count, or `0` for on-demand servers. Deploy compatible
proxy and Paper agents before using this mode; an older agent may still end or
delete these instances. Current compatible agents/coordinators preserve permanent
instances across ends, empty periods, and proxy/Paper restarts. Offline recovery
is supported through persisted match/roster reservations and fresh matching
agent reports and roster acknowledgements, not automatic player reconnection
or restoration of the gameplay plugin's own state. Failures make an instance
unavailable or release failed admissions rather than automatically deleting it;
explicit authorized dashboard deletion remains available.

For example, this permanent FFA minigame block admits join actions without
enabling Vestri startup commands:

```json
{
  "instanceMode": "permanent",
  "lobbyMode": "plugin",
  "teams": [],
  "minPlayers": 1,
  "maxPlayers": 20,
  "readyServers": 1,
  "lifecycle": {
    "ready": { "trigger": "serverLoad" },
    "onAllJoined": [],
    "onPlayerJoin": [
      { "command": "tag {player} add visitor" },
      { "command": "arena join", "sender": "player" }
    ],
    "end": { "whenEmpty": false, "deleteServer": false }
  }
}
```

Before instance startup, the backend writes
`<instance root>/data/plugins/VestriConsoleBridge/minigame.json` containing
`{slug, token, controlUrl, spec, spawnRequestId?, variant?}`. Optional `spawnRequestId` is
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

Spawn accepts `{ "requestId": "<UUID>", "variant": "duel" }` through either
the template-scoped API key endpoint or the dashboard spawn route. Omit
`variant` or send `""` for the base; ordinary templates reject named variants.
Unknown named variants return HTTP 400 without provisioning. The backend
resolves a private copy before provisioning and stores a fully resolved `spec`
without `variants` in the instance config. Its optional `variant` is the selected
name; legacy absent values mean the base. Request-ID hashing is unchanged:
reusing the same request ID with another variant returns HTTP 409 before worker
mutations. Retries with the original variant preserve the saved spec, even if
that variant has since been edited or removed from the template. Every private
target includes `variant` from the saved config, defaulting to `""`, not from the
current template. Top-level discovery retains the base and variant definitions.

Proxy synchronization writes top-level `authoritative`, `minigames`, and `servers` in
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
added to public spawn responses.

Manifest authority has these exact semantics:

- `authoritative: true` only when synchronization uses `excludeID == ""` and
  successfully loads a complete, consistent node-wide database snapshot of
  instances, servers, and resources in one read-only repeatable-read transaction.
  The `servers` map is scoped to the selected parent proxy and includes both
  ordinary dynamic and minigame instances. Static/non-instance servers are not
  part of this reconciliation contract. For that proxy, a previously tracked
  dynamic server absent from a true-authority manifest can be reconciled as
  removed. Surviving minigame configs must also validate before publication.
- `authoritative: false` whenever `excludeID != ""`. That instance is omitted,
  but this may be precommit exclusion, not a committed deletion. Coordinators
  must not infer deletion from absence in such a manifest. Missing authority
  in legacy manifests must likewise not authorize absence-based deletion.
- Query/scan/transaction errors, incomplete instance/server records, invalid
  metadata, or missing/corrupt surviving minigame configs abort synchronization
  before writing a manifest or reloading Velocity. No partial snapshot is
  published as authoritative. There is no `pendingDeletion` or deleted-ID list;
  committed deletion is represented by absence in a complete authoritative map.

The top-level `maxInstances` value within each minigame entry remains the template
cap, and `readyServers` has the mode-dependent pool/minimum semantics above.
Each private `servers[slug].spec` has the same flattened layout as
`minigames[templateName]`: inline minigame fields plus `maxInstances`, with no
extra `minigame` wrapper, hash, or version. Its minigame fields come from the saved
spawn-time instance `config.Spec`; only `maxInstances` uses the current template
cap. The top-level template entry continues to contain the current template spec.
Only top-level template entries contain variant definitions; instance specs are
fully resolved snapshots without `variants`.
Both shapes serialize normalized `instanceMode`, `lobbyMode`, and `teams: []`;
old templates and saved instance configs without these modes normalize to
`temporary` and `vestri`. Retry does not change a saved instance's modes or
teams to match an edited template.
The proxy can persist `target.spec` in its per-instance ledger and compare raw
specs to drain mismatched ready instances, while active instances retain their
original lifecycle. Ordinary server entries omit `spec`. This is a transport
contract only; the backend does not perform draining or change plugin behavior.

### Updating And Disabling Pools

Session-authenticated node owners/admins can call
`PATCH /api/nodes/{nodeRef}/minecraft/resources/{resourceId}` with
`{ "minigame": <full settings>, "maxInstances": 3 }`. `maxInstances` is optional;
`minigame` is a full replacement, not a partial merge. Only existing minigame
templates can be updated. Other resource/spec fields are rejected, and template
data/world/plugin files are never copied. Updates use the existing node plugin
lock, shared with spawn, delete, and other library mutations.

The dashboard uses this PATCH contract. Changed game settings apply to **new
instances only**; existing instances and saved-request retries keep their pinned
spawn-time settings, and active matches retain their original lifecycle.
Compatible coordinators drain incompatible ready instances rather than rewriting
their configuration. Setting `minigame.enabled: false` stops queue admissions
and replenishment and removes queued entries, but does not end active matches.

The database is authoritative: validation precedes a node-bound spec-only SQL
update, followed by the template `manifest.json` and parent-proxy discovery sync.
Post-commit file/sync work shares an independent 30-second budget and continues
after request cancellation. Success returns HTTP 200 with `resource`. A database
failure returns HTTP 500 with `committed: false` and does not mutate worker files.
Post-commit failures return HTTP 502 with `committed: true` and `resource`:
retry PATCH to repair a failed template-manifest write, or the existing manual
proxy-sync endpoint to repair discovery/reload. A failed manifest write still
attempts to publish the authoritative database state. No rollback deletes files
or attempts to undo the committed spec.

DELETE of an enabled minigame template with instances first persists
`enabled: false`, writes its manifest, and syncs discovery under the same lock.
After successful disable it returns HTTP 409 with
`Pool disabled; delete instances and retry`, not a deletion success. Already
disabled templates with instances return the same conflict. A disable's
post-commit failure returns HTTP 502 with `committed: true`; repair publication
using PATCH/sync. Explicit PATCH disable is also supported. Existing instances
and their immutable lifecycle configs are left intact. After instances are
removed, retry DELETE to remove the template normally. Ordinary templates retain
the existing delete-instances-first behavior.

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

Dynamic instance deletion, including dashboard server deletion, stops and
unregisters the instance, deletes its files, then deletes its database server
record (which cascades to `MinecraftInstance`). Dashboard and exact-key deletion
do not read minigame template/instance configs to gate that deletion. Delegated
API deletion first verifies the narrow contract below. Only after the database deletion
commits does it synchronize the parent using `excludeID == ""`, with a separate
30-second context independent of request cancellation. Thus the removed instance
is absent from the authoritative postcommit manifest, rather than temporarily
excluded from a precommit snapshot. A corrupt surviving config can fail this
final sync, but cannot undo or block the already-committed deletion.

Successful deletion returns HTTP 204. Postcommit synchronization failure returns
HTTP 502 with `{"error":"Instance deleted, but Velocity synchronization failed;
retry proxy sync","committed":true}`. Files and database records remain deleted;
the response must not be treated as evidence that the server still exists.
Recover with the same owner/admin proxy sync endpoint above. No destructive
rollback or recreation is attempted. Precommit failures do not report
`committed: true`; database/worker verification errors are not treated as absence.
With a valid authorized API key, `DELETE /api/minecraft/v1/instances/{instanceId}`
returns HTTP 404 for an absent instance (including a retry after committed
deletion), so clients may treat that result as `deleteIfPresent` success. A known
instance belonging to another key returns HTTP 403, even for the same template.
Authentication/permission/rate-limit failures keep their existing status codes.

### Dashboard Minigame Delegation

Known-ID API `DELETE`, `POST .../start`, and `POST .../stop` also permit a
dashboard-created minigame (`MinecraftInstance.keyId` empty) only when the key's
user is exactly `GameServer.createdByUserId`, the template IDs match, and both
key and instance belong to the middleware's currently authorized node. Every
request revalidates the key owner's current node owner/admin permission. This
does not grant all template keys authority over all dashboard administrators'
instances. A different creator account still receives HTTP 403; a different
node sees HTTP 404 because instance lookup is node-scoped.

The template must still be a valid minigame template bound to the instance's
parent proxy. New spawns persist `metadata.minecraftMode`; ordinary instances
cannot become delegated merely by changing their template mode. Legacy instances
without that marker require a valid saved minigame configuration bound to the
same node's Velocity proxy. Missing/corrupt legacy configuration fails closed.
New minigames can be deleted even if their runtime configuration is damaged.

Exact-key instance isolation is unchanged, including keys from the same account.
Ordinary dashboard instances remain excluded. API list and request-ID lookup
remain exact-key-only: cleanup uses the known instance ID directly, not a list or
a key-hashed dashboard spawn request. No `managedByProxy` authority flag is
published: the manifest cannot establish the identity of the proxy's configured
credential. A proxy must rely on the authenticated lifecycle result.

This same-creator delegation lets an adopted manual/web **MINIGAME** instance
be cleaned up with the matching creator's template key; it does not adopt
ordinary servers, grant player access, or authorize a different creator's key.
Manual instances are tracked independently rather than merged with a pending
spawn just because their templates match. For native `lobbyMode: "plugin"`, a
direct join or console `--send-player` admits the whole permitted party to the
exact requested instance only after a fresh agent report and acknowledgement of
the matching match ID and full-roster `rosterVersion`; a status ping cannot
bypass admission. Managed `lobbyMode: "vestri"` uses the template queue and
`minPlayers` threshold instead, without forcing entry to the manually spawned
instance. These are compatible proxy/Paper runtime behaviors, not backend
transfers or roster assignment.

Deletion regressions run against a disposable PostgreSQL database and Redis:

```sh
VESTRI_VELOCITY_TEST_DATABASE_URL='<PostgreSQL URL>' \
VESTRI_MINECRAFT_TEST_REDIS_ADDR='127.0.0.1:6379' \
go test ./internal/server -run TestMinecraftMinigame -count=1
```

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

### Preparation Diagnostics And Deployment

Deploy the backend contract first, then compatible Vestri JARs on both Velocity
and Paper/Purpur before enabling team-free or plugin-lobby templates. The backend
only validates/transports these fields; an older JAR cannot implement the native
lobby behavior. No database migration or worker code change is required for this
contract. Resynchronize the proxy after deployment or template changes using the
protected sync endpoint above.

Update both Paper template JARs and current Paper instance JARs, then restart
affected servers; updating only the proxy or template does not upgrade a running
instance. Deploy the updated frontend for regenerated template specs and verify
the intended `instanceMode` and lifecycle before spawning. Existing instances
and saved-request retries retain their pinned spawn-time spec copy, so a
template edit, regenerated spec, or JAR update cannot change their mode in place.
Recreate an incompatible instance with the intended spec after authorized
evacuation/deletion; compatible permanent instances can recover with their
original durable files instead of always being recreated.

The proxy's protected `plugins/vestri-dynamic/vestri-minigames.json` ledger stores
the original API origin (`backendUrl`, including any deployment prefix) and
template API key for preparation retries, lookup, and cleanup. Current config
changes do not replace that pinned binding or transfer backend ownership. Treat
the ledger and backups as credentials: use POSIX `0600` files and a `0700`
directory. Legacy unknown-credential records stay tracked and fail closed, not
silently forgotten or reassigned to a current key. Recover original credentials
or use authorized dashboard deletion followed by authoritative proxy sync.
Live retry/cleanup failures may be rooted in that saved origin or key, including
expiry, revocation, creator/node permissions, or template mismatch; a working
current key does not establish that the original key works. Diagnose with HTTP
status and correlated sanitized logs without exposing credentials.

`VESTRI_DYNAMIC_SYNC_OK` is not a successful spawn response. Fresh spawn first
writes the proxy manifest and reloads Velocity as a preflight, then copies the
template, writes the minigame config/properties/compose, installs the bridge,
registers forwarding, commits the instance, starts it, and synchronizes again.
A success marker can therefore precede a later preparation/API failure. Proxy
sync schedules minigame network provisioning asynchronously, so its reentrant
discovery does not synchronously wait on the spawning HTTP request.

For a `Minigame preparation pending` IOException, correlate the caller UUID with
the backend POST response and these backend/worker logs:

- `minecraft instance preparation_failure`: `stage=proxy_preflight` or
  `minigame_config`, node/request/stack/retry, and safe operation/file context.
- Manifest sync failures identify `proxy_manifest`, `proxy_data_directory`, or
  `proxy_manifest_write`; worker reload failures include `worker_status`.
- Forwarding failures identify the read/write operation and relative config file
  with `forwarding_failure`. Post-commit start/reload failures use
  `post_commit_failure` and return `serverId` with HTTP 502.
- The worker `/fs/write` handler creates parents with `MkdirAll`; its path check
  permits nonexistent descendants. A missing parent alone does not cause failure
  in the current worker. Inspect the worker's matching write/path error for an
  actual filesystem failure instead of manually precreating plugin folders.

Backend preparation logs deliberately omit credentials and worker response bodies.
The public response already contains `name`, `serverId`, `slug`, `host`, `port`,
`parentId`, and `state`. Friendly names follow the client's accepted identifier
plus positive numeric suffix, including FFA names. The private control URL uses
the parent slug's Docker service alias, not the filesystem root path.

Retry POST with the **same raw request UUID and template-scoped key** after
HTTP 502/503/504. Before database commit, cleanup removes the failed fresh instance;
after commit, the saved request reuses the same instance, token, spec, correlation,
and execution fence. Request lookup `GET /api/minecraft/v1/instances/requests/{UUID}`
returns that key's instance or `{"instance":null}` without spawning. Missing or
invalid saved configs fail closed, not by generating replacement credentials.
A generic IOException and sync marker alone do not identify the failing stage;
capture the actual API error and correlated deployment logs before assigning a
runtime root cause.

Focused regressions: `go test ./internal/server -run TestMinecraftMinigame -count=1`.
They cover validation/defaults, worker provisioning/retry/cleanup/failures,
exact request-ID and name transport, duration normalization, parent-scoped
manifests, optional teams, native lobby rejection of startup actions, pinned
lobby serialization, secret-safe preparation diagnostics, the protected manual
sync route, and token-free public instance responses.
Set `VESTRI_VELOCITY_TEST_DATABASE_URL` to a disposable PostgreSQL URL to also run
the isolated-schema discovery regression: brand-new templates with zero instances,
deleted template removal, cancellation-independent post-commit sync, and retained
resources/retry after a proxy reload failure.

These regression descriptions and deployment instructions are not a claim of
live testing. Verify manual/web adoption and cleanup authorization, exact native
admission, managed queueing, private agent connectivity, and permanent offline
restart recovery on the deployment before opening queues to players.

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
