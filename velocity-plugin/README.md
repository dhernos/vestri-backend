# Vestri Dynamic Servers for Velocity

This Java 17 plugin bridges Vestri's dynamic Minecraft instances into a running
Velocity proxy. The same JAR includes an optional Paper/Spigot console bridge.
Neither entry point provisions Docker containers itself.

## Existing responsibilities

- On proxy startup, read `vestri-dynamic-servers.json` if it exists.
- Handle the console-only `vestridynamic sync` command sent by Vestri's worker
  after dynamic instance changes, without restarting Velocity.
- Register new dynamic backends and unregister stale ones in Velocity's live
  server registry. Internal IDs must match `mcgame-<32 hexadecimal characters>`,
  hosts must be `vestri-<internal ID>`, and ports must be 25565. New instances have
  friendly registry names such as `BedWars-1`, independent of their internal IDs.
- Reject oversized or invalid manifests before changing the registry, and leave
  ordinary servers such as a manually configured lobby alone.

The backend writes the manifest and the worker triggers synchronization. The
plugin does not poll the API, balance players, move players to new servers, or
wait for Minecraft to become joinable.

## Numbered server names

New saved-template instances use `TemplateName-number` in the panel, Velocity's
configuration, and Velocity's live server registry. For example, `Bed Wars`
produces `BedWars-1`, `BedWars-2`, and so on, so tab-list plugins reading the
Velocity server name see those names instead of an opaque UUID.

Spaces and unsafe characters are removed from the template prefix; case is
preserved, prefixes are limited to 64 characters, and an empty prefix falls back
to `Minecraft`. Allocation uses the lowest free positive number on that proxy,
checks names case-insensitively, and runs under the existing node lock. Deleting
an instance frees its number for reuse. Templates whose sanitized names collide
share the available numbering space. Internal Docker stacks, paths, and addresses
still use UUID IDs. Existing instances retain their old registry names until
recreated. The new backend and proxy JAR must be deployed together.

## Install and configure

Build from this directory with `mvn clean package`. Install
`target/vestri-dynamic-servers-1.0.0.jar` in the proxy's `plugins` directory and
restart the proxy to load the updated plugin.

In Vestri's node Minecraft library, create a saved dynamic server template linked
to this Velocity proxy. Create a Minecraft API key scoped to that template. Repeat
for each template the console should manage. These are saved templates with server
files, not the built-in software choices such as `minecraft-vanilla`.

Create `vestri-dynamic-config.json` in Velocity's working directory, beside
`velocity.toml` and `vestri-dynamic-servers.json`:

```json
{
  "backendUrl": "https://panel.example.com",
  "templates": {
    "Bed Wars": "vmc_<64 hexadecimal characters from the template API key>",
    "Survival": "vmc_<64 hexadecimal characters from another template API key>"
  }
}
```

Replace the example URL and keys. Names are local command aliases; use the same
names as the saved templates to keep them recognizable. Matching is
case-insensitive and supports spaces. The API key, not the alias, determines the
actual template and node. Only configure templates belonging to this proxy.

Use the backend origin, or its deployment prefix if hosted below a subpath; the
plugin appends `/api/minecraft/v1/instances`. HTTPS is required except for HTTP on
`localhost`, `127.0.0.1`, or `::1`. Inside a proxy container, loopback refers to that
container, not the host or backend container. The configured URL must be reachable
from the proxy. Redirects are not followed, so use the final backend URL.

Protect this file like a password: restrict it to the proxy service account, do
not commit it, and never put a worker-wide API key in it. Configuration is read on
every lifecycle command, so changes do not require a restart. API keys can expire
or be revoked, and require their creator to retain node administration access.

## Console commands

Run these in the **Velocity console**, without a leading slash. Players cannot
run them, including players with wildcard permissions.

```text
vestridynamic templates
vestridynamic spawn Bed Wars
vestridynamic list Bed Wars
vestridynamic delete Bed Wars --confirm
vestridynamic delete Bed Wars --instance <server UUID> --confirm
vestridynamic spawn Bed Wars --request-id <request UUID>
vestridynamic sync
```

- `templates` lists configured aliases, not all templates in the panel.
- `spawn` copies the saved template, starts the server, and synchronizes Velocity
  through the existing backend/worker pipeline. Success reports a server UUID and
  means **starting**, not ready for players. The command prints a request UUID
  before contacting the API. If it fails or times out, retry with that same UUID
  and the same template/key instead of issuing a fresh spawn.
- `list` shows server UUIDs accessible to the configured template key.
- `delete` stops the instance, unregisters it, and permanently removes its files
  and record. `--confirm` is mandatory. Without `--instance`, exactly one instance
  must exist; zero or multiple instances cause refusal, never a bulk deletion.
  With `--instance`, the UUID must appear in that key's instance list.
- `sync` only reconciles the local manifest; it does not create or delete servers.

Lifecycle requests run on Velocity's scheduler so the console remains available
for the worker's `sync` callbacks. The backend enforces permissions, template and
node instance limits, request idempotency, and a 30-request/minute API-key limit.
Listing and deleting count separately toward that limit.

A key can only list/delete instances created with that exact key. Panel-created
instances and instances created under a replaced key will not appear; manage
those in the panel or with their original valid key. Keep the printed request UUID
for a failed spawn, since provisioning or a proxy reload may have partially
succeeded. API errors show an HTTP status without exposing response bodies or
tokens; consult backend logs for details.

## Backend console and FancyNPCs

Velocity commands are not automatically available in a Paper server's console.
For an NPC plugin's **execute console command** action, install the same JAR in
the Paper/Spigot backend's `plugins` directory as well. On that server it loads as
`VestriConsoleBridge` and registers a console-only `vestridynamic` forwarding
command. Do not use a player-command action; players are rejected even with OP
or wildcard permissions. All lifecycle commands forwarded through this bridge
execute as the Velocity console and therefore use the proxy's template-key
configuration, regardless of which allowed backend sent them.

Generate a shared bridge secret outside your logs, for example with
`openssl rand -hex 32`. Add the following section to the proxy's existing
`vestri-dynamic-config.json`, alongside `backendUrl` and `templates`:

```json
"consoleBridge": {
  "secret": "<same 64-character hexadecimal bridge secret>",
  "allowedServers": ["lobby", "BedWars-1"]
}
```

`allowedServers` contains exact Velocity registry names of trusted servers that
may originate commands, not template aliases. Add every backend that needs NPC
actions. The bridge is disabled when this section is absent. Keep the allowlist
narrow; any trusted backend console can use every template configured on the
proxy. On each allowed backend, put the same secret in the generated
`plugins/VestriConsoleBridge/config.yml`:

```yaml
bridge-secret: '<same 64-character hexadecimal bridge secret>'
```

The bridge secret is separate from the `vmc_` template API keys. Never distribute
those API keys to backend servers. Both sides reread their configuration when
handling a command; restrict all secret files to their service accounts. Restart
both servers after first installing the JAR.

In FancyNPCs, select its execute-console-command action and use this command text:

```text
vestridynamic spawn Bed Wars
```

For deletion, use `vestridynamic delete Bed Wars --confirm`, or include
`--instance <server UUID>` when more than one instance exists. Configure NPC
interaction permissions/cooldowns in your NPC plugin: console actions are trusted
automation, so an unrestricted clickable NPC can deliberately trigger the action
for any player. The bridge itself does not grant players command permissions.

This uses authenticated plugin messaging on `vestri:console`. A player must be
connected to the sending backend to carry the message, which is normally true
when an NPC is clicked. On an empty backend the command reports that it cannot
send; use the Velocity console directly for empty-server automation. A backend
console message confirms sending, not API success. Results and errors appear in
the proxy console. Spawn prints its forwarded command including `--request-id`
in the backend console, so failures can be retried with that same ID.

Velocity rejects player-originated messages, unlisted backend sources, invalid
signatures, timestamps outside a 30-second window, and replayed requests. Keep
server clocks synchronized. Only the validated lifecycle commands are forwarded;
arbitrary proxy commands and `sync` are not exposed through this channel.

## Verification

`mvn test` covers manifest synchronization and friendly-name conflicts,
console-only dispatch, multiword names, confirmation and retry parsing,
configuration loading, HTTP create/list/delete with scoped keys, signed-message
authentication, replay/expiry rejection, backend source restrictions, and shared
protocol loading without either server API. HTTP tests use a local fake backend;
they do not provision real Minecraft containers or simulate live NPC clicks.