# Vestri Backend

Backend documentation lives in the main repository:

- https://github.com/dhernos/vestri

Velocity dynamic-server plugin setup and console commands:
https://github.com/dhernos/vestri-plugin

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
Paper/Purpur servers, using the existing plugin manager's permissions and
target scope. Restart those servers after updating to load the new JAR. Release
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
