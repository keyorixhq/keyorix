## Config keys that are ignored today and will be rejected after the next minor release

On every start the server prints `WARNING: deprecated config key: "<key>" is deprecated and
ignored ... it will be rejected after the next minor release` for each key below that is present
in `keyorix.yaml`. No Keyorix feature reads them, so nothing changes while they stay; remove them
now so the config still loads at the next minor release. None has a replacement: the setting
never took effect.

| Key | Written by | What to do |
|---|---|---|
| `secrets.chunking` (the whole block) | `admin init` up to v0.96.x | delete the `chunking:` line and its indented sub-keys |
| `secrets.limits.max_secrets_per_user` | `admin init` up to v0.96.x | delete that one line; keep the other `limits:` keys such as `max_secret_size` |
| `server.http.keepalive` (the whole block) | hand-written configs only | delete it; only `server.grpc.keepalive` is read |

A config written by the current `admin init` contains none of them. A v0.96.x config contains the
first two. To check a file: `grep -n -E 'chunking|max_secrets_per_user|keepalive' keyorix.yaml`.
Take a copy first (`cp keyorix.yaml keyorix.yaml.bak`), edit with the server stopped, and confirm
the warnings are gone from the next start's log.

Renamed keys (old name still accepted, with a warning, and rewritten in memory) are a different
case; they are listed in the renamed-settings table in `docs/CONFIGURATION.md`.

Also on the first start after a v0.96.x upgrade: `keyorix audit verify` reports `NOT PROVEN`
until the first full re-walk of the chain completes; see `audit-verify-after-v096-upgrade.md`.
