### Security

- New `keyorix-migrate vault audit-access` (read-only) lists Keyorix grants that `keyorix-migrate` v0.96.0–v0.96.3's `apply-access` created wider than their source Vault policy (a policy path narrower than the project/environment it was mapped to, or a `list`-only / KV v2 `metadata/` stanza granted `secrets.read`) and that a migrated machine identity still holds, each with the API call that revokes exactly that grant; it exits 1 when it finds any. Installs that ran `apply-access` with those releases should run it with the same flags (docs/UPGRADING.md §6w).
