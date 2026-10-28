### Fixed

- `keyorix-migrate` printed every error twice (cobra, then `main`); it now prints one `Error:` line. The exit code is unchanged.
- `migrate/healthscan-policy.hcl`, the documented Vault token policy, now lets `vault plan-access` / `apply-access` / `audit-access` list a KV v1 mount (`list` on `kv1/*`: replace `kv1` with your v1 mount) and read userpass users (`auth/+/users`, `auth/+/users/+`). `+/metadata/*` never matched a v1 mount, so with the documented policy `plan-access` could not list one and reported every default-convention policy it could hold as unmappable (`cross-mount-scope`). The "could not list" warning now names the stanza for KV v1 as well as KV v2.

### Documentation

- `docs/vault-health-scan.md`: the same policy file is the token policy of the access-migration commands; a table of what they need beyond the scan, and why a KV v1 mount needs its own `list` stanza. A test over the policy parser checks that the file grants exactly the Vault calls the commands make.

### Security

- `keyorix-migrate vault plan-access` / `apply-access` / `audit-access` no longer report a `--path-map` scope as equivalent to a Vault policy when another KV mount holds paths the default convention names into that scope: with `--path-map secret/data=<team-a>:<dev>`, `kv1/team-a/dev/x` lands in team-a/dev by name, so a grant there reached it although the policy never allowed it. Such a policy is now unmappable (`cross-mount-scope`), the report prints the other mount's path, and `apply-access` re-checks it. A mount that cannot be listed counts as holding the path. Mapping the other mount's paths to their own scope with `--path-map` clears it.
- The same check covers the policy's own mount: with `--path-map secret/data/legacy=<team-a>:<dev>`, `secret/team-a/dev/x` is outside `secret/data/legacy/*` but lands in team-a/dev by name, and the evidence called that directory "policy mount". It is now judged like any other mount (`secret/team-a/dev/: present (policy mount, outside the policy)`) and the policy is `cross-mount-scope`.
