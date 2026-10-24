### Documentation
- **Removed docs for commands and features that do not exist.**
  - The sharing guide's CLI examples used `keyorix shares …`, `keyorix secret share` and `keyorix shared-secrets list`; they now point to the real `keyorix share` group.
  - Its claims of end-to-end, per-recipient encryption and of storage quotas are removed. A share is an access-control row, not a separate encrypted copy.
  - MIGRATION.md no longer documents `keyorix secret import --source vault|aws|azure|gcp`, which the CLI no longer has; live sources go through `keyorix-migrate` (migrate-from-vault.md, migrate-from-cloud.md).
  - Three command spellings are corrected: `request secret-access`/`request review` flags, `keyorix-server admin encryption migrate-provider`, and `keyorix access-review`.
