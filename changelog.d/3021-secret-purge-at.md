### Changed
- **Deleting a secret now shows its real purge date (the restore deadline)** in the CLI,
  REST and gRPC responses and in the trash listing. The date is frozen when the secret is
  soft-deleted, so a later change to `soft_delete.retention_days` can neither pull a purge
  earlier than the date already shown nor silently push it out. New nullable column
  `secret_nodes.purge_at`, added automatically on upgrade (schema epoch 2; older binaries
  keep booting, the compatibility floor stays 1). Secrets soft-deleted before the upgrade
  keep following the current window until purged.
