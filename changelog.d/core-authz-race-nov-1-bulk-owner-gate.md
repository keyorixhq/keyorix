### Security
- **Owning a secret no longer lets a user without `secrets.write` rename, suspend, resume or
  extend it through the project-wide bulk operations in core (defence in depth, the #4508
  sibling).** Bulk rename, suspend-all, resume-all and extend-expiring re-checked each secret with
  the owner pass alone, while the REST routes gate all four on project-scope `secrets.write`. Each
  now skips a secret whose owner does not hold that permission, exactly as the route refuses them;
  no client-visible change. Guard: `TestOwnerWithoutSecretsWrite_BulkOpsSkipTheirSecrets`.
