### Internal
- **Removed the caller-free full-row `UpdateSecret` storage primitive.** Secret edits already go through column-scoped writers (`UpdateSecretFields`, `TransitionSecretStatus`, `UpdateSecretRotationConfig`); no behaviour change. The fresh-canary leak fault pass for `PUT /api/v1/secrets/{id}` now faults `UpdateSecretFields` and fails if an armed fault never fires.
