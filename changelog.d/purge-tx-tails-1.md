### Fixed

- Retention purge on PostgreSQL: a failing step (for example the environments delete) no longer aborts the whole purge transaction and rolls back the steps that had succeeded. Each step now runs in its own savepoint, a failed step reports 0 rows for itself, and the `data.purged` audit event counts only what was actually removed.
- Secret share and revoke notifications that fail or panic after the share has committed are now recorded as `notification.failed` audit events (as the access-request notifications already were) instead of only being logged; a failed group-member lookup is recorded too. The share or revoke itself is still never reported as failed.
