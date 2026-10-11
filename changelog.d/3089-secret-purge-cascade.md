### Fixed
- **`admin restore` no longer refuses a backup taken after a secret purge (#3085).** The retention purge hard-deleted
  the secret and its versions but left rows that still referenced them, and restore's mandatory
  dangling-reference check counted every one. The purge now deletes, in the same transaction, the
  rows of every mutable table that references the secret or a version: access requests (and their
  approvals), shares, tags, access schedules, metadata history, version comments, notifications,
  anomaly alerts and access logs. `audit_events.secret_node_id` (append-only; audit rows are never deleted or
  rewritten) and the `access_review_items` snapshot are historical references that restore's check
  skips by name; every other reference stays strictly checked. A guard test fails when a new table
  references a secret without being classified as one or the other.
