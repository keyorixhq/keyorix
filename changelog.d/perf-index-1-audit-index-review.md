### Changed
- **Dropped the unused audit_events (machine_identity_id, event_time) index.** No query filtered on it, and it cost every audit INSERT one btree update. It is removed on upgrade (DROP INDEX CONCURRENTLY on PostgreSQL); the machine_identity_id column and audit rows are unchanged.
