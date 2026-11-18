- **INV-STORE-access-schedule-upsert-column-scoped** `SetSecretAccessSchedule` writes an
  existing `secret_access_schedules` row only with an UPDATE of `allowed_days`,
  `start_hour`, `end_hour` and `timezone` (plus `updated_at`) WHERE `secret_node_id = ?`,
  and creates one only with an INSERT ... ON CONFLICT (secret_node_id) DO NOTHING. No
  write takes a struct read earlier, so a schedule deleted by another replica is never
  re-inserted under its old id, a schedule deleted and re-created meanwhile is updated
  rather than collided with, and zero values (start hour 0) are written. Guard:
  `TestSetSecretAccessSchedule_ConcurrentDeleteIsNotRevived`,
  `TestSetSecretAccessSchedule_DeleteAndRecreateBetweenReadAndWrite`,
  `TestSetSecretAccessSchedule_ZeroStartHourIsWritten` (SQLite and two-pool Postgres).
  **Not covered**: `SecretAccessSchedule` has no security-state column in
  `securityStateColumns`, so `TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels`
  does not flag a new `Save` of it; only these tests do.
