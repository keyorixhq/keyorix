-- Revert RBAC Phase 2 environment scoping.
--
-- WARNING — SILENT SCOPE WIDENING, NOT JUST DATA LOSS: dropping
-- `environment_id` below does not delete the user_roles/group_roles ROWS
-- themselves, only the column — and the up-migration documents
-- `environment_id = 0` as "all environments in scope". Because the column
-- comes back at `DEFAULT 0` if 008's up-migration is ever reapplied (a
-- normal golang-migrate rollback-fix-reapply workflow), every previously
-- environment-scoped role/group binding silently becomes an unrestricted,
-- all-environments grant the moment the column reappears — a real RBAC
-- scope-widening bug, not merely schema churn. Before the column is dropped,
-- the FULL user_roles/group_roles rows (including their environment_id
-- values) are copied into `user_roles_backup` / `group_roles_backup`, so the
-- original per-environment scoping is recoverable and the loss is visible
-- and auditable rather than silent. These backup tables are a TEMPORARY
-- safety net only — not part of the live schema, not cleaned up
-- automatically; export/archive and drop them explicitly once the rollback
-- is confirmed safe. The backup inserts are safe to re-run across repeated
-- rollback/re-upgrade/rollback cycles (they accumulate timestamped snapshots
-- rather than colliding with an earlier backup).

-- Drop indexes
DROP INDEX IF EXISTS idx_user_roles_scope;
DROP INDEX IF EXISTS idx_group_roles_scope;
DROP INDEX IF EXISTS idx_user_roles_environment_id;
DROP INDEX IF EXISTS idx_group_roles_environment_id;

-- Back up user_roles/group_roles (full rows, including environment_id)
-- before the column is dropped. See warning above: temporary safety net,
-- not permanent storage.
CREATE TABLE IF NOT EXISTS user_roles_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  role_id INTEGER,
  project_id INTEGER,
  environment_id INTEGER,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO user_roles_backup (user_id, role_id, project_id, environment_id)
  SELECT user_id, role_id, project_id, environment_id FROM user_roles;

CREATE TABLE IF NOT EXISTS group_roles_backup (
  backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER,
  role_id INTEGER,
  project_id INTEGER,
  environment_id INTEGER,
  backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO group_roles_backup (group_id, role_id, project_id, environment_id)
  SELECT group_id, role_id, project_id, environment_id FROM group_roles;

ALTER TABLE user_roles  DROP COLUMN environment_id;
ALTER TABLE group_roles DROP COLUMN environment_id;
