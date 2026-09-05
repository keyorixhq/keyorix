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

-- environment_id is now part of each table's PRIMARY KEY (the up-migration's
-- fix for the 3-column PK silently rejecting per-environment rows), and
-- SQLite refuses to DROP COLUMN a column that's used in a PRIMARY KEY, UNIQUE,
-- FOREIGN KEY, GENERATED, or CHECK constraint -- so the plain
-- `ALTER TABLE ... DROP COLUMN environment_id` this file used before no
-- longer works. Same copy/drop/rename rebuild idiom the up-migration uses,
-- narrowing the PRIMARY KEY back to the original 3 columns. project_id is
-- deliberately kept NOT NULL DEFAULT 0 (not reverted to nullable): this
-- migration's stated scope is reverting environment scoping specifically
-- (see the file header), not the separate genuinely-NOT-NULL project_id fix.
CREATE TABLE user_roles_new (
  user_id INTEGER NOT NULL REFERENCES users(id),
  role_id INTEGER NOT NULL REFERENCES roles(id),
  project_id INTEGER NOT NULL DEFAULT 0 REFERENCES projects(id),
  PRIMARY KEY (user_id, role_id, project_id)
);
INSERT INTO user_roles_new (user_id, role_id, project_id)
  SELECT user_id, role_id, project_id FROM user_roles;
DROP TABLE user_roles;
ALTER TABLE user_roles_new RENAME TO user_roles;

CREATE TABLE group_roles_new (
  group_id INTEGER NOT NULL REFERENCES groups(id),
  role_id INTEGER NOT NULL REFERENCES roles(id),
  project_id INTEGER NOT NULL DEFAULT 0 REFERENCES projects(id),
  PRIMARY KEY (group_id, role_id, project_id)
);
INSERT INTO group_roles_new (group_id, role_id, project_id)
  SELECT group_id, role_id, project_id FROM group_roles;
DROP TABLE group_roles;
ALTER TABLE group_roles_new RENAME TO group_roles;

-- Recreate the indexes the DROP TABLE steps above implicitly took with them
-- (idx_user_roles_scope/idx_group_roles_scope are deliberately NOT recreated:
-- they enforced the 4-column scope uniqueness this down-migration is
-- specifically reverting away from).
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id     ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id     ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_project_id  ON user_roles(project_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_group_id   ON group_roles(group_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_role_id    ON group_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_project_id ON group_roles(project_id);
