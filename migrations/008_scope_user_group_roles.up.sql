-- RBAC Phase 2: scope role assignments by environment as well as project.
-- Adds environment_id to user_roles and group_roles and normalises the
-- project_id scope column to a genuinely NOT NULL 0 = global sentinel, with
-- the PRIMARY KEY widened to (subject, role, project, environment) so scope
-- can participate in uniqueness without nullable-column matching gymnastics
-- -- and so two rows differing only in environment_id are no longer rejected
-- by the original 3-column (subject, role, project) PRIMARY KEY carried over
-- from 001_init.sql, which would otherwise silently defeat this migration's
-- entire stated purpose (per-environment scoping within the same project).
--
-- The runtime path is GORM AutoMigrate (see internal/storage/factory.go,
-- models.UserRole/GroupRole both declare ProjectID and EnvironmentID as
-- `primaryKey;not null;default:0`); this file is for DBs initialised from
-- the SQL migrations 001-007.
--
-- SQLite can't ALTER a column to add a NOT NULL constraint, nor widen a
-- PRIMARY KEY, in place -- both require a full table rebuild (copy new
-- schema / copy data / drop old / rename), the same idiom
-- 005_secret_sharing.down.sql already uses for secret_nodes. Done as ONE
-- rebuild per table below (not two), since the NOT NULL fix and the PK
-- widening land in the same new table definition. The rebuild uses only
-- standard CREATE TABLE / INSERT ... SELECT / DROP TABLE / RENAME TO
-- statements (no PRAGMA, no AUTOINCREMENT), so -- unlike 005's rebuild --
-- this one remains safe to apply on both PostgreSQL and SQLite >= 3.25.0, as
-- the file's original header claimed. Nothing else in this migration set
-- declares a foreign key INTO user_roles/group_roles, so the rebuild doesn't
-- need to touch foreign-key enforcement at all.

-- 1. Backfill the global sentinel for legacy NULL project scopes, before the
--    rebuild's INSERT ... SELECT copies the data forward.
UPDATE user_roles  SET project_id = 0 WHERE project_id IS NULL;
UPDATE group_roles SET project_id = 0 WHERE project_id IS NULL;

-- 2. Rebuild user_roles: project_id genuinely NOT NULL DEFAULT 0 (previously
--    only backfilled, never actually constrained -- see this file's own
--    history), PRIMARY KEY widened to include environment_id. environment_id
--    itself is added here rather than via a separate ALTER TABLE ADD COLUMN,
--    since the table is being rebuilt anyway.
CREATE TABLE user_roles_new (
  user_id INTEGER NOT NULL REFERENCES users(id),
  role_id INTEGER NOT NULL REFERENCES roles(id),
  project_id INTEGER NOT NULL DEFAULT 0 REFERENCES projects(id),
  environment_id INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, role_id, project_id, environment_id)
);
INSERT INTO user_roles_new (user_id, role_id, project_id, environment_id)
  SELECT user_id, role_id, project_id, 0 FROM user_roles;
DROP TABLE user_roles;
ALTER TABLE user_roles_new RENAME TO user_roles;

-- 3. Rebuild group_roles: identical fix, same reasoning as user_roles above.
CREATE TABLE group_roles_new (
  group_id INTEGER NOT NULL REFERENCES groups(id),
  role_id INTEGER NOT NULL REFERENCES roles(id),
  project_id INTEGER NOT NULL DEFAULT 0 REFERENCES projects(id),
  environment_id INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (group_id, role_id, project_id, environment_id)
);
INSERT INTO group_roles_new (group_id, role_id, project_id, environment_id)
  SELECT group_id, role_id, project_id, 0 FROM group_roles;
DROP TABLE group_roles;
ALTER TABLE group_roles_new RENAME TO group_roles;

-- 4. Recreate every index the DROP TABLE steps above implicitly took with
--    them -- both the ones this migration originally created and the ones
--    002_rbac_enhancements/006_rename_namespace_to_project created earlier
--    (idx_user_roles_user_id, idx_user_roles_role_id, idx_user_roles_project_id
--    and their group_roles equivalents), so the rebuild doesn't silently
--    regress query performance that existed before it ran.
--
-- idx_user_roles_scope / idx_group_roles_scope are now redundant with the
-- 4-column PRIMARY KEY above, which already enforces this exact uniqueness.
-- Kept anyway (rather than dropped) since removing a named index is a
-- bigger behavioral change than this fix's scope, and some caller or
-- tooling may already probe for it by name -- this comment is the record of
-- why two mechanisms enforce the same constraint here, so it isn't
-- mistaken for an oversight later.
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_scope
    ON user_roles (user_id, role_id, project_id, environment_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_group_roles_scope
    ON group_roles (group_id, role_id, project_id, environment_id);

CREATE INDEX IF NOT EXISTS idx_user_roles_environment_id  ON user_roles(environment_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_environment_id ON group_roles(environment_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id     ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id     ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_project_id  ON user_roles(project_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_group_id   ON group_roles(group_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_role_id    ON group_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_project_id ON group_roles(project_id);
