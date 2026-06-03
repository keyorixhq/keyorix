-- RBAC Phase 2: scope role assignments by environment as well as project.
-- Adds environment_id to user_roles and group_roles and normalises the
-- project_id scope column to a 0 = global sentinel (NOT NULL), so scope can
-- participate in uniqueness without nullable-column matching gymnastics.
--
-- Safe to apply on both PostgreSQL and SQLite >= 3.25.0. The runtime path is
-- GORM AutoMigrate (see internal/storage/factory.go); this file is for DBs
-- initialised from the SQL migrations 001-007.

-- 1. Backfill the global sentinel for legacy NULL project scopes
UPDATE user_roles  SET project_id = 0 WHERE project_id IS NULL;
UPDATE group_roles SET project_id = 0 WHERE project_id IS NULL;

-- 2. Add the environment scope column (0 = all environments in scope)
ALTER TABLE user_roles  ADD COLUMN environment_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE group_roles ADD COLUMN environment_id INTEGER NOT NULL DEFAULT 0;

-- 3. Uniqueness guard: one row per (subject, role, project, environment)
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_scope
    ON user_roles (user_id, role_id, project_id, environment_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_group_roles_scope
    ON group_roles (group_id, role_id, project_id, environment_id);

CREATE INDEX IF NOT EXISTS idx_user_roles_environment_id  ON user_roles(environment_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_environment_id ON group_roles(environment_id);
