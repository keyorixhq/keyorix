-- Rename namespaces → projects, namespace_id → project_id throughout.
-- Safe to apply on both PostgreSQL and SQLite ≥ 3.25.0.
-- GORM AutoMigrate already creates a `projects` table on fresh installs;
-- this migration is for databases initialised with migrations 001–003.
--
-- ORDERING: this migration must run before 007_rotation_policies (which adds
-- a `project_id INTEGER REFERENCES projects(id)` column) — 007 will fail
-- outright against a database that hasn't renamed namespaces → projects yet.
-- Originally numbered 007/006 respectively; renumbered (see #201) so the
-- table-creating rename actually precedes the migration that depends on it.

-- 1. Rename the primary table
ALTER TABLE namespaces RENAME TO projects;

-- 2. Rename namespace_id columns in all referencing tables
ALTER TABLE secret_nodes    RENAME COLUMN namespace_id TO project_id;
ALTER TABLE user_roles      RENAME COLUMN namespace_id TO project_id;
ALTER TABLE group_roles     RENAME COLUMN namespace_id TO project_id;
ALTER TABLE rbac_audit_log  RENAME COLUMN namespace_id TO project_id;

-- 3. Swap the RBAC indexes to use the new column name
DROP INDEX IF EXISTS idx_user_roles_namespace_id;
CREATE INDEX IF NOT EXISTS idx_user_roles_project_id  ON user_roles(project_id);

DROP INDEX IF EXISTS idx_group_roles_namespace_id;
CREATE INDEX IF NOT EXISTS idx_group_roles_project_id ON group_roles(project_id);

-- 4. Rename namespace permissions → project permissions
UPDATE permissions
SET name     = 'projects.' || SUBSTR(name, LENGTH('namespaces.') + 1),
    resource = 'projects'
WHERE resource = 'namespaces';

-- 5. Update role description strings
UPDATE roles
SET description = REPLACE(description, 'namespaces', 'projects')
WHERE description LIKE '%namespaces%';
