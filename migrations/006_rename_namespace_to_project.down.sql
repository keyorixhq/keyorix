-- Reverse migration 006: projects → namespaces, project_id → namespace_id.

ALTER TABLE projects        RENAME TO namespaces;

ALTER TABLE secret_nodes    RENAME COLUMN project_id TO namespace_id;
ALTER TABLE user_roles      RENAME COLUMN project_id TO namespace_id;
ALTER TABLE group_roles     RENAME COLUMN project_id TO namespace_id;
ALTER TABLE rbac_audit_log  RENAME COLUMN project_id TO namespace_id;

DROP INDEX IF EXISTS idx_user_roles_project_id;
CREATE INDEX IF NOT EXISTS idx_user_roles_namespace_id  ON user_roles(namespace_id);

DROP INDEX IF EXISTS idx_group_roles_project_id;
CREATE INDEX IF NOT EXISTS idx_group_roles_namespace_id ON group_roles(namespace_id);

UPDATE permissions
SET name     = 'namespaces.' || SUBSTR(name, LENGTH('projects.') + 1),
    resource = 'namespaces'
WHERE resource = 'projects';

UPDATE roles
SET description = REPLACE(description, 'projects', 'namespaces')
WHERE description LIKE '%projects%'; -- NOSONAR -- plsql:S1739 false positive: one-time migration LIKE scan on a small table is acceptable
