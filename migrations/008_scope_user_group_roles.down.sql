-- Revert RBAC Phase 2 environment scoping.

DROP INDEX IF EXISTS idx_user_roles_scope;
DROP INDEX IF EXISTS idx_group_roles_scope;
DROP INDEX IF EXISTS idx_user_roles_environment_id;
DROP INDEX IF EXISTS idx_group_roles_environment_id;

ALTER TABLE user_roles  DROP COLUMN environment_id;
ALTER TABLE group_roles DROP COLUMN environment_id;
